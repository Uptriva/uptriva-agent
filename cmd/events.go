package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v3/process"
)

type agentEventItem struct {
	Type     string                 `json:"type"`
	Severity string                 `json:"severity"`
	Message  string                 `json:"message"`
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

var (
	eventStateMu    sync.Mutex
	prevWatchedPID  map[string]int32
	seenWatchedProc map[string]bool
	procStateReady  bool
	prevFailedUnits map[string]bool
	prevInterfaceUp map[string]bool
	eventStateReady bool
)

func processNamePIDMap() map[string]int32 {
	set := map[string]int32{}
	procs, err := process.Processes()
	if err != nil {
		return set
	}
	for _, p := range procs {
		name, err := p.Name()
		if err != nil || name == "" {
			continue
		}
		key := strings.ToLower(name)
		if cur, ok := set[key]; !ok || p.Pid < cur {
			set[key] = p.Pid
		}
	}
	return set
}

func collectProcessEvents(cfg Config) []agentEventItem {
	eventStateMu.Lock()
	defer eventStateMu.Unlock()

	var events []agentEventItem
	procSet := processNamePIDMap()
	nextWatched := map[string]int32{}
	if seenWatchedProc == nil {
		seenWatchedProc = map[string]bool{}
	}
	for _, svc := range cfg.WatchServices {
		name := strings.ToLower(strings.TrimSpace(svc))
		if name == "" {
			continue
		}
		pid, running := procSet[name]
		if running {
			nextWatched[name] = pid
		}
		firstSeen := !seenWatchedProc[name]
		seenWatchedProc[name] = true
		if procStateReady && !firstSeen {
			prevPID, wasRunning := prevWatchedPID[name]
			switch {
			case wasRunning && !running:
				events = append(events, agentEventItem{
					Type:     "process_exit",
					Severity: "critical",
					Message:  fmt.Sprintf("Watched process '%s' exited", name),
					Metadata: map[string]interface{}{"process": name},
				})
			case !wasRunning && running:
				events = append(events, agentEventItem{
					Type:     "process_recovered",
					Severity: "info",
					Message:  fmt.Sprintf("Watched process '%s' is running again", name),
					Metadata: map[string]interface{}{"process": name},
				})
			case wasRunning && running && prevPID != pid:
				events = append(events, agentEventItem{
					Type:     "process_restart",
					Severity: "warning",
					Message:  fmt.Sprintf("Watched process '%s' restarted (pid %d → %d)", name, prevPID, pid),
					Metadata: map[string]interface{}{"process": name, "pid": pid, "previous_pid": prevPID},
				})
			}
		}
	}
	prevWatchedPID = nextWatched
	procStateReady = true
	return events
}

func interfaceUpMap() map[string]bool {
	set := map[string]bool{}
	ifaces, err := net.Interfaces()
	if err != nil {
		return set
	}
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		set[ifc.Name] = ifc.Flags&net.FlagUp != 0
	}
	return set
}

func collectAgentEvents(cfg Config) []agentEventItem {
	eventStateMu.Lock()
	defer eventStateMu.Unlock()

	var events []agentEventItem

	failed := getFailedSystemdUnits()
	nextFailed := map[string]bool{}
	for _, u := range failed {
		nextFailed[u] = true
		if eventStateReady && !prevFailedUnits[u] {
			restarts := unitRestartCount(u)
			msg := fmt.Sprintf("systemd unit '%s' entered failed state", u)
			if restarts > 0 {
				msg = fmt.Sprintf("systemd unit '%s' entered failed state (restart #%d)", u, restarts)
			}
			events = append(events, agentEventItem{
				Type:     "unit_failed",
				Severity: "critical",
				Message:  msg,
				Metadata: map[string]interface{}{"unit": u, "restart_count": restarts},
			})
		}
	}
	for u := range prevFailedUnits {
		if !nextFailed[u] {
			events = append(events, agentEventItem{
				Type:     "unit_recovered",
				Severity: "info",
				Message:  fmt.Sprintf("systemd unit '%s' recovered", u),
				Metadata: map[string]interface{}{"unit": u, "restart_count": unitRestartCount(u)},
			})
		}
	}
	prevFailedUnits = nextFailed

	ifUp := interfaceUpMap()
	if eventStateReady {
		for name, up := range ifUp {
			prev, seen := prevInterfaceUp[name]
			if !seen {
				continue
			}
			if prev && !up {
				events = append(events, agentEventItem{
					Type:     "interface_down",
					Severity: "critical",
					Message:  fmt.Sprintf("Network interface '%s' went down", name),
					Metadata: map[string]interface{}{"interface": name},
				})
			} else if !prev && up {
				events = append(events, agentEventItem{
					Type:     "interface_up",
					Severity: "info",
					Message:  fmt.Sprintf("Network interface '%s' came up", name),
					Metadata: map[string]interface{}{"interface": name},
				})
			}
		}
	}
	prevInterfaceUp = ifUp

	eventStateReady = true

	if cfg.SecurityEventsEnabled || envFlagEnabled("AGENT_SECURITY_EVENTS") {
		events = append(events, collectSecurityEvents()...)
	}
	if cfg.PackageMonitoringEnabled || envFlagEnabled("AGENT_PKG_MONITORING") {
		events = append(events, collectPackageEvents()...)
	}
	if cfg.PortWatchEnabled || envFlagEnabled("AGENT_PORT_WATCH") {
		events = append(events, collectPortEvents()...)
	}
	if cfg.IntegrityMonitoringEnabled || envFlagEnabled("AGENT_INTEGRITY_MON") {
		events = append(events, collectIntegrityEvents(cfg)...)
	}
	if cfg.KernelEventsEnabled || envFlagEnabled("AGENT_KERNEL_EVENTS") {
		events = append(events, collectKernelEvents()...)
	}
	if cfg.CertWatchEnabled || envFlagEnabled("AGENT_CERT_WATCH") {
		events = append(events, collectCertEvents(cfg)...)
	}
	if cfg.SystemPostureEnabled || envFlagEnabled("AGENT_SYSTEM_POSTURE") {
		events = append(events, collectPostureEvents()...)
	}
	if cfg.ContainerWatchEnabled || envFlagEnabled("AGENT_CONTAINER_WATCH") {
		events = append(events, collectContainerEvents()...)
	}
	if cfg.LogWatchEnabled || envFlagEnabled("AGENT_LOG_WATCH") {
		events = append(events, collectLogWatchEvents(cfg)...)
	}
	return events
}

func sendAgentEvents(cfg Config, events []agentEventItem) {
	b, err := json.Marshal(map[string]interface{}{"events": events})
	if err != nil {
		return
	}
	req, err := http.NewRequest("POST", cfg.APIURL+"/api/v1/uptime/agents/events", bytes.NewBuffer(b))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Agent-Token", cfg.Token)
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("[agent] failed to send events: %v\n", err)
		return
	}
	resp.Body.Close()
}
