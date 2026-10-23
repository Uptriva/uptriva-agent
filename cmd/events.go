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
)

type agentEventItem struct {
	Type     string                 `json:"type"`
	Severity string                 `json:"severity"`
	Message  string                 `json:"message"`
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

var (
	eventStateMu       sync.Mutex
	prevWatchedRunning map[string]bool
	prevFailedUnits    map[string]bool
	prevInterfaceUp    map[string]bool
	eventStateReady    bool
)

func processNameSet() map[string]bool {
	set := map[string]bool{}
	var names []string
	if err := json.Unmarshal([]byte(getRunningProcesses()), &names); err != nil {
		return set
	}
	for _, n := range names {
		set[strings.ToLower(n)] = true
	}
	return set
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

	procSet := processNameSet()
	nextWatched := map[string]bool{}
	for _, svc := range cfg.WatchServices {
		name := strings.ToLower(strings.TrimSpace(svc))
		if name == "" {
			continue
		}
		running := procSet[name]
		nextWatched[name] = running
		if eventStateReady {
			if prevWatchedRunning[name] && !running {
				events = append(events, agentEventItem{
					Type:     "process_exit",
					Severity: "critical",
					Message:  fmt.Sprintf("Watched process '%s' exited", name),
					Metadata: map[string]interface{}{"process": name},
				})
			} else if !prevWatchedRunning[name] && running {
				events = append(events, agentEventItem{
					Type:     "process_recovered",
					Severity: "info",
					Message:  fmt.Sprintf("Watched process '%s' is running again", name),
					Metadata: map[string]interface{}{"process": name},
				})
			}
		}
	}
	prevWatchedRunning = nextWatched

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
