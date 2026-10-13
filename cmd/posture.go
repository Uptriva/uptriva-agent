package main

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

var defaultCertGlobs = []string{
	"/etc/letsencrypt/live/*/cert.pem",
	"/etc/ssl/localcerts/*.pem",
	"/etc/ssl/localcerts/*.crt",
}

var rebootRequiredPaths = []string{
	"/var/run/reboot-required",
	"/run/reboot-required",
}

var (
	certMu           sync.Mutex
	certBands        map[string]string
	lastCertCheck    time.Time
	postureMu        sync.Mutex
	prevReboot       bool
	prevFwActive     bool
	postureReady     bool
	lastPostureCheck time.Time
	containerMu      sync.Mutex
	prevCtrs         map[string]bool
	ctrReady         bool
	ctrCmd           string
	ctrCmdProbe      bool
)

func certPaths(cfg Config) []string {
	seen := map[string]bool{}
	var out []string
	for _, g := range append(append([]string{}, defaultCertGlobs...), cfg.WatchCerts...) {
		matches, err := filepath.Glob(g)
		if err != nil {
			if !seen[g] {
				seen[g] = true
				out = append(out, g)
			}
			continue
		}
		for _, m := range matches {
			if !seen[m] {
				seen[m] = true
				out = append(out, m)
			}
		}
	}
	return out
}

func certExpiryBand(path string) (string, time.Time, string, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", time.Time{}, "", false
	}
	var leaf *x509.Certificate
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}
		if leaf == nil || c.NotAfter.Before(leaf.NotAfter) {
			leaf = c
		}
	}
	if leaf == nil {
		return "", time.Time{}, "", false
	}
	name := leaf.Subject.CommonName
	if name == "" && len(leaf.DNSNames) > 0 {
		name = leaf.DNSNames[0]
	}
	days := time.Until(leaf.NotAfter).Hours() / 24
	switch {
	case days < 0:
		return "expired", leaf.NotAfter, name, true
	case days <= 3:
		return "critical", leaf.NotAfter, name, true
	case days <= 14:
		return "warning", leaf.NotAfter, name, true
	default:
		return "ok", leaf.NotAfter, name, true
	}
}

func collectCertEvents(cfg Config) []agentEventItem {
	certMu.Lock()
	defer certMu.Unlock()

	if time.Since(lastCertCheck) < 5*time.Minute {
		return nil
	}
	lastCertCheck = time.Now()

	if certBands == nil {
		certBands = map[string]string{}
	}
	var events []agentEventItem
	cur := map[string]string{}
	for _, p := range certPaths(cfg) {
		band, expiry, name, ok := certExpiryBand(p)
		if !ok {
			continue
		}
		cur[p] = band
		prev, seen := certBands[p]
		days := int(time.Until(expiry).Hours() / 24)
		meta := map[string]interface{}{"path": p, "cn": name, "expires_at": expiry.Format(time.RFC3339), "days_left": days}
		label := p
		if name != "" {
			label = fmt.Sprintf("%s (%s)", name, p)
		}
		switch {
		case band == "ok":
			if seen && prev != "ok" {
				events = append(events, agentEventItem{
					Type:     "cert_renewed",
					Severity: "info",
					Message:  fmt.Sprintf("Certificate renewed: %s", label),
					Metadata: meta,
				})
			}
		case band == "expired":
			if !seen || prev != "expired" {
				events = append(events, agentEventItem{
					Type:     "cert_expired",
					Severity: "critical",
					Message:  fmt.Sprintf("Certificate expired: %s", label),
					Metadata: meta,
				})
			}
		default:
			if !seen || prev != band {
				sev := "warning"
				if band == "critical" {
					sev = "critical"
				}
				events = append(events, agentEventItem{
					Type:     "cert_expiring",
					Severity: sev,
					Message:  fmt.Sprintf("Certificate expires in %dd: %s", days, label),
					Metadata: meta,
				})
			}
		}
	}
	for p, prev := range certBands {
		if _, ok := cur[p]; !ok && prev != "gone" {
			events = append(events, agentEventItem{
				Type:     "cert_removed",
				Severity: "info",
				Message:  fmt.Sprintf("Watched certificate gone: %s", p),
				Metadata: map[string]interface{}{"path": p},
			})
		}
	}
	for p := range certBands {
		if _, ok := cur[p]; !ok {
			certBands[p] = "gone"
		}
	}
	for p, b := range cur {
		certBands[p] = b
	}
	if len(events) > 20 {
		events = events[:20]
	}
	return events
}

func rebootRequired() bool {
	for _, p := range rebootRequiredPaths {
		if _, err := os.Stat(p); err == nil {
			return true
		}
	}
	if _, err := exec.LookPath("needs-restarting"); err == nil {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "needs-restarting", "-r")
		if err := cmd.Run(); err != nil {
			if ee, ok := err.(*exec.ExitError); ok && ee.ExitCode() == 1 {
				return true
			}
		}
	}
	return false
}

func commandOutput(args ...string) (string, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, args[0], args[1:]...).Output()
	if err != nil {
		return "", false
	}
	return string(out), true
}

func firewallActive() (string, bool) {
	if _, err := exec.LookPath("ufw"); err == nil {
		if out, ok := commandOutput("ufw", "status"); ok && strings.Contains(out, "Status: active") {
			return "ufw", true
		}
	}
	if _, err := exec.LookPath("firewall-cmd"); err == nil {
		if _, ok := commandOutput("firewall-cmd", "--state"); ok {
			return "firewalld", true
		}
	}
	if _, err := exec.LookPath("nft"); err == nil {
		if out, ok := commandOutput("nft", "list", "ruleset"); ok && strings.Contains(out, "table ") {
			return "nftables", true
		}
	}
	if _, err := exec.LookPath("iptables"); err == nil {
		if out, ok := commandOutput("iptables", "-S"); ok {
			for _, line := range strings.Split(out, "\n") {
				if strings.HasPrefix(line, "-A ") || strings.HasPrefix(line, "-N ") {
					return "iptables", true
				}
			}
		}
	}
	return "", false
}

func collectPostureEvents() []agentEventItem {
	if runtime.GOOS != "linux" {
		return nil
	}
	postureMu.Lock()
	defer postureMu.Unlock()

	if postureReady && time.Since(lastPostureCheck) < 5*time.Minute {
		return nil
	}
	lastPostureCheck = time.Now()

	reboot := rebootRequired()
	fwName, fwActive := firewallActive()

	var events []agentEventItem
	if !postureReady {
		postureReady = true
		prevReboot = reboot
		prevFwActive = fwActive
		if reboot {
			events = append(events, agentEventItem{
				Type:     "reboot_required",
				Severity: "warning",
				Message:  "System reboot required (pending kernel/package updates)",
			})
		}
		if !fwActive {
			events = append(events, agentEventItem{
				Type:     "firewall_inactive",
				Severity: "warning",
				Message:  "No active host firewall detected (ufw, firewalld, nftables, iptables)",
			})
		}
		return events
	}

	if reboot != prevReboot {
		if reboot {
			events = append(events, agentEventItem{
				Type:     "reboot_required",
				Severity: "warning",
				Message:  "System reboot required (pending kernel/package updates)",
			})
		} else {
			events = append(events, agentEventItem{
				Type:     "reboot_cleared",
				Severity: "info",
				Message:  "Pending reboot cleared",
			})
		}
		prevReboot = reboot
	}
	if fwActive != prevFwActive {
		if fwActive {
			events = append(events, agentEventItem{
				Type:     "firewall_active",
				Severity: "info",
				Message:  fmt.Sprintf("Host firewall active (%s)", fwName),
			})
		} else {
			events = append(events, agentEventItem{
				Type:     "firewall_inactive",
				Severity: "warning",
				Message:  "Host firewall became inactive",
			})
		}
		prevFwActive = fwActive
	}
	return events
}

func containerCmd() string {
	if ctrCmdProbe {
		return ctrCmd
	}
	ctrCmdProbe = true
	for _, c := range []string{"docker", "podman"} {
		if _, err := exec.LookPath(c); err == nil {
			ctrCmd = c
			break
		}
	}
	return ctrCmd
}

func runningContainers() (map[string]bool, bool) {
	c := containerCmd()
	if c == "" {
		return nil, false
	}
	out, ok := commandOutput(c, "ps", "--format", "{{.Names}}")
	if !ok {
		return nil, false
	}
	set := map[string]bool{}
	for _, line := range strings.Split(out, "\n") {
		name := strings.TrimSpace(line)
		if name != "" {
			set[name] = true
		}
	}
	return set, true
}

func collectContainerEvents() []agentEventItem {
	if runtime.GOOS != "linux" {
		return nil
	}
	if containerCmd() == "" {
		return nil
	}
	containerMu.Lock()
	defer containerMu.Unlock()

	cur, ok := runningContainers()
	if !ok {
		return nil
	}
	if !ctrReady {
		ctrReady = true
		prevCtrs = cur
		return nil
	}

	var events []agentEventItem
	for name := range cur {
		if !prevCtrs[name] {
			events = append(events, agentEventItem{
				Type:     "container_started",
				Severity: "info",
				Message:  fmt.Sprintf("Container started: %s", name),
				Metadata: map[string]interface{}{"container": name},
			})
		}
	}
	for name := range prevCtrs {
		if !cur[name] {
			events = append(events, agentEventItem{
				Type:     "container_stopped",
				Severity: "warning",
				Message:  fmt.Sprintf("Container stopped: %s", name),
				Metadata: map[string]interface{}{"container": name},
			})
		}
	}
	prevCtrs = cur
	if len(events) > 20 {
		events = events[:20]
	}
	return events
}
