package main

import (
	"bufio"
	"context"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"
)

type packageUpdateInfo struct {
	Manager         string
	Updates         int
	SecurityUpdates int
	Checked         bool
}

var (
	pkgCacheMu     sync.Mutex
	lastPkgCheck   time.Time
	lastPkgInfo    packageUpdateInfo
	prevPkgUpdates = -1
)

func countLinesWith(text, needle string) int {
	count := 0
	scanner := bufio.NewScanner(strings.NewReader(text))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "Listing") {
			continue
		}
		if needle == "" || strings.Contains(line, needle) {
			count++
		}
	}
	return count
}

func runPkgProbe(name string, args ...string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil && len(out) == 0 {
		return ""
	}
	return string(out)
}

func probePackageUpdates() packageUpdateInfo {
	if runtime.GOOS != "linux" {
		return packageUpdateInfo{}
	}

	if _, err := exec.LookPath("apt"); err == nil {
		out := runPkgProbe("apt", "list", "--upgradable")
		return packageUpdateInfo{
			Manager:         "apt",
			Updates:         countLinesWith(out, ""),
			SecurityUpdates: countLinesWith(out, "security"),
			Checked:         true,
		}
	}
	if _, err := exec.LookPath("dnf"); err == nil {
		out := runPkgProbe("dnf", "-q", "check-update")
		return packageUpdateInfo{
			Manager:         "dnf",
			Updates:         countLinesWith(out, ""),
			SecurityUpdates: countLinesWith(out, "security"),
			Checked:         true,
		}
	}
	if _, err := exec.LookPath("yum"); err == nil {
		out := runPkgProbe("yum", "-q", "check-update")
		return packageUpdateInfo{
			Manager:         "yum",
			Updates:         countLinesWith(out, ""),
			SecurityUpdates: countLinesWith(out, "security"),
			Checked:         true,
		}
	}
	if _, err := exec.LookPath("checkupdates"); err == nil {
		out := runPkgProbe("checkupdates")
		return packageUpdateInfo{
			Manager: "pacman",
			Updates: countLinesWith(out, ""),
			Checked: true,
		}
	}
	return packageUpdateInfo{}
}

func collectPackageEvents() []agentEventItem {
	pkgCacheMu.Lock()
	defer pkgCacheMu.Unlock()

	if time.Since(lastPkgCheck) < 30*time.Minute {
		return nil
	}
	lastPkgCheck = time.Now()

	info := probePackageUpdates()
	if !info.Checked {
		return nil
	}
	lastPkgInfo = info

	var events []agentEventItem
	if prevPkgUpdates >= 0 && info.Updates != prevPkgUpdates {
		severity := "info"
		eventType := "pkg_updates_available"
		if info.SecurityUpdates > 0 {
			severity = "warning"
		}
		if info.Updates == 0 {
			eventType = "pkg_updates_cleared"
		}
		events = append(events, agentEventItem{
			Type:     eventType,
			Severity: severity,
			Message:  fmt.Sprintf("%d package updates pending via %s (%d security)", info.Updates, info.Manager, info.SecurityUpdates),
			Metadata: map[string]interface{}{
				"manager":          info.Manager,
				"updates":          info.Updates,
				"security_updates": info.SecurityUpdates,
			},
		})
	}
	prevPkgUpdates = info.Updates
	return events
}
