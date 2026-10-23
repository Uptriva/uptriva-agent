package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	gopsnet "github.com/shirou/gopsutil/v3/net"
)

var defaultIntegrityWatchFiles = []string{
	"/etc/passwd",
	"/etc/shadow",
	"/etc/group",
	"/etc/ssh/sshd_config",
	"/etc/crontab",
	"/root/.ssh/authorized_keys",
}

var defaultIntegrityWatchGlobs = []string{
	"/home/*/.ssh/authorized_keys",
}

func integrityWatchGlobs() []string {
	switch runtime.GOOS {
	case "darwin":
		return []string{"/Users/*/.ssh/authorized_keys"}
	case "windows":
		return []string{`C:\Users\*\.ssh\authorized_keys`}
	}
	return defaultIntegrityWatchGlobs
}

var (
	integrityMu     sync.Mutex
	integrityHashes map[string]string
	prevPasswdUsers map[string]int
	integrityReady  bool

	portWatchMu    sync.Mutex
	prevListenSock map[string]bool
	portWatchReady bool

	lastKernelCheck time.Time
)

func listeningSockets() map[string]bool {
	if runtime.GOOS != "linux" {
		return listeningSocketsGopsutil()
	}
	set := map[string]bool{}
	for _, f := range []struct {
		path  string
		proto string
	}{
		{"/proc/net/tcp", "tcp"},
		{"/proc/net/tcp6", "tcp6"},
	} {
		file, err := os.Open(f.path)
		if err != nil {
			continue
		}
		local := map[string]bool{}
		scanner := bufio.NewScanner(file)
		scanner.Scan()
		for scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			if len(fields) < 4 || fields[3] != "0A" {
				continue
			}
			laddr := fields[1]
			idx := strings.LastIndex(laddr, ":")
			if idx < 0 {
				continue
			}
			port, err := strconv.ParseUint(laddr[idx+1:], 16, 16)
			if err != nil || port == 0 {
				continue
			}
			local[fmt.Sprintf("%s/%d", f.proto, port)] = true
		}
		if scanner.Err() == nil {
			for s := range local {
				set[s] = true
			}
		}
		file.Close()
	}
	return set
}

func listeningSocketsGopsutil() map[string]bool {
	set := map[string]bool{}
	conns, err := gopsnet.Connections("tcp")
	if err != nil {
		return set
	}
	for _, c := range conns {
		if c.Status != "LISTEN" || c.Laddr.Port == 0 {
			continue
		}
		set[fmt.Sprintf("tcp/%d", c.Laddr.Port)] = true
	}
	return set
}

func collectPortEvents() []agentEventItem {
	portWatchMu.Lock()
	defer portWatchMu.Unlock()

	cur := listeningSockets()
	if !portWatchReady {
		portWatchReady = true
		prevListenSock = cur
		return nil
	}

	var events []agentEventItem
	for s := range cur {
		if !prevListenSock[s] {
			events = append(events, agentEventItem{
				Type:     "listener_opened",
				Severity: "warning",
				Message:  fmt.Sprintf("New listening socket %s", s),
				Metadata: map[string]interface{}{"socket": s},
			})
		}
	}
	for s := range prevListenSock {
		if !cur[s] {
			events = append(events, agentEventItem{
				Type:     "listener_closed",
				Severity: "info",
				Message:  fmt.Sprintf("Listening socket %s closed", s),
				Metadata: map[string]interface{}{"socket": s},
			})
		}
	}
	prevListenSock = cur
	if len(events) > 20 {
		events = events[:20]
	}
	return events
}

func localUserNames() map[string]int {
	switch runtime.GOOS {
	case "linux":
		return parsePasswdUsers()
	case "darwin":
		return parseDsclUsers()
	case "windows":
		return parseWindowsUsers()
	}
	return nil
}

func parseDsclUsers() map[string]int {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "dscl", ".", "-list", "/Users", "UniqueID").Output()
	if err != nil {
		return nil
	}
	users := map[string]int{}
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] == "" {
			continue
		}
		uid, err := strconv.Atoi(fields[len(fields)-1])
		if err != nil {
			continue
		}
		users[fields[0]] = uid
	}
	return users
}

func parseWindowsUsers() map[string]int {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command",
		"Get-LocalUser | Select-Object -ExpandProperty Name").Output()
	if err != nil {
		return nil
	}
	users := map[string]int{}
	for _, line := range strings.Split(string(out), "\n") {
		name := strings.TrimSpace(line)
		if name != "" {
			users[name] = 0
		}
	}
	return users
}

func parsePasswdUsers() map[string]int {
	f, err := os.Open("/etc/passwd")
	if err != nil {
		return nil
	}
	defer f.Close()
	users := map[string]int{}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), ":")
		if len(fields) < 3 || fields[0] == "" {
			continue
		}
		uid, err := strconv.Atoi(fields[2])
		if err != nil {
			continue
		}
		users[fields[0]] = uid
	}
	if scanner.Err() != nil {
		return nil
	}
	return users
}

func collectIntegrityEvents(cfg Config) []agentEventItem {
	integrityMu.Lock()
	defer integrityMu.Unlock()

	watchSet := append([]string{}, defaultIntegrityWatchFiles...)
	watchSet = append(watchSet, cfg.WatchFiles...)
	switch runtime.GOOS {
	case "darwin":
		watchSet = append(watchSet, "/etc/ssh/sshd_config", "/var/root/.ssh/authorized_keys", "/etc/crontab")
	case "windows":
		watchSet = append(watchSet,
			`C:\ProgramData\ssh\sshd_config`,
			`C:\ProgramData\ssh\administrators_authorized_keys`)
	}
	for _, glob := range integrityWatchGlobs() {
		if matches, err := filepath.Glob(glob); err == nil {
			watchSet = append(watchSet, matches...)
		}
	}

	hashes := map[string]string{}
	for _, p := range watchSet {
		if h, err := fileSHA256(p); err == nil {
			hashes[p] = h
		}
	}
	passwdUsers := localUserNames()

	if !integrityReady {
		integrityReady = true
		integrityHashes = hashes
		if passwdUsers != nil {
			prevPasswdUsers = passwdUsers
		}
		return nil
	}

	var events []agentEventItem
	for p, h := range hashes {
		prev, existed := integrityHashes[p]
		if !existed {
			events = append(events, agentEventItem{
				Type:     "integrity_file_added",
				Severity: "info",
				Message:  fmt.Sprintf("Watched file appeared: %s", p),
				Metadata: map[string]interface{}{"path": p},
			})
		} else if prev != h {
			events = append(events, agentEventItem{
				Type:     "integrity_file_changed",
				Severity: "warning",
				Message:  fmt.Sprintf("Watched file changed: %s", p),
				Metadata: map[string]interface{}{"path": p},
			})
		}
	}
	for p := range integrityHashes {
		if _, ok := hashes[p]; !ok {
			events = append(events, agentEventItem{
				Type:     "integrity_file_removed",
				Severity: "warning",
				Message:  fmt.Sprintf("Watched file removed: %s", p),
				Metadata: map[string]interface{}{"path": p},
			})
		}
	}

	if passwdUsers != nil {
		for name, uid := range passwdUsers {
			if _, ok := prevPasswdUsers[name]; !ok {
				severity := "warning"
				msg := fmt.Sprintf("New user account '%s' (uid %d)", name, uid)
				if uid == 0 {
					severity = "critical"
					msg = fmt.Sprintf("New user account '%s' with uid 0", name)
				}
				events = append(events, agentEventItem{
					Type:     "user_added",
					Severity: severity,
					Message:  msg,
					Metadata: map[string]interface{}{"user": name, "uid": uid},
				})
			}
		}
		for name, uid := range prevPasswdUsers {
			if _, ok := passwdUsers[name]; !ok {
				events = append(events, agentEventItem{
					Type:     "user_removed",
					Severity: "info",
					Message:  fmt.Sprintf("User account '%s' removed (uid %d)", name, uid),
					Metadata: map[string]interface{}{"user": name, "uid": uid},
				})
			}
		}
		prevPasswdUsers = passwdUsers
	}

	integrityHashes = hashes
	if len(events) > 20 {
		events = events[:20]
	}
	return events
}

var kernelEventPatterns = []struct {
	Type     string
	Severity string
	Needles  []string
}{
	{"oom_kill", "critical", []string{"Out of memory: Killed process", "invoked oom-killer"}},
	{"process_segfault", "warning", []string{"segfault at"}},
	{"hardware_error", "warning", []string{"Hardware Error", "mce:", "EDAC"}},
}

func collectKernelEvents() []agentEventItem {
	if runtime.GOOS != "linux" {
		return nil
	}
	if _, err := exec.LookPath("journalctl"); err != nil {
		return nil
	}

	now := time.Now()
	if lastKernelCheck.IsZero() {
		lastKernelCheck = now
		return nil
	}
	since := lastKernelCheck
	lastKernelCheck = now

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "journalctl",
		"-k",
		"--since", since.Format("2006-01-02 15:04:05"),
		"--no-pager", "-q", "-o", "cat")
	out, err := cmd.Output()
	if err != nil {
		return nil
	}

	type hit struct {
		count  int
		sample string
	}
	hits := map[string]*hit{}
	order := []string{}
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	scanner.Buffer(make([]byte, 0, 256*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		for _, p := range kernelEventPatterns {
			matched := false
			for _, needle := range p.Needles {
				if strings.Contains(line, needle) {
					matched = true
					break
				}
			}
			if !matched {
				continue
			}
			h, ok := hits[p.Type]
			if !ok {
				h = &hit{}
				hits[p.Type] = h
				order = append(order, p.Type)
			}
			h.count++
			if h.sample == "" {
				if len(line) > 200 {
					line = line[:200]
				}
				h.sample = line
			}
			break
		}
	}

	var events []agentEventItem
	for _, t := range order {
		severity := "warning"
		for _, p := range kernelEventPatterns {
			if p.Type == t {
				severity = p.Severity
				break
			}
		}
		h := hits[t]
		events = append(events, agentEventItem{
			Type:     t,
			Severity: severity,
			Message:  fmt.Sprintf("Kernel reported %d %s event(s): %s", h.count, t, h.sample),
			Metadata: map[string]interface{}{"count": h.count, "sample": h.sample},
		})
		if len(events) >= 20 {
			break
		}
	}
	return events
}
