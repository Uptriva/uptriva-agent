package main

import (
	"bufio"
	"context"
	"fmt"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"
)

var lastSecurityCheck time.Time

var authFailurePatterns = []string{
	"Failed password",
	"authentication failure",
	"Invalid user",
	"sudo: authentication failure",
	"possible break-in attempt",
}

var authSuccessPatterns = []string{
	"Accepted password",
	"Accepted publickey",
	"Accepted keyboard-interactive",
}

func collectSecurityEvents() []agentEventItem {
	now := time.Now()
	if lastSecurityCheck.IsZero() {
		lastSecurityCheck = now
		return nil
	}
	since := lastSecurityCheck
	lastSecurityCheck = now

	switch runtime.GOOS {
	case "linux":
		return collectSecurityEventsLinux(since)
	case "darwin":
		return collectSecurityEventsDarwin(since)
	case "windows":
		return collectSecurityEventsWindows(since)
	}
	return nil
}

func collectSecurityEventsLinux(since time.Time) []agentEventItem {
	if _, err := exec.LookPath("journalctl"); err != nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "journalctl",
		"-u", "ssh", "-u", "sshd", "-u", "sudo",
		"--since", since.Format("2006-01-02 15:04:05"),
		"--no-pager", "-q", "-o", "cat")
	out, err := cmd.Output()
	if err != nil {
		return nil
	}
	return parseAuthLines(string(out))
}

func collectSecurityEventsDarwin(since time.Time) []agentEventItem {
	dur := time.Since(since)
	if dur < time.Second {
		dur = time.Second
	}
	if dur > time.Hour {
		dur = time.Hour
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "log", "show",
		"--last", fmt.Sprintf("%ds", int(dur.Seconds())),
		"--style", "compact",
		"--predicate", `process == "sshd" OR process == "sudo"`)
	out, err := cmd.Output()
	if err != nil {
		return nil
	}
	return parseAuthLines(string(out))
}

func collectSecurityEventsWindows(since time.Time) []agentEventItem {
	ms := int(time.Since(since).Milliseconds())
	if ms < 1000 {
		ms = 1000
	}
	if ms > int(time.Hour.Milliseconds()) {
		ms = int(time.Hour.Milliseconds())
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	query := fmt.Sprintf("*[System[(EventID=4624 or EventID=4625) and TimeCreated[timediff(@SystemTime) <= %d]]]", ms)
	cmd := exec.CommandContext(ctx, "wevtutil", "qe", "Security", "/q:"+query, "/f:text", "/c:500")
	out, err := cmd.Output()
	if err != nil {
		return nil
	}
	return parseWindowsSecurityLog(string(out))
}

func parseAuthLines(out string) []agentEventItem {
	counts := map[authFailKey]int{}
	var order []authFailKey
	var logins []agentEventItem
	scanner := bufio.NewScanner(strings.NewReader(out))
	scanner.Buffer(make([]byte, 0, 256*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		matched := false
		for _, p := range authFailurePatterns {
			if strings.Contains(line, p) {
				_, src := parseSSHLoginLine(line)
				k := authFailKey{source: src, pattern: p}
				if _, ok := counts[k]; !ok {
					order = append(order, k)
				}
				counts[k]++
				matched = true
				break
			}
		}
		if matched {
			continue
		}
		for _, p := range authSuccessPatterns {
			if !strings.Contains(line, p) {
				continue
			}
			user, src := parseSSHLoginLine(line)
			msg := "Successful SSH login"
			if user != "" && src != "" {
				msg = fmt.Sprintf("Successful SSH login: %s from %s", user, src)
			} else if user != "" {
				msg = fmt.Sprintf("Successful SSH login: %s", user)
			}
			logins = append(logins, agentEventItem{
				Type:     "ssh_login",
				Severity: "info",
				Message:  msg,
				Metadata: map[string]interface{}{"user": user, "source": src},
			})
			break
		}
	}
	if len(logins) > 10 {
		logins = logins[:10]
	}
	return buildAuthEvents(logins, counts, order)
}

type authFailKey struct {
	source  string
	pattern string
}

func buildAuthEvents(logins []agentEventItem, counts map[authFailKey]int, order []authFailKey) []agentEventItem {
	var events []agentEventItem
	events = append(events, logins...)
	for _, k := range order {
		msg := fmt.Sprintf("Failed authentication: %d attempt(s) matching %q", counts[k], k.pattern)
		if k.source != "" {
			msg = fmt.Sprintf("Failed authentication: %d attempt(s) from %s", counts[k], k.source)
		}
		events = append(events, agentEventItem{
			Type:     "auth_failed",
			Severity: "warning",
			Message:  msg,
			Metadata: map[string]interface{}{"pattern": k.pattern, "source": k.source, "count": counts[k]},
		})
		if len(events) >= 20 {
			break
		}
	}
	return events
}

func windowsEventField(block, name string) string {
	idx := strings.Index(block, name+":")
	if idx < 0 {
		return ""
	}
	rest := block[idx+len(name)+1:]
	if nl := strings.Index(rest, "\n"); nl >= 0 {
		rest = rest[:nl]
	}
	return strings.TrimSpace(rest)
}

func parseWindowsSecurityLog(out string) []agentEventItem {
	blocks := strings.Split(out, "Event[")
	var logins []agentEventItem
	counts := map[authFailKey]int{}
	var order []authFailKey

	for _, block := range blocks {
		idStr := windowsEventField(block, "Event ID")
		eventID, err := strconv.Atoi(idStr)
		if err != nil {
			continue
		}
		src := windowsEventField(block, "Source Network Address")
		if src == "" {
			src = windowsEventField(block, "Source Address")
		}
		if src == "-" {
			src = ""
		}

		switch eventID {
		case 4625:
			user := windowsEventField(block, "Account Name")
			k := authFailKey{source: src, pattern: "logon_failure"}
			if user != "" {
				k.pattern = "logon_failure:" + user
			}
			if _, ok := counts[k]; !ok {
				order = append(order, k)
			}
			counts[k]++
		case 4624:
			lt, err := strconv.Atoi(windowsEventField(block, "Logon Type"))
			if err != nil || (lt != 3 && lt != 10 && lt != 11) {
				continue
			}
			account := windowsEventField(block, "Account Name")
			if account == "" || strings.HasSuffix(account, "$") {
				continue
			}
			msg := fmt.Sprintf("Remote logon (type %d): %s", lt, account)
			if src != "" {
				msg = fmt.Sprintf("Remote logon (type %d): %s from %s", lt, account, src)
			}
			logins = append(logins, agentEventItem{
				Type:     "remote_login",
				Severity: "info",
				Message:  msg,
				Metadata: map[string]interface{}{"user": account, "source": src, "logon_type": lt},
			})
		}
	}
	if len(logins) > 10 {
		logins = logins[:10]
	}
	return buildAuthEvents(logins, counts, order)
}

func parseSSHLoginLine(line string) (string, string) {
	user := ""
	src := ""
	fields := strings.Fields(line)
	for i, f := range fields {
		if f == "for" && i+1 < len(fields) && user == "" {
			user = fields[i+1]
		}
		if f == "from" && i+1 < len(fields) && src == "" {
			src = fields[i+1]
		}
	}
	return user, src
}
