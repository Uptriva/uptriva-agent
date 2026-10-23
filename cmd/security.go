package main

import (
	"bufio"
	"context"
	"fmt"
	"os/exec"
	"runtime"
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
	if runtime.GOOS != "linux" {
		return nil
	}
	if _, err := exec.LookPath("journalctl"); err != nil {
		return nil
	}

	now := time.Now()
	if lastSecurityCheck.IsZero() {
		lastSecurityCheck = now
		return nil
	}
	since := lastSecurityCheck
	lastSecurityCheck = now

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

	type failKey struct {
		source  string
		pattern string
	}
	counts := map[failKey]int{}
	var order []failKey
	var logins []agentEventItem
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	scanner.Buffer(make([]byte, 0, 256*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		matched := false
		for _, p := range authFailurePatterns {
			if strings.Contains(line, p) {
				_, src := parseSSHLoginLine(line)
				k := failKey{source: src, pattern: p}
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
