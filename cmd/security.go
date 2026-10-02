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

	counts := map[string]int{}
	var order []string
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		line := scanner.Text()
		for _, p := range authFailurePatterns {
			if strings.Contains(line, p) {
				if _, ok := counts[p]; !ok {
					order = append(order, p)
				}
				counts[p]++
				break
			}
		}
	}

	var events []agentEventItem
	for _, p := range order {
		events = append(events, agentEventItem{
			Type:     "auth_failed",
			Severity: "warning",
			Message:  fmt.Sprintf("Failed authentication: %d attempt(s) matching %q", counts[p], p),
			Metadata: map[string]interface{}{"pattern": p, "count": counts[p]},
		})
		if len(events) >= 20 {
			break
		}
	}
	return events
}
