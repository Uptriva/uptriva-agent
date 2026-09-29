package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"time"
)

const commandPollInterval = 15 * time.Second
const commandExecTimeout = 120 * time.Second

type AgentCommandPoll struct {
	ID      string `json:"id"`
	Command string `json:"command"`
	Params  string `json:"params"`
}

func agentHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
		},
	}
}

func pollAgentCommands(apiURL, token string) {
	req, err := http.NewRequest("GET", apiURL+"/api/v1/uptime/agents/commands", nil)
	if err != nil {
		return
	}
	req.Header.Set("X-Agent-Token", token)
	resp, err := agentHTTPClient().Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return
	}
	var out struct {
		Commands []AgentCommandPoll `json:"commands"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return
	}
	for _, cmd := range out.Commands {
		cmd := cmd
		go executeAgentCommand(apiURL, token, cmd)
	}
}

func executeAgentCommand(apiURL, token string, cmd AgentCommandPoll) {
	var params map[string]string
	if cmd.Params != "" {
		_ = json.Unmarshal([]byte(cmd.Params), &params)
	}

	status := "completed"
	var result string

	if cmd.Command == "reboot_host" {
		ackAgentCommand(apiURL, token, cmd.ID, "completed", "reboot scheduled")
		rebootHost()
		return
	}

	switch cmd.Command {
	case "restart_service":
		result = restartService(params["service"])
	case "exec_script":
		if !execScriptAllowed(&config) {
			status = "failed"
			result = "exec_script is disabled on this agent — set --allow-exec-script or AGENT_ALLOW_EXEC_SCRIPT=true"
			break
		}
		result = runScript(params["script"])
	case "collect_diagnostics":
		result = collectDiagnostics(apiURL)
	case "update_packages":
		result = updatePackages()
	default:
		status = "failed"
		result = fmt.Sprintf("unknown command: %s", cmd.Command)
	}
	if strings.HasPrefix(result, "ERROR: ") {
		status = "failed"
		result = strings.TrimPrefix(result, "ERROR: ")
	}

	ackAgentCommand(apiURL, token, cmd.ID, status, result)
}

func ackAgentCommand(apiURL, token, commandID, status, result string) {
	payload, _ := json.Marshal(map[string]string{
		"status": status,
		"result": result,
	})
	req, err := http.NewRequest("POST", apiURL+"/api/v1/uptime/agents/commands/"+commandID+"/ack", bytes.NewBuffer(payload))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Agent-Token", token)
	resp, err := agentHTTPClient().Do(req)
	if err == nil {
		resp.Body.Close()
	}
	if err != nil || resp.StatusCode != 200 {
		fmt.Printf("[agent] failed to ack command %s\n", commandID)
	}
}

var serviceNameRe = regexp.MustCompile(`^[A-Za-z0-9_.:@-]+$`)

func restartService(service string) string {
	if service == "" {
		return "ERROR: no service specified"
	}
	if !serviceNameRe.MatchString(service) || strings.HasPrefix(service, "-") {
		return "ERROR: invalid service name"
	}
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "linux":
		cmd = exec.Command("systemctl", "restart", service)
	case "darwin":
		cmd = exec.Command("launchctl", "kickstart", "-k", "system/"+service)
	case "windows":
		cmd = exec.Command("powershell", "-NoProfile", "-Command", "Restart-Service -Name '"+service+"' -Force")
	default:
		return "ERROR: unsupported platform " + runtime.GOOS
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Sprintf("ERROR: restart failed: %v — %s", err, truncate(string(out), 2000))
	}
	return fmt.Sprintf("service %s restarted", service)
}

func runScript(script string) string {
	if script == "" {
		return "ERROR: no script provided"
	}
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("powershell", "-NoProfile", "-Command", script)
	} else {
		cmd = exec.Command("/bin/sh", "-c", script)
	}
	type result struct {
		out string
		err error
	}
	ch := make(chan result, 1)
	go func() {
		out, err := cmd.CombinedOutput()
		ch <- result{out: string(out), err: err}
	}()
	select {
	case r := <-ch:
		out := truncate(r.out, 4000)
		if r.err != nil {
			return fmt.Sprintf("ERROR: script failed: %v — %s", r.err, out)
		}
		return out
	case <-time.After(commandExecTimeout):
		if cmd.Process != nil {
			cmd.Process.Kill()
		}
		return "ERROR: script timed out"
	}
}

const packageUpdateTimeout = 15 * time.Minute

func updatePackages() string {
	type step struct {
		name string
		args []string
	}
	var steps []step
	switch runtime.GOOS {
	case "linux":
		if _, err := exec.LookPath("apt-get"); err == nil {
			steps = []step{
				{"apt-get", []string{"update"}},
				{"apt-get", []string{"-y", "upgrade"}},
			}
		} else if _, err := exec.LookPath("dnf"); err == nil {
			steps = []step{{"dnf", []string{"-y", "update"}}}
		} else if _, err := exec.LookPath("yum"); err == nil {
			steps = []step{{"yum", []string{"-y", "update"}}}
		} else if _, err := exec.LookPath("pacman"); err == nil {
			steps = []step{{"pacman", []string{"-Syu", "--noconfirm"}}}
		} else if _, err := exec.LookPath("apk"); err == nil {
			steps = []step{{"apk", []string{"upgrade"}}}
		} else {
			return "ERROR: no supported package manager found"
		}
	case "darwin":
		if _, err := exec.LookPath("brew"); err == nil {
			steps = []step{{"brew", []string{"update"}}, {"brew", []string{"upgrade"}}}
		} else {
			return "ERROR: brew not found"
		}
	case "windows":
		steps = []step{{"winget", []string{"upgrade", "--all", "--silent", "--accept-source-agreements", "--accept-package-agreements"}}}
	default:
		return "ERROR: unsupported platform " + runtime.GOOS
	}

	ctx, cancel := context.WithTimeout(context.Background(), packageUpdateTimeout)
	defer cancel()

	var log strings.Builder
	for _, s := range steps {
		env := os.Environ()
		if s.name == "apt-get" {
			env = append(env, "DEBIAN_FRONTEND=noninteractive")
		}
		cmd := exec.CommandContext(ctx, s.name, s.args...)
		cmd.Env = env
		out, err := cmd.CombinedOutput()
		fmt.Fprintf(&log, "$ %s %s\n%s\n", s.name, strings.Join(s.args, " "), truncate(string(out), 2000))
		if err != nil {
			lastPkgCheck = time.Time{}
			return fmt.Sprintf("ERROR: %s failed: %v\n%s", s.name, err, truncate(log.String(), 4000))
		}
	}

	lastPkgCheck = time.Time{}
	return truncate(log.String(), 4000)
}

func rebootHost() {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "linux":
		cmd = exec.Command("systemctl", "reboot")
	case "darwin":
		cmd = exec.Command("shutdown", "-r", "now")
	case "windows":
		cmd = exec.Command("shutdown", "/r", "/t", "0")
	default:
		return
	}
	go func() {
		time.Sleep(2 * time.Second)
		if err := cmd.Run(); err != nil {
			fmt.Printf("[agent] reboot failed: %v\n", err)
		}
	}()
}

func collectDiagnostics(apiURL string) string {
	payload, err := collectMetrics(apiURL)
	if err != nil {
		return "ERROR: " + err.Error()
	}
	b, _ := json.Marshal(payload)
	return truncate(string(b), 6000)
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "...[truncated]"
}
