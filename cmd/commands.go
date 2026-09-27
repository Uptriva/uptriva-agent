package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
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

	switch cmd.Command {
	case "restart_service":
		result = restartService(params["service"])
	case "exec_script":
		result = runScript(params["script"])
	case "collect_diagnostics":
		result = collectDiagnostics(apiURL)
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

func restartService(service string) string {
	if service == "" {
		return "ERROR: no service specified"
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
