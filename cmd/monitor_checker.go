package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os/exec"
	"strings"
	"time"
)

type AssignedMonitor struct {
	ID                 string  `json:"id"`
	Type               string  `json:"type"`
	Target             string  `json:"target"`
	Interval           int     `json:"interval"`
	ExpectedStatus     *int    `json:"expected_status"`
	ExpectedBody       *string `json:"expected_body"`
	LatencyThresholdMs *int    `json:"latency_threshold_ms"`
}

type MonitorCheckResult struct {
	Status  string `json:"status"`
	Latency int    `json:"latency"`
	Message string `json:"message"`
}

func fetchAssignedMonitors(apiURL, token string) ([]AssignedMonitor, error) {
	req, err := http.NewRequest("GET", apiURL+"/api/v1/uptime/agents/monitors", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Agent-Token", token)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch monitors: %d", resp.StatusCode)
	}

	var data struct {
		Monitors []AssignedMonitor `json:"monitors"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, err
	}
	return data.Monitors, nil
}

func checkHTTP(target string, expectedStatus *int, expectedBody *string) (string, int, string) {
	start := time.Now()
	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	resp, err := client.Get(target)
	latency := int(time.Since(start).Milliseconds())
	if err != nil {
		return "down", latency, err.Error()
	}
	defer resp.Body.Close()

	if expectedStatus != nil && resp.StatusCode != *expectedStatus {
		return "down", latency, fmt.Sprintf("status %d, expected %d", resp.StatusCode, *expectedStatus)
	}

	if expectedBody != nil {
		buf := new(bytes.Buffer)
		buf.ReadFrom(resp.Body)
		body := buf.String()
		if !strings.Contains(body, *expectedBody) {
			return "down", latency, "response body mismatch"
		}
	}

	return "up", latency, ""
}

func checkTCP(target string) (string, int, string) {
	start := time.Now()
	conn, err := net.DialTimeout("tcp", target, 10*time.Second)
	latency := int(time.Since(start).Milliseconds())
	if err != nil {
		return "down", latency, err.Error()
	}
	conn.Close()
	return "up", latency, ""
}

func checkPing(target string) (string, int, string) {
	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "ping", "-c", "1", "-W", "5", target)
	if _, err := cmd.Output(); err != nil {
		latency := int(time.Since(start).Milliseconds())
		return "down", latency, "ping failed"
	}
	latency := int(time.Since(start).Milliseconds())
	return "up", latency, ""
}

func checkDNS(target string) (string, int, string) {
	start := time.Now()
	resolver := net.Resolver{PreferGo: true}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	host := target
	if !strings.HasPrefix(host, "http") {
		host = "http://" + host
	}
	u, err := http.NewRequest("GET", host, nil)
	if err != nil {
		latency := int(time.Since(start).Milliseconds())
		return "down", latency, err.Error()
	}

	_, err = resolver.LookupHost(ctx, u.URL.Hostname())
	latency := int(time.Since(start).Milliseconds())
	if err != nil {
		return "down", latency, err.Error()
	}
	return "up", latency, ""
}

func runMonitorCheck(monitor AssignedMonitor) MonitorCheckResult {
	switch monitor.Type {
	case "http", "https":
		status, latency, msg := checkHTTP(monitor.Target, monitor.ExpectedStatus, monitor.ExpectedBody)
		return MonitorCheckResult{Status: status, Latency: latency, Message: msg}
	case "tcp":
		status, latency, msg := checkTCP(monitor.Target)
		return MonitorCheckResult{Status: status, Latency: latency, Message: msg}
	case "ping":
		status, latency, msg := checkPing(monitor.Target)
		return MonitorCheckResult{Status: status, Latency: latency, Message: msg}
	case "dns":
		status, latency, msg := checkDNS(monitor.Target)
		return MonitorCheckResult{Status: status, Latency: latency, Message: msg}
	default:
		return MonitorCheckResult{Status: "down", Latency: 0, Message: "unsupported check type: " + monitor.Type}
	}
}

func submitMonitorResult(apiURL, monitorID, token string, result MonitorCheckResult) error {
	payload, _ := json.Marshal(result)
	req, err := http.NewRequest("POST", apiURL+"/api/v1/uptime/monitors/"+monitorID+"/status", bytes.NewBuffer(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Agent-Token", token)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}

func startMonitorChecker(apiURL, token string) {
	lastCheck := make(map[string]time.Time)

	for {
		monitors, err := fetchAssignedMonitors(apiURL, token)
		if err != nil {
			fmt.Printf("[agent] failed to fetch assigned monitors: %v\n", err)
			time.Sleep(30 * time.Second)
			continue
		}

		for _, m := range monitors {
			interval := time.Duration(m.Interval) * time.Second
			if interval < 10*time.Second {
				interval = 30 * time.Second
			}

			if last, ok := lastCheck[m.ID]; ok && time.Since(last) < interval {
				continue
			}

			result := runMonitorCheck(m)
			if err := submitMonitorResult(apiURL, m.ID, token, result); err != nil {
				fmt.Printf("[agent] failed to submit result for monitor %s: %v\n", m.ID, err)
			} else {
				fmt.Printf("[agent] monitor %s -> %s (%dms)\n", m.ID, result.Status, result.Latency)
			}
			lastCheck[m.ID] = time.Now()
		}

		time.Sleep(10 * time.Second)
	}
}
