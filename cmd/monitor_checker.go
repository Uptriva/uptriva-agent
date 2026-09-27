package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/smtp"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

type AssignedMonitor struct {
	ID                 string          `json:"id"`
	Type               string          `json:"type"`
	Target             string          `json:"target"`
	Interval           int             `json:"interval"`
	Settings           json.RawMessage `json:"settings"`
	ExpectedStatus     *int            `json:"expected_status"`
	ExpectedBody       *string         `json:"expected_body"`
	LatencyThresholdMs *int            `json:"latency_threshold_ms"`
	VerifySSL          *bool           `json:"verify_ssl"`
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

func checkHTTP(target string, expectedStatus *int, expectedBody *string, verifySSL bool) (string, int, string) {
	start := time.Now()
	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: !verifySSL},
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
		bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		if err != nil {
			return "down", latency, "failed to read response body"
		}
		if !strings.Contains(string(bodyBytes), *expectedBody) {
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

func tcpConnectLatency(addr string) int {
	start := time.Now()
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return -1
	}
	conn.Close()
	return int(time.Since(start).Milliseconds())
}

func checkPing(target string) (string, int, string) {
	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.CommandContext(ctx, "ping", "-n", "1", "-w", "5000", target)
	case "darwin":
		cmd = exec.CommandContext(ctx, "ping", "-c", "1", "-W", "5000", target)
	default:
		cmd = exec.CommandContext(ctx, "ping", "-c", "1", "-W", "5", target)
	}
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

func checkUDP(target string) (string, int, string) {
	start := time.Now()
	if _, _, err := net.SplitHostPort(target); err != nil {
		return "down", 0, "invalid target format, expected host:port"
	}
	conn, err := net.DialTimeout("udp", target, 3*time.Second)
	if err != nil {
		return "down", int(time.Since(start).Milliseconds()), err.Error()
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	payload := make([]byte, 56)
	if _, err := conn.Write(payload); err != nil {
		return "down", int(time.Since(start).Milliseconds()), "failed to send UDP probe"
	}
	buf := make([]byte, 1500)
	_, err = conn.Read(buf)
	latency := int(time.Since(start).Milliseconds())
	if err == nil {
		return "up", latency, "UDP server responded"
	}
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		return "degraded", latency, "UDP no response (port may be open or filtered)"
	}
	return "down", latency, err.Error()
}

func checkSSLCert(target string) (string, int, string) {
	start := time.Now()
	host := target
	if i := strings.Index(host, "://"); i >= 0 {
		host = host[i+3:]
	}
	if i := strings.IndexAny(host, "/?#"); i >= 0 {
		host = host[:i]
	}
	if !strings.Contains(host, ":") {
		host += ":443"
	}
	serverName := host
	if h, _, err := net.SplitHostPort(host); err == nil {
		serverName = h
	}
	rawConn, err := net.DialTimeout("tcp", host, 10*time.Second)
	if err != nil {
		return "down", int(time.Since(start).Milliseconds()), err.Error()
	}
	conn := tls.Client(rawConn, &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true,
		ServerName:         serverName,
	})
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	err = conn.Handshake()
	latency := int(time.Since(start).Milliseconds())
	if err != nil {
		rawConn.Close()
		return "down", latency, err.Error()
	}
	defer conn.Close()
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return "down", latency, "no certificates found"
	}
	cert := certs[0]
	daysRemaining := int(time.Until(cert.NotAfter).Hours() / 24)
	if time.Now().After(cert.NotAfter) {
		return "down", latency, "certificate expired"
	}
	if daysRemaining < 7 {
		return "degraded", latency, fmt.Sprintf("certificate expires in %d days", daysRemaining)
	}
	return "up", latency, fmt.Sprintf("valid (%d days remaining)", daysRemaining)
}

func checkDomain(target string) (string, int, string, bool) {
	host := strings.ToLower(strings.TrimSpace(target))
	if host == "" || strings.ContainsAny(host, " \t\r\n|;&`$(){}[]<>\"'\\") {
		return "", 0, "", false
	}
	if _, err := exec.LookPath("whois"); err != nil {
		return "", 0, "", false
	}
	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "whois", host).CombinedOutput()
	latency := int(time.Since(start).Milliseconds())
	if err != nil {
		return "down", latency, "whois lookup failed", true
	}
	outStr := strings.ToLower(string(out))
	if strings.Contains(outStr, "no match") || strings.Contains(outStr, "not found") {
		return "down", latency, "domain not found or unregistered", true
	}
	return "up", latency, "domain registered", true
}

func checkRedis(target string, settings json.RawMessage) (string, int, string) {
	start := time.Now()
	addr := target
	useTLS := strings.HasPrefix(target, "rediss://")
	addr = strings.TrimPrefix(addr, "rediss://")
	addr = strings.TrimPrefix(addr, "redis://")

	var cfg struct {
		Password string `json:"password"`
		UseTLS   bool   `json:"use_tls"`
	}
	if len(settings) > 0 {
		json.Unmarshal(settings, &cfg)
	}
	if cfg.UseTLS {
		useTLS = true
	}

	var conn net.Conn
	var err error
	if useTLS {
		host := addr
		if h, _, serr := net.SplitHostPort(addr); serr == nil {
			host = h
		}
		conn, err = tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", addr, &tls.Config{
			MinVersion: tls.VersionTLS12,
			ServerName: host,
		})
	} else {
		conn, err = net.DialTimeout("tcp", addr, 5*time.Second)
	}
	if err != nil {
		return "down", int(time.Since(start).Milliseconds()), err.Error()
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	if cfg.Password != "" {
		if _, err := conn.Write(fmt.Appendf(nil, "AUTH %s\r\n", cfg.Password)); err != nil {
			return "down", int(time.Since(start).Milliseconds()), "failed to send AUTH"
		}
		buf := make([]byte, 128)
		n, err := conn.Read(buf)
		if err != nil {
			return "down", int(time.Since(start).Milliseconds()), err.Error()
		}
		if !strings.HasPrefix(string(buf[:n]), "+OK") {
			return "down", int(time.Since(start).Milliseconds()), "authentication failed"
		}
	}

	if _, err := conn.Write([]byte("PING\r\n")); err != nil {
		return "down", int(time.Since(start).Milliseconds()), "failed to send PING"
	}
	buf := make([]byte, 128)
	n, err := conn.Read(buf)
	latency := int(time.Since(start).Milliseconds())
	if err != nil {
		return "down", latency, err.Error()
	}
	resp := string(buf[:n])
	if strings.HasPrefix(resp, "+PONG") {
		return "up", latency, ""
	}
	return "down", latency, "unexpected response: " + strings.TrimSpace(resp)
}

func checkSMTPStartTLS(target string) (string, int, string) {
	start := time.Now()
	if !strings.Contains(target, ":") {
		return "down", 0, "target must include port (e.g. host:587)"
	}
	hostOnly := target
	if h, _, err := net.SplitHostPort(target); err == nil {
		hostOnly = h
	}
	conn, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		return "down", int(time.Since(start).Milliseconds()), err.Error()
	}
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	smtpClient, err := smtp.NewClient(conn, hostOnly)
	if err != nil {
		conn.Close()
		return "down", int(time.Since(start).Milliseconds()), err.Error()
	}
	defer smtpClient.Close()
	if err := smtpClient.Hello("localhost"); err != nil {
		return "down", int(time.Since(start).Milliseconds()), "SMTP EHLO failed"
	}
	if ok, _ := smtpClient.Extension("STARTTLS"); !ok {
		return "down", int(time.Since(start).Milliseconds()), "server does not support STARTTLS"
	}
	if err := smtpClient.StartTLS(&tls.Config{
		ServerName: hostOnly,
		MinVersion: tls.VersionTLS12,
	}); err != nil {
		return "down", int(time.Since(start).Milliseconds()), "STARTTLS handshake failed"
	}
	return "up", int(time.Since(start).Milliseconds()), "STARTTLS successful"
}

func runMonitorCheck(monitor AssignedMonitor) (MonitorCheckResult, bool) {
	switch monitor.Type {
	case "http", "https":
		verifySSL := true
		if monitor.VerifySSL != nil {
			verifySSL = *monitor.VerifySSL
		}
		status, latency, msg := checkHTTP(monitor.Target, monitor.ExpectedStatus, monitor.ExpectedBody, verifySSL)
		return MonitorCheckResult{Status: status, Latency: latency, Message: msg}, true
	case "tcp", "pop3", "imap", "telnet", "postgres", "mysql", "smtp", "smtp_connect":
		status, latency, msg := checkTCP(monitor.Target)
		return MonitorCheckResult{Status: status, Latency: latency, Message: msg}, true
	case "smtp_starttls":
		status, latency, msg := checkSMTPStartTLS(monitor.Target)
		return MonitorCheckResult{Status: status, Latency: latency, Message: msg}, true
	case "ping", "icmp":
		status, latency, msg := checkPing(monitor.Target)
		return MonitorCheckResult{Status: status, Latency: latency, Message: msg}, true
	case "dns":
		status, latency, msg := checkDNS(monitor.Target)
		return MonitorCheckResult{Status: status, Latency: latency, Message: msg}, true
	case "udp":
		status, latency, msg := checkUDP(monitor.Target)
		return MonitorCheckResult{Status: status, Latency: latency, Message: msg}, true
	case "ssl":
		status, latency, msg := checkSSLCert(monitor.Target)
		return MonitorCheckResult{Status: status, Latency: latency, Message: msg}, true
	case "domain":
		status, latency, msg, ok := checkDomain(monitor.Target)
		if !ok {
			return MonitorCheckResult{}, false
		}
		return MonitorCheckResult{Status: status, Latency: latency, Message: msg}, true
	case "redis":
		status, latency, msg := checkRedis(monitor.Target, monitor.Settings)
		return MonitorCheckResult{Status: status, Latency: latency, Message: msg}, true
	case "game_server":
		status, latency, msg := checkGameServer(monitor.Target, monitor.Settings)
		return MonitorCheckResult{Status: status, Latency: latency, Message: msg}, true
	default:
		return MonitorCheckResult{}, false
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

			result, supported := runMonitorCheck(m)
			if !supported {
				fmt.Printf("[agent] skipping monitor %s: unsupported check type %s\n", m.ID, m.Type)
				lastCheck[m.ID] = time.Now()
				continue
			}
			if err := submitMonitorResult(apiURL, m.ID, token, result); err != nil {
				fmt.Printf("[agent] failed to submit result for monitor %s: %v\n", m.ID, err)
				lastCheck[m.ID] = time.Now().Add(-interval + 30*time.Second)
			} else {
				fmt.Printf("[agent] monitor %s -> %s (%dms)\n", m.ID, result.Status, result.Latency)
				lastCheck[m.ID] = time.Now()
			}
		}

		time.Sleep(10 * time.Second)
	}
}
