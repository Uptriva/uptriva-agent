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
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strconv"
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
	Status  string                 `json:"status"`
	Latency int                    `json:"latency"`
	Message string                 `json:"message"`
	Metrics map[string]interface{} `json:"metrics,omitempty"`
}

var blockedTargetNets []*net.IPNet

func init() {
	for _, cidr := range []string{
		"169.254.0.0/16", "fe80::/10", "ff00::/8", "224.0.0.0/4",
		"100.64.0.0/10", "192.0.0.0/24", "198.18.0.0/15", "240.0.0.0/4", "fec0::/10",
	} {
		_, n, err := net.ParseCIDR(cidr)
		if err == nil {
			blockedTargetNets = append(blockedTargetNets, n)
		}
	}
}

var blockedExactIPs = []net.IP{
	net.IPv4(169, 254, 169, 254),
	net.IPv4(100, 100, 2, 136),
	net.ParseIP("fd00:ec2::254"),
}

func blockedTargetHost(target string) string {
	host := target
	if strings.Contains(target, "://") {
		if u, err := url.Parse(target); err == nil && u.Host != "" {
			host = u.Host
		}
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return strings.Trim(host, "[]")
}

func isBlockedIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}
	for _, n := range blockedTargetNets {
		if n.Contains(ip) {
			return true
		}
	}
	for _, b := range blockedExactIPs {
		if ip.Equal(b) {
			return true
		}
	}
	return false
}

func isBlockedTarget(target string) bool {
	host := blockedTargetHost(target)
	if host == "" {
		return false
	}
	if strings.EqualFold(host, "metadata.google.internal") || strings.EqualFold(host, "metadata.goog") {
		return true
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return false
	}
	for _, ip := range ips {
		if isBlockedIP(ip) {
			return true
		}
	}
	return false
}

func resolveCheckedHost(ctx context.Context, host string) ([]net.IP, error) {
	if strings.EqualFold(host, "metadata.google.internal") || strings.EqualFold(host, "metadata.goog") {
		return nil, fmt.Errorf("blocked target host: %s", host)
	}
	if ip := net.ParseIP(strings.Trim(host, "[]")); ip != nil {
		if isBlockedIP(ip) {
			return nil, fmt.Errorf("blocked target IP: %s", host)
		}
		return []net.IP{ip}, nil
	}
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("no IPs found for host %s", host)
	}
	for _, ip := range ips {
		if isBlockedIP(ip) {
			return nil, fmt.Errorf("blocked resolved IP %s for host %s", ip.String(), host)
		}
	}
	return ips, nil
}

func checkedDialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	ips, err := resolveCheckedHost(ctx, host)
	if err != nil {
		return nil, err
	}
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	var lastErr error
	for _, ip := range ips {
		conn, derr := dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		if derr == nil {
			return conn, nil
		}
		lastErr = derr
	}
	return nil, lastErr
}

func checkedDialTimeout(network, addr string, timeout time.Duration) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return checkedDialContext(ctx, network, addr)
}

func checkedHTTPClient(timeout time.Duration, verifySSL bool) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: !verifySSL},
			DialContext:     checkedDialContext,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("too many redirects")
			}
			if isBlockedTarget(req.URL.String()) {
				return fmt.Errorf("redirect target blocked")
			}
			return nil
		},
	}
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
	client := checkedHTTPClient(30*time.Second, verifySSL)
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
	conn, err := checkedDialTimeout("tcp", target, 10*time.Second)
	latency := int(time.Since(start).Milliseconds())
	if err != nil {
		return "down", latency, err.Error()
	}
	conn.Close()
	return "up", latency, ""
}

func tcpConnectLatency(addr string) int {
	start := time.Now()
	conn, err := checkedDialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return -1
	}
	conn.Close()
	return int(time.Since(start).Milliseconds())
}

func validExecTarget(t string) bool {
	if t == "" || strings.HasPrefix(t, "-") {
		return false
	}
	for _, r := range t {
		ok := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') ||
			r == '.' || r == '-' || r == ':' || r == '_' || r == '[' || r == ']' || r == '%'
		if !ok {
			return false
		}
	}
	return true
}

func checkPing(target string) (string, int, string) {
	start := time.Now()
	if !validExecTarget(target) {
		return "down", 0, "invalid ping target"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	resolveCtx, resolveCancel := context.WithTimeout(ctx, 5*time.Second)
	ips, err := resolveCheckedHost(resolveCtx, target)
	resolveCancel()
	if err != nil {
		return "down", 0, err.Error()
	}
	pingTarget := ips[0].String()
	for _, ip := range ips {
		if ip.To4() != nil {
			pingTarget = ip.String()
			break
		}
	}

	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.CommandContext(ctx, "ping", "-n", "1", "-w", "5000", pingTarget)
	case "darwin":
		cmd = exec.CommandContext(ctx, "ping", "-c", "1", "-W", "5000", pingTarget)
	default:
		cmd = exec.CommandContext(ctx, "ping", "-c", "1", "-W", "5", pingTarget)
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
	conn, err := checkedDialTimeout("udp", target, 3*time.Second)
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
	rawConn, err := checkedDialTimeout("tcp", host, 10*time.Second)
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
	if host == "" || strings.HasPrefix(host, "-") || strings.ContainsAny(host, " \t\r\n|;&`$(){}[]<>\"'\\") {
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
		rawConn, derr := checkedDialTimeout("tcp", addr, 5*time.Second)
		if derr != nil {
			return "down", int(time.Since(start).Milliseconds()), derr.Error()
		}
		conn = tls.Client(rawConn, &tls.Config{
			MinVersion: tls.VersionTLS12,
			ServerName: host,
		})
		if herr := conn.(*tls.Conn).Handshake(); herr != nil {
			rawConn.Close()
			return "down", int(time.Since(start).Milliseconds()), herr.Error()
		}
	} else {
		conn, err = checkedDialTimeout("tcp", addr, 5*time.Second)
	}
	if err != nil {
		return "down", int(time.Since(start).Milliseconds()), err.Error()
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	if cfg.Password != "" {
		if strings.ContainsAny(cfg.Password, "\r\n\x00") {
			return "down", int(time.Since(start).Milliseconds()), "credentials contain invalid characters"
		}
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
	conn, err := checkedDialTimeout("tcp", target, 10*time.Second)
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

type infraSettings struct {
	ExpectedState      string `json:"expected_state"`
	Path               string `json:"path"`
	Token              string `json:"token"`
	InsecureSkipVerify bool   `json:"insecure_skip_verify"`
	ExpectSubstring    string `json:"expect_substring"`
	TCPPorts           string `json:"tcp_ports"`
	Service            string `json:"service"`
	MinReplicas        int    `json:"min_replicas"`
	Port               int    `json:"port"`
	Community          string `json:"community"`
	Username           string `json:"username"`
	Password           string `json:"password"`
	OID                string `json:"oid"`
	Namespace          string `json:"namespace"`
	Deployment         string `json:"deployment"`
	Kind               string `json:"kind"`
	MinReady           int    `json:"min_ready"`
	Kubeconfig         string `json:"kubeconfig"`
}

func checkContainerRuntime(binary, target string, settings json.RawMessage) (string, int, string) {
	if !validExecTarget(target) {
		return "down", 0, "invalid container name"
	}
	var s infraSettings
	json.Unmarshal(settings, &s)
	expected := s.ExpectedState
	if expected == "" {
		expected = "running"
	}
	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, binary, "inspect", "-f", "{{.State.Status}}|{{.State.RestartCount}}", target).CombinedOutput()
	latency := int(time.Since(start).Milliseconds())
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if len(msg) > 120 {
			msg = msg[:120]
		}
		if msg == "" {
			msg = binary + " not available or container not found"
		}
		return "down", latency, binary + " inspect failed: " + msg
	}
	parts := strings.SplitN(strings.TrimSpace(string(out)), "|", 2)
	state := parts[0]
	restarts := "?"
	if len(parts) > 1 {
		restarts = parts[1]
	}
	if state != expected {
		return "down", latency, fmt.Sprintf("container state '%s' (expected '%s'), restarts=%s", state, expected, restarts)
	}
	return "up", latency, fmt.Sprintf("container %s, restarts=%s", state, restarts)
}

func checkInfraHTTP(target string, s infraSettings, defaultPort, defaultPath, authHeaderName, authPrefix string) (string, int, string) {
	host := strings.TrimPrefix(strings.TrimPrefix(strings.TrimSuffix(target, "/"), "https://"), "http://")
	if h, _, err := net.SplitHostPort(host); err != nil || h == "" {
		host = net.JoinHostPort(strings.Trim(host, "[]"), defaultPort)
	}
	path := s.Path
	if path == "" {
		path = defaultPath
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	req, err := http.NewRequest("GET", "https://"+host+path, nil)
	if err != nil {
		return "down", 0, "invalid target"
	}
	if token := strings.TrimSpace(s.Token); token != "" {
		req.Header.Set(authHeaderName, authPrefix+token)
	}
	start := time.Now()
	client := checkedHTTPClient(10*time.Second, !s.InsecureSkipVerify)
	resp, err := client.Do(req)
	latency := int(time.Since(start).Milliseconds())
	if err != nil {
		errMsg := err.Error()
		if len(errMsg) > 120 {
			errMsg = errMsg[:120]
		}
		return "down", latency, errMsg
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "down", latency, fmt.Sprintf("HTTP %d", resp.StatusCode)
	}
	if s.ExpectSubstring != "" && !strings.Contains(string(body), s.ExpectSubstring) {
		return "down", latency, "HTTP 200 but response missing expected content"
	}
	return "up", latency, fmt.Sprintf("HTTP %d", resp.StatusCode)
}

func checkKubernetes(target string, settings json.RawMessage) (string, int, string) {
	var s infraSettings
	json.Unmarshal(settings, &s)
	return checkInfraHTTP(target, s, "6443", "/readyz", "Authorization", "Bearer ")
}

func checkKubeDeployment(target string, settings json.RawMessage) (string, int, string, map[string]interface{}) {
	var s infraSettings
	json.Unmarshal(settings, &s)
	kind := strings.ToLower(strings.TrimSpace(s.Kind))
	if kind == "" {
		kind = "deployment"
	}
	if kind != "deployment" && kind != "statefulset" && kind != "daemonset" {
		return "down", 0, "unsupported workload kind: " + kind, nil
	}
	ns := strings.TrimSpace(s.Namespace)
	if ns == "" {
		ns = "default"
	}
	name := strings.TrimSpace(s.Deployment)
	if name == "" {
		name = strings.TrimSpace(target)
	}
	if !validExecTarget(name) || !validExecTarget(ns) {
		return "down", 0, "invalid workload or namespace name", nil
	}
	kubeconfig := strings.TrimSpace(s.Kubeconfig)
	if kubeconfig == "" {
		for _, p := range []string{"/etc/rancher/k3s/k3s.yaml", os.Getenv("HOME") + "/.kube/config", "/root/.kube/config"} {
			if _, err := os.Stat(p); err == nil {
				kubeconfig = p
				break
			}
		}
	}
	if kubeconfig == "" {
		return "down", 0, "no kubeconfig found on agent host", nil
	}
	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "kubectl", "--kubeconfig", kubeconfig, "-n", ns, "get", kind, name, "-o", "json").CombinedOutput()
	latency := int(time.Since(start).Milliseconds())
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if len(msg) > 160 {
			msg = msg[:160]
		}
		return "down", latency, "kubectl failed: " + msg, nil
	}
	var wl struct {
		Spec struct {
			Replicas int                    `json:"replicas"`
			Selector map[string]interface{} `json:"selector"`
		} `json:"spec"`
		Status struct {
			ReadyReplicas          int `json:"readyReplicas"`
			AvailableReplicas      int `json:"availableReplicas"`
			DesiredNumberScheduled int `json:"desiredNumberScheduled"`
			NumberReady            int `json:"numberReady"`
		} `json:"status"`
	}
	if err := json.Unmarshal(out, &wl); err != nil {
		return "down", latency, "could not parse workload status", nil
	}
	desired := wl.Spec.Replicas
	ready := wl.Status.ReadyReplicas
	if kind == "daemonset" {
		desired = wl.Status.DesiredNumberScheduled
		ready = wl.Status.NumberReady
	}
	metrics := map[string]interface{}{
		"kind":      kind,
		"workload":  name,
		"namespace": ns,
		"desired":   desired,
		"ready":     ready,
	}
	if sel := kubeSelectorString(wl.Spec.Selector); sel != "" {
		pods := kubeListPods(kubeconfig, ns, sel)
		if len(pods) > 0 {
			metrics["pods"] = pods
		}
	}
	want := desired
	if s.MinReady > 0 {
		want = s.MinReady
	}
	if want > 0 && ready >= want {
		return "up", latency, fmt.Sprintf("%s %d/%d replicas ready", kind, ready, desired), metrics
	}
	if ready > 0 {
		return "degraded", latency, fmt.Sprintf("%s %d/%d replicas ready (want %d)", kind, ready, desired, want), metrics
	}
	return "down", latency, fmt.Sprintf("%s 0/%d replicas ready", kind, desired), metrics
}

func kubeSelectorString(selector map[string]interface{}) string {
	ml, _ := selector["matchLabels"].(map[string]interface{})
	if len(ml) == 0 {
		return ""
	}
	keys := make([]string, 0, len(ml))
	for k := range ml {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		v, _ := ml[k].(string)
		if validExecTarget(k) && validExecTarget(v) {
			parts = append(parts, k+"="+v)
		}
	}
	return strings.Join(parts, ",")
}

func kubeListPods(kubeconfig, ns, selector string) []map[string]interface{} {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "kubectl", "--kubeconfig", kubeconfig, "-n", ns, "get", "pods", "-l", selector, "-o", "json").CombinedOutput()
	if err != nil {
		return nil
	}
	var list struct {
		Items []struct {
			Metadata struct {
				Name              string `json:"name"`
				CreationTimestamp string `json:"creationTimestamp"`
			} `json:"metadata"`
			Spec struct {
				NodeName string `json:"nodeName"`
			} `json:"spec"`
			Status struct {
				Phase             string `json:"phase"`
				ContainerStatuses []struct {
					Ready        bool `json:"ready"`
					RestartCount int  `json:"restartCount"`
				} `json:"containerStatuses"`
			} `json:"status"`
		} `json:"items"`
	}
	if err := json.Unmarshal(out, &list); err != nil {
		return nil
	}
	top := kubeTopPods(kubeconfig, ns, selector)
	pods := make([]map[string]interface{}, 0, len(list.Items))
	for _, p := range list.Items {
		readyCount := 0
		restarts := 0
		total := len(p.Status.ContainerStatuses)
		for _, cs := range p.Status.ContainerStatuses {
			if cs.Ready {
				readyCount++
			}
			restarts += cs.RestartCount
		}
		pod := map[string]interface{}{
			"name":          p.Metadata.Name,
			"phase":         p.Status.Phase,
			"ready":         fmt.Sprintf("%d/%d", readyCount, total),
			"restarts":      restarts,
			"node":          p.Spec.NodeName,
			"container_set": total,
		}
		if t, ok := top[p.Metadata.Name]; ok {
			pod["cpu_milli"] = t[0]
			pod["mem_mib"] = t[1]
		}
		if p.Metadata.CreationTimestamp != "" {
			if started, err := time.Parse(time.RFC3339, p.Metadata.CreationTimestamp); err == nil {
				pod["age_seconds"] = int(time.Since(started).Seconds())
			}
		}
		unhealthy := p.Status.Phase != "Running" || readyCount < total || restarts > 0
		if unhealthy {
			if logs := kubePodLogs(kubeconfig, ns, p.Metadata.Name, 8); len(logs) > 0 {
				pod["logs"] = logs
			}
		}
		pods = append(pods, pod)
	}
	return pods
}

func kubeTopPods(kubeconfig, ns, selector string) map[string][2]int {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "kubectl", "--kubeconfig", kubeconfig, "-n", ns, "top", "pods", "-l", selector, "--no-headers").CombinedOutput()
	if err != nil {
		return nil
	}
	top := map[string][2]int{}
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		cpu, _ := strconv.Atoi(strings.TrimSuffix(fields[1], "m"))
		mem, _ := strconv.Atoi(strings.TrimSuffix(fields[2], "Mi"))
		top[fields[0]] = [2]int{cpu, mem}
	}
	return top
}

func kubePodLogs(kubeconfig, ns, pod string, tail int) []string {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "kubectl", "--kubeconfig", kubeconfig, "-n", ns, "logs", pod, "--tail", strconv.Itoa(tail)).CombinedOutput()
	if err != nil {
		return nil
	}
	var lines []string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if len(line) > 200 {
			line = line[:200]
		}
		lines = append(lines, line)
		if len(lines) >= tail {
			break
		}
	}
	return lines
}

func checkProxmox(target string, settings json.RawMessage) (string, int, string) {
	var s infraSettings
	json.Unmarshal(settings, &s)
	return checkInfraHTTP(target, s, "8006", "/api2/json/version", "Authorization", "PVEAPIToken=")
}

func checkVMware(target string, settings json.RawMessage) (string, int, string) {
	var s infraSettings
	json.Unmarshal(settings, &s)
	return checkInfraHTTP(target, s, "443", "/sdk/vimService.wsdl", "vmware-api-session-id", "")
}

func checkCeph(target string, settings json.RawMessage) (string, int, string) {
	var s infraSettings
	json.Unmarshal(settings, &s)
	if s.Path == "" && s.ExpectSubstring == "" {
		s.ExpectSubstring = `"status":"HEALTH_OK"`
	}
	return checkInfraHTTP(target, s, "8443", "/api/health", "Authorization", "Bearer ")
}

func checkDockerSwarm(_ string, settings json.RawMessage) (string, int, string) {
	var s infraSettings
	json.Unmarshal(settings, &s)
	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "docker", "info", "-f", "{{.Swarm.LocalNodeState}}|{{.Swarm.ControlAvailable}}").CombinedOutput()
	latency := int(time.Since(start).Milliseconds())
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if len(msg) > 120 {
			msg = msg[:120]
		}
		return "down", latency, "docker swarm check failed: " + msg
	}
	parts := strings.Split(strings.TrimSpace(string(out)), "|")
	state := parts[0]
	if state != "active" {
		return "down", latency, fmt.Sprintf("node swarm state '%s' (expected active)", state)
	}
	if svc := strings.TrimSpace(s.Service); svc != "" {
		if !validExecTarget(svc) {
			return "down", latency, "invalid service name"
		}
		svcOut, svcErr := exec.CommandContext(ctx, "docker", "service", "ls", "--filter", "name="+svc, "--format", "{{.Replicas}}").CombinedOutput()
		if svcErr != nil {
			return "down", latency, "service lookup failed: " + strings.TrimSpace(string(svcOut))
		}
		replicas := strings.TrimSpace(string(svcOut))
		parts := strings.SplitN(replicas, "/", 2)
		if len(parts) != 2 {
			return "down", latency, fmt.Sprintf("service '%s' not found or no replicas", svc)
		}
		var ready, desired int
		fmt.Sscanf(parts[0], "%d", &ready)
		fmt.Sscanf(parts[1], "%d", &desired)
		min := s.MinReplicas
		if min < 1 {
			min = 1
		}
		if ready < min {
			return "down", latency, fmt.Sprintf("service '%s' replicas %s (min %d)", svc, replicas, min)
		}
		return "up", latency, fmt.Sprintf("swarm active, service '%s' replicas %s", svc, replicas)
	}
	return "up", latency, "swarm node active"
}

func checkNetworkDevice(target string, settings json.RawMessage) (string, int, string) {
	var s infraSettings
	json.Unmarshal(settings, &s)
	status, latency, msg := checkPing(target)
	if status != "up" {
		return status, latency, msg
	}
	ports := strings.Split(s.TCPPorts, ",")
	var closed []string
	for _, p := range ports {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		addr := net.JoinHostPort(target, p)
		if tcpConnectLatency(addr) < 0 {
			closed = append(closed, p)
		}
	}
	if len(closed) > 0 {
		return "down", latency, fmt.Sprintf("host up but ports closed: %s", strings.Join(closed, ","))
	}
	return "up", latency, msg
}

func infraHostPort(target string, defaultPort int) string {
	host := strings.TrimSpace(target)
	if _, _, err := net.SplitHostPort(host); err == nil {
		return host
	}
	return net.JoinHostPort(strings.Trim(host, "[]"), fmt.Sprintf("%d", defaultPort))
}

func checkRabbitMQ(target string, settings json.RawMessage) (string, int, string) {
	var s infraSettings
	json.Unmarshal(settings, &s)
	addr := infraHostPort(target, 5672)
	if s.Port > 0 {
		host, _, _ := net.SplitHostPort(addr)
		addr = net.JoinHostPort(host, fmt.Sprintf("%d", s.Port))
	}
	start := time.Now()
	conn, err := checkedDialTimeout("tcp", addr, 8*time.Second)
	if err != nil {
		return "down", int(time.Since(start).Milliseconds()), "TCP connect failed: " + err.Error()
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(8 * time.Second))
	if _, err := conn.Write([]byte("AMQP\x00\x00\x09\x01")); err != nil {
		return "down", int(time.Since(start).Milliseconds()), "protocol header write failed"
	}
	buf := make([]byte, 7)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return "down", int(time.Since(start).Milliseconds()), "no AMQP frame in response"
	}
	latency := int(time.Since(start).Milliseconds())
	if buf[0] != 0x01 {
		return "down", latency, fmt.Sprintf("unexpected response byte 0x%02x (not an AMQP frame)", buf[0])
	}
	class := int(buf[3])<<8 | int(buf[4])
	method := int(buf[5])<<8 | int(buf[6])
	if class == 10 && method == 10 {
		return "up", latency, "AMQP broker responded with connection.start"
	}
	return "up", latency, fmt.Sprintf("AMQP frame received (class %d method %d)", class, method)
}

func checkMQTT(target string, settings json.RawMessage) (string, int, string) {
	var s infraSettings
	json.Unmarshal(settings, &s)
	addr := infraHostPort(target, 1883)
	if s.Port > 0 {
		host, _, _ := net.SplitHostPort(addr)
		addr = net.JoinHostPort(host, fmt.Sprintf("%d", s.Port))
	}

	clientID := "shxrk-probe"
	username := strings.TrimSpace(s.Username)
	if len(username) > 255 || len(s.Password) > 255 {
		return "down", 0, "MQTT credentials exceed 255-byte limit"
	}
	var vh []byte
	vh = append(vh, 0x00, 0x04, 'M', 'Q', 'T', 'T', 0x04)
	flags := byte(0x02)
	if username != "" {
		flags |= 0x80
		if s.Password != "" {
			flags |= 0x40
		}
	}
	vh = append(vh, flags, 0x00, 0x3C)
	payload := []byte{0x00, byte(len(clientID))}
	payload = append(payload, clientID...)
	if username != "" {
		u := username
		payload = append(payload, 0x00, byte(len(u)))
		payload = append(payload, u...)
		if s.Password != "" {
			payload = append(payload, 0x00, byte(len(s.Password)))
			payload = append(payload, s.Password...)
		}
	}
	remain := len(vh) + len(payload)
	pkt := []byte{0x10, byte(remain)}
	pkt = append(pkt, vh...)
	pkt = append(pkt, payload...)

	start := time.Now()
	conn, err := checkedDialTimeout("tcp", addr, 8*time.Second)
	if err != nil {
		return "down", int(time.Since(start).Milliseconds()), "TCP connect failed: " + err.Error()
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(8 * time.Second))
	if _, err := conn.Write(pkt); err != nil {
		return "down", int(time.Since(start).Milliseconds()), "CONNECT write failed"
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return "down", int(time.Since(start).Milliseconds()), "no CONNACK in response"
	}
	latency := int(time.Since(start).Milliseconds())
	if buf[0] != 0x20 {
		return "down", latency, fmt.Sprintf("unexpected packet type 0x%02x (expected CONNACK 0x20)", buf[0])
	}
	rc := buf[3]
	if rc == 0 {
		return "up", latency, "MQTT broker accepted CONNECT"
	}
	return "up", latency, fmt.Sprintf("MQTT broker responded (CONNACK rc=%d — broker alive, auth not accepted)", rc)
}

func checkKafka(target string, settings json.RawMessage) (string, int, string) {
	var s infraSettings
	json.Unmarshal(settings, &s)
	addr := infraHostPort(target, 9092)
	if s.Port > 0 {
		host, _, _ := net.SplitHostPort(addr)
		addr = net.JoinHostPort(host, fmt.Sprintf("%d", s.Port))
	}

	clientID := "shxrk-probe"
	body := []byte{0x00, 0x12, 0x00, 0x00}
	body = append(body, 0x00, 0x00, 0x00, 0x01)
	body = append(body, 0x00, byte(len(clientID)))
	body = append(body, clientID...)
	frame := make([]byte, 4)
	frame[3] = byte(len(body))
	pkt := append(frame, body...)

	start := time.Now()
	conn, err := checkedDialTimeout("tcp", addr, 8*time.Second)
	if err != nil {
		return "down", int(time.Since(start).Milliseconds()), "TCP connect failed: " + err.Error()
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(8 * time.Second))
	if _, err := conn.Write(pkt); err != nil {
		return "down", int(time.Since(start).Milliseconds()), "ApiVersions write failed"
	}
	head := make([]byte, 8)
	if _, err := io.ReadFull(conn, head); err != nil {
		return "down", int(time.Since(start).Milliseconds()), "no response frame"
	}
	latency := int(time.Since(start).Milliseconds())
	corrID := int(head[4])<<24 | int(head[5])<<16 | int(head[6])<<8 | int(head[7])
	if corrID != 1 {
		return "down", latency, fmt.Sprintf("unexpected correlation id %d", corrID)
	}
	return "up", latency, "Kafka broker answered ApiVersions"
}

func berLen(n int) []byte {
	if n < 0x80 {
		return []byte{byte(n)}
	}
	b := []byte{}
	for n > 0 {
		b = append([]byte{byte(n & 0xff)}, b...)
		n >>= 8
	}
	return append([]byte{0x80 | byte(len(b))}, b...)
}

func berTLV(tag byte, val []byte) []byte {
	out := []byte{tag}
	out = append(out, berLen(len(val))...)
	return append(out, val...)
}

func berOID(oid string) []byte {
	parts := strings.Split(strings.TrimSpace(oid), ".")
	var nums []int
	for _, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil {
			return nil
		}
		nums = append(nums, n)
	}
	if len(nums) < 2 || nums[0] > 2 || nums[1] > 39 {
		return nil
	}
	out := []byte{byte(nums[0]*40 + nums[1])}
	for _, n := range nums[2:] {
		if n < 0 {
			return nil
		}
		if n < 0x80 {
			out = append(out, byte(n))
			continue
		}
		var enc []byte
		for n > 0 {
			enc = append([]byte{byte(n & 0x7f)}, enc...)
			n >>= 7
		}
		for i := 0; i < len(enc)-1; i++ {
			enc[i] |= 0x80
		}
		out = append(out, enc...)
	}
	return out
}

func checkSNMP(target string, settings json.RawMessage) (string, int, string) {
	var s infraSettings
	json.Unmarshal(settings, &s)
	community := strings.TrimSpace(s.Community)
	if community == "" {
		community = "public"
	}
	oid := strings.TrimSpace(s.OID)
	if oid == "" {
		oid = "1.3.6.1.2.1.1.3.0"
	}
	oidBytes := berOID(oid)
	if oidBytes == nil {
		return "down", 0, "invalid OID"
	}
	addr := infraHostPort(target, 161)
	if s.Port > 0 {
		host, _, _ := net.SplitHostPort(addr)
		addr = net.JoinHostPort(host, fmt.Sprintf("%d", s.Port))
	}

	reqID := int(time.Now().UnixNano() & 0x7fffffff)
	reqIDBytes := []byte{byte(reqID >> 24), byte(reqID >> 16), byte(reqID >> 8), byte(reqID)}
	varbind := berTLV(0x30, append(berTLV(0x06, oidBytes), 0x05, 0x00))
	varbindList := berTLV(0x30, varbind)
	pdu := berTLV(0xa0, append(append(append(
		berTLV(0x02, reqIDBytes),
		berTLV(0x02, []byte{0x00})...),
		berTLV(0x02, []byte{0x00})...),
		varbindList...))
	msg := berTLV(0x30, append(append(
		berTLV(0x02, []byte{0x01}),
		berTLV(0x04, []byte(community))...),
		pdu...))

	start := time.Now()
	conn, err := checkedDialTimeout("udp", addr, 5*time.Second)
	if err != nil {
		return "down", int(time.Since(start).Milliseconds()), "UDP dial failed: " + err.Error()
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write(msg); err != nil {
		return "down", int(time.Since(start).Milliseconds()), "SNMP write failed"
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return "down", int(time.Since(start).Milliseconds()), "no SNMP response (community wrong or device unreachable)"
	}
	latency := int(time.Since(start).Milliseconds())
	resp := buf[:n]
	if n < 4 || resp[0] != 0x30 {
		return "down", latency, "malformed SNMP response"
	}
	if !bytes.Contains(resp, reqIDBytes) {
		return "down", latency, "SNMP response did not echo request id"
	}
	for i := 0; i < n; i++ {
		if resp[i] == 0xa2 {
			return "up", latency, "SNMPv2c GetResponse received"
		}
	}
	return "down", latency, "response was not an SNMP GetResponse"
}

var agentSupportedCheckTypes = []string{
	"http", "https", "tcp", "telnet", "postgres", "mysql",
	"smtp", "pop3", "imap", "smtp_connect", "smtp_starttls",
	"ping", "icmp", "dns", "udp", "ssl", "domain", "redis",
	"game_server", "lavalink", "ftp", "sftp", "ssh",
	"docker", "podman", "docker_swarm", "vmware", "ceph",
	"kubernetes", "kube_deploy", "proxmox", "network_device",
	"rabbitmq", "kafka", "mqtt", "snmp",
}

func runMonitorCheck(monitor AssignedMonitor) (MonitorCheckResult, bool) {
	if isBlockedTarget(monitor.Target) {
		return MonitorCheckResult{Status: "down", Latency: 0, Message: "blocked target: link-local/cloud-metadata addresses are not allowed"}, true
	}

	switch monitor.Type {
	case "http", "https":
		verifySSL := true
		if monitor.VerifySSL != nil {
			verifySSL = *monitor.VerifySSL
		}
		status, latency, msg := checkHTTP(monitor.Target, monitor.ExpectedStatus, monitor.ExpectedBody, verifySSL)
		return MonitorCheckResult{Status: status, Latency: latency, Message: msg}, true
	case "tcp", "telnet", "postgres", "mysql", "smtp_connect":
		status, latency, msg := checkTCP(monitor.Target)
		return MonitorCheckResult{Status: status, Latency: latency, Message: msg}, true
	case "smtp", "pop3", "imap":
		verifySSL := true
		if monitor.VerifySSL != nil {
			verifySSL = *monitor.VerifySSL
		}
		status, latency, msg := checkMailAuth(monitor.Type, monitor.Target, monitor.Settings, verifySSL)
		return MonitorCheckResult{Status: status, Latency: latency, Message: msg}, true
	case "ftp":
		verifySSL := true
		if monitor.VerifySSL != nil {
			verifySSL = *monitor.VerifySSL
		}
		status, latency, msg := checkFTP(monitor.Target, monitor.Settings, verifySSL)
		return MonitorCheckResult{Status: status, Latency: latency, Message: msg}, true
	case "sftp":
		status, latency, msg := checkSFTPAuth(monitor.Target, monitor.Settings)
		return MonitorCheckResult{Status: status, Latency: latency, Message: msg}, true
	case "ssh":
		status, latency, msg := checkSSHAuth(monitor.Target, monitor.Settings)
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
	case "lavalink":
		status, latency, msg, metrics := checkLavalink(monitor.Target, monitor.Settings)
		return MonitorCheckResult{Status: status, Latency: latency, Message: msg, Metrics: metrics}, true
	case "docker":
		status, latency, msg := checkContainerRuntime("docker", monitor.Target, monitor.Settings)
		return MonitorCheckResult{Status: status, Latency: latency, Message: msg}, true
	case "podman":
		status, latency, msg := checkContainerRuntime("podman", monitor.Target, monitor.Settings)
		return MonitorCheckResult{Status: status, Latency: latency, Message: msg}, true
	case "docker_swarm":
		status, latency, msg := checkDockerSwarm(monitor.Target, monitor.Settings)
		return MonitorCheckResult{Status: status, Latency: latency, Message: msg}, true
	case "vmware":
		status, latency, msg := checkVMware(monitor.Target, monitor.Settings)
		return MonitorCheckResult{Status: status, Latency: latency, Message: msg}, true
	case "ceph":
		status, latency, msg := checkCeph(monitor.Target, monitor.Settings)
		return MonitorCheckResult{Status: status, Latency: latency, Message: msg}, true
	case "kubernetes":
		status, latency, msg := checkKubernetes(monitor.Target, monitor.Settings)
		return MonitorCheckResult{Status: status, Latency: latency, Message: msg}, true
	case "kube_deploy":
		status, latency, msg, metrics := checkKubeDeployment(monitor.Target, monitor.Settings)
		return MonitorCheckResult{Status: status, Latency: latency, Message: msg, Metrics: metrics}, true
	case "proxmox":
		status, latency, msg := checkProxmox(monitor.Target, monitor.Settings)
		return MonitorCheckResult{Status: status, Latency: latency, Message: msg}, true
	case "network_device":
		status, latency, msg := checkNetworkDevice(monitor.Target, monitor.Settings)
		return MonitorCheckResult{Status: status, Latency: latency, Message: msg}, true
	case "rabbitmq":
		status, latency, msg := checkRabbitMQ(monitor.Target, monitor.Settings)
		return MonitorCheckResult{Status: status, Latency: latency, Message: msg}, true
	case "kafka":
		status, latency, msg := checkKafka(monitor.Target, monitor.Settings)
		return MonitorCheckResult{Status: status, Latency: latency, Message: msg}, true
	case "mqtt":
		status, latency, msg := checkMQTT(monitor.Target, monitor.Settings)
		return MonitorCheckResult{Status: status, Latency: latency, Message: msg}, true
	case "snmp":
		status, latency, msg := checkSNMP(monitor.Target, monitor.Settings)
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

type lavalinkMonitorSettings struct {
	Password string `json:"password"`
	UseTLS   bool   `json:"use_tls"`
}

func checkLavalink(target string, settings json.RawMessage) (string, int, string, map[string]interface{}) {
	var s lavalinkMonitorSettings
	json.Unmarshal(settings, &s)
	if strings.TrimSpace(s.Password) == "" {
		return "down", 0, "lavalink REST password required", nil
	}
	host := strings.TrimPrefix(strings.TrimPrefix(strings.TrimSuffix(target, "/"), "https://"), "http://")
	if h, _, err := net.SplitHostPort(host); err != nil || h == "" {
		host = net.JoinHostPort(strings.Trim(host, "[]"), "2333")
	}
	scheme := "http"
	if s.UseTLS {
		scheme = "https"
	}
	req, err := http.NewRequest("GET", scheme+"://"+host+"/v4/stats", nil)
	if err != nil {
		return "down", 0, "invalid target", nil
	}
	req.Header.Set("Authorization", s.Password)
	start := time.Now()
	client := checkedHTTPClient(10*time.Second, true)
	resp, err := client.Do(req)
	latency := int(time.Since(start).Milliseconds())
	if err != nil {
		errMsg := err.Error()
		if len(errMsg) > 120 {
			errMsg = errMsg[:120]
		}
		return "down", latency, errMsg, nil
	}
	defer resp.Body.Close()
	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		return "down", latency, "lavalink auth failed — check REST password", nil
	}
	if resp.StatusCode != 200 {
		return "down", latency, fmt.Sprintf("HTTP %d from /v4/stats", resp.StatusCode), nil
	}
	var stats struct {
		Players        int   `json:"players"`
		PlayingPlayers int   `json:"playingPlayers"`
		Uptime         int64 `json:"uptime"`
		Memory         struct {
			Free      int64 `json:"free"`
			Used      int64 `json:"used"`
			Allocated int64 `json:"allocated"`
		} `json:"memory"`
		CPU struct {
			Cores        int     `json:"cores"`
			SystemLoad   float64 `json:"systemLoad"`
			LavalinkLoad float64 `json:"lavalinkLoad"`
		} `json:"cpu"`
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err := json.Unmarshal(body, &stats); err != nil {
		return "down", latency, "invalid stats response — is this a Lavalink v4 node?", nil
	}
	metrics := map[string]interface{}{
		"players":         stats.Players,
		"playing_players": stats.PlayingPlayers,
		"uptime_ms":       stats.Uptime,
		"memory_used_mb":  stats.Memory.Used / 1024 / 1024,
		"lavalink_load":   stats.CPU.LavalinkLoad,
		"system_load":     stats.CPU.SystemLoad,
	}
	return "up", latency, fmt.Sprintf("%d players (%d playing) · %d MB used · uptime %s",
		stats.Players, stats.PlayingPlayers, stats.Memory.Used/1024/1024, formatUptimeMs(stats.Uptime)), metrics
}

func formatUptimeMs(ms int64) string {
	d := time.Duration(ms) * time.Millisecond
	if d >= 24*time.Hour {
		return fmt.Sprintf("%dd%dh", int(d.Hours())/24, int(d.Hours())%24)
	}
	if d >= time.Hour {
		return fmt.Sprintf("%dh%dm", int(d.Hours()), int(d.Minutes())%60)
	}
	return fmt.Sprintf("%dm", int(d.Minutes()))
}
