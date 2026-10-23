package main

import (
	"bufio"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"
)

const logWatchBufferSize = 256

type logWatchRule struct {
	ID          string `json:"id"`
	Pattern     string `json:"pattern"`
	Severity    string `json:"severity"`
	ThrottleSec int    `json:"throttle_secs"`
	MaxLen      int    `json:"max_len"`
}

type logWatchState struct {
	mu       sync.Mutex
	rules    []logWatchRule
	compiled map[string]*regexp.Regexp
	buffer   chan agentEventItem
	throttle map[string]time.Time
}

var (
	logWatchInstanceMu sync.Mutex
	logWatchInstance   *logWatchState
)

func defaultLogWatchRules() []logWatchRule {
	return []logWatchRule{
		{ID: "ssh_failed_password", Pattern: `(?i)failed password`, Severity: "warning", ThrottleSec: 30, MaxLen: 240},
		{ID: "ssh_invalid_user", Pattern: `(?i)invalid user`, Severity: "warning", ThrottleSec: 30, MaxLen: 240},
		{ID: "oom_kill", Pattern: `(?i)out of memory:\s*killed process|killed process\s+\d+\s+\(\S+\)\s+total-vm`, Severity: "critical", ThrottleSec: 60, MaxLen: 300},
		{ID: "segfault", Pattern: `(?i)segfault`, Severity: "critical", ThrottleSec: 60, MaxLen: 300},
		{ID: "storage_error", Pattern: `(?i)ata\d+.*(?:error|exception)|nvme.*(?:error|fail)`, Severity: "critical", ThrottleSec: 60, MaxLen: 300},
		{ID: "sudo_usage", Pattern: `(?i)sudo:\s+\S+\s*:`, Severity: "info", ThrottleSec: 10, MaxLen: 240},
		{ID: "unit_failed", Pattern: `(?i)failed to start|entered failed state`, Severity: "critical", ThrottleSec: 30, MaxLen: 300},
		{ID: "service_started", Pattern: `(?i)systemd\[\d+\]:\s+Started `, Severity: "info", ThrottleSec: 10, MaxLen: 240},
	}
}

func getLogWatchState() *logWatchState {
	logWatchInstanceMu.Lock()
	defer logWatchInstanceMu.Unlock()
	if logWatchInstance == nil {
		logWatchInstance = &logWatchState{
			buffer:   make(chan agentEventItem, logWatchBufferSize),
			throttle: make(map[string]time.Time),
		}
	}
	return logWatchInstance
}

func (s *logWatchState) setRules(rules []logWatchRule) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rules = rules
	s.compiled = make(map[string]*regexp.Regexp, len(rules))
	for _, r := range rules {
		re, err := regexp.Compile(r.Pattern)
		if err != nil {
			fmt.Printf("[logwatch] invalid rule %s: %v\n", r.ID, err)
			continue
		}
		s.compiled[r.ID] = re
	}
}

func (s *logWatchState) match(line string, unit string) {
	s.mu.Lock()
	compiled := s.compiled
	rules := s.rules
	s.mu.Unlock()
	if compiled == nil {
		return
	}
	for _, r := range rules {
		re := compiled[r.ID]
		if re == nil {
			continue
		}
		if !re.MatchString(line) {
			continue
		}
		message := line
		if r.MaxLen > 0 && len(message) > r.MaxLen {
			message = message[:r.MaxLen] + "…"
		}
		hash := sha256.Sum256([]byte(r.ID + "|" + message))
		key := hex.EncodeToString(hash[:8])

		s.mu.Lock()
		last, ok := s.throttle[key]
		now := time.Now()
		if ok && now.Sub(last) < time.Duration(r.ThrottleSec)*time.Second {
			s.mu.Unlock()
			continue
		}
		s.throttle[key] = now
		s.mu.Unlock()

		select {
		case s.buffer <- agentEventItem{
			Type:     "log_match",
			Severity: r.Severity,
			Message:  fmt.Sprintf("[%s] %s", r.ID, message),
			Metadata: map[string]interface{}{
				"rule_id": r.ID,
				"unit":    unit,
				"matched": message,
			},
		}:
		default:
		}
	}
}

func (s *logWatchState) cleanupThrottle() {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for k, v := range s.throttle {
		if now.Sub(v) > 10*time.Minute {
			delete(s.throttle, k)
		}
	}
}

type journaldEntry struct {
	Message          string `json:"MESSAGE"`
	SystemdUnit      string `json:"_SYSTEMD_UNIT"`
	HostName         string `json:"_HOSTNAME"`
	SyslogIdentifier string `json:"SYSLOG_IDENTIFIER"`
	Priority         string `json:"PRIORITY"`
}

func fetchLogWatchRules(apiURL, token string) ([]logWatchRule, error) {
	req, err := http.NewRequest("GET", apiURL+"/api/v1/uptime/agents/logwatch-rules", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Agent-Token", token)
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	var body struct {
		Rules []logWatchRule `json:"rules"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, err
	}
	if len(body.Rules) == 0 {
		return nil, fmt.Errorf("no rules")
	}
	return body.Rules, nil
}

func startLogWatcher(cfg Config) {
	state := getLogWatchState()
	rules := defaultLogWatchRules()
	if remoteRules, err := fetchLogWatchRules(cfg.APIURL, cfg.Token); err == nil {
		rules = remoteRules
		fmt.Printf("[logwatch] loaded %d rules from server\n", len(rules))
	} else {
		fmt.Printf("[logwatch] using %d default rules (%v)\n", len(rules), err)
	}
	state.setRules(rules)
	go state.cleanupLoop()
	go state.runWatcher()
}

func (s *logWatchState) cleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		s.cleanupThrottle()
	}
}

func (s *logWatchState) runWatcher() {
	if runtime.GOOS == "linux" {
		if _, err := exec.LookPath("journalctl"); err == nil {
			s.runJournald()
		}
	}
	s.runFileTail()
}

func (s *logWatchState) runJournald() {
	cmd := exec.Command("journalctl", "-f", "-o", "json", "--no-tail")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		fmt.Printf("[logwatch] journalctl stdout pipe failed: %v\n", err)
		return
	}
	if err := cmd.Start(); err != nil {
		fmt.Printf("[logwatch] journalctl start failed: %v\n", err)
		return
	}
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()

	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 1024), 256*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		var entry journaldEntry
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			continue
		}
		msg := entry.Message
		if msg == "" {
			continue
		}
		unit := entry.SystemdUnit
		if unit == "" {
			unit = entry.SyslogIdentifier
		}
		s.match(msg, unit)
	}
	fmt.Printf("[logwatch] journald stream ended: %v\n", scanner.Err())
}

func (s *logWatchState) runFileTail() {
	files := s.tailFiles()
	if len(files) == 0 {
		return
	}
	args := append([]string{"-F"}, files...)
	cmd := exec.Command("tail", args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		fmt.Printf("[logwatch] tail stdout pipe failed: %v\n", err)
		return
	}
	if err := cmd.Start(); err != nil {
		fmt.Printf("[logwatch] tail start failed: %v\n", err)
		return
	}
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()

	reader := bufio.NewReader(stdout)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			if err != io.EOF {
				fmt.Printf("[logwatch] tail read ended: %v\n", err)
			}
			return
		}
		line = strings.TrimSuffix(line, "\n")
		if line == "" {
			continue
		}
		s.match(line, "")
	}
}

func (s *logWatchState) tailFiles() []string {
	candidates := []string{"/var/log/syslog", "/var/log/auth.log", "/var/log/messages", "/var/log/secure"}
	if runtime.GOOS == "darwin" {
		candidates = []string{"/var/log/system.log"}
	}
	var out []string
	for _, f := range candidates {
		if _, err := os.Stat(f); err == nil {
			out = append(out, f)
		}
	}
	return out
}

func collectLogWatchEvents(cfg Config) []agentEventItem {
	if !cfg.LogWatchEnabled && !envFlagEnabled("AGENT_LOG_WATCH") {
		return nil
	}
	state := getLogWatchState()
	var events []agentEventItem
	for {
		select {
		case ev := <-state.buffer:
			events = append(events, ev)
		default:
			return events
		}
	}
}
