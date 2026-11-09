package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

var AgentVersion = "dev"

var (
	prevNetMu  sync.Mutex
	prevNetIn  int64
	prevNetOut int64
	prevNetTs  time.Time
)

const (
	DefaultAPIURL                    = "https://api.uptriva.com"
	DefaultGitHubReleaseRepo         = "Uptriva/uptriva-agent"
	LegacyAPIURL                     = "https://api.shxrk.systems"
	MinInterval                      = 15
	DefaultInterval                  = 30
	DefaultAutoUpdateEnabled         = true
	DefaultAutoUpdateIntervalMinutes = 30
)

var apiBaseURLs = []string{DefaultAPIURL, LegacyAPIURL}

type Config struct {
	APIURL                     string   `json:"api_url"`
	Token                      string   `json:"token"`
	AgentID                    string   `json:"agent_id"`
	Interval                   int      `json:"interval"`
	Port                       int      `json:"port"`
	AutoUpdateEnabled          bool     `json:"auto_update_enabled"`
	AutoUpdateIntervalMinutes  int      `json:"auto_update_interval_minutes"`
	AcceptedPrivacyPolicy      string   `json:"accepted_privacy_policy"`
	BetaChannel                bool     `json:"beta_channel"`
	WatchServices              []string `json:"watch_services"`
	WatchFiles                 []string `json:"watch_files"`
	SecurityEventsEnabled      bool     `json:"security_events_enabled"`
	PackageMonitoringEnabled   bool     `json:"package_monitoring_enabled"`
	PortWatchEnabled           bool     `json:"port_watch_enabled"`
	IntegrityMonitoringEnabled bool     `json:"integrity_monitoring_enabled"`
	KernelEventsEnabled        bool     `json:"kernel_events_enabled"`
	CertWatchEnabled           bool     `json:"cert_watch_enabled"`
	SystemPostureEnabled       bool     `json:"system_posture_enabled"`
	ContainerWatchEnabled      bool     `json:"container_watch_enabled"`
	LogWatchEnabled            bool     `json:"log_watch_enabled"`
	WatchCerts                 []string `json:"watch_certs"`
	DisableRemoteCommands      bool     `json:"disable_remote_commands"`
	EnableRemoteCommands       bool     `json:"enable_remote_commands"`
	AllowExecScript            bool     `json:"allow_exec_script"`
	AllowSystemCommands        bool     `json:"allow_system_commands"`
}

func remoteCommandsEnabled(c *Config) bool {
	if c.DisableRemoteCommands || envFlagEnabled("AGENT_DISABLE_COMMANDS") {
		return false
	}
	return c.EnableRemoteCommands || envFlagEnabled("AGENT_ENABLE_COMMANDS")
}

func execScriptAllowed(c *Config) bool {
	return c.AllowExecScript || envFlagEnabled("AGENT_ALLOW_EXEC_SCRIPT")
}

func systemCommandsAllowed(c *Config) bool {
	return c.AllowSystemCommands || envFlagEnabled("AGENT_ALLOW_SYSTEM_CMDS")
}

func envFlagEnabled(name string) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(name))) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

func configPath() string {
	if p := strings.TrimSpace(os.Getenv("UPTRIVA_AGENT_CONFIG")); p != "" {
		return p
	}
	if p := strings.TrimSpace(os.Getenv("SHXRK_AGENT_CONFIG")); p != "" {
		return p
	}
	if _, err := os.Stat("agent_config.json"); err == nil {
		return "agent_config.json"
	}
	if runtime.GOOS == "darwin" {
		home, _ := os.UserHomeDir()
		newPath := filepath.Join(home, ".uptriva", "agent_config.json")
		if _, err := os.Stat(newPath); err == nil {
			return newPath
		}
		legacyPath := filepath.Join(home, ".shxrk", "agent_config.json")
		if _, err := os.Stat(legacyPath); err == nil {
			return legacyPath
		}
		return newPath
	}
	if _, err := os.Stat("/etc/uptriva/agent_config.json"); err == nil {
		return "/etc/uptriva/agent_config.json"
	}
	if _, err := os.Stat("/etc/shxrk/agent_config.json"); err == nil {
		return "/etc/shxrk/agent_config.json"
	}
	return "/etc/uptriva/agent_config.json"
}

func saveConfig(config Config) error {
	b, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}
	p := configPath()
	if dir := filepath.Dir(p); dir != "." {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return err
		}
	}
	return os.WriteFile(p, b, 0600)
}

func loadConfig() (Config, error) {
	var config Config
	b, err := os.ReadFile(configPath())
	if err != nil {
		return config, err
	}
	if err := json.Unmarshal(b, &config); err != nil {
		return config, err
	}
	if config.AutoUpdateIntervalMinutes <= 0 {
		config.AutoUpdateIntervalMinutes = DefaultAutoUpdateIntervalMinutes
	}
	return config, nil
}

func signPayload(payload []byte, apiKey string) string {
	h := hmac.New(sha256.New, []byte(apiKey))
	h.Write(payload)
	return hex.EncodeToString(h.Sum(nil))
}

type MetricsPayload struct {
	CPUUsage         float64  `json:"cpu_usage"`
	CPUCores         int      `json:"cpu_cores"`
	RAMUsage         float64  `json:"ram_usage"`
	DiskUsage        float64  `json:"disk_usage"`
	NetIn            int64    `json:"net_in"`
	NetOut           int64    `json:"net_out"`
	Processes        string   `json:"processes"`
	Interval         int      `json:"interval"`
	Version          string   `json:"version"`
	Load1            float64  `json:"load_1"`
	Load5            float64  `json:"load_5"`
	Load15           float64  `json:"load_15"`
	UptimeSecs       uint64   `json:"uptime_secs"`
	MemoryJSON       string   `json:"memory_detail"`
	DisksJSON        string   `json:"disks_detail"`
	SystemdJSON      string   `json:"systemd_units"`
	FailedUnits      string   `json:"failed_units"`
	SelfPingMs       int      `json:"self_ping_ms"`
	CheckTypes       []string `json:"check_types,omitempty"`
	CPUBreakdownJSON string   `json:"cpu_breakdown,omitempty"`
	DiskIOJSON       string   `json:"disk_io,omitempty"`
	PortsJSON        string   `json:"listen_ports,omitempty"`
	SmartJSON        string   `json:"smart_drives,omitempty"`
	SystemInfoJSON   string   `json:"system_info,omitempty"`
}

func collectMetrics(apiURL string) (MetricsPayload, error) {
	var payload MetricsPayload

	payload.CPUUsage = getCPUUsage()
	payload.CPUCores = getCPUCoreCount()
	payload.RAMUsage = getRAMUsage()
	payload.DiskUsage = getDiskUsage()

	now := time.Now()
	curIn, curOut := getNetworkBytes()
	prevNetMu.Lock()
	if !prevNetTs.IsZero() {
		elapsed := now.Sub(prevNetTs).Seconds()
		if elapsed > 0 {
			payload.NetIn = int64(float64(curIn-prevNetIn) / elapsed)
			payload.NetOut = int64(float64(curOut-prevNetOut) / elapsed)
			if payload.NetIn < 0 {
				payload.NetIn = 0
			}
			if payload.NetOut < 0 {
				payload.NetOut = 0
			}
		}
	}
	prevNetIn = curIn
	prevNetOut = curOut
	prevNetTs = now
	prevNetMu.Unlock()

	payload.Processes = getRunningProcesses()

	payload.Load1, payload.Load5, payload.Load15 = getLoadAverages()
	payload.UptimeSecs = getUptime()

	memDetail := getMemoryDetail()
	if b, err := json.Marshal(memDetail); err == nil {
		payload.MemoryJSON = string(b)
	}

	diskDetails := getDiskDetails()
	if b, err := json.Marshal(diskDetails); err == nil {
		payload.DisksJSON = string(b)
	}

	systemdUnits := getSystemdUnits()
	if systemdUnits != nil {
		if b, err := json.Marshal(systemdUnits); err == nil {
			payload.SystemdJSON = string(b)
		}
	}

	failedUnits := getFailedSystemdUnits()
	if len(failedUnits) > 0 {
		if b, err := json.Marshal(failedUnits); err == nil {
			payload.FailedUnits = string(b)
		}
	} else {
		payload.FailedUnits = "[]"
	}

	payload.SelfPingMs = measureSelfPing(apiURL)

	if cpuBreakdown := getCPUBreakdown(); cpuBreakdown != nil {
		if b, err := json.Marshal(cpuBreakdown); err == nil {
			payload.CPUBreakdownJSON = string(b)
		}
	}

	if diskIO := getDiskIORates(); len(diskIO) > 0 {
		if b, err := json.Marshal(diskIO); err == nil {
			payload.DiskIOJSON = string(b)
		}
	}

	if ports := getListenPorts(); len(ports) > 0 {
		if b, err := json.Marshal(ports); err == nil {
			payload.PortsJSON = string(b)
		}
	}

	if drives := getSmartDrives(); len(drives) > 0 {
		if b, err := json.Marshal(drives); err == nil {
			payload.SmartJSON = string(b)
		}
	}

	if info := getSystemInfo(); info != nil {
		if b, err := json.Marshal(info); err == nil {
			payload.SystemInfoJSON = string(b)
		}
	}

	return payload, nil
}

func collectMetricsWithInterval(apiURL string, interval int) (MetricsPayload, error) {
	p, err := collectMetrics(apiURL)
	if err != nil {
		return p, err
	}
	p.Interval = interval
	p.Version = AgentVersion
	p.CheckTypes = agentSupportedCheckTypes
	return p, nil
}

func performHandshake(token string) (Config, error) {
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown-host"
	}

	timestamp := fmt.Sprintf("%d", time.Now().Unix())

	interval := DefaultInterval
	if cfg, err := loadConfig(); err == nil && cfg.Interval > 0 {
		interval = cfg.Interval
	}

	payload := map[string]interface{}{
		"token":       token,
		"hostname":    hostname,
		"version":     AgentVersion,
		"timestamp":   timestamp,
		"interval":    interval,
		"check_types": agentSupportedCheckTypes,
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return Config{}, err
	}

	signature := signPayload(b, token)

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
			},
		},
	}

	var lastErr error
	var res struct {
		AgentID string `json:"agent_id"`
		Token   string `json:"token"`
	}
	apiURL := ""
	for _, base := range apiBaseURLs {
		req, err := http.NewRequest("POST", base+"/api/v1/uptime/agents/handshake", bytes.NewBuffer(b))
		if err != nil {
			lastErr = err
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Agent-Signature", signature)
		req.Header.Set("X-Agent-Timestamp", timestamp)

		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			lastErr = fmt.Errorf("handshake failed with status %d: %s", resp.StatusCode, string(body))
			continue
		}
		if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
			resp.Body.Close()
			lastErr = err
			continue
		}
		resp.Body.Close()
		apiURL = base
		break
	}
	if apiURL == "" {
		return Config{}, lastErr
	}

	sessionToken := token
	if res.Token != "" {
		sessionToken = res.Token
	}

	return Config{
		APIURL:                    apiURL,
		Token:                     sessionToken,
		AgentID:                   res.AgentID,
		Interval:                  DefaultInterval,
		AutoUpdateEnabled:         DefaultAutoUpdateEnabled,
		AutoUpdateIntervalMinutes: DefaultAutoUpdateIntervalMinutes,
	}, nil
}

func probeAPIBase(base string) bool {
	client := &http.Client{Timeout: 4 * time.Second}
	resp, err := client.Get(base + "/health")
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

func resolveAPIURL(stored string) string {
	if stored != LegacyAPIURL {
		return stored
	}
	if probeAPIBase(DefaultAPIURL) {
		return DefaultAPIURL
	}
	return stored
}

type AgentManifest struct {
	Version              string                   `json:"version"`
	MinAgentVersion      string                   `json:"min_agent_version"`
	PrivacyPolicyVersion string                   `json:"privacy_policy_version"`
	PrivacyPolicyURL     string                   `json:"privacy_policy_url"`
	ReleaseNotes         string                   `json:"release_notes"`
	RequiresConsent      bool                     `json:"requires_consent"`
	Platforms            map[string]PlatformAsset `json:"platforms"`
	KeyID                string                   `json:"key_id,omitempty"`
	Signature            string                   `json:"signature,omitempty"`
}

var releasePublicKeyHex = ""

var releasePublicKey = func() ed25519.PublicKey {
	hexKey := os.Getenv("AGENT_RELEASE_PUBKEY")
	if hexKey == "" {
		hexKey = releasePublicKeyHex
	}
	if hexKey == "" {
		return nil
	}
	raw, err := hex.DecodeString(hexKey)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil
	}
	return ed25519.PublicKey(raw)
}()

func manifestSigningPayload(m *AgentManifest) []byte {
	signed := *m
	signed.KeyID = ""
	signed.Signature = ""
	payload, _ := json.Marshal(signed)
	return payload
}

func verifyManifestSignature(m *AgentManifest) error {
	if len(releasePublicKey) == 0 {
		if envFlagEnabled("AGENT_ALLOW_UNSIGNED_RELEASES") {
			return nil
		}
		return fmt.Errorf("release public key not configured, refusing unsigned release")
	}
	if m.Signature == "" {
		return fmt.Errorf("manifest is unsigned but signature verification is enabled")
	}
	sig, err := hex.DecodeString(m.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("manifest has an invalid signature")
	}
	if !ed25519.Verify(releasePublicKey, manifestSigningPayload(m), sig) {
		return fmt.Errorf("manifest signature verification failed")
	}
	return nil
}

type PlatformAsset struct {
	Checksum string `json:"checksum"`
	URL      string `json:"url"`
}

func fetchManifest(betaChannel bool) (*AgentManifest, error) {
	return fetchManifestFromGitHub(betaChannel)
}

type githubReleaseAsset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
}

type githubRelease struct {
	TagName    string               `json:"tag_name"`
	Prerelease bool                 `json:"prerelease"`
	Assets     []githubReleaseAsset `json:"assets"`
}

func githubReleaseRepo() string {
	if repo := strings.TrimSpace(os.Getenv("AGENT_GITHUB_REPO")); repo != "" {
		return repo
	}
	return DefaultGitHubReleaseRepo
}

func githubAPIGet(url string) (*http.Response, error) {
	client := &http.Client{Timeout: 15 * time.Second}
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "uptriva-agent/"+AgentVersion)
	return client.Do(req)
}

func fetchManifestFromGitHub(betaChannel bool) (*AgentManifest, error) {
	apiBase := "https://api.github.com/repos/" + githubReleaseRepo()
	var release githubRelease
	if betaChannel {
		resp, err := githubAPIGet(apiBase + "/releases?per_page=15")
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("github releases returned %d", resp.StatusCode)
		}
		var releases []githubRelease
		if err := json.NewDecoder(resp.Body).Decode(&releases); err != nil {
			return nil, err
		}
		found := false
		for _, r := range releases {
			if r.Prerelease {
				release = r
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("no beta release found on github")
		}
	} else {
		resp, err := githubAPIGet(apiBase + "/releases/latest")
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("github releases returned %d", resp.StatusCode)
		}
		if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
			return nil, err
		}
	}

	manifestURL := ""
	for _, asset := range release.Assets {
		if asset.Name == "manifest.json" {
			manifestURL = asset.BrowserDownloadURL
			break
		}
	}
	if manifestURL == "" {
		return nil, fmt.Errorf("release %s has no manifest.json asset", release.TagName)
	}

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Get(manifestURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("manifest asset returned %d", resp.StatusCode)
	}
	var manifest AgentManifest
	if err := json.NewDecoder(resp.Body).Decode(&manifest); err != nil {
		return nil, err
	}
	if err := verifyManifestSignature(&manifest); err != nil {
		return nil, err
	}
	return &manifest, nil
}

func downloadFile(assetURL string) (*http.Response, error) {
	client := &http.Client{Timeout: 120 * time.Second}
	if strings.HasPrefix(assetURL, "http://") || strings.HasPrefix(assetURL, "https://") {
		resp, err := client.Get(assetURL)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			return nil, fmt.Errorf("download returned %d", resp.StatusCode)
		}
		return resp, nil
	}
	return nil, fmt.Errorf("relative asset URLs are not supported: %s", assetURL)
}

func compareVersions(a, b string) int {
	a = strings.TrimPrefix(strings.TrimSpace(a), "v")
	b = strings.TrimPrefix(strings.TrimSpace(b), "v")
	aParts := strings.Split(a, ".")
	bParts := strings.Split(b, ".")
	maxLen := len(aParts)
	if len(bParts) > maxLen {
		maxLen = len(bParts)
	}
	for i := 0; i < maxLen; i++ {
		var aNum, bNum int
		if i < len(aParts) {
			fmt.Sscanf(aParts[i], "%d", &aNum)
		}
		if i < len(bParts) {
			fmt.Sscanf(bParts[i], "%d", &bNum)
		}
		if aNum < bNum {
			return -1
		}
		if aNum > bNum {
			return 1
		}
	}
	return 0
}

func getPlatformKey() string {
	return runtime.GOOS + "/" + runtime.GOARCH
}

func getBinaryPath() string {
	if runtime.GOOS == "windows" {
		return "C:\\Program Files\\Uptriva\\uptriva-agent.exe"
	}
	return "/usr/local/bin/uptriva-agent"
}

func getCurrentBinaryPath() string {
	exe, err := os.Executable()
	if err != nil {
		return getBinaryPath()
	}
	return exe
}

type UpdateResult struct {
	Updated              bool
	RequiresConsent      bool
	PrivacyPolicyVersion string
	PrivacyPolicyURL     string
	ReleaseNotes         string
	NewVersion           string
}

func checkForUpdate(config Config) (*UpdateResult, error) {
	manifest, err := fetchManifest(config.BetaChannel)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch manifest: %w", err)
	}

	if compareVersions(manifest.Version, AgentVersion) <= 0 {
		return &UpdateResult{Updated: false}, nil
	}

	if manifest.MinAgentVersion != "" && compareVersions(AgentVersion, manifest.MinAgentVersion) < 0 {
		return nil, fmt.Errorf("update %s requires agent >= %s (current %s)", manifest.Version, manifest.MinAgentVersion, AgentVersion)
	}

	if manifest.RequiresConsent && config.AcceptedPrivacyPolicy != manifest.PrivacyPolicyVersion {
		return &UpdateResult{
			Updated:              false,
			RequiresConsent:      true,
			PrivacyPolicyVersion: manifest.PrivacyPolicyVersion,
			PrivacyPolicyURL:     manifest.PrivacyPolicyURL,
			ReleaseNotes:         manifest.ReleaseNotes,
			NewVersion:           manifest.Version,
		}, nil
	}

	return &UpdateResult{
		Updated:         false,
		RequiresConsent: false,
		ReleaseNotes:    manifest.ReleaseNotes,
		NewVersion:      manifest.Version,
	}, nil
}

func downloadAndInstallUpdate(manifest *AgentManifest) error {
	platformKey := getPlatformKey()
	asset, ok := manifest.Platforms[platformKey]
	if !ok {
		return fmt.Errorf("no binary available for platform %s", platformKey)
	}

	resp, err := downloadFile(asset.URL)
	if err != nil {
		return fmt.Errorf("failed to download: %w", err)
	}
	defer resp.Body.Close()

	tmpPath := getCurrentBinaryPath() + ".new"
	if runtime.GOOS == "windows" {
		tmpPath = os.Getenv("TEMP") + "\\uptriva-agent.new.exe"
	}

	f, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}

	h := sha256.New()
	if _, err := io.Copy(io.MultiWriter(f, h), resp.Body); err != nil {
		f.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("failed to write temp file: %w", err)
	}
	f.Close()

	actualChecksum := hex.EncodeToString(h.Sum(nil))
	if actualChecksum != asset.Checksum {
		os.Remove(tmpPath)
		return fmt.Errorf("checksum mismatch: expected %s, got %s", asset.Checksum, actualChecksum)
	}

	testCmd := exec.Command(tmpPath, "-version")
	if err := testCmd.Run(); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("downloaded binary is invalid: %w", err)
	}

	binPath := getCurrentBinaryPath()
	backupPath := binPath + ".bak"
	backupSumPath := binPath + ".bak.sha256"

	if _, err := os.Stat(binPath); err == nil {
		os.Remove(backupSumPath)
		os.Rename(binPath, backupPath)
		if sum, serr := fileSHA256(backupPath); serr == nil {
			os.WriteFile(backupSumPath, []byte(sum), 0644)
		}
	}

	if err := os.Rename(tmpPath, binPath); err != nil {
		if _, berr := os.Stat(backupPath); berr == nil {
			os.Rename(backupPath, binPath)
		}
		os.Remove(tmpPath)
		return fmt.Errorf("failed to replace binary: %w", err)
	}

	markerPath := binPath + ".update-pending"
	if err := os.WriteFile(markerPath, []byte("0"), 0644); err != nil {
		os.Rename(binPath, tmpPath)
		restoreVerifiedBackup(binPath)
		os.Remove(tmpPath)
		return fmt.Errorf("failed to write update marker, rolled back: %w", err)
	}

	return nil
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func restoreVerifiedBackup(binPath string) bool {
	backupPath := binPath + ".bak"
	sumPath := binPath + ".bak.sha256"
	expected, err := os.ReadFile(sumPath)
	if err != nil {
		fmt.Println("[update] rollback refused: no checksum record for backup binary")
		return false
	}
	actual, err := fileSHA256(backupPath)
	if err != nil || actual != strings.TrimSpace(string(expected)) {
		fmt.Println("[update] rollback refused: backup binary checksum mismatch")
		return false
	}
	if err := os.Rename(backupPath, binPath); err != nil {
		return false
	}
	os.Remove(sumPath)
	return true
}

func checkPendingUpdate() {
	binPath := getCurrentBinaryPath()
	markerPath := binPath + ".update-pending"

	data, err := os.ReadFile(markerPath)
	if err != nil {
		return
	}

	attempts, _ := strconv.Atoi(strings.TrimSpace(string(data)))

	if attempts >= 2 {
		backupPath := binPath + ".bak"
		if _, err := os.Stat(backupPath); err == nil {
			if restoreVerifiedBackup(binPath) {
				os.Remove(markerPath)
				fmt.Println("[update] rollback: restored verified previous binary after repeated failed starts")
				os.Exit(1)
			}
			os.Remove(markerPath)
			fmt.Println("[update] rollback: backup verification failed, staying on current binary")
		}
		return
	}

	_ = os.WriteFile(markerPath, []byte(strconv.Itoa(attempts+1)), 0644)
}

func confirmUpdate() {
	binPath := getCurrentBinaryPath()
	if _, err := os.Stat(binPath + ".update-pending"); err != nil {
		return
	}
	os.Remove(binPath + ".update-pending")
	os.Remove(binPath + ".bak")
	os.Remove(binPath + ".bak.sha256")
	fmt.Println("[update] update confirmed healthy, previous version removed")
}

func performUpdate(config *Config) bool {
	manifest, err := fetchManifest(config.BetaChannel)
	if err != nil {
		fmt.Printf("[update] failed to fetch manifest: %v\n", err)
		return false
	}

	if compareVersions(manifest.Version, AgentVersion) <= 0 {
		return false
	}

	if manifest.MinAgentVersion != "" && compareVersions(AgentVersion, manifest.MinAgentVersion) < 0 {
		fmt.Printf("[update] refusing update to %s: requires agent >= %s (current %s)\n", manifest.Version, manifest.MinAgentVersion, AgentVersion)
		return false
	}

	if manifest.RequiresConsent && config.AcceptedPrivacyPolicy != manifest.PrivacyPolicyVersion {
		fmt.Printf("[update] update to %s available but requires privacy policy consent (v%s)\n", manifest.Version, manifest.PrivacyPolicyVersion)
		fmt.Printf("[update] review at %s\n", manifest.PrivacyPolicyURL)
		fmt.Println("[update] run: uptriva-agent -accept-privacy-policy to consent and update")
		return false
	}

	fmt.Printf("[update] upgrading from %s to %s...\n", AgentVersion, manifest.Version)
	if err := downloadAndInstallUpdate(manifest); err != nil {
		fmt.Printf("[update] failed: %v\n", err)
		return false
	}

	config.AcceptedPrivacyPolicy = manifest.PrivacyPolicyVersion
	_ = saveConfig(*config)

	fmt.Printf("[update] successfully upgraded to %s\n", manifest.Version)
	return true
}

func main() {
	tokenFlag := flag.String("token", "", "")
	intervalFlag := flag.Int("interval", DefaultInterval, "")
	portFlag := flag.Int("port", 0, "")
	versionFlag := flag.Bool("version", false, "")
	updateFlag := flag.Bool("update", false, "")
	checkUpdateFlag := flag.Bool("check-update", false, "")
	acceptPrivacyFlag := flag.Bool("accept-privacy-policy", false, "")
	betaFlag := flag.Bool("beta", false, "")
	securityEventsFlag := flag.Bool("security-events", false, "")
	noSecurityEventsFlag := flag.Bool("no-security-events", false, "")
	pkgMonitoringFlag := flag.Bool("package-monitoring", false, "")
	noPkgMonitoringFlag := flag.Bool("no-package-monitoring", false, "")
	portWatchFlag := flag.Bool("port-watch", false, "")
	noPortWatchFlag := flag.Bool("no-port-watch", false, "")
	integrityFlag := flag.Bool("integrity-monitoring", false, "")
	noIntegrityFlag := flag.Bool("no-integrity-monitoring", false, "")
	kernelEventsFlag := flag.Bool("kernel-events", false, "")
	noKernelEventsFlag := flag.Bool("no-kernel-events", false, "")
	certWatchFlag := flag.Bool("cert-watch", false, "")
	noCertWatchFlag := flag.Bool("no-cert-watch", false, "")
	systemPostureFlag := flag.Bool("system-posture", false, "")
	noSystemPostureFlag := flag.Bool("no-system-posture", false, "")
	containerWatchFlag := flag.Bool("container-watch", false, "")
	noContainerWatchFlag := flag.Bool("no-container-watch", false, "")
	logWatchFlag := flag.Bool("log-watch", false, "")
	noLogWatchFlag := flag.Bool("no-log-watch", false, "")
	disableCommandsFlag := flag.Bool("no-remote-commands", false, "")
	enableCommandsFlag := flag.Bool("remote-commands", false, "")
	allowExecFlag := flag.Bool("allow-exec-script", false, "")
	flag.Parse()

	switch flag.Arg(0) {
	case "update":
		*updateFlag = true
	case "check-update":
		*checkUpdateFlag = true
	case "version":
		*versionFlag = true
	}

	if *tokenFlag == "" {
		*tokenFlag = strings.TrimSpace(os.Getenv("AGENT_TOKEN"))
	}

	if *versionFlag {
		fmt.Println(AgentVersion)
		os.Exit(0)
	}

	if *checkUpdateFlag {
		config, err := loadConfig()
		if err != nil {
			config = Config{}
		}
		if *betaFlag {
			config.BetaChannel = true
		}
		if config.BetaChannel {
			fmt.Println("[check-update] using beta channel")
		}
		result, err := checkForUpdate(config)
		if err != nil {
			fmt.Printf("Error checking for update: %v\n", err)
			os.Exit(1)
		}
		if result.RequiresConsent {
			fmt.Printf("Update available: %s -> %s\n", AgentVersion, result.NewVersion)
			fmt.Printf("Privacy policy changed (v%s). Review: %s\n", result.PrivacyPolicyVersion, result.PrivacyPolicyURL)
			fmt.Println("Run: uptriva-agent -accept-privacy-policy to consent and update")
			os.Exit(0)
		}
		if result.NewVersion != "" {
			fmt.Printf("Update available: %s -> %s\n", AgentVersion, result.NewVersion)
			os.Exit(0)
		}
		fmt.Println("No update available.")
		os.Exit(0)
	}

	if *acceptPrivacyFlag {
		config, err := loadConfig()
		if err != nil {
			fmt.Printf("Error loading config: %v\n", err)
			os.Exit(1)
		}
		if *betaFlag {
			config.BetaChannel = true
		}
		manifest, err := fetchManifest(config.BetaChannel)
		if err != nil {
			fmt.Printf("Error fetching manifest: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Accepting privacy policy v%s\n", manifest.PrivacyPolicyVersion)
		fmt.Printf("Review at: %s\n", manifest.PrivacyPolicyURL)
		config.AcceptedPrivacyPolicy = manifest.PrivacyPolicyVersion
		if err := saveConfig(config); err != nil {
			fmt.Printf("Error saving config: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Privacy policy accepted. Proceeding with update...")
		if performUpdate(&config) {
			fmt.Println("Update installed. Restart the agent to use the new version.")
			os.Exit(0)
		}
		fmt.Println("No update available or update failed.")
		os.Exit(0)
	}

	if *updateFlag {
		fmt.Println("Checking for updates...")
		config, err := loadConfig()
		if err != nil {
			config = Config{}
		}
		if *betaFlag {
			config.BetaChannel = true
			_ = saveConfig(config)
		}
		if config.BetaChannel {
			fmt.Println("[update] using beta channel")
		}
		if performUpdate(&config) {
			fmt.Println("Update installed. Restart the agent to use the new version.")
			os.Exit(0)
		}
		fmt.Println("No update available or update failed.")
		os.Exit(0)
	}

	checkPendingUpdate()

	var config Config

	if *tokenFlag != "" {
		cfg, err := performHandshake(*tokenFlag)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
		config = cfg
		if *intervalFlag >= MinInterval {
			config.Interval = *intervalFlag
		} else {
			config.Interval = MinInterval
		}
		config.Port = *portFlag
		if *betaFlag {
			config.BetaChannel = true
		}
		config.SecurityEventsEnabled = *securityEventsFlag
		config.PackageMonitoringEnabled = *pkgMonitoringFlag

		if err := saveConfig(config); err != nil {
			fmt.Printf("Error saving config: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Agent registered successfully. Starting metric collection...")
	} else {
		cfg, err := loadConfig()
		if err != nil {
			fmt.Println("Error: Config file agent_config.json not found and no --token provided.")
			flag.Usage()
			os.Exit(1)
		}
		config = cfg
		if *securityEventsFlag || *noSecurityEventsFlag || *pkgMonitoringFlag || *noPkgMonitoringFlag || *disableCommandsFlag || *enableCommandsFlag || *allowExecFlag || *portWatchFlag || *noPortWatchFlag || *integrityFlag || *noIntegrityFlag || *kernelEventsFlag || *noKernelEventsFlag || *certWatchFlag || *noCertWatchFlag || *systemPostureFlag || *noSystemPostureFlag || *containerWatchFlag || *noContainerWatchFlag || *logWatchFlag || *noLogWatchFlag {
			if *securityEventsFlag {
				config.SecurityEventsEnabled = true
			}
			if *noSecurityEventsFlag {
				config.SecurityEventsEnabled = false
			}
			if *pkgMonitoringFlag {
				config.PackageMonitoringEnabled = true
			}
			if *noPkgMonitoringFlag {
				config.PackageMonitoringEnabled = false
			}
			if *portWatchFlag {
				config.PortWatchEnabled = true
			}
			if *noPortWatchFlag {
				config.PortWatchEnabled = false
			}
			if *integrityFlag {
				config.IntegrityMonitoringEnabled = true
			}
			if *noIntegrityFlag {
				config.IntegrityMonitoringEnabled = false
			}
			if *kernelEventsFlag {
				config.KernelEventsEnabled = true
			}
			if *noKernelEventsFlag {
				config.KernelEventsEnabled = false
			}
			if *certWatchFlag {
				config.CertWatchEnabled = true
			}
			if *noCertWatchFlag {
				config.CertWatchEnabled = false
			}
			if *systemPostureFlag {
				config.SystemPostureEnabled = true
			}
			if *noSystemPostureFlag {
				config.SystemPostureEnabled = false
			}
			if *containerWatchFlag {
				config.ContainerWatchEnabled = true
			}
			if *noContainerWatchFlag {
				config.ContainerWatchEnabled = false
			}
			if *logWatchFlag {
				config.LogWatchEnabled = true
			}
			if *noLogWatchFlag {
				config.LogWatchEnabled = false
			}
			if *disableCommandsFlag {
				config.DisableRemoteCommands = true
				config.EnableRemoteCommands = false
			}
			if *enableCommandsFlag {
				config.EnableRemoteCommands = true
				config.DisableRemoteCommands = false
			}
			if *allowExecFlag {
				config.AllowExecScript = true
			}
			if err := saveConfig(config); err != nil {
				fmt.Printf("Error saving config: %v\n", err)
			}
			fmt.Printf("[agent] addons: security-events=%v package-monitoring=%v port-watch=%v integrity-monitoring=%v kernel-events=%v cert-watch=%v system-posture=%v container-watch=%v log-watch=%v remote-commands=%v exec-script=%v\n",
				config.SecurityEventsEnabled, config.PackageMonitoringEnabled, config.PortWatchEnabled, config.IntegrityMonitoringEnabled, config.KernelEventsEnabled, config.CertWatchEnabled, config.SystemPostureEnabled, config.ContainerWatchEnabled, config.LogWatchEnabled, remoteCommandsEnabled(&config), execScriptAllowed(&config))
		}
	}

	if config.Interval < MinInterval {
		config.Interval = MinInterval
	}

	if resolved := resolveAPIURL(config.APIURL); resolved != config.APIURL {
		fmt.Printf("[agent] API endpoint migrated %s -> %s\n", config.APIURL, resolved)
		config.APIURL = resolved
		_ = saveConfig(config)
	}

	go maybeMigrateLegacyInstall()

	if *betaFlag && !config.BetaChannel {
		config.BetaChannel = true
		_ = saveConfig(config)
	}

	if config.BetaChannel {
		fmt.Println("[agent] BETA CHANNEL enabled - fetching beta manifests")
	}

	autoUpdate := config.AutoUpdateEnabled
	if os.Getenv("AGENT_DISABLE_UPDATE") == "true" {
		autoUpdate = false
	}
	if autoUpdate {
		fmt.Printf("[agent] auto-update enabled every %d minutes\n", config.AutoUpdateIntervalMinutes)
	} else {
		fmt.Println("[agent] auto-update disabled")
	}

	go startMonitorChecker(config.APIURL, config.Token)

	if config.LogWatchEnabled || envFlagEnabled("AGENT_LOG_WATCH") {
		go startLogWatcher(config)
	}

	if config.Port > 0 {
		go func() {
			authMiddleware := func(next http.HandlerFunc) http.HandlerFunc {
				return func(w http.ResponseWriter, r *http.Request) {
					authHeader := r.Header.Get("Authorization")
					expectedAuth := "Bearer " + config.Token
					if subtle.ConstantTimeCompare([]byte(authHeader), []byte(expectedAuth)) != 1 {
						http.Error(w, "Unauthorized", http.StatusUnauthorized)
						return
					}
					next(w, r)
				}
			}
			http.HandleFunc("/metrics", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
				payload, err := collectMetrics(config.APIURL)
				if err != nil {
					http.Error(w, err.Error(), 500)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(payload)
			}))
			_ = http.ListenAndServe(fmt.Sprintf("127.0.0.1:%d", config.Port), nil)
		}()
	}

	var updateTicker *time.Ticker
	var updateCh <-chan time.Time
	if autoUpdate {
		updateInterval := time.Duration(config.AutoUpdateIntervalMinutes) * time.Minute
		if updateInterval <= 0 {
			updateInterval = DefaultAutoUpdateIntervalMinutes * time.Minute
		}
		updateTicker = time.NewTicker(updateInterval)
		updateCh = updateTicker.C
		defer updateTicker.Stop()
	}

	metricTicker := time.NewTicker(time.Duration(config.Interval) * time.Second)
	defer metricTicker.Stop()

	commandTicker := time.NewTicker(commandPollInterval)
	defer commandTicker.Stop()

	for {
		select {
		case <-commandTicker.C:
			if remoteCommandsEnabled(&config) {
				pollAgentCommands(config.APIURL, config.Token, &config)
			}
		case <-updateCh:
			if autoUpdate && performUpdate(&config) {
				os.Exit(0)
			}
		case <-metricTicker.C:
			payload, err := collectMetricsWithInterval(config.APIURL, config.Interval)
			if err != nil {
				continue
			}
			b, err := json.Marshal(payload)
			if err != nil {
				continue
			}
			sendMetrics := func() (*http.Response, error) {
				req, err := http.NewRequest("POST", config.APIURL+"/api/v1/uptime/agents/metrics", bytes.NewBuffer(b))
				if err != nil {
					return nil, err
				}
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("X-Agent-Token", config.Token)
				client := &http.Client{
					Timeout: 5 * time.Second,
					Transport: &http.Transport{
						TLSClientConfig: &tls.Config{
							MinVersion: tls.VersionTLS12,
						},
					},
				}
				return client.Do(req)
			}
			resp, err := sendMetrics()
			if err != nil {
				time.Sleep(10 * time.Second)
				resp, err = sendMetrics()
			}
			if err != nil {
				fmt.Printf("[agent] failed to send metrics: %v\n", err)
				continue
			}
			resp.Body.Close()
			switch resp.StatusCode {
			case 204:
				fmt.Printf("[agent] metrics sent successfully (%s)\n", time.Now().Format("15:04:05"))
				confirmUpdate()
			case 401, 403:
				fmt.Printf("[agent] metrics rejected with %d — re-running handshake\n", resp.StatusCode)
				if cfg, herr := performHandshake(config.Token); herr == nil {
					config.AgentID = cfg.AgentID
					config.Token = cfg.Token
					_ = saveConfig(config)
					fmt.Printf("[agent] handshake recovered, agent_id=%s\n", config.AgentID)
				} else {
					fmt.Printf("[agent] handshake failed: %v\n", herr)
				}
			case 429:
				wait := 30 * time.Second
				if ra := resp.Header.Get("Retry-After"); ra != "" {
					if secs, perr := strconv.Atoi(ra); perr == nil && secs > 0 {
						wait = time.Duration(secs) * time.Second
					}
				}
				fmt.Printf("[agent] rate limited, backing off %s\n", wait)
				time.Sleep(wait)
			default:
				fmt.Printf("[agent] metrics endpoint returned %d\n", resp.StatusCode)
			}
			if events := collectAgentEvents(config); len(events) > 0 {
				sendAgentEvents(config, events)
			}
		}
	}
}
