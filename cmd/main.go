package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

var AgentVersion = "dev"

var (
	prevNetIn  int64
	prevNetOut int64
	prevNetTs  time.Time
)

const (
	DefaultAPIURL                    = "https://api.shxrk.systems"
	DefaultDownloadURL               = "https://download.shxrk.systems"
	MinInterval                      = 15
	DefaultInterval                  = 30
	DefaultAutoUpdateEnabled         = true
	DefaultAutoUpdateIntervalMinutes = 30
)

type Config struct {
	APIURL                    string `json:"api_url"`
	Token                     string `json:"token"`
	AgentID                   string `json:"agent_id"`
	Interval                  int    `json:"interval"`
	Port                      int    `json:"port"`
	AutoUpdateEnabled         bool   `json:"auto_update_enabled"`
	AutoUpdateIntervalMinutes int    `json:"auto_update_interval_minutes"`
	AcceptedPrivacyPolicy     string `json:"accepted_privacy_policy"`
	BetaChannel               bool   `json:"beta_channel"`
}

func saveConfig(config Config) error {
	b, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile("agent_config.json", b, 0600)
}

func loadConfig() (Config, error) {
	var config Config
	b, err := os.ReadFile("agent_config.json")
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
	CPUUsage  float64 `json:"cpu_usage"`
	RAMUsage  float64 `json:"ram_usage"`
	DiskUsage float64 `json:"disk_usage"`
	NetIn     int64   `json:"net_in"`
	NetOut    int64   `json:"net_out"`
	Processes string  `json:"processes"`
	Interval  int     `json:"interval"`
}

func collectMetrics() (MetricsPayload, error) {
	var payload MetricsPayload

	payload.CPUUsage = getCPUUsage()
	payload.RAMUsage = getRAMUsage()
	payload.DiskUsage = getDiskUsage()

	now := time.Now()
	curIn, curOut := getNetworkBytes()
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

	payload.Processes = getRunningProcesses()

	return payload, nil
}

func collectMetricsWithInterval(interval int) (MetricsPayload, error) {
	p, err := collectMetrics()
	if err != nil {
		return p, err
	}
	p.Interval = interval
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
		"token":     token,
		"hostname":  hostname,
		"version":   AgentVersion,
		"timestamp": timestamp,
		"interval":  interval,
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

	req, err := http.NewRequest("POST", DefaultAPIURL+"/api/v1/uptime/agents/handshake", bytes.NewBuffer(b))
	if err != nil {
		return Config{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Agent-Signature", signature)
	req.Header.Set("X-Agent-Timestamp", timestamp)

	resp, err := client.Do(req)
	if err != nil {
		return Config{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return Config{}, fmt.Errorf("handshake failed with status %d: %s", resp.StatusCode, string(body))
	}

	var res struct {
		AgentID string `json:"agent_id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return Config{}, err
	}

	return Config{
		APIURL:                    DefaultAPIURL,
		Token:                     token,
		AgentID:                   res.AgentID,
		Interval:                  DefaultInterval,
		AutoUpdateEnabled:         DefaultAutoUpdateEnabled,
		AutoUpdateIntervalMinutes: DefaultAutoUpdateIntervalMinutes,
	}, nil
}

type AgentManifest struct {
	Version              string                   `json:"version"`
	MinAgentVersion      string                   `json:"min_agent_version"`
	PrivacyPolicyVersion string                   `json:"privacy_policy_version"`
	PrivacyPolicyURL     string                   `json:"privacy_policy_url"`
	ReleaseNotes         string                   `json:"release_notes"`
	RequiresConsent      bool                     `json:"requires_consent"`
	Platforms            map[string]PlatformAsset `json:"platforms"`
}

type PlatformAsset struct {
	Checksum string `json:"checksum"`
	URL      string `json:"url"`
}

func fetchManifest(downloadURL string, betaChannel bool) (*AgentManifest, error) {
	client := &http.Client{Timeout: 15 * time.Second}
	manifestPath := "/manifest"
	if betaChannel {
		manifestPath = "/manifest/beta"
	}
	resp, err := client.Get(downloadURL + manifestPath)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("manifest endpoint returned %d", resp.StatusCode)
	}
	var manifest AgentManifest
	if err := json.NewDecoder(resp.Body).Decode(&manifest); err != nil {
		return nil, err
	}
	return &manifest, nil
}

func compareVersions(a, b string) int {
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
		return "C:\\Program Files\\ShxrkSystems\\uptime-agent.exe"
	}
	return "/usr/local/bin/uptime-agent"
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
	manifest, err := fetchManifest(DefaultDownloadURL, config.BetaChannel)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch manifest: %w", err)
	}

	if compareVersions(manifest.Version, AgentVersion) <= 0 {
		return &UpdateResult{Updated: false}, nil
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

	downloadFullURL := DefaultDownloadURL + asset.URL
	client := &http.Client{Timeout: 120 * time.Second}
	resp, err := client.Get(downloadFullURL)
	if err != nil {
		return fmt.Errorf("failed to download: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download returned %d", resp.StatusCode)
	}

	tmpPath := getCurrentBinaryPath() + ".new"
	if runtime.GOOS == "windows" {
		tmpPath = os.Getenv("TEMP") + "\\uptime-agent.new.exe"
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

	if _, err := os.Stat(binPath); err == nil {
		os.Rename(binPath, backupPath)
	}

	if err := os.Rename(tmpPath, binPath); err != nil {
		if _, berr := os.Stat(backupPath); berr == nil {
			os.Rename(backupPath, binPath)
		}
		os.Remove(tmpPath)
		return fmt.Errorf("failed to replace binary: %w", err)
	}

	os.Remove(backupPath)
	return nil
}

func performUpdate(config *Config) bool {
	manifest, err := fetchManifest(DefaultDownloadURL, config.BetaChannel)
	if err != nil {
		fmt.Printf("[update] failed to fetch manifest: %v\n", err)
		return false
	}

	if compareVersions(manifest.Version, AgentVersion) <= 0 {
		return false
	}

	if manifest.RequiresConsent && config.AcceptedPrivacyPolicy != manifest.PrivacyPolicyVersion {
		fmt.Printf("[update] update to %s available but requires privacy policy consent (v%s)\n", manifest.Version, manifest.PrivacyPolicyVersion)
		fmt.Printf("[update] review at %s\n", manifest.PrivacyPolicyURL)
		fmt.Println("[update] run: uptime-agent -accept-privacy-policy to consent and update")
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
	flag.Parse()

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
			fmt.Println("Run: uptime-agent -accept-privacy-policy to consent and update")
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
		manifest, err := fetchManifest(DefaultDownloadURL, config.BetaChannel)
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
	}

	if config.Interval < MinInterval {
		config.Interval = MinInterval
	}

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

	if config.Port > 0 {
		go func() {
			authMiddleware := func(next http.HandlerFunc) http.HandlerFunc {
				return func(w http.ResponseWriter, r *http.Request) {
					authHeader := r.Header.Get("Authorization")
					expectedAuth := "Bearer " + config.Token
					if authHeader != expectedAuth {
						http.Error(w, "Unauthorized", http.StatusUnauthorized)
						return
					}
					next(w, r)
				}
			}
			http.HandleFunc("/metrics", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
				payload, err := collectMetrics()
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
	if autoUpdate {
		updateInterval := time.Duration(config.AutoUpdateIntervalMinutes) * time.Minute
		if updateInterval <= 0 {
			updateInterval = DefaultAutoUpdateIntervalMinutes * time.Minute
		}
		updateTicker = time.NewTicker(updateInterval)
		defer updateTicker.Stop()
	}

	metricTicker := time.NewTicker(time.Duration(config.Interval) * time.Second)
	defer metricTicker.Stop()

	for {
		select {
		case <-updateTicker.C:
			if autoUpdate && performUpdate(&config) {
				os.Exit(0)
			}
		case <-metricTicker.C:
			payload, err := collectMetricsWithInterval(config.Interval)
			if err != nil {
				continue
			}
			b, err := json.Marshal(payload)
			if err != nil {
				continue
			}
			req, err := http.NewRequest("POST", config.APIURL+"/api/v1/uptime/agents/metrics", bytes.NewBuffer(b))
			if err != nil {
				continue
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
			resp, err := client.Do(req)
			if err != nil {
				fmt.Printf("[agent] failed to send metrics: %v\n", err)
				continue
			}
			resp.Body.Close()
			if resp.StatusCode == 204 {
				fmt.Printf("[agent] metrics sent successfully (%s)\n", time.Now().Format("15:04:05"))
			} else {
				fmt.Printf("[agent] metrics endpoint returned %d\n", resp.StatusCode)
			}
		}
	}
}
