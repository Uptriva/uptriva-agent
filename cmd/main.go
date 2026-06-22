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

const (
	DefaultAPIURL   = "https://api.shxrk.systems"
	MinInterval     = 15
	DefaultInterval = 30
)

type Config struct {
	APIURL   string `json:"api_url"`
	APIKey   string `json:"api_key"`
	AgentID  string `json:"agent_id"`
	OrgID    string `json:"org_id"`
	Interval int    `json:"interval"`
	Port     int    `json:"port"`
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
	return config, nil
}

func hashHostname(hostname string) string {
	h := sha256.New()
	h.Write([]byte(hostname))
	return hex.EncodeToString(h.Sum(nil))
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
}

func collectMetrics() (MetricsPayload, error) {
	var payload MetricsPayload

	payload.CPUUsage = getCPUUsage()
	payload.RAMUsage = getRAMUsage()
	payload.DiskUsage = getDiskUsage()

	netIn, netOut := getNetworkBytes()
	payload.NetIn = netIn
	payload.NetOut = netOut

	payload.Processes = getRunningProcesses()

	return payload, nil
}

func performHandshake(token string) (Config, error) {
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown-host"
	}

	hostnameHash := hashHostname(hostname)
	timestamp := fmt.Sprintf("%d", time.Now().Unix())

	payload := map[string]string{
		"token":         token,
		"hostname_hash": hostnameHash,
		"timestamp":     timestamp,
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
		APIKey  string `json:"api_key"`
		AgentID string `json:"agent_id"`
		OrgID   string `json:"org_id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return Config{}, err
	}

	return Config{
		APIURL:   DefaultAPIURL,
		APIKey:   res.APIKey,
		AgentID:  res.AgentID,
		OrgID:    res.OrgID,
		Interval: DefaultInterval,
	}, nil
}

func getDownloadURL() string {
	osName := runtime.GOOS
	arch := runtime.GOARCH
	filename := "uptime-agent"
	if osName == "windows" {
		filename = "uptime-agent.exe"
	}
	return fmt.Sprintf("https://download.shxrk.systems/agents/%s/%s/%s", osName, arch, filename)
}

func checkAndUpdate() bool {
	resp, err := http.Get("https://download.shxrk.systems/version")
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false
	}
	remoteVersionBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return false
	}
	remoteVersion := strings.TrimSpace(string(remoteVersionBytes))
	if remoteVersion == "" || remoteVersion == AgentVersion {
		return false
	}

	downloadURL := getDownloadURL()
	tmpPath := "/usr/local/bin/uptime-agent.new"
	if runtime.GOOS == "windows" {
		tmpPath = os.Getenv("TEMP") + "\\uptime-agent.new.exe"
	}

	client := &http.Client{Timeout: 60 * time.Second}
	dlResp, err := client.Get(downloadURL)
	if err != nil {
		fmt.Printf("Update: failed to download new version: %v\n", err)
		return false
	}
	defer dlResp.Body.Close()
	if dlResp.StatusCode != http.StatusOK {
		fmt.Printf("Update: download returned %d\n", dlResp.StatusCode)
		return false
	}

	f, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
	if err != nil {
		fmt.Printf("Update: failed to create temp file: %v\n", err)
		return false
	}
	_, err = io.Copy(f, dlResp.Body)
	f.Close()
	if err != nil {
		fmt.Printf("Update: failed to write temp file: %v\n", err)
		return false
	}

	testCmd := exec.Command(tmpPath, "-version")
	if err := testCmd.Run(); err != nil {
		fmt.Printf("Update: downloaded binary is invalid, removing: %v\n", err)
		os.Remove(tmpPath)
		return false
	}

	binPath := "/usr/local/bin/uptime-agent"
	if runtime.GOOS == "windows" {
		binPath = "C:\\Program Files\\ShxrkSystems\\uptime-agent.exe"
	}

	if err := os.Rename(tmpPath, binPath); err != nil {
		fmt.Printf("Update: failed to replace binary: %v\n", err)
		os.Remove(tmpPath)
		return false
	}

	fmt.Printf("Update: upgraded to %s. Restarting...\n", remoteVersion)
	return true
}

func main() {
	tokenFlag := flag.String("token", "", "")
	intervalFlag := flag.Int("interval", DefaultInterval, "")
	portFlag := flag.Int("port", 0, "")
	versionFlag := flag.Bool("version", false, "")
	updateFlag := flag.Bool("update", false, "")
	flag.Parse()

	if *versionFlag {
		fmt.Println(AgentVersion)
		os.Exit(0)
	}

	if *updateFlag {
		fmt.Println("Checking for updates...")
		if checkAndUpdate() {
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

		if err := saveConfig(config); err != nil {
			fmt.Printf("Error saving config: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Agent registered successfully. Config saved.")
		os.Exit(0)
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

	if config.Port > 0 {
		go func() {
			authMiddleware := func(next http.HandlerFunc) http.HandlerFunc {
				return func(w http.ResponseWriter, r *http.Request) {
					authHeader := r.Header.Get("Authorization")
					expectedAuth := "Bearer " + config.APIKey
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

	autoUpdate := os.Getenv("AGENT_DISABLE_UPDATE") != "true"
	var updateTicker *time.Ticker
	if autoUpdate {
		updateTicker = time.NewTicker(30 * time.Minute)
		defer updateTicker.Stop()
	}

	metricTicker := time.NewTicker(time.Duration(config.Interval) * time.Second)
	defer metricTicker.Stop()

	for {
		select {
		case <-updateTicker.C:
			if autoUpdate && checkAndUpdate() {
				os.Exit(0)
			}
		case <-metricTicker.C:
			payload, err := collectMetrics()
			if err != nil {
				continue
			}
			b, err := json.Marshal(payload)
			if err != nil {
				continue
			}
			timestamp := fmt.Sprintf("%d", time.Now().Unix())
			signature := signPayload(b, config.APIKey)
			req, err := http.NewRequest("POST", config.APIURL+"/api/v1/uptime/agents/metrics", bytes.NewBuffer(b))
			if err != nil {
				continue
			}
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Agent-Key", config.APIKey)
			req.Header.Set("X-Agent-Signature", signature)
			req.Header.Set("X-Agent-Timestamp", timestamp)
			client := &http.Client{
				Timeout: 5 * time.Second,
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{
						MinVersion: tls.VersionTLS12,
					},
				},
			}
			resp, err := client.Do(req)
			if err == nil {
				resp.Body.Close()
			}
		}
	}
}
