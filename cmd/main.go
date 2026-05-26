package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

type Config struct {
	APIURL   string `json:"api_url"`
	APIKey   string `json:"api_key"`
	AgentID  string `json:"agent_id"`
	OrgID    string `json:"org_id"`
	Interval int    `json:"interval"`
	Port     int    `json:"port"`
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

func performHandshake(apiURL, token string) (Config, error) {
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown-host"
	}

	payload := map[string]string{
		"token":    token,
		"hostname": hostname,
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return Config{}, err
	}

	resp, err := http.Post(apiURL+"/api/v1/agents/handshake", "application/json", bytes.NewBuffer(b))
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
		APIURL:   apiURL,
		APIKey:   res.APIKey,
		AgentID:  res.AgentID,
		OrgID:    res.OrgID,
		Interval: 10,
	}, nil
}

func main() {
	tokenFlag := flag.String("token", "", "")
	apiFlag := flag.String("api", "http://localhost:8081", "")
	intervalFlag := flag.Int("interval", 10, "")
	portFlag := flag.Int("port", 0, "")
	flag.Parse()

	configPath := "agent_config.json"
	var config Config

	if *tokenFlag != "" {
		cfg, err := performHandshake(*apiFlag, *tokenFlag)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
		config = cfg
		config.Interval = *intervalFlag
		config.Port = *portFlag

		b, err := json.MarshalIndent(config, "", "  ")
		if err == nil {
			_ = os.WriteFile(configPath, b, 0600)
		}
	} else {
		b, err := os.ReadFile(configPath)
		if err != nil {
			fmt.Println("Error: Config file agent_config.json not found and no --token provided.")
			flag.Usage()
			os.Exit(1)
		}
		if err := json.Unmarshal(b, &config); err != nil {
			fmt.Printf("Error parsing config file: %v\n", err)
			os.Exit(1)
		}
	}

	if config.Interval <= 0 {
		config.Interval = 10
	}

	if config.Port > 0 {
		go func() {
			http.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
				payload, err := collectMetrics()
				if err != nil {
					http.Error(w, err.Error(), 500)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(payload)
			})
			_ = http.ListenAndServe(fmt.Sprintf(":%d", config.Port), nil)
		}()
	}

	ticker := time.NewTicker(time.Duration(config.Interval) * time.Second)
	for range ticker.C {
		payload, err := collectMetrics()
		if err != nil {
			continue
		}

		b, err := json.Marshal(payload)
		if err != nil {
			continue
		}

		req, err := http.NewRequest("POST", config.APIURL+"/api/v1/agents/metrics", bytes.NewBuffer(b))
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Agent-Key", config.APIKey)

		client := &http.Client{Timeout: 5 * time.Second}
		resp, err := client.Do(req)
		if err == nil {
			resp.Body.Close()
		}
	}
}
