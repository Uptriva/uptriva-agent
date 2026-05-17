package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
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

func readProcStat() (uint64, uint64, error) {
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		return 0, 0, err
	}
	lines := strings.Split(string(data), "\n")
	if len(lines) == 0 {
		return 0, 0, fmt.Errorf("empty stat")
	}
	fields := strings.Fields(lines[0])
	if len(fields) < 5 || fields[0] != "cpu" {
		return 0, 0, fmt.Errorf("invalid cpu fields")
	}
	var total, idle uint64
	for i := 1; i < len(fields); i++ {
		val, err := strconv.ParseUint(fields[i], 10, 64)
		if err != nil {
			continue
		}
		total += val
		if i == 4 {
			idle = val
		}
	}
	return total, idle, nil
}

func readRAMUsage() (float64, error) {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0, err
	}
	var total, available float64
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		if fields[0] == "MemTotal:" {
			val, _ := strconv.ParseFloat(fields[1], 64)
			total = val
		} else if fields[0] == "MemAvailable:" {
			val, _ := strconv.ParseFloat(fields[1], 64)
			available = val
		}
	}
	if total == 0 {
		return 0, fmt.Errorf("could not parse memory total")
	}
	if available == 0 {
		return 0, fmt.Errorf("could not parse memory available")
	}
	return ((total - available) / total) * 100, nil
}

func readDiskUsage() (float64, error) {
	var stat syscall.Statfs_t
	err := syscall.Statfs("/", &stat)
	if err != nil {
		return 0, err
	}
	total := stat.Blocks * uint64(stat.Bsize)
	free := stat.Bfree * uint64(stat.Bsize)
	if total == 0 {
		return 0, fmt.Errorf("total space is 0")
	}
	used := total - free
	return (float64(used) / float64(total)) * 100, nil
}

func readNetworkBytes() (int64, int64, error) {
	data, err := os.ReadFile("/proc/net/dev")
	if err != nil {
		return 0, 0, err
	}
	lines := strings.Split(string(data), "\n")
	var netIn, netOut int64
	for _, line := range lines {
		if !strings.Contains(line, ":") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 10 {
			continue
		}
		rxBytes, _ := strconv.ParseInt(fields[1], 10, 64)
		txBytes, _ := strconv.ParseInt(fields[9], 10, 64)
		netIn += rxBytes
		netOut += txBytes
	}
	return netIn, netOut, nil
}

func readRunningProcesses() (string, error) {
	files, err := os.ReadDir("/proc")
	if err != nil {
		return "", err
	}
	var list []string
	for _, file := range files {
		if !file.IsDir() {
			continue
		}
		pid := file.Name()
		if _, err := strconv.Atoi(pid); err != nil {
			continue
		}
		commPath := filepath.Join("/proc", pid, "comm")
		comm, err := os.ReadFile(commPath)
		if err == nil {
			name := strings.TrimSpace(string(comm))
			if name != "" {
				list = append(list, name)
			}
		}
	}
	b, err := json.Marshal(list)
	if err != nil {
		return "[]", err
	}
	return string(b), nil
}

func collectMetrics(prevTotal, prevIdle *uint64) (MetricsPayload, error) {
	var payload MetricsPayload

	total, idle, err := readProcStat()
	if err == nil {
		if *prevTotal > 0 {
			diffTotal := total - *prevTotal
			diffIdle := idle - *prevIdle
			if diffTotal > 0 {
				payload.CPUUsage = float64(diffTotal-diffIdle) / float64(diffTotal) * 100
			}
		}
		*prevTotal = total
		*prevIdle = idle
	} else {
		payload.CPUUsage = 0.0
	}

	ram, err := readRAMUsage()
	if err == nil {
		payload.RAMUsage = ram
	} else {
		payload.RAMUsage = 0.0
	}

	disk, err := readDiskUsage()
	if err == nil {
		payload.DiskUsage = disk
	} else {
		payload.DiskUsage = 0.0
	}

	netIn, netOut, err := readNetworkBytes()
	if err == nil {
		payload.NetIn = netIn
		payload.NetOut = netOut
	}

	procs, err := readRunningProcesses()
	if err == nil {
		payload.Processes = procs
	} else {
		payload.Processes = "[]"
	}

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
			var prevTotal, prevIdle uint64
			http.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
				payload, err := collectMetrics(&prevTotal, &prevIdle)
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

	var prevTotal, prevIdle uint64
	ticker := time.NewTicker(time.Duration(config.Interval) * time.Second)
	for range ticker.C {
		payload, err := collectMetrics(&prevTotal, &prevIdle)
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
