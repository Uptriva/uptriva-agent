package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
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

func getEncryptionKey() string {
	key := os.Getenv("AGENT_ENCRYPTION_KEY")
	if key == "" {
		fmt.Println("FATAL: AGENT_ENCRYPTION_KEY environment variable is required")
		os.Exit(1)
	}
	if len(key) < 32 {
		key = key + strings.Repeat("0", 32-len(key))
	}
	if len(key) > 32 {
		key = key[:32]
	}
	return key
}

func encryptConfig(config Config) ([]byte, error) {
	key := []byte(getEncryptionKey())
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	plaintext, _ := json.Marshal(config)
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return []byte(base64.StdEncoding.EncodeToString(ciphertext)), nil
}

func decryptConfig(encrypted []byte) (Config, error) {
	key := []byte(getEncryptionKey())
	block, err := aes.NewCipher(key)
	if err != nil {
		return Config{}, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return Config{}, err
	}

	decoded, err := base64.StdEncoding.DecodeString(string(encrypted))
	if err != nil {
		return Config{}, err
	}

	nonceSize := gcm.NonceSize()
	if len(decoded) < nonceSize {
		return Config{}, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := decoded[:nonceSize], decoded[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return Config{}, err
	}

	var config Config
	json.Unmarshal(plaintext, &config)
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

func ensureHTTPS(url string) string {
	if strings.HasPrefix(url, "http://") {
		return "https://" + strings.TrimPrefix(url, "http://")
	}
	if !strings.HasPrefix(url, "https://") {
		return "https://" + url
	}
	return url
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

	apiURL = ensureHTTPS(apiURL)

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

	req, err := http.NewRequest("POST", apiURL+"/api/v1/agents/handshake", bytes.NewBuffer(b))
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
		APIURL:   apiURL,
		APIKey:   res.APIKey,
		AgentID:  res.AgentID,
		OrgID:    res.OrgID,
		Interval: 10,
	}, nil
}

func main() {
	tokenFlag := flag.String("token", "", "")
	apiFlag := flag.String("api", "https://api.shxrk.systems", "")
	intervalFlag := flag.Int("interval", 10, "")
	portFlag := flag.Int("port", 0, "")
	flag.Parse()

	configPath := "agent_config.enc"
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

		b, err := encryptConfig(config)
		if err == nil {
			_ = os.WriteFile(configPath, b, 0600)
		}
	} else {
		b, err := os.ReadFile(configPath)
		if err != nil {
			fmt.Println("Error: Config file agent_config.enc not found and no --token provided.")
			flag.Usage()
			os.Exit(1)
		}
		config, err = decryptConfig(b)
		if err != nil {
			fmt.Printf("Error parsing config file: %v\n", err)
			os.Exit(1)
		}
	}

	if config.Interval <= 0 {
		config.Interval = 10
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

		timestamp := fmt.Sprintf("%d", time.Now().Unix())
		signature := signPayload(b, config.APIKey)

		req, err := http.NewRequest("POST", config.APIURL+"/api/v1/agents/metrics", bytes.NewBuffer(b))
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
