package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"time"
)

const k8sDiscoveryInterval = 5 * time.Minute

type k8sDiscoveryItem struct {
	Kind      string `json:"kind"`
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	Host      string `json:"host"`
	Port      int    `json:"port"`
	Path      string `json:"path,omitempty"`
	TLS       bool   `json:"tls"`
	Signature string `json:"signature"`
}

type k8sListMeta struct {
	Metadata struct {
		Name      string `json:"name"`
		Namespace string `json:"namespace"`
	} `json:"metadata"`
}

func k8sDiscoveryEnabled(c *Config) bool {
	if c.DisableK8sDiscovery || envFlagEnabled("AGENT_DISABLE_K8S_DISCOVERY") {
		return false
	}
	return true
}

func kubectlAvailable() bool {
	_, err := exec.LookPath("kubectl")
	return err == nil
}

func runKubectlJSON(ctx context.Context, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "kubectl", args...)
	return cmd.Output()
}

func collectK8sDiscoveries() []k8sDiscoveryItem {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	items := make([]k8sDiscoveryItem, 0, 32)

	if raw, err := runKubectlJSON(ctx, "get", "ingresses.networking.k8s.io", "-A", "-o", "json"); err == nil {
		var list struct {
			Items []struct {
				k8sListMeta
				Spec struct {
					IngressClassName *string `json:"ingressClassName"`
					Rules            []struct {
						Host string `json:"host"`
						HTTP *struct {
							Paths []struct {
								Path     string `json:"path"`
								PathType string `json:"pathType"`
							} `json:"paths"`
						} `json:"http"`
					} `json:"rules"`
					TLS []struct {
						Hosts []string `json:"hosts"`
					} `json:"tls"`
				} `json:"spec"`
			} `json:"items"`
		}
		if json.Unmarshal(raw, &list) == nil {
			for _, ing := range list.Items {
				tlsHosts := map[string]bool{}
				for _, t := range ing.Spec.TLS {
					for _, h := range t.Hosts {
						tlsHosts[h] = true
					}
				}
				for _, rule := range ing.Spec.Rules {
					if rule.Host == "" {
						continue
					}
					path := "/"
					if rule.HTTP != nil && len(rule.HTTP.Paths) > 0 && rule.HTTP.Paths[0].Path != "" {
						path = rule.HTTP.Paths[0].Path
					}
					sig := fmt.Sprintf("ingress:%s:%s:%s:%s", ing.Metadata.Namespace, ing.Metadata.Name, rule.Host, path)
					items = append(items, k8sDiscoveryItem{
						Kind: "ingress", Namespace: ing.Metadata.Namespace, Name: ing.Metadata.Name,
						Host: rule.Host, Port: 443, Path: path, TLS: tlsHosts[rule.Host], Signature: sig,
					})
					if !tlsHosts[rule.Host] {
						items = append(items, k8sDiscoveryItem{
							Kind: "ingress", Namespace: ing.Metadata.Namespace, Name: ing.Metadata.Name,
							Host: rule.Host, Port: 80, Path: path, TLS: false,
							Signature: fmt.Sprintf("ingress:%s:%s:%s:%s:http", ing.Metadata.Namespace, ing.Metadata.Name, rule.Host, path),
						})
					}
				}
			}
		}
	}

	if raw, err := runKubectlJSON(ctx, "get", "services", "-A", "-o", "json"); err == nil {
		var list struct {
			Items []struct {
				k8sListMeta
				Spec struct {
					Type      string `json:"type"`
					ClusterIP string `json:"clusterIP"`
					Ports     []struct {
						Port     int    `json:"port"`
						NodePort int    `json:"nodePort"`
						Name     string `json:"name"`
						Protocol string `json:"protocol"`
					} `json:"ports"`
					ExternalIPs         []string `json:"externalIPs"`
					LoadBalancerIngress []struct {
						IP       string `json:"ip"`
						Hostname string `json:"hostname"`
					}
				} `json:"spec"`
				Status struct {
					LoadBalancer struct {
						Ingress []struct {
							IP       string `json:"ip"`
							Hostname string `json:"hostname"`
						} `json:"ingress"`
					} `json:"loadBalancer"`
				} `json:"status"`
			} `json:"items"`
		}
		if json.Unmarshal(raw, &list) == nil {
			for _, svc := range list.Items {
				if svc.Spec.Type != "LoadBalancer" && svc.Spec.Type != "NodePort" {
					continue
				}
				host := ""
				for _, ing := range svc.Status.LoadBalancer.Ingress {
					if ing.Hostname != "" {
						host = ing.Hostname
						break
					}
					if ing.IP != "" {
						host = ing.IP
						break
					}
				}
				if host == "" && len(svc.Spec.ExternalIPs) > 0 {
					host = svc.Spec.ExternalIPs[0]
				}
				if host == "" && svc.Spec.ClusterIP != "" && svc.Spec.ClusterIP != "None" {
					host = svc.Spec.ClusterIP
				}
				if host == "" {
					continue
				}
				for _, p := range svc.Spec.Ports {
					port := p.Port
					if svc.Spec.Type == "NodePort" && p.NodePort > 0 && len(svc.Spec.ExternalIPs) == 0 && len(svc.Status.LoadBalancer.Ingress) == 0 {
						port = p.NodePort
					}
					sig := fmt.Sprintf("service:%s:%s:%s:%d", svc.Metadata.Namespace, svc.Metadata.Name, host, port)
					items = append(items, k8sDiscoveryItem{
						Kind: "service", Namespace: svc.Metadata.Namespace, Name: svc.Metadata.Name,
						Host: host, Port: port, Signature: sig,
					})
				}
			}
		}
	}

	return items
}

func sendK8sDiscoveries(cfg Config, items []k8sDiscoveryItem) {
	payload, _ := json.Marshal(map[string]interface{}{"items": items})
	req, err := http.NewRequest("POST", cfg.APIURL+"/api/v1/uptime/agents/discoveries", bytes.NewBuffer(payload))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Agent-Token", cfg.Token)
	client := &http.Client{
		Timeout:   10 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}},
	}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("[agent] k8s discovery push failed: %v\n", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		fmt.Printf("[agent] k8s discovery push rejected: %d\n", resp.StatusCode)
	}
}

func startK8sDiscovery(config Config) {
	if !k8sDiscoveryEnabled(&config) {
		return
	}
	if !kubectlAvailable() {
		fmt.Println("[agent] k8s discovery disabled — kubectl not found")
		return
	}
	fmt.Println("[agent] k8s discovery enabled (kubectl available)")

	ticker := time.NewTicker(k8sDiscoveryInterval)
	defer ticker.Stop()
	for {
		items := collectK8sDiscoveries()
		if len(items) > 0 {
			sendK8sDiscoveries(config, items)
			fmt.Printf("[agent] pushed %d k8s discoveries\n", len(items))
		}
		<-ticker.C
	}
}
