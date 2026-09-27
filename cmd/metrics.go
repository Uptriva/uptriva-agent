package main

import (
	"bufio"
	"context"
	"encoding/json"
	"log"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/host"
	"github.com/shirou/gopsutil/v3/load"
	"github.com/shirou/gopsutil/v3/mem"
	"github.com/shirou/gopsutil/v3/net"
	"github.com/shirou/gopsutil/v3/process"
)

var cpuFallbackLogged bool

func getCPUUsage() float64 {
	percents, err := cpu.Percent(0, false)
	if err == nil && len(percents) > 0 && !(runtime.GOOS == "darwin" && percents[0] == 0) {
		return percents[0]
	}
	if runtime.GOOS == "darwin" {
		if v, ok := getCPUUsageDarwin(); ok {
			if !cpuFallbackLogged {
				cpuFallbackLogged = true
				log.Printf("[metrics] gopsutil cpu.Percent unavailable on darwin (err=%v) — using top fallback", err)
			}
			return v
		}
	}
	if !cpuFallbackLogged {
		cpuFallbackLogged = true
		log.Printf("[metrics] CPU collection failed on %s: err=%v", runtime.GOOS, err)
	}
	return 0.0
}

func getCPUUsageDarwin() (float64, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "top", "-l", "2", "-n", "0", "-s", "1").Output()
	if err != nil {
		return 0, false
	}
	var lastUsageLine string
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, "CPU usage:") {
			lastUsageLine = line
		}
	}
	if lastUsageLine == "" {
		return 0, false
	}
	for _, field := range strings.Split(lastUsageLine[strings.Index(lastUsageLine, "CPU usage:")+len("CPU usage:"):], ",") {
		field = strings.TrimSpace(field)
		if !strings.HasSuffix(field, "idle") {
			continue
		}
		idle, perr := strconv.ParseFloat(strings.TrimSpace(strings.TrimSuffix(strings.TrimSuffix(field, "idle"), "%")), 64)
		if perr != nil {
			return 0, false
		}
		usage := 100 - idle
		if usage < 0 {
			usage = 0
		}
		return usage, true
	}
	return 0, false
}

func getCPUCoreCount() int {
	count, err := cpu.Counts(true)
	if err == nil {
		return count
	}
	return 0
}

func getRAMUsage() float64 {
	v, err := mem.VirtualMemory()
	if err == nil {
		return v.UsedPercent
	}
	return 0.0
}

type MemoryDetail struct {
	TotalMB     uint64  `json:"total_mb"`
	AvailableMB uint64  `json:"available_mb"`
	UsedMB      uint64  `json:"used_mb"`
	UsedPercent float64 `json:"used_percent"`
	SwapTotalMB uint64  `json:"swap_total_mb"`
	SwapUsedMB  uint64  `json:"swap_used_mb"`
	SwapPercent float64 `json:"swap_percent"`
}

func getMemoryDetail() MemoryDetail {
	var detail MemoryDetail
	v, err := mem.VirtualMemory()
	if err == nil {
		detail.TotalMB = v.Total / (1024 * 1024)
		detail.AvailableMB = v.Available / (1024 * 1024)
		detail.UsedMB = v.Used / (1024 * 1024)
		detail.UsedPercent = v.UsedPercent
	}
	s, err := mem.SwapMemory()
	if err == nil {
		detail.SwapTotalMB = s.Total / (1024 * 1024)
		detail.SwapUsedMB = s.Used / (1024 * 1024)
		if s.Total > 0 {
			detail.SwapPercent = s.UsedPercent
		}
	}
	return detail
}

func getDiskUsage() float64 {
	path := "/"
	if runtime.GOOS == "windows" {
		path = "C:\\"
	}
	d, err := disk.Usage(path)
	if err == nil {
		return d.UsedPercent
	}
	return 0.0
}

type DiskDetail struct {
	MountPoint  string  `json:"mount_point"`
	Device      string  `json:"device"`
	Fstype      string  `json:"fstype"`
	TotalGB     float64 `json:"total_gb"`
	UsedGB      float64 `json:"used_gb"`
	FreeGB      float64 `json:"free_gb"`
	UsedPercent float64 `json:"used_percent"`
}

func getDiskDetails() []DiskDetail {
	partitions, err := disk.Partitions(false)
	if err != nil {
		return nil
	}
	var details []DiskDetail
	seen := make(map[string]bool)
	for _, p := range partitions {
		if seen[p.Mountpoint] {
			continue
		}
		seen[p.Mountpoint] = true
		u, err := disk.Usage(p.Mountpoint)
		if err != nil || u.Total == 0 {
			continue
		}
		details = append(details, DiskDetail{
			MountPoint:  p.Mountpoint,
			Device:      p.Device,
			Fstype:      p.Fstype,
			TotalGB:     float64(u.Total) / (1024 * 1024 * 1024),
			UsedGB:      float64(u.Used) / (1024 * 1024 * 1024),
			FreeGB:      float64(u.Free) / (1024 * 1024 * 1024),
			UsedPercent: u.UsedPercent,
		})
	}
	return details
}

var netFallbackLogged bool

func getNetworkBytes() (int64, int64) {
	stats, err := net.IOCounters(false)
	if err == nil && len(stats) > 0 && (stats[0].BytesRecv > 0 || stats[0].BytesSent > 0) {
		return int64(stats[0].BytesRecv), int64(stats[0].BytesSent)
	}
	if runtime.GOOS == "darwin" {
		if recv, sent, ok := getNetworkBytesDarwin(); ok {
			if !netFallbackLogged {
				netFallbackLogged = true
				log.Printf("[metrics] gopsutil net.IOCounters unavailable on darwin (err=%v) — using netstat fallback", err)
			}
			return recv, sent
		}
	}
	if !netFallbackLogged {
		netFallbackLogged = true
		log.Printf("[metrics] network counter collection failed on %s: err=%v", runtime.GOOS, err)
	}
	return 0, 0
}

func getNetworkBytesDarwin() (int64, int64, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "netstat", "-ibn").Output()
	if err != nil {
		return 0, 0, false
	}
	var recv, sent int64
	found := false
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 10 || !strings.HasPrefix(fields[2], "<Link#") {
			continue
		}
		ib, err1 := strconv.ParseInt(fields[6], 10, 64)
		ob, err2 := strconv.ParseInt(fields[9], 10, 64)
		if err1 != nil || err2 != nil {
			continue
		}
		recv += ib
		sent += ob
		found = true
	}
	if !found {
		return 0, 0, false
	}
	return recv, sent, true
}

func getRunningProcesses() string {
	procs, err := process.Processes()
	if err != nil {
		return "[]"
	}
	var names []string
	for _, p := range procs {
		name, err := p.Name()
		if err == nil && name != "" {
			names = append(names, name)
		}
	}
	b, err := json.Marshal(names)
	if err == nil {
		return string(b)
	}
	return "[]"
}

func getLoadAverages() (float64, float64, float64) {
	avg, err := load.Avg()
	if err == nil && avg != nil {
		return avg.Load1, avg.Load5, avg.Load15
	}
	return 0, 0, 0
}

func getUptime() uint64 {
	uptime, err := host.Uptime()
	if err == nil {
		return uptime
	}
	return 0
}

type SystemdUnit struct {
	Unit        string `json:"unit"`
	LoadState   string `json:"load_state"`
	ActiveState string `json:"active_state"`
	SubState    string `json:"sub_state"`
}

func getSystemdUnits() []SystemdUnit {
	if runtime.GOOS != "linux" {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "systemctl", "list-units", "--type=service", "--all", "--no-legend", "--no-pager", "--plain")
	out, err := cmd.Output()
	if err != nil {
		return nil
	}

	var units []SystemdUnit
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		units = append(units, SystemdUnit{
			Unit:        fields[0],
			LoadState:   fields[1],
			ActiveState: fields[2],
			SubState:    fields[3],
		})
	}
	return units
}

func getFailedSystemdUnits() []string {
	units := getSystemdUnits()
	var failed []string
	for _, u := range units {
		if u.ActiveState == "failed" {
			failed = append(failed, u.Unit)
		}
	}
	return failed
}

func measureSelfPing(apiURL string) int {
	host := apiURL
	host = strings.TrimPrefix(host, "https://")
	host = strings.TrimPrefix(host, "http://")
	if idx := strings.Index(host, "/"); idx >= 0 {
		host = host[:idx]
	}
	if idx := strings.Index(host, ":"); idx >= 0 {
		host = host[:idx]
	}
	if host == "" {
		return -1
	}

	status, latency, _ := checkPing(host)
	if status == "up" && latency >= 0 {
		return latency
	}

	return tcpConnectLatency(host + ":443")
}
