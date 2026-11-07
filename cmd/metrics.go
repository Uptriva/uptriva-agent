package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
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
		log.Printf("[metrics] CPU collection failed on %s (gopsutil err=%v, darwin top fallback failed)", runtime.GOOS, err)
	}
	return 0.0
}

func getCPUUsageDarwin() (float64, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	topBin := "/usr/bin/top"
	if _, statErr := os.Stat(topBin); statErr != nil {
		topBin = "top"
	}
	out, err := exec.CommandContext(ctx, topBin, "-l", "2", "-n", "0", "-s", "1").Output()
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
		numStr := strings.TrimSpace(strings.TrimSuffix(field, "idle"))
		numStr = strings.TrimSpace(strings.TrimSuffix(numStr, "%"))
		idle, perr := strconv.ParseFloat(numStr, 64)
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
	netstatBin := "/usr/sbin/netstat"
	if _, statErr := os.Stat(netstatBin); statErr != nil {
		netstatBin = "netstat"
	}
	out, err := exec.CommandContext(ctx, netstatBin, "-ibn").Output()
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

type SystemInfo struct {
	OS                   string `json:"os"`
	Platform             string `json:"platform,omitempty"`
	PlatformFamily       string `json:"platform_family,omitempty"`
	PlatformVersion      string `json:"platform_version,omitempty"`
	KernelVersion        string `json:"kernel_version,omitempty"`
	KernelArch           string `json:"kernel_arch,omitempty"`
	Hostname             string `json:"hostname,omitempty"`
	CPUModel             string `json:"cpu_model,omitempty"`
	CPUPhysicalCores     int    `json:"cpu_physical_cores,omitempty"`
	CPUThreads           int    `json:"cpu_threads,omitempty"`
	VirtualizationRole   string `json:"virtualization_role,omitempty"`
	VirtualizationSystem string `json:"virtualization_system,omitempty"`
}

var (
	systemInfoOnce   sync.Once
	cachedSystemInfo *SystemInfo
)

func getSystemInfo() *SystemInfo {
	systemInfoOnce.Do(func() {
		info := &SystemInfo{OS: runtime.GOOS}
		if hi, err := host.Info(); err == nil && hi != nil {
			info.OS = hi.OS
			info.Platform = hi.Platform
			info.PlatformFamily = hi.PlatformFamily
			info.PlatformVersion = hi.PlatformVersion
			info.KernelVersion = hi.KernelVersion
			info.KernelArch = hi.KernelArch
			info.Hostname = hi.Hostname
			info.VirtualizationRole = hi.VirtualizationRole
			info.VirtualizationSystem = hi.VirtualizationSystem
		}
		if infos, err := cpu.Info(); err == nil && len(infos) > 0 {
			info.CPUModel = infos[0].ModelName
			threads := 0
			for _, c := range infos {
				threads += int(c.Cores)
			}
			info.CPUThreads = threads
			if n, err := cpu.Counts(false); err == nil {
				info.CPUPhysicalCores = n
			}
		}
		cachedSystemInfo = info
	})
	return cachedSystemInfo
}

type CPUBreakdown struct {
	User   float64 `json:"user"`
	System float64 `json:"system"`
	IOWait float64 `json:"iowait"`
	Steal  float64 `json:"steal"`
	Idle   float64 `json:"idle"`
}

func getCPUBreakdown() *CPUBreakdown {
	times, err := cpu.Times(false)
	if err != nil || len(times) == 0 {
		return nil
	}
	t := times[0]
	total := t.User + t.System + t.Idle + t.Iowait + t.Steal + t.Nice + t.Irq + t.Softirq + t.Guest + t.GuestNice
	if total <= 0 {
		return nil
	}
	return &CPUBreakdown{
		User:   t.User / total * 100,
		System: t.System / total * 100,
		IOWait: t.Iowait / total * 100,
		Steal:  t.Steal / total * 100,
		Idle:   t.Idle / total * 100,
	}
}

type DiskIORate struct {
	Device        string `json:"device"`
	ReadBytesSec  int64  `json:"read_bytes_sec"`
	WriteBytesSec int64  `json:"write_bytes_sec"`
}

var (
	prevDiskIO   map[string][2]uint64
	prevDiskIOTs time.Time
	prevDiskIOMu sync.Mutex
)

func getDiskIORates() []DiskIORate {
	counters, err := disk.IOCounters()
	if err != nil || len(counters) == 0 {
		return nil
	}
	now := time.Now()
	prevDiskIOMu.Lock()
	defer prevDiskIOMu.Unlock()

	elapsed := now.Sub(prevDiskIOTs).Seconds()
	var rates []DiskIORate
	for name, c := range counters {
		prev, ok := prevDiskIO[name]
		if !ok || prevDiskIO == nil || elapsed <= 0 {
			continue
		}
		readDelta := int64(0)
		writeDelta := int64(0)
		if c.ReadBytes >= prev[0] {
			readDelta = int64(float64(c.ReadBytes-prev[0]) / elapsed)
		}
		if c.WriteBytes >= prev[1] {
			writeDelta = int64(float64(c.WriteBytes-prev[1]) / elapsed)
		}
		rates = append(rates, DiskIORate{Device: name, ReadBytesSec: readDelta, WriteBytesSec: writeDelta})
	}
	next := make(map[string][2]uint64, len(counters))
	for name, c := range counters {
		next[name] = [2]uint64{c.ReadBytes, c.WriteBytes}
	}
	prevDiskIO = next
	prevDiskIOTs = now
	return rates
}

type ListenPort struct {
	Proto   string `json:"proto"`
	Address string `json:"address"`
	Port    uint32 `json:"port"`
	Process string `json:"process,omitempty"`
	Pid     int32  `json:"pid,omitempty"`
}

func getListenPorts() []ListenPort {
	conns, err := net.Connections("all")
	if err != nil {
		return nil
	}
	seen := make(map[string]bool)
	var ports []ListenPort
	for _, c := range conns {
		if c.Status != "LISTEN" && c.Status != "" {
			continue
		}
		if c.Type != 1 && c.Type != 2 {
			continue
		}
		proto := "tcp"
		if c.Type == 2 {
			proto = "udp"
		}
		key := fmt.Sprintf("%s:%s:%d:%d", proto, c.Laddr.IP, c.Laddr.Port, c.Pid)
		if seen[key] {
			continue
		}
		seen[key] = true
		p := ListenPort{Proto: proto, Address: c.Laddr.IP, Port: c.Laddr.Port, Pid: c.Pid}
		if c.Pid > 0 {
			if proc, err := process.NewProcess(c.Pid); err == nil {
				if name, err := proc.Name(); err == nil {
					p.Process = name
				}
			}
		}
		ports = append(ports, p)
	}
	return ports
}

type SmartDrive struct {
	Device     string `json:"device"`
	Model      string `json:"model,omitempty"`
	Protocol   string `json:"protocol,omitempty"`
	PowerOnHrs int64  `json:"power_on_hours,omitempty"`
	WearoutPct int64  `json:"wearout_percent,omitempty"`
	TempC      int64  `json:"temperature_c,omitempty"`
	Health     string `json:"health,omitempty"`
	Available  bool   `json:"available"`
}

func getSmartDrives() []SmartDrive {
	if runtime.GOOS != "linux" {
		return nil
	}
	if _, err := exec.LookPath("smartctl"); err != nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "smartctl", "--scan").Output()
	if err != nil {
		return nil
	}
	var drives []SmartDrive
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 1 || !strings.HasPrefix(fields[0], "/dev/") {
			continue
		}
		dev := fields[0]
		d := SmartDrive{Device: dev}
		fillSmartDrive(ctx, &d)
		drives = append(drives, d)
	}
	return drives
}

func fillSmartDrive(ctx context.Context, d *SmartDrive) {
	out, err := exec.CommandContext(ctx, "smartctl", "-a", d.Device, "-j").Output()
	if err == nil {
		var doc struct {
			ModelName   string `json:"model_name"`
			Protocol    string `json:"device_protocol"`
			PowerOnTime struct {
				Hours int64 `json:"hours"`
			} `json:"power_on_time"`
			Temperature struct {
				Current int64 `json:"current"`
			} `json:"temperature"`
			NvmeSmartHealth struct {
				PercentageUsed int64 `json:"percentage_used"`
			} `json:"nvme_smart_health_information_log"`
			SmartStatus struct {
				Passed bool `json:"passed"`
			} `json:"smart_status"`
			AataSmartAttributes struct {
				Table []struct {
					Name  string `json:"name"`
					Value int64  `json:"value"`
					Raw   struct {
						Value int64 `json:"value"`
					} `json:"raw"`
				} `json:"table"`
			} `json:"ata_smart_attributes"`
		}
		if json.Unmarshal(out, &doc) == nil {
			d.Available = true
			d.Model = doc.ModelName
			d.Protocol = doc.Protocol
			d.PowerOnHrs = doc.PowerOnTime.Hours
			d.TempC = doc.Temperature.Current
			if doc.NvmeSmartHealth.PercentageUsed > 0 {
				d.WearoutPct = doc.NvmeSmartHealth.PercentageUsed
			}
			for _, attr := range doc.AataSmartAttributes.Table {
				switch attr.Name {
				case "Wear_Leveling_Count", "Percent_Lifetime_Remain", "Percentage_Used_Endurance_Indicator":
					d.WearoutPct = 100 - attr.Value
				case "Media_Wearout_Indicator":
					d.WearoutPct = 100 - attr.Value
				}
			}
			if doc.SmartStatus.Passed {
				d.Health = "passed"
			} else {
				d.Health = "failed"
			}
			return
		}
	}
	d.Available = false
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

func unitRestartCount(unit string) int {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "systemctl", "show", unit, "-p", "NRestarts", "--value").Output()
	if err != nil {
		return -1
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(out)))
	if err != nil {
		return -1
	}
	return n
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
