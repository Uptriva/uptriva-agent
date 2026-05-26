package main

import (
	"encoding/json"
	"runtime"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/mem"
	"github.com/shirou/gopsutil/v3/net"
	"github.com/shirou/gopsutil/v3/process"
)

func getCPUUsage() float64 {
	percents, err := cpu.Percent(0, false)
	if err == nil && len(percents) > 0 {
		return percents[0]
	}
	return 0.0
}

func getRAMUsage() float64 {
	v, err := mem.VirtualMemory()
	if err == nil {
		return v.UsedPercent
	}
	return 0.0
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

func getNetworkBytes() (int64, int64) {
	stats, err := net.IOCounters(false)
	if err == nil && len(stats) > 0 {
		return int64(stats[0].BytesRecv), int64(stats[0].BytesSent)
	}
	return 0, 0
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
