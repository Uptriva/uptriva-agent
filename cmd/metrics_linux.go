package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

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
