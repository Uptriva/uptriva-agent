package main

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
)

func readProcStat() (uint64, uint64, error) {
	return 100, 50, nil
}

func readRAMUsage() (float64, error) {
	outTotal, err := exec.Command("sysctl", "-n", "hw.memsize").Output()
	if err != nil {
		outTotal, err = exec.Command("sysctl", "-n", "hw.physmem").Output()
		if err != nil {
			return 0, err
		}
	}
	outUser, err := exec.Command("sysctl", "-n", "hw.usermem").Output()
	if err != nil {
		return 0, err
	}

	totalStr := strings.TrimSpace(string(outTotal))
	userStr := strings.TrimSpace(string(outUser))

	total, err := strconv.ParseUint(totalStr, 10, 64)
	if err != nil {
		return 0, err
	}
	user, err := strconv.ParseUint(userStr, 10, 64)
	if err != nil {
		return 0, err
	}

	if total == 0 {
		return 0, fmt.Errorf("total memory is 0")
	}
	used := total - user
	return (float64(used) / float64(total)) * 100, nil
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
	return (float64(total-free) / float64(total)) * 100, nil
}

func readNetworkBytes() (int64, int64, error) {
	return 0, 0, nil
}

func readRunningProcesses() (string, error) {
	cmd := exec.Command("ps", "-axco", "command")
	out, err := cmd.Output()
	if err != nil {
		return "[]", err
	}
	lines := strings.Split(string(out), "\n")
	var list []string
	for i, line := range lines {
		if i == 0 {
			continue
		}
		name := strings.TrimSpace(line)
		if name != "" {
			list = append(list, name)
		}
	}
	b, err := json.Marshal(list)
	if err != nil {
		return "[]", err
	}
	return string(b), nil
}
