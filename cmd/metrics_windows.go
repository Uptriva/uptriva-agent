package main

import (
	"fmt"
)

func readProcStat() (uint64, uint64, error) {
	return 0, 0, fmt.Errorf("unsupported OS")
}

func readRAMUsage() (float64, error) {
	return 0, fmt.Errorf("unsupported OS")
}

func readDiskUsage() (float64, error) {
	return 0, fmt.Errorf("unsupported OS")
}

func readNetworkBytes() (int64, int64, error) {
	return 0, 0, fmt.Errorf("unsupported OS")
}

func readRunningProcesses() (string, error) {
	return "[]", fmt.Errorf("unsupported OS")
}
