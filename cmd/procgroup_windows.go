//go:build windows

package main

import "os/exec"

func setProcGroup(cmd *exec.Cmd) {
}

func killProcGroup(cmd *exec.Cmd) {
	if cmd.Process != nil {
		_ = cmd.Process.Kill()
	}
}
