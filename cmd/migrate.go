package main

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

func maybeMigrateLegacyInstall() {
	if os.Getenv("AGENT_NO_MIGRATE") == "1" || os.Getenv("AGENT_NO_MIGRATE") == "true" {
		return
	}
	time.Sleep(20 * time.Second)
	switch runtime.GOOS {
	case "linux":
		if os.Getenv("INVOCATION_ID") != "" {
			migrateSystemdInstall()
		}
	case "darwin":
		if os.Getenv("XPC_SERVICE_NAME") != "" {
			migrateLaunchdInstall()
		}
	}
}

func resolvedExecutable() string {
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		return resolved
	}
	return exe
}

func copyFileContents(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

func copyDirContents(src, dst string) error {
	entries, err := os.ReadDir(src)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dst, 0700); err != nil {
		return err
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		if err := copyFileContents(filepath.Join(src, e.Name()), filepath.Join(dst, e.Name()), info.Mode()); err != nil {
			return err
		}
	}
	return nil
}

func migrationMarker(configDir string) string {
	return filepath.Join(configDir, ".migrated")
}

func migrationDone(configDir string) bool {
	_, err := os.Stat(migrationMarker(configDir))
	return err == nil
}

type legacySystemdInstall struct {
	bin        string
	configDirs []string
	unit       string
	unitNam    string
}

func legacySystemdInstalls() []legacySystemdInstall {
	return []legacySystemdInstall{
		{bin: "/usr/local/bin/shxrk-agent", configDirs: []string{"/etc/shxrk"}, unit: "/etc/systemd/system/shxrk-agent.service", unitNam: "shxrk-agent"},
		{bin: "/usr/local/bin/uptime-agent", configDirs: []string{"/etc/uptime-agent", "/etc/shxrk"}, unit: "/etc/systemd/system/uptime-agent.service", unitNam: "uptime-agent"},
	}
}

func migrateSystemdInstall() {
	const (
		newBin    = "/usr/local/bin/uptriva-agent"
		newDir    = "/etc/uptriva"
		newUnit   = "/etc/systemd/system/uptriva-agent.service"
		newUnitNm = "uptriva-agent"
	)

	running := resolvedExecutable()
	installs := legacySystemdInstalls()
	var legacy *legacySystemdInstall
	for i := range installs {
		if running == installs[i].bin {
			legacy = &installs[i]
			break
		}
	}
	if legacy == nil {
		return
	}
	if _, err := os.Stat(legacy.unit); err != nil {
		return
	}

	finish := func() {
		exec.Command("systemctl", "disable", legacy.unitNam).Run()
		os.Remove(legacy.unit)
		if err := os.Remove(legacy.bin); err == nil {
			os.Symlink(newBin, legacy.bin)
		}
		if err := os.WriteFile(migrationMarker(newDir), []byte("1"), 0644); err != nil {
			fmt.Printf("[migrate] marker write failed: %v\n", err)
		}
		exec.Command("systemctl", "daemon-reload").Run()
		fmt.Println("[migrate] uptriva-agent is active; retiring legacy service")
		exec.Command("systemctl", "stop", legacy.unitNam).Run()
	}

	if migrationDone(newDir) {
		finish()
		return
	}

	fmt.Printf("[migrate] legacy %s installation detected, migrating to uptriva-agent\n", legacy.unitNam)

	configCopied := false
	for _, dir := range legacy.configDirs {
		if _, err := os.Stat(dir); err != nil {
			continue
		}
		if err := copyDirContents(dir, newDir); err != nil {
			fmt.Printf("[migrate] config copy from %s failed, aborting: %v\n", dir, err)
			return
		}
		configCopied = true
		break
	}
	if !configCopied {
		fmt.Println("[migrate] no legacy config directory found, continuing with fresh config")
	}
	if err := copyFileContents(legacy.bin, newBin, 0755); err != nil {
		fmt.Printf("[migrate] binary copy failed, aborting: %v\n", err)
		return
	}

	unitBody, err := os.ReadFile(legacy.unit)
	if err != nil {
		fmt.Printf("[migrate] cannot read legacy unit, aborting: %v\n", err)
		return
	}
	unit := string(unitBody)
	for _, l := range installs {
		unit = strings.ReplaceAll(unit, l.bin, newBin)
		for _, dir := range l.configDirs {
			unit = strings.ReplaceAll(unit, dir, newDir)
		}
	}
	unit = strings.ReplaceAll(unit, "Uptime Monitoring Agent", "Uptriva Monitoring Agent")
	unit = strings.ReplaceAll(unit, "Shxrk Systems Monitoring Agent", "Uptriva Monitoring Agent")
	if err := os.WriteFile(newUnit, []byte(unit), 0644); err != nil {
		fmt.Printf("[migrate] cannot write new unit, aborting: %v\n", err)
		return
	}

	rollback := func() {
		exec.Command("systemctl", "disable", "--now", newUnitNm).Run()
		os.Remove(newUnit)
		os.Remove(newBin)
		exec.Command("systemctl", "daemon-reload").Run()
	}

	if err := exec.Command("systemctl", "daemon-reload").Run(); err != nil {
		fmt.Printf("[migrate] daemon-reload failed, aborting: %v\n", err)
		rollback()
		return
	}
	if err := exec.Command("systemctl", "enable", "--now", newUnitNm).Run(); err != nil {
		fmt.Printf("[migrate] enabling new unit failed, aborting: %v\n", err)
		rollback()
		return
	}

	active := false
	for i := 0; i < 15; i++ {
		if err := exec.Command("systemctl", "is-active", "--quiet", newUnitNm).Run(); err == nil {
			active = true
			break
		}
		time.Sleep(time.Second)
	}
	if !active {
		fmt.Println("[migrate] new unit did not become active, rolling back")
		rollback()
		return
	}

	finish()
}

func migrateLaunchdInstall() {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return
	}
	var (
		legacyBin   = filepath.Join(home, ".local", "bin", "shxrk-agent")
		newBin      = filepath.Join(home, ".local", "bin", "uptriva-agent")
		legacyDir   = filepath.Join(home, ".shxrk")
		newDir      = filepath.Join(home, ".uptriva")
		legacyPlist = filepath.Join(home, "Library", "LaunchAgents", "systems.shxrk.agent.plist")
		newPlist    = filepath.Join(home, "Library", "LaunchAgents", "com.uptriva.agent.plist")
		legacyLabel = "systems.shxrk.agent"
		newLabel    = "com.uptriva.agent"
	)

	if resolvedExecutable() != legacyBin {
		return
	}
	if _, err := os.Stat(legacyPlist); err != nil {
		return
	}

	finish := func() {
		if err := os.Remove(legacyBin); err == nil {
			os.Symlink(newBin, legacyBin)
		}
		os.Remove(legacyPlist)
		if err := os.WriteFile(migrationMarker(newDir), []byte("1"), 0644); err != nil {
			fmt.Printf("[migrate] marker write failed: %v\n", err)
		}
		fmt.Println("[migrate] uptriva-agent is active; retiring legacy LaunchAgent")
		exec.Command("launchctl", "remove", legacyLabel).Run()
	}

	if migrationDone(newDir) {
		finish()
		return
	}

	fmt.Println("[migrate] legacy shxrk-agent installation detected, migrating to uptriva-agent")

	if err := copyDirContents(legacyDir, newDir); err != nil {
		fmt.Printf("[migrate] config copy failed, aborting: %v\n", err)
		return
	}
	if err := copyFileContents(legacyBin, newBin, 0755); err != nil {
		fmt.Printf("[migrate] binary copy failed, aborting: %v\n", err)
		return
	}

	plistBody, err := os.ReadFile(legacyPlist)
	if err != nil {
		fmt.Printf("[migrate] cannot read legacy plist, aborting: %v\n", err)
		return
	}
	plist := string(plistBody)
	plist = strings.ReplaceAll(plist, legacyBin, newBin)
	plist = strings.ReplaceAll(plist, legacyDir, newDir)
	plist = strings.ReplaceAll(plist, legacyLabel, newLabel)
	if err := os.WriteFile(newPlist, []byte(plist), 0644); err != nil {
		fmt.Printf("[migrate] cannot write new plist, aborting: %v\n", err)
		return
	}

	rollback := func() {
		exec.Command("launchctl", "unload", newPlist).Run()
		os.Remove(newPlist)
		os.Remove(newBin)
	}

	if err := exec.Command("launchctl", "load", newPlist).Run(); err != nil {
		fmt.Printf("[migrate] loading new plist failed, aborting: %v\n", err)
		rollback()
		return
	}

	active := false
	for i := 0; i < 15; i++ {
		out, err := exec.Command("launchctl", "list").Output()
		if err == nil && strings.Contains(string(out), newLabel) {
			active = true
			break
		}
		time.Sleep(time.Second)
	}
	if !active {
		fmt.Println("[migrate] new agent did not register with launchd, rolling back")
		rollback()
		return
	}

	finish()
}
