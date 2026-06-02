//go:build windows

// Polymorphic Malware Behavior Simulator
// FOR AUTHORIZED SECURITY TESTING ONLY
// Use with Trend Micro SEPA / Apex One / Vision One in isolated lab environments.
//
// Simulates: EICAR drop, file mutation, persistence, process injection,
// C2 beaconing, and ransomware file operations to generate Vision One workbenches.
//
// Build (from macOS/Linux):
//
//	GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o ../polymorphic-demo.exe .
//
// MUTATION_MARKER_INITIAL01
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// c2Targets holds all beacon destinations. Rotated each round.
// 1. Trend Micro WRS test URL  → guaranteed network reputation alert
// 2. Known test host
// 3. User-supplied via -c2 flag
var c2Targets []string

func main() {
	// If POLY_GEN is set, we're a mutation chain child — skip all modules except re-mutating.
	if genStr := os.Getenv("POLY_GEN"); genStr != "" {
		gen, _ := strconv.Atoi(genStr)
		runAsMutationChild(gen)
		return
	}

	c2Flag      := flag.String("c2", "puginarug.com", "Additional C2 beacon target (hostname or IP)")
	intervalSec := flag.Int("interval", 30, "Seconds between beacon rounds")
	cleanup     := flag.Bool("cleanup", false, "Remove all artifacts created by this tool")
	noEicar     := flag.Bool("no-eicar", false, "Skip EICAR file drop")
	noMutate    := flag.Bool("no-mutate", false, "Skip file mutation")
	noPersist   := flag.Bool("no-persist", false, "Skip persistence installation")
	noInject    := flag.Bool("no-inject", false, "Skip process injection (use if not Administrator)")
	noBeacon    := flag.Bool("no-beacon", false, "Skip C2 beacon")
	noRansom    := flag.Bool("no-ransom", false, "Skip ransomware simulation")
	flag.Parse()

	c2Targets = []string{
		"https://wrs.test.trendmicro.com/EVIL",
		"https://wrs49.winshipway.com",
		"http://" + *c2Flag,
	}

	printBanner()

	if *cleanup {
		runCleanup()
		return
	}

	logf("Host      : %s (%s)", os.Getenv("COMPUTERNAME"), os.Getenv("USERNAME"))
	logf("Start time: %s", time.Now().Format("2006-01-02 15:04:05"))
	logf("Log file  : %s", logFilePath())
	fmt.Println()

	// Module 1: EICAR
	if !*noEicar {
		dropEicar()
		fmt.Println()
		time.Sleep(2 * time.Second)
	}

	// Module 2: File mutation
	if !*noMutate {
		mutate()
		fmt.Println()
	}

	// Module 3: Persistence
	if !*noPersist {
		installPersistence()
		fmt.Println()
	}

	// Module 4: Process injection
	if !*noInject {
		injectProcess()
		fmt.Println()
	}

	// Module 5: C2 beacon (goroutine — runs until process exits)
	if !*noBeacon {
		go startBeacon(time.Duration(*intervalSec) * time.Second)
		fmt.Println()
	}

	// Module 6: Ransomware simulation
	if !*noRansom {
		runRansomSim()
		fmt.Println()
	}

	// Summary
	fmt.Println()
	logf("╔══════════════════════════════════════════════════════════════════╗")
	logf("║  ALL MODULES COMPLETE                                            ║")
	logf("╚══════════════════════════════════════════════════════════════════╝")
	logf("Check Vision One → Workbench → filter host: %s", os.Getenv("COMPUTERNAME"))
	logf("Allow 2-5 minutes for event correlation to produce workbenches")
	fmt.Println()
	logf("Expected Vision One alerts:")
	logf("  [Malware]  EICAR test file (immediate)")
	logf("  [Behavior] Process injection T1055.002")
	logf("  [Behavior] Registry run key T1547.001")
	logf("  [Behavior] Scheduled task   T1053.005")
	logf("  [Network]  C2 beacon        T1071.001")
	logf("  [Ransom]   Mass file ops    T1486")
	fmt.Println()

	if !*noBeacon {
		logf("Beacon is running — press Ctrl+C to stop, or re-run with -cleanup")
		select {} // block until Ctrl+C
	}
}

// ── Logging ──────────────────────────────────────────────────────────────────

func logFilePath() string {
	tmp := os.Getenv("TEMP")
	if tmp == "" {
		tmp = os.TempDir()
	}
	return filepath.Join(tmp, "polymorphic_demo_log.txt")
}

func logf(format string, args ...any) {
	ts  := time.Now().Format("15:04:05")
	msg := fmt.Sprintf(format, args...)
	line := fmt.Sprintf("[%s] %s", ts, msg)
	fmt.Println(line)
	f, err := os.OpenFile(logFilePath(), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err == nil {
		fmt.Fprintln(f, line)
		f.Close()
	}
}

func printBanner() {
	red := "\033[31m"
	rst := "\033[0m"
	fmt.Println(red)
	fmt.Println("  ╔══════════════════════════════════════════════════════════════════╗")
	fmt.Println("  ║   POLYMORPHIC MALWARE BEHAVIOR SIMULATOR v1.0                    ║")
	fmt.Println("  ║   Trend Micro SEPA / Apex One / Vision One Demo                  ║")
	fmt.Println("  ║   FOR AUTHORIZED SECURITY TESTING ONLY                           ║")
	fmt.Println("  ╚══════════════════════════════════════════════════════════════════╝")
	fmt.Println(rst)
}

// ── Cleanup ───────────────────────────────────────────────────────────────────

func runCleanup() {
	logf("=== CLEANUP MODE ===")

	// Registry run key
	runHidden("reg.exe", "delete",
		`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`,
		"/v", "WinSvcHost32", "/f")
	logf("  Registry key removed")

	// Scheduled task
	runHidden("schtasks.exe", "/Delete", "/TN", "WinSvcHost32", "/F")
	logf("  Scheduled task removed")

	// AppData copy
	appdata := os.Getenv("APPDATA")
	os.Remove(filepath.Join(appdata, "Microsoft", "Windows", "WinSvcHost32.exe"))
	logf("  AppData copy removed")

	// Startup folder copy
	startupDir := filepath.Join(appdata, "Microsoft", "Windows",
		"Start Menu", "Programs", "Startup")
	os.Remove(filepath.Join(startupDir, "WinSvcHost32.exe"))
	logf("  Startup folder entry removed")

	// TEMP artifacts
	tmp := os.Getenv("TEMP")
	if tmp == "" {
		tmp = os.TempDir()
	}
	entries, _ := os.ReadDir(tmp)
	for _, e := range entries {
		name := e.Name()
		if strings.HasPrefix(name, "eicar_test_") ||
			strings.HasPrefix(name, "WinSvcHost_") ||
			strings.HasPrefix(name, "Documents_Backup_") ||
			name == "polymorphic_demo_log.txt" {
			os.RemoveAll(filepath.Join(tmp, name))
		}
	}
	logf("  TEMP artifacts removed")

	logf("=== CLEANUP COMPLETE ===")
}

// ── Utility ───────────────────────────────────────────────────────────────────

func tmpDir() string {
	tmp := os.Getenv("TEMP")
	if tmp == "" {
		tmp = os.TempDir()
	}
	return tmp
}

func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0755)
}
