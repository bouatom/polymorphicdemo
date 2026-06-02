//go:build windows

package main

// Module 2: Polymorphic Mutation Chain
// MITRE: T1027 (Obfuscated Files), T1036.003 (Rename System Utilities)
//
// Each generation of this binary:
//   1. Appends 16 random bytes to its own image (changes SHA-256, PE still executes)
//   2. Writes the mutated copy to TEMP under a new name
//   3. Spawns the mutant as a new process with POLY_GEN=N set
//   4. The mutant repeats steps 1-3 up to maxGenerations deep
//
// Visual demo effect in TEMP:
//   WinSvcHost_gen1_a3f7b2c1.exe   (hash A)
//   WinSvcHost_gen2_90d1e4f8.exe   (hash B)
//   WinSvcHost_gen3_6c2a1d57.exe   (hash C)
//
// Trend Micro sees multiple distinct binaries spawning children from TEMP,
// each with a unique hash — the behavioral chain is the detection signal.

import (
	"crypto/sha256"
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"
)

const maxGenerations = 3

// mutate is called from the original run (gen 0).
// It spawns gen 1, which spawns gen 2, etc.
func mutate() {
	logf("MODULE 2: Polymorphic Mutation Chain")
	logf("  Technique: T1027 — each generation has unique SHA-256, same behavior")
	logf("  Depth    : %d generations", maxGenerations)
	spawnMutant(0)
}

// runAsMutationChild is called when POLY_GEN env var is set.
// The child waits briefly (so Trend Micro can scan it), then spawns the next gen.
func runAsMutationChild(gen int) {
	logf("  [GEN %d] Polymorphic child active — hash differs from parent", gen)
	logf("  [GEN %d] SHA-256: %s", gen, selfHashPrefix())

	if gen >= maxGenerations {
		logf("  [GEN %d] Mutation chain complete (%d unique hashes generated)", gen, gen)
		// Brief pause so the agent has time to log this process before it exits
		time.Sleep(3 * time.Second)
		return
	}

	// Pause so Trend Micro behavioral engine can observe this process
	time.Sleep(2 * time.Second)
	spawnMutant(gen)
}

// spawnMutant creates gen+1 from the current binary and executes it.
func spawnMutant(currentGen int) {
	nextGen := currentGen + 1

	exePath, err := os.Executable()
	if err != nil {
		logf("  Could not resolve own path: %v", err)
		return
	}

	data, err := os.ReadFile(exePath)
	if err != nil {
		logf("  Could not read own binary: %v", err)
		return
	}

	parentHash := sha256Prefix(data)

	// Append 16 cryptographically random bytes after the PE image.
	// The Windows PE loader ignores trailing data — binary executes identically.
	// SHA-256 changes completely (avalanche effect).
	trailer := make([]byte, 16)
	rand.Read(trailer)
	mutantData := append(data, trailer...)

	mutantName := fmt.Sprintf("WinSvcHost_gen%d_%08x.exe", nextGen, rand.Uint32())
	mutantPath := filepath.Join(tmpDir(), mutantName)

	if err := os.WriteFile(mutantPath, mutantData, 0755); err != nil {
		logf("  Could not write mutant: %v", err)
		return
	}

	mutantHash := sha256Prefix(mutantData)

	logf("  GEN %d → GEN %d", currentGen, nextGen)
	logf("    Parent hash : %s...  (%s)", parentHash, filepath.Base(exePath))
	logf("    Mutant hash : %s...  (%s)", mutantHash, mutantName)
	logf("    Trailer     : %X", trailer)

	// Execute the mutant — it will observe POLY_GEN and call runAsMutationChild
	cmd := exec.Command(mutantPath)
	cmd.Env = append(os.Environ(), fmt.Sprintf("POLY_GEN=%d", nextGen))
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: false} // visible console = demo-friendly
	if err := cmd.Start(); err != nil {
		logf("  Failed to spawn gen %d: %v", nextGen, err)
		return
	}

	logf("    Spawned gen %d (PID %d)", nextGen, cmd.Process.Pid)
	logf("    Expect: Vision One sees new PE from TEMP with different hash")
}

func sha256Prefix(data []byte) string {
	h := sha256.Sum256(data)
	return fmt.Sprintf("%X", h[:6]) // 12 hex chars is enough to show they differ
}

func selfHashPrefix() string {
	exePath, err := os.Executable()
	if err != nil {
		return "unknown"
	}
	data, err := os.ReadFile(exePath)
	if err != nil {
		return "unreadable"
	}
	return sha256Prefix(data)
}
