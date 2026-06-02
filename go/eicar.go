//go:build windows

package main

// Module 1: EICAR Drop
// Triggers: Trend Micro MALWR detection → Vision One Malware Detection workbench
//
// Assembles the EICAR Anti-Malware Test File string at runtime so that the binary
// itself is not flagged by static scanning during transfer. EICAR is a standardized
// test artifact (https://www.eicar.org) with no harmful payload.

import (
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
)

func dropEicar() {
	logf("MODULE 1: EICAR Drop")
	logf("  Target: Vision One Malware Detection alert")

	// Build the EICAR standard test string from components (avoids static detection
	// of this binary before execution). The assembled string is not harmful.
	p1 := "X5O!P%@AP[4\\PZX54(P^)"
	p2 := "7CC)7}"
	p3 := "$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
	eicar := p1 + p2 + p3

	filename := fmt.Sprintf("eicar_test_%08x.com", rand.Uint32())
	outPath  := filepath.Join(tmpDir(), filename)

	if err := os.WriteFile(outPath, []byte(eicar), 0644); err != nil {
		logf("  EICAR drop failed: %v", err)
		return
	}

	logf("  Dropped : %s", outPath)
	logf("  Expect  : Immediate MALWR alert + Vision One workbench entry")
}
