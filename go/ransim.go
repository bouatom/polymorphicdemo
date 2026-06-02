//go:build windows

package main

// Module 6: Ransomware Simulation
// MITRE: T1486 (Data Encrypted for Impact), T1083 (File and Directory Discovery)
// Triggers: Vision One Ransomware Indicators
//
// Creates 75 test "document" files in a temp directory, XOR-encrypts each (key: 0x42),
// renames them to .polyenc, and drops a ransom note. The high-volume file read →
// high-entropy write → bulk rename is what Trend Micro's behavioral engine detects.
//
// RECOVERY: XOR every byte of a .polyenc file with 0x42 to restore it.
// No real user files are touched.

import (
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var docExtensions = []string{
	".docx", ".xlsx", ".pdf", ".jpg", ".png",
	".txt", ".csv", ".pptx", ".db", ".bak",
}

func runRansomSim() {
	logf("MODULE 6: Ransomware Simulation")
	logf("  Techniques: T1486 (mass encryption), T1083 (file enumeration)")

	// Isolated staging directory — never touches real user documents
	ransomDir := filepath.Join(tmpDir(),
		fmt.Sprintf("Documents_Backup_%08x", rand.Uint32()))
	if err := os.MkdirAll(ransomDir, 0755); err != nil {
		logf("  Could not create staging dir: %v", err)
		return
	}
	logf("  Staging dir: %s", ransomDir)

	// Generate 75 realistic "victim" files
	const fileCount = 75
	logf("  Creating %d test files...", fileCount)
	for i := 1; i <= fileCount; i++ {
		ext  := docExtensions[i%len(docExtensions)]
		name := fmt.Sprintf("Document_%03d%s", i, ext)
		body := fmt.Sprintf(
			"CONFIDENTIAL DOCUMENT %d\r\nCreated: %s\r\n%s",
			i,
			time.Now().Format(time.RFC3339),
			strings.Repeat("Lorem ipsum dolor sit amet, consectetur adipiscing. ", 50+rand.Intn(100)),
		)
		os.WriteFile(filepath.Join(ransomDir, name), []byte(body), 0644)
	}

	// XOR-encrypt each file and rename to .polyenc
	// High-volume read → high-entropy write → bulk rename = ransomware behavioral signature
	logf("  Encrypting files (XOR 0x42 — fully recoverable)...")
	const xorKey = byte(0x42)
	encrypted := 0

	entries, _ := os.ReadDir(ransomDir)
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		oldPath := filepath.Join(ransomDir, e.Name())
		data, err := os.ReadFile(oldPath)
		if err != nil {
			continue
		}

		// XOR-transform (increases file entropy, triggers heuristic)
		for i := range data {
			data[i] ^= xorKey
		}

		// Write encrypted content
		os.WriteFile(oldPath, data, 0644)

		// Rename to .polyenc (bulk rename is the ransomware trigger)
		base    := strings.TrimSuffix(e.Name(), filepath.Ext(e.Name()))
		newPath := filepath.Join(ransomDir, base+".polyenc")
		os.Rename(oldPath, newPath)
		encrypted++
	}

	// Drop ransom note
	note := fmt.Sprintf(`YOUR FILES HAVE BEEN ENCRYPTED
================================

[THIS IS A SECURITY TESTING SIMULATION]
[NOT REAL RANSOMWARE — AUTHORIZED TREND MICRO LAB TEST ONLY]

%d files in this folder have been encrypted.

Decryption details:
  Algorithm : XOR
  Key       : 0x42 (decimal 66)
  Extension : .polyenc

PowerShell recovery (one file):
  $b = [IO.File]::ReadAllBytes('file.polyenc')
  for ($i=0; $i -lt $b.Length; $i++) { $b[$i] = $b[$i] -bxor 0x42 }
  [IO.File]::WriteAllBytes('file.docx', $b)

Staged in: %s
`, encrypted, ransomDir)

	os.WriteFile(filepath.Join(ransomDir, "README_DECRYPT.txt"), []byte(note), 0644)

	logf("  Encrypted: %d files → .polyenc", encrypted)
	logf("  Ransom note: %s\\README_DECRYPT.txt", ransomDir)
	logf("  Expect: Vision One T1486 ransomware indicator alert")
}
