# Polymorphic Malware Behavior Simulator

**FOR AUTHORIZED SECURITY TESTING ONLY**
Use exclusively in approved lab environments with Trend Micro Standard Endpoint Protection (SEPA) or Apex One installed and enrolled in Vision One.

---

## Overview

This tool simulates six polymorphic malware behaviors to generate Vision One workbenches for demo and validation purposes. It covers the full detection stack: file-based detection, behavioral analysis, network reputation, and ransomware heuristics.

| Module | Behavior | MITRE | Expected Vision One Alert |
|--------|----------|-------|--------------------------|
| 1 | EICAR file drop | — | Malware Detection |
| 2 | File mutation (hash change) | T1027 | Polymorphic evasion (telemetry) |
| 3 | Registry + scheduled task + startup | T1547.001, T1053.005 | Suspicious Behavior — Persistence |
| 4 | Process injection (OpenProcess → CreateRemoteThread) | T1055.002 | Suspicious Behavior — Injection |
| 5 | C2 beacon (HTTP, rotating UA) | T1071.001 | Network Correlation — C2 |
| 6 | Mass file encrypt + rename (.polyenc) | T1486, T1083 | Ransomware Indicators |

---

## Prerequisites

- Windows 10/11 x64 test machine (dedicated lab VM recommended)
- Trend Micro SEPA or Apex One agent installed and connected to Vision One
- Vision One XDR / Endpoint Sensor enabled on the agent
- PowerShell 5.1+ (for the PS1 version)
- Go 1.21+ on the build machine (for the EXE version)

---

## Quick Start

### Option A — PowerShell Script (no build required)

Copy `polymorphic-demo.ps1` to the Windows test machine, then:

```powershell
# Run full simulation (Administrator recommended for injection module)
powershell.exe -ExecutionPolicy Bypass -File .\polymorphic-demo.ps1

# Skip process injection if not running as Administrator
powershell.exe -ExecutionPolicy Bypass -File .\polymorphic-demo.ps1 -NoInject

# Custom C2 target, faster beacon
powershell.exe -ExecutionPolicy Bypass -File .\polymorphic-demo.ps1 -C2Target "192.168.100.5" -BeaconInterval 15

# Clean up all artifacts after demo
powershell.exe -ExecutionPolicy Bypass -File .\polymorphic-demo.ps1 -Cleanup
```

### Option B — Compiled EXE (more realistic as a threat artifact)

Build from macOS or Linux:

```bash
chmod +x build.sh && ./build.sh
```

Copy `polymorphic-demo.exe` to the Windows test machine, then:

```cmd
REM Full simulation (run as Administrator)
polymorphic-demo.exe

REM Non-admin (skip injection)
polymorphic-demo.exe -no-inject

REM Custom beacon interval
polymorphic-demo.exe -interval 15 -c2 192.168.100.5

REM Clean up
polymorphic-demo.exe -cleanup
```

---

## C2 Beacon Targets

The tool beacons to all three targets each round:

| Target | Purpose |
|--------|---------|
| `https://wrs.test.trendmicro.com/EVIL` | Trend Micro WRS test URL — guaranteed network reputation alert |
| `https://wrs49.winshipway.com` | Additional test host |
| `http://<your -c2 / -C2Target>` | Configurable (default: `puginarug.com`) |

---

## Demo Flow (Recommended Order)

1. **Pre-demo**: Open Vision One console → Workbench → note any existing alerts
2. **Run the tool** (as Administrator for full coverage)
3. **Wait 2–5 minutes** for Trend Micro to correlate events into workbenches
4. **Navigate to Vision One**:
   - Workbench → filter by hostname → review correlated incidents
   - XDR Threat Investigation → Timeline → see individual events
   - Detection Model → review triggered rules

**Recommended presentation order:**
1. Show Vision One dashboard (clean state)
2. Run tool → switch to Vision One → refresh Workbench
3. Walk through each workbench entry (malware → behavioral → network → ransomware)
4. Click into Timeline to show the correlated event chain
5. Run `-Cleanup` to demonstrate remediation

---

## Expected Vision One Alerts

Within 5 minutes of running, you should see:

```
Workbench: Possible malware activity on <HOSTNAME>
├── [Malware]     EICAR.TEST.FILE detected in C:\Users\...\TEMP\eicar_test_*.com
├── [Behavior]    Suspicious registry modification (T1547.001)
│                 HKCU\...\Run → WinSvcHost32
├── [Behavior]    Suspicious scheduled task created (T1053.005)
│                 Task: WinSvcHost32, trigger: ONLOGON
├── [Behavior]    Process injection detected (T1055.002)
│                 notepad.exe → remote thread created
├── [Network]     Connection to malicious URL (T1071.001)
│                 → wrs.test.trendmicro.com, wrs49.winshipway.com
└── [Ransom]      Ransomware-like file operations (T1486)
                  75 files encrypted, renamed to .polyenc
```

---

## Post-Demo Cleanup

**Always clean up after demos:**

```powershell
# PowerShell
.\polymorphic-demo.ps1 -Cleanup

# EXE
.\polymorphic-demo.exe -cleanup
```

Cleanup removes:
- Registry run key (`HKCU:\...\Run\WinSvcHost32`)
- Scheduled task (`WinSvcHost32`)
- Startup folder entry
- AppData copy of the executable/script
- All TEMP artifacts (EICAR files, mutant copies, encrypted files)
- Background beacon jobs/goroutines

---

## Troubleshooting

| Issue | Resolution |
|-------|-----------|
| Process injection module skipped | Run as Administrator |
| No Vision One workbenches appear | Verify agent is enrolled: check Trend Micro console → Agents → confirm status is "Connected" |
| EICAR not detected | Confirm real-time scan is enabled in SEPA/Apex One policy |
| Network alerts not firing | Verify web reputation (WRS) is enabled in the SEPA policy |
| Scheduled task fails | On some Windows versions, schtasks may require admin — run elevated |
| Beacon shows "no response" | Expected for WRS test URL — the connection attempt is what's logged, not the response |

---

## File Recovery (Ransomware Simulation)

To decrypt `.polyenc` files after the demo:

```powershell
# Decrypt a single file
$b = [IO.File]::ReadAllBytes('Document_001.polyenc')
for ($i = 0; $i -lt $b.Length; $i++) { $b[$i] = $b[$i] -bxor 0x42 }
[IO.File]::WriteAllBytes('Document_001.docx', $b)

# Decrypt all files in staging directory
Get-ChildItem "$env:TEMP\Documents_Backup_*" -Recurse -Filter "*.polyenc" | ForEach-Object {
    $b = [IO.File]::ReadAllBytes($_.FullName)
    for ($i = 0; $i -lt $b.Length; $i++) { $b[$i] = $b[$i] -bxor 0x42 }
    $out = $_.FullName -replace '\.polyenc$', '.recovered'
    [IO.File]::WriteAllBytes($out, $b)
}
```

Or just run `-Cleanup` which removes the entire staging directory.

---

## Architecture Notes

- **Polymorphic mutation**: Each run of the PS1 script generates a new child copy with a different SHA256 (mutation marker replaced). The EXE appends 16 random bytes after the PE structure (ignored by the Windows loader) to change the hash.
- **Injection payload**: `48 31 C0 C3` (xor rax,rax; ret) — the minimal safe x64 thread function. The API call sequence is the detection artifact, not the payload.
- **Ransomware XOR key**: `0x42` — trivially reversible, chosen specifically so real-time ransomware protection triggers before files are "truly" lost.
- **No admin required** for: EICAR drop, mutation, registry HKCU, startup folder, beacon, ransomware sim.
- **Admin required** for: Process injection module (OpenProcess with PROCESS\_ALL\_ACCESS).
