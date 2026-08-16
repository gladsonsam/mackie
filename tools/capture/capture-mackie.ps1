# Guided packet capture of Master Fader <-> Mackie DL32S.
#
# Uses pktmon, which is built into Windows - no Wireshark, no Npcap, no reboot.
# Verified on Windows 11 build 26200.
#
# Run from an ELEVATED PowerShell on the machine running Master Fader:
#
#   powershell -NoProfile -ExecutionPolicy Bypass -File .\capture-mackie.ps1
#
# Produces, in .\out\:
#   mackie-<stamp>.pcapng   capture, filtered to the mixer
#   steps-<stamp>.tsv       epoch_ms / step number / label, one line per Enter
#
# The steps file is what lets the analyser slice the capture by action instead
# of guessing. Press Enter only AFTER you have finished each step.

[CmdletBinding()]
param(
    [string] $MixerIp = '192.168.1.100',
    [string] $OutDir  = (Join-Path $PSScriptRoot 'out')
)

$ErrorActionPreference = 'Stop'

# --- The click sequence -------------------------------------------------------
# Order matters. Capture starts BEFORE Master Fader launches so we see the
# connect handshake, which is when the app fetches its name tables.
$Steps = @(
    'Launch Master Fader and wait until it is fully connected to the mixer (~15s).'
    'Open the Snapshots / Shows list. Let it finish populating, then close it.'
    'Recall the FIRST snapshot. Wait 10 seconds.'
    'Recall the SECOND snapshot. Wait 10 seconds.'
    'Rename the first snapshot to exactly:  SNAPTOKEN   (then confirm/save).'
    'Open the Mute Groups view.'
    'Turn mute group 1 ON. Wait 10 seconds. Turn it OFF.'
    'Turn mute group 2 ON. Wait 10 seconds. Turn it OFF.'
    'Rename mute group 1 to exactly:  MGTOKEN   (then confirm/save).'
    'Add channel 5 to mute group 3. Wait 5 seconds. Remove it again.'
    'QUIT Master Fader completely. Wait 5 seconds.'
    'Relaunch Master Fader, wait until fully connected (~15s).'
    'Open the Snapshots list, then the Mute Groups view. Close both.'
    'RESTORE: rename SNAPTOKEN and MGTOKEN back to their original names.'
)

# --- Preflight ----------------------------------------------------------------
$isAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { throw 'Run this from an elevated PowerShell (pktmon needs admin).' }

if (-not (Get-Command pktmon.exe -ErrorAction SilentlyContinue)) {
    throw 'pktmon.exe not found - unexpected on Windows 10 1809+.'
}
if (-not (Test-Connection -ComputerName $MixerIp -Count 2 -Quiet)) {
    throw "Mixer $MixerIp is not answering. Is it powered on and on the network?"
}
Write-Host "mixer $MixerIp reachable" -ForegroundColor DarkGray

# --- Safety briefing ----------------------------------------------------------
Write-Host ''
Write-Host 'Before starting:' -ForegroundColor Yellow
Write-Host '  1. Save the current show on the mixer. Steps 5 and 9 RENAME a real' -ForegroundColor Yellow
Write-Host '     snapshot and a real mute group; step 14 renames them back, but a' -ForegroundColor Yellow
Write-Host '     saved show is the safety net.' -ForegroundColor Yellow
Write-Host '  2. Disable the Mackie DL integration in Home Assistant, so' -ForegroundColor Yellow
Write-Host '     nothing else drives the mixer during capture.' -ForegroundColor Yellow
Write-Host ''
$orig1 = Read-Host 'Current name of snapshot 1   (so you can restore it)'
$orig2 = Read-Host 'Current name of mute group 1 (so you can restore it)'

# --- Start capture ------------------------------------------------------------
if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir | Out-Null }
$stamp    = Get-Date -Format 'yyyyMMdd-HHmmss'
$etlPath  = Join-Path $OutDir "mackie-$stamp.etl"
$pcapPath = Join-Path $OutDir "mackie-$stamp.pcapng"
$stepPath = Join-Path $OutDir "steps-$stamp.tsv"

# Clean slate: a stale session or leftover filter would silently capture the
# wrong thing.
cmd /c 'pktmon stop'          2>&1 | Out-Null
cmd /c 'pktmon filter remove' 2>&1 | Out-Null

cmd /c "pktmon filter add MackieCap -i $MixerIp" 2>&1 | Out-Null

# --pkt-size 0 logs the WHOLE packet; the default truncates at 128 bytes, which
# would decapitate exactly the name payloads we are here for.
# --comp nics captures at the adapter rather than at every stack layer.
$start = cmd /c "pktmon start --capture --comp nics --pkt-size 0 -f `"$etlPath`"" 2>&1
if ($LASTEXITCODE -ne 0) { $start | Write-Host; throw 'pktmon failed to start.' }

"epoch_ms`tstep`tlabel" | Set-Content -Path $stepPath -Encoding UTF8
function Write-Step {
    param([int] $N, [string] $Label)
    $ms = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
    "$ms`t$N`t$Label" | Add-Content -Path $stepPath -Encoding UTF8
}
Write-Step -N 0 -Label "CAPTURE START | orig snapshot1='$orig1' orig mutegroup1='$orig2'"

Write-Host ''
Write-Host 'Capturing.' -ForegroundColor Green
Write-Host ('-' * 72)

# --- Walk the steps -----------------------------------------------------------
try {
    for ($i = 0; $i -lt $Steps.Count; $i++) {
        $n = $i + 1
        Write-Host ''
        Write-Host "STEP $n of $($Steps.Count)" -ForegroundColor Cyan
        Write-Host "  $($Steps[$i])"
        Read-Host '  press Enter when this step is COMPLETE'
        Write-Step -N $n -Label $Steps[$i]
        Write-Host '  logged.' -ForegroundColor DarkGray
    }
}
finally {
    Write-Step -N 999 -Label 'CAPTURE END'
    Start-Sleep -Seconds 2
    Write-Host ''
    Write-Host 'Stopping capture...' -ForegroundColor DarkGray
    cmd /c 'pktmon stop' 2>&1 | Select-String 'Packets|events lost|Log file' | ForEach-Object { Write-Host "  $_" }
    cmd /c 'pktmon filter remove' 2>&1 | Out-Null

    Write-Host 'Converting to pcapng...' -ForegroundColor DarkGray
    cmd /c "pktmon etl2pcap `"$etlPath`" -o `"$pcapPath`"" 2>&1 |
        Select-String 'Packets|Formatted' | ForEach-Object { Write-Host "  $_" }
}

Write-Host ''
Write-Host ('-' * 72)
if (Test-Path $pcapPath) {
    $size = (Get-Item $pcapPath).Length
    Write-Host 'Done.' -ForegroundColor Green
    Write-Host "  capture: $pcapPath"
    Write-Host "  steps:   $stepPath"
    Write-Host ("  size:    {0:N1} MB" -f ($size / 1MB))
    if ($size -lt 100KB) {
        Write-Host 'WARNING: capture is small - did Master Fader really connect?' -ForegroundColor Yellow
    }
} else {
    Write-Host 'Conversion produced no pcapng - the .etl is still there:' -ForegroundColor Red
    Write-Host "  $etlPath"
}
