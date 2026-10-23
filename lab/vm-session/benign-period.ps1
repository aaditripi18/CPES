# Benign period of the vm-live-v1 session (docs/design/vm-live-v1.md).
# Run inside the lab VM in an ADMINISTRATOR PowerShell window, then use the VM
# normally until the timer ends. Writes C:\CPES-session\benign-period.csv.

param([int]$Minutes = 30)

$dir = "C:\CPES-session"
$log = Join-Path $dir "benign-period.csv"
New-Item -ItemType Directory -Force $dir | Out-Null

function Mark([string]$what) {
    [pscustomobject]@{ Event = $what; TimeUtc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ") } |
        Export-Csv $log -Append -NoTypeInformation
    Write-Host "$what at $(Get-Date -Format HH:mm:ss)"
}

Mark "benign-start"

# A legitimate service lifecycle, as in the corpus-v3 benign partition.
sc.exe create BenignSvcLive binPath= "C:\Windows\System32\svchost.exe" start= demand | Out-Null
Start-Sleep 5
sc.exe delete BenignSvcLive | Out-Null

# One Defender quick scan, in the background.
Start-Job { Start-MpScan -ScanType QuickScan } | Out-Null

Write-Host ""
Write-Host "Use the VM normally until the timer ends: open and close File Explorer, Notepad,"
Write-Host "Settings and Task Manager, and twice open PowerShell with 'Run as administrator'"
Write-Host "(click Yes) and close it. Do not run any Atomic test."
$end = (Get-Date).AddMinutes($Minutes)
while ((Get-Date) -lt $end) {
    Write-Host -NoNewline ("`r{0} min left   " -f [math]::Ceiling(($end - (Get-Date)).TotalMinutes))
    Start-Sleep 30
}
Write-Host ""
Mark "benign-end"
