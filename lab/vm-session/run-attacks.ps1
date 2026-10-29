# Attack runs of the vm-live-v1 session (docs/design/vm-live-v1.md).
#   -Part uac    in a NORMAL (non-administrator) PowerShell window: 4 UAC tests x 5 rounds
#   -Part admin  in an ADMINISTRATOR PowerShell window: 6 tests x 5 rounds
# Round-robin order, each run followed by its cleanup, runs started >= 180 s apart.
# Ground truth is appended to C:\CPES-session\atomic-log.csv by Invoke-AtomicTest.

param(
    [Parameter(Mandatory)][ValidateSet("uac", "admin")][string]$Part,
    [int]$Rounds = 5,
    [int]$GapSeconds = 180,
    [string]$LogName = "atomic-log.csv"   # VM3 pilot uses -Rounds 1 -LogName pilot-atomic-log.csv
)

$ErrorActionPreference = "Continue"
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if ($Part -eq "uac" -and $isAdmin) { throw "Part 'uac' must run in a NORMAL (non-administrator) PowerShell window." }
if ($Part -eq "admin" -and -not $isAdmin) { throw "Part 'admin' must run in an ADMINISTRATOR PowerShell window." }

$tests = @{
    uac   = @(("T1548.002", 1), ("T1548.002", 3), ("T1548.002", 5), ("T1548.002", 7))
    admin = @(("T1543.003", 2), ("T1543.003", 3), ("T1055.001", 1), ("T1134.001", 1), ("T1134.001", 2), ("T1134.002", 1))
}[$Part]

Import-Module "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1" -Force
$log = "C:\CPES-session\$LogName"
$total = $Rounds * $tests.Count
$n = 0
for ($round = 1; $round -le $Rounds; $round++) {
    foreach ($test in $tests) {
        $n++
        $next = (Get-Date).AddSeconds($GapSeconds)
        Write-Host "[$n/$total] $($test[0]) #$($test[1])  $(Get-Date -Format HH:mm:ss)"
        Invoke-AtomicTest $test[0] -TestNumbers $test[1] -ExecutionLogPath $log -TimeoutSeconds 90
        Start-Sleep 20
        Invoke-AtomicTest $test[0] -TestNumbers $test[1] -Cleanup -TimeoutSeconds 60 | Out-Null
        $wait = ($next - (Get-Date)).TotalSeconds
        if ($wait -gt 0) { Start-Sleep -Seconds ([int][math]::Ceiling($wait)) }
    }
}
Write-Host "Part '$Part' finished at $(Get-Date -Format HH:mm:ss): $total runs."
