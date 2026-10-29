# Read-only preflight for a VM session (docs/design/package-v3-and-vm2.md).
# Run inside the lab VM, in an ADMINISTRATOR PowerShell window, after setup and
# before the benign period. Changes nothing; prints each check and writes the
# same lines to C:\CPES-session\preflight.txt for the session record.

param([string]$AtomicsPath = "C:\AtomicRedTeam\atomics")

$dir = "C:\CPES-session"
New-Item -ItemType Directory -Force $dir | Out-Null
$report = Join-Path $dir "preflight.txt"
$lines = [System.Collections.Generic.List[string]]::new()

function Check([string]$name, [bool]$ok, [string]$detail = "") {
    $line = "{0} {1}{2}" -f ($(if ($ok) { "[ OK ]" } else { "[FAIL]" })), $name, $(if ($detail) { "  -- $detail" } else { "" })
    $lines.Add($line)
    Write-Host $line -ForegroundColor $(if ($ok) { "Green" } else { "Red" })
}
function Note([string]$text) { $lines.Add("       $text"); Write-Host "       $text" }

$os = Get-CimInstance Win32_OperatingSystem
Note "$($os.Caption) build $($os.BuildNumber), host $env:COMPUTERNAME, user $env:USERDOMAIN\$env:USERNAME, $(Get-Date -Format o)"

# The session user must be an ordinary administrator, not the built-in Administrator:
# the built-in account runs without UAC admin approval, so UAC bypasses gain nothing.
$me = [Security.Principal.WindowsIdentity]::GetCurrent()
Check "session user is not the built-in Administrator" (-not $me.User.Value.EndsWith("-500")) $me.Name
$lua = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System").EnableLUA
Check "UAC enabled (EnableLUA = 1)" ($lua -eq 1) "EnableLUA = $lua"

foreach ($svc in "Sysmon64", "winlogbeat") {
    $s = Get-Service $svc -ErrorAction SilentlyContinue
    Check "service $svc running" ($s -and $s.Status -eq "Running") $(if ($s) { "$($s.Status)" } else { "not installed" })
}
$sysmonDrv = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\SysmonDrv\Parameters" -ErrorAction SilentlyContinue)
Check "Sysmon configuration loaded" ($null -ne $sysmonDrv.Rules) $(if ($sysmonDrv.ConfigHash) { "ConfigHash $($sysmonDrv.ConfigHash)" } else { "" })
$pipes = Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -FilterXPath "*[System[(EventID=17 or EventID=18)]]" -MaxEvents 1 -ErrorAction SilentlyContinue
Check "Sysmon logs named pipes (EID 17/18, config v2)" ($null -ne $pipes)

$audit = (auditpol /get /subcategory:"Security System Extension" /r | ConvertFrom-Csv)."Inclusion Setting"
Check "audit 'Security System Extension' includes Success (Security 4697)" ($audit -match "Success") $audit

$esUp = Test-NetConnection -ComputerName "127.0.0.1" -Port 9200 -InformationLevel Quiet -WarningAction SilentlyContinue
Check "Elasticsearch listening on 9200" $esUp
$heap = Get-ChildItem "C:\Elastic" -Recurse -Filter "heap.options" -ErrorAction SilentlyContinue | Select-Object -First 1
Check "Elasticsearch heap capped (jvm.options.d\heap.options)" ($null -ne $heap) $(if ($heap) { (Get-Content $heap.FullName) -join " " } else { "" })

$mp = Get-MpComputerStatus -ErrorAction SilentlyContinue
if ($mp) {
    Note "Defender: AntivirusEnabled=$($mp.AntivirusEnabled) RealTimeProtectionEnabled=$($mp.RealTimeProtectionEnabled) BehaviorMonitorEnabled=$($mp.BehaviorMonitorEnabled) IsTamperProtected=$($mp.IsTamperProtected)"
    Note "Defender real-time protection must be OFF before the attack runs, not before the benign period."
} else { Note "Defender: Get-MpComputerStatus unavailable" }

$nics = Get-NetAdapter | Where-Object Status -eq "Up"
Note "network adapters up: $(($nics | ForEach-Object { $_.Name + ' (' + $_.InterfaceDescription + ')' }) -join '; ')"
$internet = Test-NetConnection -ComputerName "1.1.1.1" -Port 443 -InformationLevel Quiet -WarningAction SilentlyContinue
Check "no internet route (NAT off)" (-not $internet) $(if ($internet) { "1.1.1.1:443 reachable -- disable the NAT adapter before the attack runs" } else { "" })

Check "Invoke-AtomicRedTeam module present" (Test-Path "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1")
Check "atomics folder present" (Test-Path $AtomicsPath)

# Binaries the UAC tests rely on; on Windows Server some may be absent.
foreach ($bin in "eventvwr.exe", "fodhelper.exe", "ComputerDefaults.exe", "sdclt.exe", "mavinject.exe") {
    $p = Join-Path "$env:WINDIR\System32" $bin
    Check "binary $bin present" (Test-Path $p) $p
}

if (Test-Path "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1") {
    Import-Module "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1" -Force
    $tests = @(("T1548.002", 1), ("T1548.002", 3), ("T1548.002", 5), ("T1548.002", 7),
               ("T1543.003", 2), ("T1543.003", 3), ("T1055.001", 1),
               ("T1134.001", 1), ("T1134.001", 2), ("T1134.002", 1))
    foreach ($t in $tests) {
        $out = Invoke-AtomicTest $t[0] -TestNumbers $t[1] -CheckPrereqs -PathToAtomicsFolder $AtomicsPath *>&1 | Out-String
        $ok = $out -notmatch "Prerequisites not met"
        Check "prereqs $($t[0]) #$($t[1])" $ok $(if (-not $ok) { "run: Invoke-AtomicTest $($t[0]) -TestNumbers $($t[1]) -GetPrereqs (with NAT on)" } else { "" })
    }
}

$lines | Set-Content -Encoding utf8 $report
Write-Host ""
Write-Host "Written to $report"
