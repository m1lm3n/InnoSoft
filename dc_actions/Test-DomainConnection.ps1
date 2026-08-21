<#
    Test-DomainConnection.ps1

    Phase 2's "test connection" action, as a standalone script the web
    backend launches as a child process (same "PowerShell as a proven
    child-process boundary" pattern as AdAudit.CredentialHelper and
    CollectionJobRunner) - not a library function, since the caller here is
    C#, not another PowerShell script.

    Deliberately mirrors run-remote.ps1's own New-TargetSession auth-retry
    logic (Negotiate -> Default -> Kerberos fallback, no Basic) rather than
    doing a plain LDAP bind: the thing actually at risk of failing in
    production is WinRM/PSRemoting with the domain's Trusted/NTLM setup,
    not raw AD authentication, so this test needs to exercise the same
    path a real collection run will take or it proves the wrong thing.

    Usage: password comes in on stdin (never a CLI argument - visible in
    process listings; never an environment variable), everything else is a
    parameter. Prints exactly one line to stdout: "OK: ..." or "FAIL: ...".
    Exit code 0 on success, 1 on a connection failure, 2 on bad usage.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Server,
    [Parameter(Mandatory = $true)][string]$Username,
    [string]$Method = 'Negotiate'
)

$ErrorActionPreference = 'Stop'

function Read-StdinSecret {
    # Same BOM-stripping approach as AdAudit.CredentialHelper - Windows
    # PowerShell/pwsh piping into a redirected-stdin native/managed process
    # is not guaranteed to hand back a clean UTF-8 string otherwise.
    $stdin = [Console]::OpenStandardInput()
    $ms = New-Object System.IO.MemoryStream
    $stdin.CopyTo($ms)
    $bytes = $ms.ToArray()
    $bom = [System.Text.Encoding]::UTF8.GetPreamble()
    $start = 0
    if ($bytes.Length -ge $bom.Length) {
        $matches = $true
        for ($i = 0; $i -lt $bom.Length; $i++) { if ($bytes[$i] -ne $bom[$i]) { $matches = $false; break } }
        if ($matches) { $start = $bom.Length }
    }
    return [System.Text.Encoding]::UTF8.GetString($bytes, $start, $bytes.Length - $start).Trim()
}

$plainPassword = Read-StdinSecret
if (-not $plainPassword) {
    Write-Output "FAIL: no password received on stdin"
    exit 2
}

$secure = ConvertTo-SecureString -String $plainPassword -AsPlainText -Force
$plainPassword = $null
$cred = New-Object System.Management.Automation.PSCredential($Username, $secure)

$attempts = @($Method)
foreach ($fallback in 'Negotiate', 'Default', 'Kerberos') {
    if ($attempts -notcontains $fallback) { $attempts += $fallback }
}

$lastError = $null
$session = $null
foreach ($auth in $attempts) {
    try {
        $sp = @{ ComputerName = $Server; Credential = $cred; ErrorAction = 'Stop' }
        if ($auth -ne 'Default') { $sp['Authentication'] = $auth }
        $session = New-PSSession @sp
        break
    }
    catch {
        if (-not $lastError) { $lastError = $_.Exception.Message }
    }
}

if (-not $session) {
    Write-Output "FAIL: $lastError"
    exit 1
}

try {
    $remoteHost = Invoke-Command -Session $session -ScriptBlock { $env:COMPUTERNAME } -ErrorAction Stop
    Write-Output "OK: connected to $Server (remote host: $remoteHost)"
    exit 0
}
catch {
    Write-Output "FAIL: connected but the test command failed - $($_.Exception.Message)"
    exit 1
}
finally {
    Remove-PSSession -Session $session -ErrorAction SilentlyContinue
}
