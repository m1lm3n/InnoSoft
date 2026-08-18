<#
    deploy.ps1

    Copies the audit toolkit to the domain controllers listed in
    targets.psd1.

    Copying is done with robocopy /XO, so unchanged files are skipped and a
    file that is newer on the controller is never overwritten by an older
    local one.

    Credentials come from the same encrypted store run-remote.ps1 fills:

        .\run-remote.ps1 -all -setcredential

    After that a plain .\deploy.ps1 -all works from any console, with no
    runas needed. Order of precedence: -CredentialMap, -Credential, the
    store, then a prompt when -PromptOnDenied is given.

    Reachability is checked on TCP 445 rather than ICMP, which is blocked
    across this estate. Use -UsePing to go back to a ping.

    Usage
        .\deploy.ps1 -list
        .\deploy.ps1
        .\deploy.ps1 -domain kkk.lo
        .\deploy.ps1 -all
        .\deploy.ps1 -all -whatif
        .\deploy.ps1 -all -includeextra
        .\deploy.ps1 -all -promptondenied
        .\deploy.ps1 -domain xxx.lo -credential (Get-Credential xxx\admin)

    deploy.ps1 and run-remote.ps1 exclude themselves: they are useless on a
    controller and their presence there suggests deployment can be driven
    from the server.

    Exit codes
        0  everything copied or already up to date
        1  at least one target failed
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$Domain = 'nnn.lo',

    [switch]$All,
    [switch]$List,

    # Mirror: delete files on the controller that no longer exist locally.
    # Scoped to -Include and protected by -Exclude, but still destructive.
    [switch]$Mirror,

    [string[]]$Include = @('*.ps1', '*.psm1', '*.psd1'),
    [string[]]$Exclude = @('deploy.ps1', 'run-remote.ps1'),

    # Source folder, defaults to the folder this script lives in
    [string]$Source,

    # Destination on each controller, as a local path
    [string]$RemotePath = 'C:\scripts',

    # Also copy to the extra controllers named in targets.psd1
    [switch]$IncludeExtra,

    # Skip the reachability test entirely
    [switch]$NoProbe,

    # Probe with ICMP instead of TCP 445
    [switch]$UsePing,

    # Refuse to deploy while the working tree has uncommitted changes
    [switch]$RequireClean,

    [System.Management.Automation.PSCredential]$Credential,
    [hashtable]$CredentialMap = @{},
    [switch]$PromptOnDenied,

    [string]$CredentialStorePath = (Join-Path $env:USERPROFILE '.dc_actions\creds'),
    [switch]$NoCredentialStore,

    # Usernames only, used to prefill the credential prompt
    [string]$EnvFile,

    # Alternative target table
    [string]$TargetsFile
)

$ErrorActionPreference = 'Stop'

# Report where a failure actually happened. Without this a terminating
# error at script scope is blamed on the line that invoked the script,
# which tells you nothing.
trap {
    Write-Host ''
    Write-Host 'UNHANDLED ERROR' -ForegroundColor Red
    Write-Host "  $($_.Exception.GetType().Name): $(($_.Exception.Message -split "`n")[0])" -ForegroundColor Red
    if ($_.InvocationInfo) {
        Write-Host "  line $($_.InvocationInfo.ScriptLineNumber): $($_.InvocationInfo.Line.Trim())" -ForegroundColor Red
    }
    if ($_.ScriptStackTrace) {
        Write-Host '  stack:' -ForegroundColor DarkGray
        $_.ScriptStackTrace -split "`n" | ForEach-Object { Write-Host "    $_" -ForegroundColor DarkGray }
    }
    Write-Host ''
    continue
}

# ---------------------------------------------------------------
# Shared target table
# ---------------------------------------------------------------
$targetsModule = Join-Path $PSScriptRoot 'AuditTargets.psm1'
if (-not (Test-Path $targetsModule)) {
    throw "AuditTargets.psm1 not found beside this script. It reads targets.psd1."
}
Import-Module $targetsModule -Force -DisableNameChecking

$Targets = Get-AuditTargets -Path $TargetsFile

if ($List) {
    Show-AuditTargets -Path $TargetsFile
    return
}

# ---------------------------------------------------------------
# Paths
# ---------------------------------------------------------------
if (-not $Source) { $Source = $PSScriptRoot }
if (-not (Test-Path $Source)) { throw "Source folder not found: $Source" }

if (-not $EnvFile) { $EnvFile = Join-Path $Source '.env' }

# Guard against a rename: never ship this file under whatever name it has
$selfName = Split-Path -Leaf $PSCommandPath
if ($selfName -and $Exclude -notcontains $selfName) { $Exclude += $selfName }

# ---------------------------------------------------------------
# Credentials
# ---------------------------------------------------------------
function Import-StoredCredential {
    param([string]$Dom)
    if ($NoCredentialStore) { return $null }
    $safe = $Dom -replace '[^\w\.\-]', '_'
    $path = Join-Path $CredentialStorePath "$safe.cred.xml"
    if (-not (Test-Path $path)) { return $null }
    try { return Import-Clixml -Path $path }
    catch {
        Write-Warning "Stored credential for $Dom is unusable: $($_.Exception.Message)"
        return $null
    }
}

function Import-EnvUsernames {
    $map = @{}
    if (-not (Test-Path $EnvFile)) { return $map }
    foreach ($line in (Get-Content $EnvFile)) {
        $t = "$line".Trim()
        if (-not $t) { continue }
        if ($t.StartsWith('#')) { continue }
        $parts = $t -split '=', 2
        if ($parts.Count -ne 2) { continue }
        $k = $parts[0].Trim()
        $v = $parts[1].Trim() -replace '^["'']|["'']$', ''
        if ($k -and $v) { $map[$k] = $v }
    }
    return $map
}

$EnvUsers = Import-EnvUsernames
if ($EnvUsers.Count) {
    Write-Host "Loaded $($EnvUsers.Count) username hint(s) from $EnvFile" -ForegroundColor DarkGray
}

function Resolve-DeployCredential {
    param([string]$Dom, [string]$Server, [switch]$Interactive)

    if ($CredentialMap.ContainsKey($Dom)) { return $CredentialMap[$Dom] }
    if ($Credential) { return $Credential }

    $stored = Import-StoredCredential -Dom $Dom
    if ($stored) { return $stored }

    if (-not $Interactive) { return $null }

    $msg = "Credentials for $Dom ($Server)"
    if ($EnvUsers.ContainsKey($Dom)) {
        return (Get-Credential -Message $msg -UserName $EnvUsers[$Dom])
    }
    return (Get-Credential -Message $msg)
}

# ---------------------------------------------------------------
# Git context: useful in the log and a guard against shipping work
# in progress
# ---------------------------------------------------------------
$gitInfo = 'not a git repository'
$gitDirty = $false
if (Get-Command git.exe -ErrorAction SilentlyContinue) {
    Push-Location $Source
    try {
        $branch = (& git rev-parse --abbrev-ref HEAD 2>$null)
        $short = (& git rev-parse --short HEAD 2>$null)
        $status = @(& git status --porcelain 2>$null)
        if ($branch) {
            # Casting a multi element array straight to [bool] throws in
            # Windows PowerShell, and git returns one line per changed file.
            $gitDirty = ($status.Count -gt 0)
            $gitInfo = "$branch@$short"
            if ($gitDirty) { $gitInfo += ' (uncommitted changes)' }
        }
    }
    catch { }
    finally { Pop-Location }
}

Write-Host ""
Write-Host "Source:  $Source" -ForegroundColor Cyan
Write-Host "Git:     $gitInfo" -ForegroundColor $(if ($gitDirty) { 'Yellow' } else { 'Cyan' })
Write-Host "Files:   $($Include -join ', ')" -ForegroundColor Cyan
Write-Host "Exclude: $($Exclude -join ', ')" -ForegroundColor Cyan
Write-Host "Remote:  $RemotePath" -ForegroundColor Cyan
if ($Mirror) {
    Write-Host "Mode:    MIRROR - files missing locally will be deleted remotely" -ForegroundColor Yellow
}

if ($RequireClean -and $gitDirty) {
    throw "Working tree has uncommitted changes. Commit them, or drop -RequireClean."
}

# ---------------------------------------------------------------
# Which domains, and which hosts within them
# ---------------------------------------------------------------
$selected = @()
if ($All) { $selected = @($Targets.Keys) } else { $selected = @($Domain) }

foreach ($dom in $selected) {
    if (-not $Targets.Contains($dom)) {
        throw "Unknown domain '$dom'. Run .\deploy.ps1 -list to see the table."
    }
}

$hostsFor = @{}
foreach ($dom in $selected) {
    # Not $list: variable names are case insensitive, so it would collide
    # with the [switch]$List parameter and fail the type constraint.
    $hostList = @($Targets[$dom].Server)
    if ($IncludeExtra) { $hostList += @($Targets[$dom].Extra) }
    $hostsFor[$dom] = @($hostList | Where-Object { $_ } | Select-Object -Unique)
}

# ---------------------------------------------------------------
# Deploy
# ---------------------------------------------------------------
$results = New-Object System.Collections.Generic.List[object]

function Test-HostReachable {
    param([string]$Server)
    if ($NoProbe) { return $true }
    try {
        if ($UsePing) {
            return [bool](Test-Connection -ComputerName $Server -Count 1 -Quiet -ErrorAction SilentlyContinue)
        }
        return [bool](Test-NetConnection -ComputerName $Server -Port 445 `
                -InformationLevel Quiet -WarningAction SilentlyContinue)
    }
    catch { return $false }
}

foreach ($dom in $selected) {

    Write-Host ""
    Write-Host ("--- $dom " + ('-' * [Math]::Max(0, 44 - $dom.Length))) -ForegroundColor Cyan

    $cred = Resolve-DeployCredential -Dom $dom -Server $Targets[$dom].Server
    if ($cred) { Write-Host "  credential: $($cred.UserName)" -ForegroundColor DarkGray }

    foreach ($server in $hostsFor[$dom]) {

        Write-Host "  $server" -ForegroundColor White

        $status = 'ok'
        $detail = ''
        $driveName = $null
        $share = "\\$server\" + ($RemotePath -replace '^([A-Za-z]):', '$1$')

        if (-not (Test-HostReachable -Server $server)) {
            $how = if ($UsePing) { 'no ping response' } else { 'TCP 445 closed' }
            Write-Host "    unreachable ($how)" -ForegroundColor Red
            $results.Add([PSCustomObject]@{ Domain = $dom; Server = $server; Status = 'unreachable'; Detail = $how })
            continue
        }

        # An authenticated PSDrive is enough: SMB caches the session per
        # server, so the robocopy that follows reuses it.
        if ($cred) {
            try {
                $driveName = 'dep' + [guid]::NewGuid().ToString('N').Substring(0, 6)
                New-PSDrive -Name $driveName -PSProvider FileSystem -Root "\\$server\c$" `
                    -Credential $cred -ErrorAction Stop | Out-Null
            }
            catch {
                Write-Host "    authentication failed: $(($_.Exception.Message -split "`n")[0])" -ForegroundColor Red
                $results.Add([PSCustomObject]@{ Domain = $dom; Server = $server; Status = 'auth failed'; Detail = '' })
                continue
            }
        }

        # Test-Path throws on access denied instead of returning false,
        # which used to abort the whole run at the first refusal.
        $shareOk = $false
        try { $shareOk = Test-Path "\\$server\c$" -ErrorAction Stop }
        catch { $shareOk = $false }

        if (-not $shareOk -and $PromptOnDenied) {
            Write-Host "    access denied, asking for credentials" -ForegroundColor DarkYellow
            try {
                if ($driveName) { Remove-PSDrive -Name $driveName -Force -ErrorAction SilentlyContinue }
                $cred = Resolve-DeployCredential -Dom $dom -Server $server -Interactive
                if ($cred) {
                    $driveName = 'dep' + [guid]::NewGuid().ToString('N').Substring(0, 6)
                    New-PSDrive -Name $driveName -PSProvider FileSystem -Root "\\$server\c$" `
                        -Credential $cred -ErrorAction Stop | Out-Null
                    $shareOk = Test-Path "\\$server\c$" -ErrorAction SilentlyContinue
                }
            }
            catch { $shareOk = $false }
        }

        if (-not $shareOk) {
            Write-Host "    no access to \\$server\c$" -ForegroundColor Red
            if ($cred) {
                Write-Host "    $($cred.UserName) was refused - check the password or the rights" -ForegroundColor DarkYellow
            }
            else {
                Write-Host "    no credential for this domain. Store one once:" -ForegroundColor DarkYellow
                Write-Host "      .\run-remote.ps1 -domain $dom -setcredential" -ForegroundColor DarkYellow
            }
            if ($driveName) { Remove-PSDrive -Name $driveName -Force -ErrorAction SilentlyContinue }
            $results.Add([PSCustomObject]@{ Domain = $dom; Server = $server; Status = 'no access'; Detail = 'admin share unreachable' })
            continue
        }

        if ($PSCmdlet.ShouldProcess($share, "copy $($Include -join ',')")) {
            try {
                if (-not (Test-Path $share)) {
                    New-Item -ItemType Directory -Path $share -Force | Out-Null
                    Write-Host "    created $share" -ForegroundColor DarkGray
                }

                $rcArgs = @($Source, $share) + $Include +
                @('/XO', '/NJH', '/NJS', '/NDL', '/NP', '/R:2', '/W:2')
                if ($Exclude) { $rcArgs += '/XF'; $rcArgs += $Exclude }
                if ($Mirror) { $rcArgs += '/MIR' }

                $output = & robocopy.exe @rcArgs 2>&1
                $rc = $LASTEXITCODE

                # robocopy: 0 nothing to do, 1 copied, 2 extras present,
                # 3 both. Anything from 8 up is a real failure.
                if ($rc -ge 8) {
                    $status = 'failed'
                    $detail = "robocopy exit $rc"
                    Write-Host "    robocopy failed, exit code $rc" -ForegroundColor Red
                    $output | Where-Object { "$_" -match '\S' } | Select-Object -Last 5 |
                    ForEach-Object { Write-Host "      $_" -ForegroundColor Red }
                }
                else {
                    $lines = @($output | Where-Object { "$_" -match '\.ps1|\.psm1|\.psd1' })
                    $extra = @($lines | Where-Object { "$_" -match 'EXTRA File' })
                    $copied = @($lines | Where-Object { "$_" -notmatch 'EXTRA File' })

                    if ($copied.Count) {
                        Write-Host "    copied $($copied.Count) file(s)" -ForegroundColor Green
                        foreach ($c in $copied) {
                            Write-Host ("      " + (Split-Path ("$c".Trim()) -Leaf)) -ForegroundColor DarkGray
                        }
                    }
                    else {
                        Write-Host "    already up to date" -ForegroundColor DarkGray
                    }

                    if ($extra.Count) {
                        Write-Host "    $($extra.Count) file(s) present only on the target:" -ForegroundColor DarkYellow
                        foreach ($e in $extra) {
                            Write-Host ("      " + (Split-Path ("$e".Trim()) -Leaf)) -ForegroundColor DarkYellow
                        }
                        Write-Host "      left untouched, use -mirror to remove them" -ForegroundColor DarkGray
                    }

                    $detail = "copied $($copied.Count), extra $($extra.Count)"
                }

                # Files arriving over the network carry the zone marker and
                # will not run under a stricter execution policy.
                try {
                    Get-ChildItem $share -File -Recurse -ErrorAction SilentlyContinue |
                    Where-Object { $_.Extension -in '.ps1', '.psm1', '.psd1' } |
                    Unblock-File -ErrorAction SilentlyContinue
                    Write-Host "    unblocked remote scripts" -ForegroundColor DarkGray
                }
                catch { Write-Warning "    could not unblock: $($_.Exception.Message)" }
            }
            catch {
                $status = 'failed'
                $detail = ($_.Exception.Message -split "`n")[0]
                Write-Host "    $detail" -ForegroundColor Red
            }
        }
        else {
            $status = 'skipped (whatif)'
        }

        if ($driveName) { Remove-PSDrive -Name $driveName -Force -ErrorAction SilentlyContinue }

        $results.Add([PSCustomObject]@{ Domain = $dom; Server = $server; Status = $status; Detail = $detail })
    }
}

# ---------------------------------------------------------------
# Summary
# ---------------------------------------------------------------
Write-Host ""
Write-Host ("=" * 70) -ForegroundColor Cyan
$results | Format-Table Domain, Server, Status, Detail -AutoSize

$failed = @($results | Where-Object { $_.Status -notin 'ok', 'skipped (whatif)' })
if ($failed.Count) {
    Write-Host "$($failed.Count) of $($results.Count) target(s) failed" -ForegroundColor Red
    exit 1
}

Write-Host "All $($results.Count) target(s) up to date" -ForegroundColor Green
Write-Host ""
Write-Host "Next: .\run-remote.ps1 -all" -ForegroundColor DarkGray
Write-Host ""