<#
    deploy.ps1

    Copies the audit toolkit to one or more domain controllers.

    Targets are declared in the $Targets table below, keyed by domain.
    Copying is done with robocopy /XO, so unchanged files are skipped and
    a file that is newer on the DC is never overwritten by an older local one.

    Usage:
        .\deploy.ps1                      # deploy to the default domain
        .\deploy.ps1 -domain kkk.lo
        .\deploy.ps1 -all                 # every domain in the table
        .\deploy.ps1 -all -whatif         # show what would happen, copy nothing
        .\deploy.ps1 -domain ttt.lo -mirror
        .\deploy.ps1 -list                # print the target table and exit
        .\deploy.ps1 -exclude deploy.ps1,notes.ps1
        .\deploy.ps1 -domain xxx.lo -credential (Get-Credential xxx\admin)
        .\deploy.ps1 -all -promptondenied
        .\deploy.ps1 -all -credentialmap @{ 'xxx.lo' = $c1; 'ttt.lo' = $c2 }

    A single logon can rarely reach every domain. Supply credentials per
    domain, or use -promptondenied to be asked only where access fails.

    deploy.ps1 excludes itself: it is useless on a domain controller and
    its presence there implies deployment can be run from the server.

    Exit codes:
        0  everything copied or already up to date
        1  at least one target failed
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$Domain = 'nnn.lo',

    # Deploy to every domain in the target table
    [switch]$All,

    # Print the target table and exit
    [switch]$List,

    # Mirror: delete files on the DC that no longer exist locally.
    # Scoped to the -Include filter, but still destructive - read the note.
    [switch]$Mirror,

    # Which files to ship
    [string[]]$Include = @('*.ps1'),

    # Files never shipped. This script itself is pointless on a DC, and
    # having it there suggests deployment can be driven from the server.
    [string[]]$Exclude = @('deploy.ps1'),

    # Source folder, defaults to the folder this script lives in
    [string]$Source,

    # Remote folder on each DC, expressed as a local path
    [string]$RemotePath = 'C:\scripts',

    # Skip the reachability test (faster, but failures are less obvious)
    [switch]$NoPing,

    # Commit the working tree first if it is dirty
    [switch]$RequireClean,

    # Credentials for domains where the current logon has no rights.
    # One credential for every target:
    #     -Credential (Get-Credential xxx\admin)
    # Or per domain:
    #     -CredentialMap @{ 'xxx.lo' = Get-Credential xxx\admin }
    [System.Management.Automation.PSCredential]$Credential,
    [hashtable]$CredentialMap = @{},

    # Ask for credentials interactively when a target refuses access
    [switch]$PromptOnDenied
)

$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------
# Target table - edit this when a domain is added or a DC is renamed
# ---------------------------------------------------------------
$Targets = [ordered]@{
    'nnn.lo'     = @{ Server = 'dc-nnn.nnn.lo'; Note = 'users: reten, conversion, sales' }
    'kkk.lo'     = @{ Server = 'dc-kkk.kkk.lo'; Note = 'scouts, operators - admin Anton' }
    'xxx.lo'     = @{ Server = 'dc-xxx.xxx.lo'; Note = 'admin Silver' }
    'ttt.lo'     = @{ Server = 'dc-ttt.ttt.lo'; Note = 'single DC, fault tolerant' }
    'a.lo'       = @{ Server = 'dc.a.lo'; Note = 'auth for OnlyOffice and Nextcloud' }
    'core64.com' = @{ Server = 'dc-dc1.core64.com'; Note = 'management domain' }
}

# ---------------------------------------------------------------
# List mode
# ---------------------------------------------------------------
if ($List) {
    Write-Host ""
    Write-Host "Deployment targets:" -ForegroundColor Cyan
    foreach ($k in $Targets.Keys) {
        Write-Host ("  {0,-12} {1,-24} {2}" -f $k, $Targets[$k].Server, $Targets[$k].Note)
    }
    Write-Host ""
    return
}

if (-not $Source) { $Source = $PSScriptRoot }
if (-not $Source) { $Source = Split-Path -Parent $MyInvocation.MyCommand.Path }

if (-not (Test-Path $Source)) { throw "Source folder not found: $Source" }

# Guard against a rename: exclude this file under whatever name it has now
$selfName = Split-Path -Leaf $MyInvocation.MyCommand.Path
if ($selfName -and $Exclude -notcontains $selfName) { $Exclude += $selfName }

# ---------------------------------------------------------------
# Git context - handy in the log, and a guard against shipping WIP
# ---------------------------------------------------------------
$gitInfo = 'not a git repository'
$gitDirty = $false
$git = Get-Command git.exe -ErrorAction SilentlyContinue
if ($git) {
    Push-Location $Source
    try {
        $branch = (& git rev-parse --abbrev-ref HEAD 2>$null)
        $short = (& git rev-parse --short HEAD 2>$null)
        $status = (& git status --porcelain 2>$null)
        if ($branch) {
            $gitDirty = [bool]$status
            $gitInfo = "$branch@$short" + $(if ($gitDirty) { ' (uncommitted changes)' } else { '' })
        }
    }
    catch { }
    finally { Pop-Location }
}

Write-Host ""
Write-Host "Source:  $Source" -ForegroundColor Cyan
Write-Host "Git:     $gitInfo" -ForegroundColor $(if ($gitDirty) { 'Yellow' } else { 'Cyan' })
Write-Host "Files:   $($Include -join ', ')" -ForegroundColor Cyan
if ($Exclude) { Write-Host "Exclude: $($Exclude -join ', ')" -ForegroundColor Cyan }
Write-Host "Remote:  $RemotePath" -ForegroundColor Cyan
if ($Mirror) { Write-Host "Mode:    MIRROR - files missing locally will be deleted remotely" -ForegroundColor Yellow }

if ($RequireClean -and $gitDirty) {
    throw "Working tree has uncommitted changes. Commit them, or drop -RequireClean."
}

# ---------------------------------------------------------------
# Which domains
# ---------------------------------------------------------------
$selected = if ($All) { @($Targets.Keys) } else { @($Domain) }

foreach ($dom in $selected) {
    if (-not $Targets.Contains($dom)) {
        throw "Unknown domain '$dom'. Run .\deploy.ps1 -list to see the table."
    }
}

# ---------------------------------------------------------------
# Deploy
# ---------------------------------------------------------------
$results = New-Object System.Collections.Generic.List[object]

foreach ($dom in $selected) {
    $server = $Targets[$dom].Server
    $share = "\\$server\" + ($RemotePath -replace '^([A-Za-z]):', '$1$')

    Write-Host ""
    Write-Host ("--- $dom  ->  $server " + ('-' * [Math]::Max(0, 30 - $dom.Length))) -ForegroundColor Cyan

    $status = 'ok'
    $detail = ''

    # reachability
    if (-not $NoPing) {
        $alive = $false
        try { $alive = Test-Connection -ComputerName $server -Count 1 -Quiet -ErrorAction SilentlyContinue }
        catch { $alive = $false }
        if (-not $alive) {
            Write-Host "  unreachable (no ping response)" -ForegroundColor Red
            $results.Add([PSCustomObject]@{ Domain = $dom; Server = $server; Status = 'unreachable'; Detail = '' })
            continue
        }
    }

    # Open an authenticated session when credentials were supplied. A mapped
    # PSDrive is enough: SMB caches the session per server, so robocopy that
    # runs afterwards reuses it.
    $cred = $null
    if ($CredentialMap.ContainsKey($dom)) { $cred = $CredentialMap[$dom] }
    elseif ($Credential) { $cred = $Credential }

    $driveName = $null
    if ($cred) {
        try {
            $driveName = "dep$([guid]::NewGuid().ToString('N').Substring(0,6))"
            New-PSDrive -Name $driveName -PSProvider FileSystem `
                -Root "\\$server\c$" -Credential $cred -ErrorAction Stop | Out-Null
            Write-Host "  authenticated as $($cred.UserName)" -ForegroundColor DarkGray
        }
        catch {
            Write-Host "  could not authenticate as $($cred.UserName): $($_.Exception.Message)" -ForegroundColor Red
            $results.Add([PSCustomObject]@{ Domain = $dom; Server = $server; Status = 'auth failed'; Detail = $_.Exception.Message })
            continue
        }
    }

    # admin share. Test-Path throws on access denied instead of returning
    # false, which used to abort the whole -all run at the first refusal.
    $shareOk = $false
    try { $shareOk = Test-Path "\\$server\c$" -ErrorAction Stop }
    catch { $shareOk = $false }

    if (-not $shareOk -and $PromptOnDenied -and -not $cred) {
        Write-Host "  access denied, asking for credentials" -ForegroundColor DarkYellow
        try {
            $cred = Get-Credential -Message "Credentials for $dom ($server)"
            $driveName = "dep$([guid]::NewGuid().ToString('N').Substring(0,6))"
            New-PSDrive -Name $driveName -PSProvider FileSystem `
                -Root "\\$server\c$" -Credential $cred -ErrorAction Stop | Out-Null
            $shareOk = Test-Path "\\$server\c$" -ErrorAction SilentlyContinue
        }
        catch { $shareOk = $false }
    }

    if (-not $shareOk) {
        Write-Host "  no access to \\$server\c$" -ForegroundColor Red
        Write-Host "  pass credentials for this domain:" -ForegroundColor DarkYellow
        Write-Host "    .\deploy.ps1 -domain $dom -credential (Get-Credential)" -ForegroundColor DarkYellow
        $results.Add([PSCustomObject]@{ Domain = $dom; Server = $server; Status = 'no access'; Detail = 'admin share unreachable' })
        if ($driveName) { Remove-PSDrive -Name $driveName -Force -ErrorAction SilentlyContinue }
        continue
    }

    if ($PSCmdlet.ShouldProcess($share, "copy $($Include -join ',')")) {
        try {
            if (-not (Test-Path $share)) {
                New-Item -ItemType Directory -Path $share -Force | Out-Null
                Write-Host "  created $share" -ForegroundColor DarkGray
            }

            $rcArgs = @($Source, $share) + $Include + @('/XO', '/NJH', '/NJS', '/NDL', '/NP', '/R:2', '/W:2')
            if ($Exclude) {
                # /XF also protects these from deletion when /MIR is on
                $rcArgs += '/XF'
                $rcArgs += $Exclude
            }
            if ($Mirror) { $rcArgs += '/MIR' }

            $output = & robocopy.exe @rcArgs 2>&1
            $rc = $LASTEXITCODE

            # robocopy: 0 = nothing to do, 1 = files copied, 2 = extras present,
            # 3 = both; anything 8 or above is a real failure
            if ($rc -ge 8) {
                $status = 'failed'
                $detail = "robocopy exit $rc"
                Write-Host "  robocopy failed, exit code $rc" -ForegroundColor Red
                $output | Where-Object { "$_" -match '\S' } | Select-Object -Last 5 |
                    ForEach-Object { Write-Host "    $_" -ForegroundColor Red }
            }
            else {
                $lines = @($output | Where-Object { "$_" -match '\.ps1|\.psm1|\.psd1' })
                # robocopy lists files that exist only on the target as
                # "*EXTRA File"; they were not copied and must not be counted
                $extra = @($lines | Where-Object { "$_" -match 'EXTRA File' })
                $copied = @($lines | Where-Object { "$_" -notmatch 'EXTRA File' })

                if ($copied.Count) {
                    Write-Host "  copied $($copied.Count) file(s)" -ForegroundColor Green
                    foreach ($c in $copied) {
                        Write-Host ("    " + ("$c".Trim())) -ForegroundColor DarkGray
                    }
                }
                else {
                    Write-Host "  already up to date" -ForegroundColor DarkGray
                }

                if ($extra.Count) {
                    Write-Host "  $($extra.Count) file(s) present only on the target:" -ForegroundColor DarkYellow
                    foreach ($e in $extra) {
                        $name = ("$e".Trim() -split '\\')[-1]
                        Write-Host "    $name" -ForegroundColor DarkYellow
                    }
                    Write-Host "  left untouched. Use -mirror to remove them." -ForegroundColor DarkGray
                }

                $detail = "copied $($copied.Count), extra $($extra.Count)"
            }

            # Files arriving over the network carry the zone marker and will
            # refuse to run under a stricter execution policy.
            try {
                Get-ChildItem $share -File -Recurse -ErrorAction SilentlyContinue |
                    Where-Object { $_.Extension -in '.ps1', '.psm1', '.psd1' } |
                    Unblock-File -ErrorAction SilentlyContinue
                Write-Host "  unblocked remote scripts" -ForegroundColor DarkGray
            }
            catch { Write-Warning "  could not unblock: $($_.Exception.Message)" }
        }
        catch {
            $status = 'failed'
            $detail = $_.Exception.Message
            Write-Host "  $($_.Exception.Message)" -ForegroundColor Red
        }
    }
    else {
        $status = 'skipped (whatif)'
    }

    if ($driveName) { Remove-PSDrive -Name $driveName -Force -ErrorAction SilentlyContinue }

    $results.Add([PSCustomObject]@{ Domain = $dom; Server = $server; Status = $status; Detail = $detail })
}

# ---------------------------------------------------------------
# Summary
# ---------------------------------------------------------------
Write-Host ""
Write-Host ("=" * 60) -ForegroundColor Cyan
$results | Format-Table Domain, Server, Status, Detail -AutoSize
$failed = @($results | Where-Object { $_.Status -notin 'ok', 'skipped (whatif)' })
if ($failed.Count) {
    Write-Host "$($failed.Count) of $($results.Count) target(s) failed" -ForegroundColor Red
    exit 1
}
Write-Host "All $($results.Count) target(s) up to date" -ForegroundColor Green
Write-Host ""
Write-Host "Next: log in to a DC and run" -ForegroundColor DarkGray
Write-Host "  cd $RemotePath; .\run-gpo.ps1 -domain <domain> -server <dc>" -ForegroundColor DarkGray
Write-Host "  cd $RemotePath; .\run-adhealth.ps1 -domain <domain> -server <dc>" -ForegroundColor DarkGray
Write-Host ""