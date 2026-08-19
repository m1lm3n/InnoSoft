<#
    Fix-NlaDependency.ps1

    Adds Netlogon to the service dependencies of NlaSvc on domain
    controllers, so the network profile is evaluated after the directory
    service is up.

    Why this is needed
        NLA decides the network profile once, at boot. On a controller that
        is still starting its own directory service, the check fails and the
        adapter is marked Public. The Public firewall profile limits WinRM
        to the local subnet, so remote management stops working from
        anywhere else, and other services behave unexpectedly too.

    Why the registry and not sc.exe
        "sc.exe config NlaSvc depend= ..." REPLACES the whole dependency
        list. Getting that command slightly wrong leaves the service with no
        dependencies at all. This script reads DependOnService, appends
        Netlogon and writes it back, keeping whatever was there before.

    Usage
        .\Fix-NlaDependency.ps1 -Domain nnn.lo -WhatIf     # show, change nothing
        .\Fix-NlaDependency.ps1 -Domain nnn.lo
        .\Fix-NlaDependency.ps1 -Domain nnn.lo -RestartNla
        .\Fix-NlaDependency.ps1 -All
        .\Fix-NlaDependency.ps1 -Domain nnn.lo -Revert
        .\Fix-NlaDependency.ps1 -All -ExcludeHost *-core.*    # skip the dead RODCs

    The change only takes effect at the next boot. -RestartNla additionally
    restarts the service now, which re-evaluates the profile immediately.
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [string]$Domain = 'nnn.lo',
    [switch]$All,

    # Work on these hosts instead of enumerating the domain controllers
    [string[]]$ComputerName,

    # Skip these hosts entirely. Useful for controllers that are known to be
    # offline, so they stop being reported as failures on every run.
    [string[]]$ExcludeHost = @(),

    # Restart NlaSvc after the change, so the profile is corrected now
    [switch]$RestartNla,

    # Put DependOnService back from the backup file
    [switch]$Revert,

    # No $PSScriptRoot-based default here: with [CmdletBinding()], PSScriptRoot
    # is empty during param default evaluation when the script is invoked via
    # -File from an external process (confirmed PowerShell 5.1 quirk - works
    # fine interactively, breaks when launched by another process). Resolved
    # in the script body instead, where PSScriptRoot is reliable.
    [string]$BackupPath,

    [System.Management.Automation.PSCredential]$Credential,
    [hashtable]$CredentialMap = @{},
    [string]$CredentialStorePath = (Join-Path $env:USERPROFILE '.dc_actions\creds'),

    [ValidateSet('Default', 'Kerberos', 'Negotiate')]
    [string]$Authentication = 'Negotiate',

    # Alternative target table, defaults to targets.psd1 beside the script
    [string]$TargetsFile
)

$ErrorActionPreference = 'Stop'

if (-not $BackupPath) { $BackupPath = Join-Path $PSScriptRoot 'nla-dependency-backup.csv' }

# Targets come from targets.psd1, shared with deploy.ps1 and run-remote.ps1
$targetsModule = Join-Path $PSScriptRoot 'AuditTargets.psm1'
if (-not (Test-Path $targetsModule)) {
    throw "AuditTargets.psm1 not found next to this script. It reads targets.psd1."
}
Import-Module $targetsModule -Force -DisableNameChecking

$Targets = Get-AuditTargets -Path $TargetsFile

# ---------------------------------------------------------------
# Credentials, same encrypted store as run-remote.ps1
# ---------------------------------------------------------------
function Get-DomainCredential {
    param([string]$Dom)
    if ($CredentialMap.ContainsKey($Dom)) { return $CredentialMap[$Dom] }
    if ($Credential) { return $Credential }
    $safe = $Dom -replace '[^\w\.\-]', '_'
    $path = Join-Path $CredentialStorePath "$safe.cred.xml"
    if (Test-Path $path) {
        try { return Import-Clixml $path } catch { }
    }
    return (Get-Credential -Message "Credentials for $Dom")
}

function Convert-NetworkCategory {
    # 0 Public, 1 Private, 2 DomainAuthenticated
    param($Value)
    switch ("$Value") {
        '0' { 'Public' }
        '1' { 'Private' }
        '2' { 'DomainAuthenticated' }
        default { "$Value" }
    }
}

function New-DcSession {
    param([string]$Server, $Cred)
    foreach ($auth in @($Authentication, 'Negotiate', 'Default')) {
        try {
            $sp = @{ ComputerName = $Server; ErrorAction = 'Stop' }
            if ($Cred) {
                $sp['Credential'] = $Cred
                if ($auth -ne 'Default') { $sp['Authentication'] = $auth }
            }
            return New-PSSession @sp
        }
        catch { $script:LastErr = $_.Exception.Message }
    }
    return $null
}

# ---------------------------------------------------------------
# Which controllers
# ---------------------------------------------------------------
function Get-DomainControllerList {
    <#
        Asks the primary controller for the list, rather than querying LDAP
        from here. This workstation runs under a local account, so an ADSI
        bind from the local process returns nothing and every property comes
        back null.
    #>
    param([string]$Server, $Cred)

    $session = New-DcSession -Server $Server -Cred $Cred
    if (-not $session) { throw "no session to $Server : $script:LastErr" }

    try {
        return Invoke-Command -Session $session -ScriptBlock {
            $root = [ADSI]'LDAP://RootDSE'
            $base = $root.defaultNamingContext[0]
            $s = New-Object System.DirectoryServices.DirectorySearcher
            $s.SearchRoot = [ADSI]"LDAP://OU=Domain Controllers,$base"
            $s.Filter = '(objectCategory=computer)'
            [void]$s.PropertiesToLoad.Add('dnshostname')
            @($s.FindAll() | ForEach-Object {
                    if ($_.Properties['dnshostname'].Count) { $_.Properties['dnshostname'][0] }
                } | Where-Object { $_ })
        }
    }
    finally { Remove-PSSession $session -ErrorAction SilentlyContinue -WhatIf:$false }
}

$selected = if ($All) { @($Targets.Keys) } else { @($Domain) }
foreach ($d in $selected) {
    if (-not $Targets.Contains($d)) { throw "Unknown domain '$d'" }
}

Write-Host ""
Write-Host "NlaSvc dependency fix" -ForegroundColor Cyan
Write-Host "Backup file: $BackupPath" -ForegroundColor DarkGray
if ($Revert) { Write-Host "Mode: REVERT from backup" -ForegroundColor Yellow }

$backup = @()
if (Test-Path $BackupPath) { $backup = @(Import-Csv $BackupPath) }

$results = New-Object System.Collections.Generic.List[object]

foreach ($dom in $selected) {
    $primary = $Targets[$dom].Server
    Write-Host ""
    Write-Host ("--- $dom " + ('-' * [Math]::Max(0, 40 - $dom.Length))) -ForegroundColor Cyan

    $cred = Get-DomainCredential -Dom $dom

    # list of controllers to work on
    $hosts = @()
    if ($ComputerName) { $hosts = $ComputerName }
    else {
        try {
            $hosts = Get-DomainControllerList -Server $primary -Cred $cred
            Write-Host "  controllers: $($hosts -join ', ')" -ForegroundColor DarkGray
        }
        catch {
            Write-Host "  could not list controllers: $($_.Exception.Message)" -ForegroundColor Red
            Write-Host "  falling back to $primary" -ForegroundColor DarkYellow
            $hosts = @($primary)
        }
    }

    foreach ($h in $hosts) {
        if ($ExcludeHost | Where-Object { $h -like $_ }) {
            Write-Host ""
            Write-Host "  $h" -ForegroundColor DarkGray
            Write-Host "    excluded by request" -ForegroundColor DarkGray
            $results.Add([PSCustomObject]@{ Domain = $dom; Host = $h; Status = 'excluded'; Before = ''; After = '' })
            continue
        }

        Write-Host ""
        Write-Host "  $h" -ForegroundColor White

        $before = @()
        $session = New-DcSession -Server $h -Cred $cred
        if (-not $session) {
            Write-Host "    no session: $script:LastErr" -ForegroundColor Red
            $results.Add([PSCustomObject]@{ Domain = $dom; Host = $h; Status = 'no session'; Before = ''; After = '' })
            continue
        }

        try {
            $state = Invoke-Command -Session $session -ScriptBlock {
                $key = 'HKLM:\SYSTEM\CurrentControlSet\Services\NlaSvc'
                $dep = (Get-ItemProperty -Path $key -Name DependOnService -ErrorAction SilentlyContinue).DependOnService
                [PSCustomObject]@{
                    Dependencies = @($dep)
                    # NetworkCategory is an enum and would arrive as a bare
                    # number after serialisation, so resolve it here
                    Profiles     = @(Get-NetConnectionProfile | ForEach-Object {
                            [PSCustomObject]@{
                                InterfaceAlias  = $_.InterfaceAlias
                                NetworkCategory = "$($_.NetworkCategory)"
                                Name            = $_.Name
                            }
                        })
                    NlaStatus    = (Get-Service NlaSvc).Status.ToString()
                }
            }

            $before = @($state.Dependencies)
            Write-Host "    depends on:   $($before -join ', ')"
            foreach ($p in $state.Profiles) {
                $cat = Convert-NetworkCategory $p.NetworkCategory
                $lvl = if ($cat -eq 'DomainAuthenticated') { 'Green' } else { 'Yellow' }
                Write-Host "    profile:      $($p.InterfaceAlias) = $cat ($($p.Name))" -ForegroundColor $lvl
            }

            # ---------- revert ----------
            if ($Revert) {
                $saved = $backup | Where-Object { $_.Host -eq $h } | Select-Object -First 1
                if (-not $saved) {
                    Write-Host "    no backup entry for this host, skipping" -ForegroundColor DarkYellow
                    $results.Add([PSCustomObject]@{ Domain = $dom; Host = $h; Status = 'no backup'; Before = ($before -join ','); After = '' })
                    continue
                }
                $restore = @($saved.Before -split ',' | Where-Object { $_ })
                if ($PSCmdlet.ShouldProcess($h, "restore DependOnService to $($restore -join ', ')")) {
                    Invoke-Command -Session $session -ArgumentList (, $restore) -ScriptBlock {
                        param($dep)
                        Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NlaSvc' `
                            -Name DependOnService -Value ([string[]]$dep) -Type MultiString
                    }
                    Write-Host "    restored to:  $($restore -join ', ')" -ForegroundColor Green
                    $results.Add([PSCustomObject]@{ Domain = $dom; Host = $h; Status = 'reverted'; Before = ($before -join ','); After = ($restore -join ',') })
                }
                continue
            }

            # ---------- apply ----------
            if ($before -contains 'Netlogon') {
                Write-Host "    already depends on Netlogon, nothing to do" -ForegroundColor Green
                $results.Add([PSCustomObject]@{ Domain = $dom; Host = $h; Status = 'already set'; Before = ($before -join ','); After = ($before -join ',') })
                continue
            }

            $after = @($before) + 'Netlogon'

            if ($PSCmdlet.ShouldProcess($h, "add Netlogon to NlaSvc dependencies")) {
                # keep the original value before touching anything
                $backup = @($backup | Where-Object { $_.Host -ne $h })
                $backup += [PSCustomObject]@{
                    Host    = $h
                    Domain  = $dom
                    Before  = ($before -join ',')
                    SavedAt = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
                }
                $backup | Export-Csv $BackupPath -NoTypeInformation -Encoding UTF8

                $applied = Invoke-Command -Session $session -ArgumentList (, $after) -ScriptBlock {
                    param($dep)
                    $key = 'HKLM:\SYSTEM\CurrentControlSet\Services\NlaSvc'
                    Set-ItemProperty -Path $key -Name DependOnService -Value ([string[]]$dep) -Type MultiString
                    return @((Get-ItemProperty -Path $key -Name DependOnService).DependOnService)
                }

                if ($applied -contains 'Netlogon') {
                    Write-Host "    now depends on: $($applied -join ', ')" -ForegroundColor Green
                    $status = 'updated'
                }
                else {
                    Write-Host "    the write did not take effect" -ForegroundColor Red
                    $status = 'failed'
                }

                # ---------- optional restart ----------
                # Restarting NlaSvc makes the firewall re-evaluate the network
                # profile, which can drop the very WinRM session issuing the
                # command. The restart is therefore detached from the session
                # and the outcome checked on a fresh connection.
                $restartStatus = ''
                if ($RestartNla -and $status -eq 'updated') {
                    if ($PSCmdlet.ShouldProcess($h, 'restart NlaSvc')) {
                        Write-Host "    restarting NlaSvc (detached)..." -ForegroundColor DarkGray
                        try {
                            Invoke-Command -Session $session -ScriptBlock {
                                # Win32_Process survives the caller losing its session
                                $cmd = 'cmd.exe /c net stop NlaSvc & net start NlaSvc'
                                [void](Invoke-CimMethod -ClassName Win32_Process -MethodName Create `
                                        -Arguments @{ CommandLine = $cmd })
                            } -ErrorAction Stop
                        }
                        catch {
                            Write-Host "    the restart command may not have been delivered: $(($_.Exception.Message -split "`n")[0])" -ForegroundColor DarkYellow
                        }

                        Remove-PSSession $session -ErrorAction SilentlyContinue -WhatIf:$false
                        $session = $null

                        Write-Host "    waiting for the service to settle..." -ForegroundColor DarkGray
                        Start-Sleep -Seconds 25

                        $verified = $false
                        for ($try = 1; $try -le 3 -and -not $verified; $try++) {
                            $session = New-DcSession -Server $h -Cred $cred
                            if (-not $session) {
                                Write-Host "    reconnect attempt $try failed, waiting..." -ForegroundColor DarkYellow
                                Start-Sleep -Seconds 10
                                continue
                            }
                            try {
                                $post = Invoke-Command -Session $session -ScriptBlock {
                                    [PSCustomObject]@{
                                        NlaStatus = (Get-Service NlaSvc).Status.ToString()
                                        Profiles  = @(Get-NetConnectionProfile | ForEach-Object {
                                                [PSCustomObject]@{
                                                    InterfaceAlias  = $_.InterfaceAlias
                                                    NetworkCategory = "$($_.NetworkCategory)"
                                                    Name            = $_.Name
                                                }
                                            })
                                    }
                                } -ErrorAction Stop
                                $verified = $true

                                Write-Host "    NlaSvc:       $($post.NlaStatus)" -ForegroundColor $(if ($post.NlaStatus -eq 'Running') { 'Green' } else { 'Red' })
                                foreach ($p in $post.Profiles) {
                                    $cat = Convert-NetworkCategory $p.NetworkCategory
                                    $lvl = if ($cat -eq 'DomainAuthenticated') { 'Green' } else { 'Yellow' }
                                    Write-Host "    profile now:  $($p.InterfaceAlias) = $cat ($($p.Name))" -ForegroundColor $lvl
                                }
                                $restartStatus = if ($post.NlaStatus -eq 'Running') { 'restarted' } else { "NlaSvc $($post.NlaStatus)" }
                            }
                            catch {
                                Remove-PSSession $session -ErrorAction SilentlyContinue -WhatIf:$false
                                $session = $null
                                Start-Sleep -Seconds 10
                            }
                        }

                        if (-not $verified) {
                            Write-Host "    could not verify after the restart - check the host by hand" -ForegroundColor Yellow
                            $restartStatus = 'unverified'
                        }
                    }
                }

                $reported = if ($restartStatus -and $restartStatus -ne 'restarted') { "$status ($restartStatus)" } else { $status }
                $results.Add([PSCustomObject]@{ Domain = $dom; Host = $h; Status = $reported; Before = ($before -join ','); After = ($applied -join ',') })
            }
            else {
                Write-Host "    would set:    $($after -join ', ')" -ForegroundColor DarkGray
                $results.Add([PSCustomObject]@{ Domain = $dom; Host = $h; Status = 'whatif'; Before = ($before -join ','); After = ($after -join ',') })
            }
        }
        catch {
            Write-Host "    $(($_.Exception.Message -split "`n")[0])" -ForegroundColor Red
            # $before is set once the registry has been read, so report what
            # is known rather than losing the fact that the change went in
            $known = if ($before) { ($before -join ',') } else { '' }
            $results.Add([PSCustomObject]@{ Domain = $dom; Host = $h; Status = 'error'; Before = $known; After = '' })
        }
        finally {
            if ($session) { Remove-PSSession $session -ErrorAction SilentlyContinue -WhatIf:$false }
        }
    }
}

Write-Host ""
Write-Host ("=" * 70) -ForegroundColor Cyan
$results | Format-Table Domain, Host, Status, Before, After -AutoSize

$changed = @($results | Where-Object { $_.Status -eq 'updated' })
if ($changed.Count) {
    Write-Host "Changed: $($changed.Count) controller(s)" -ForegroundColor Green
    Write-Host "The dependency takes effect at the next boot." -ForegroundColor DarkGray
    if (-not $RestartNla) {
        Write-Host "To correct the profile now without rebooting, rerun with -restartnla," -ForegroundColor DarkGray
        Write-Host "or on each controller: Restart-Service NlaSvc -Force" -ForegroundColor DarkGray
    }
    Write-Host ""
    Write-Host "Verify after the next reboot:" -ForegroundColor DarkGray
    Write-Host "  Get-NetConnectionProfile      # expect DomainAuthenticated" -ForegroundColor DarkGray
    Write-Host "  sc.exe qc NlaSvc              # expect Netlogon in the list" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "To undo: .\Fix-NlaDependency.ps1 -domain <domain> -revert" -ForegroundColor DarkGray
}

$failed = @($results | Where-Object { $_.Status -in 'failed', 'error', 'no session' })
$partial = @($results | Where-Object { "$($_.Status)" -like 'updated (*' })
if ($partial.Count) {
    Write-Host ""
    Write-Host "$($partial.Count) controller(s): the dependency was written but the restart" -ForegroundColor Yellow
    Write-Host "could not be confirmed. The change still applies at the next boot." -ForegroundColor Yellow
    foreach ($p in $partial) { Write-Host "    $($p.Host): $($p.Status)" -ForegroundColor Yellow }
}
if ($failed.Count) {
    Write-Host "$($failed.Count) controller(s) failed" -ForegroundColor Red
    exit 1
}