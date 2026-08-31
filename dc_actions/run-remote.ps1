<#
    run-remote.ps1

    Runs the audit toolkit on each domain controller over WinRM and copies
    the results back. Far faster than driving the collectors over the
    network from a workstation: everything the scripts read is local to the
    controller, so a domain finishes in seconds instead of an hour.

    One-shot tool: nothing persists between runs except the CSV folders
    themselves (kept on disk under -LocalRoot as the baseline for the next
    run's comparison) and the HTML report. No database, no stored
    credentials - targets and usernames come from $env:ADAUDIT_TARGETS
    (see AuditTargets.psm1's header for the JSON shape), passwords are
    asked for interactively every run.

    Usage:
        .\run-remote.ps1                       # default domain
        .\run-remote.ps1 -domain kkk.lo
        .\run-remote.ps1 -all
        .\run-remote.ps1 -all -only gpo        # one toolkit across every domain
        .\run-remote.ps1 -all -promptondenied
        .\run-remote.ps1 -list

    Authentication:
        Negotiate is the default here. Kerberos, which PowerShell would use
        on its own, fails when this workstation belongs to a different
        domain from the controller. Override with -authentication if needed.

    Trusts:
        Domains marked "Trusted": false in $env:ADAUDIT_TARGETS have no
        trust to the management domain, so Kerberos cannot work there. They
        need NTLM, which WinRM only permits for hosts listed in
        TrustedHosts:

            .\run-remote.ps1 -all -ensuretrustedhosts     # elevated console
            .\run-remote.ps1 -all -ensuretrustedhosts -restoretrustedhosts

        Recheck after any change to the trust layout:
            nltest /domain_trusts /all_trusts /v

    If a target reports "port closed", the controller is usually showing a
    Public network profile, which limits WinRM to its own subnet. On the
    controller: Get-NetConnectionProfile, then Restart-Service NlaSvc -Force.

    Results land in <LocalRoot>\<domain>\<date>\ on this machine and are
    never deleted - each dated folder is the baseline the next run compares
    against.

    Collection runs on the controller, analysis runs here. That split
    matters: every analyzer compares the current run with the previous one,
    and that history only exists locally - the working folder on the
    controller is wiped after each run. Use -analyzeonserver to go back to
    analysing remotely, at the cost of losing the comparison.
#>

[CmdletBinding()]
param(
    [string]$Domain = 'nnn.lo',
    [switch]$All,
    [switch]$List,

    # Which toolkits to run
    [ValidateSet('gpo', 'adhealth', 'adsecurity', 'all')]
    [string[]]$Only = @('all'),

    # Where the scripts live on the controller
    [string]$RemoteScripts = 'C:\scripts',

    # Working folder on the controller, cleaned up afterwards
    [string]$RemoteWork = 'C:\audit-work',

    # Where results are collected locally
    [string]$LocalRoot = 'C:\audit',

    [System.Management.Automation.PSCredential]$Credential,
    [hashtable]$CredentialMap = @{},
    [switch]$PromptOnDenied,

    # Add the untrusted controllers to the WinRM TrustedHosts list so NTLM
    # can be used. Needs an elevated console. See the note near $Targets.
    [switch]$EnsureTrustedHosts,

    # Put TrustedHosts back the way it was once the run finishes
    [switch]$RestoreTrustedHosts,

    # Kerberos is the default and fails when the workstation sits in a
    # different domain from the target. Negotiate falls back to NTLM.
    [ValidateSet('Default', 'Kerberos', 'Negotiate', 'CredSSP', 'Basic')]
    [string]$Authentication = 'Negotiate',

    # Leave the working folder on the controller
    [switch]$KeepRemote,

    # Run the analysis on the controller instead of here. Off by default:
    # the analyzers compare against the previous run, and that history lives
    # locally, not on a controller whose working folder is wiped every time.
    [switch]$AnalyzeOnServer,

    # Skip building the HTML report
    [switch]$NoReport,

    # Open the report when it is finished
    [switch]$OpenReport,

    # Where the report goes
    [string]$ReportPath
)

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path

# Output capture and report rendering live in their own modules so this
# script stays about running things, not about formatting them.
$script:CanReport = $true
foreach ($mod in 'AuditCapture', 'AuditHtml') {
    $modPath = Join-Path $here "$mod.psm1"
    if (Test-Path $modPath) { Import-Module $modPath -Force -DisableNameChecking }
    else {
        Write-Warning "$mod.psm1 not found next to this script - the HTML report will be skipped"
        $script:CanReport = $false
    }
}

# ---------------------------------------------------------------
# Credential handling - nothing is ever written to disk. Username comes
# from the target's entry in $env:ADAUDIT_TARGETS (if given); the password
# is always asked for interactively, once per domain per run.
# ---------------------------------------------------------------
function Resolve-DomainCredential {
    <#
        Order of precedence:
          1. -CredentialMap entry for this domain
          2. -Credential passed on the command line
          3. interactive prompt, prefilled with the target's Username if
             $env:ADAUDIT_TARGETS provided one
    #>
    param([string]$Dom, [string]$Server, [switch]$Interactive)

    if ($CredentialMap.ContainsKey($Dom)) { return $CredentialMap[$Dom] }
    if ($Credential) { return $Credential }
    if (-not $Interactive) { return $null }

    $hint = "$($Targets[$Dom].Username)"
    $msg = "Credentials for $Dom ($Server)"
    if ($hint) { return Get-Credential -Message $msg -UserName $hint }
    return Get-Credential -Message $msg
}

# ---------------------------------------------------------------
# TrustedHosts
#
# Without a trust, a workstation in the management domain cannot obtain a
# Kerberos ticket for an untrusted domain. NTLM still works, but WinRM
# refuses NTLM unless the target is listed in TrustedHosts. Listing a host
# means the client stops verifying the server identity for that name, so
# keep the list to specific names and never use a wildcard.
# ---------------------------------------------------------------
function Test-IsElevated {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    return (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Initialize-WinRmClient {
    <#
        The WSMan: provider talks to the local WinRM service, so nothing can
        be read or written while that service is stopped. This is only the
        CLIENT side: no listener is created and no firewall rule is opened,
        unlike what "winrm quickconfig" would do.
    #>
    $svc = Get-Service WinRM -ErrorAction SilentlyContinue
    if (-not $svc) {
        Write-Host "  the WinRM service is not present on this machine" -ForegroundColor Red
        return $false
    }
    if ($svc.Status -eq 'Running') { return $true }

    if (-not (Test-IsElevated)) {
        Write-Host "  the WinRM service is stopped and starting it needs an elevated console:" -ForegroundColor Yellow
        Write-Host "    Start-Service WinRM" -ForegroundColor Yellow
        return $false
    }

    try {
        Start-Service WinRM -ErrorAction Stop
        Write-Host "  started the local WinRM service (client side only)" -ForegroundColor DarkGray
        Start-Sleep -Milliseconds 500
        return $true
    }
    catch {
        Write-Host "  could not start WinRM: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

function Get-TrustedHostList {
    if (-not (Initialize-WinRmClient)) { return $null }
    try { return (Get-Item WSMan:\localhost\Client\TrustedHosts -ErrorAction Stop).Value }
    catch {
        Write-Verbose "TrustedHosts unreadable: $($_.Exception.Message)"
        return $null
    }
}

function Add-TrustedHostEntry {
    param([string[]]$HostNames)

    if (-not (Initialize-WinRmClient)) {
        Write-Host "  cannot manage TrustedHosts without the WinRM service. Run as admin:" -ForegroundColor Yellow
        Write-Host "    Start-Service WinRM" -ForegroundColor Yellow
        Write-Host "    Set-Item WSMan:\localhost\Client\TrustedHosts -Value '$($HostNames -join ',')' -Concatenate -Force" -ForegroundColor Yellow
        return $false
    }

    $current = Get-TrustedHostList
    $have = @()
    if ($current) { $have = @($current -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }) }

    $missing = @($HostNames | Where-Object { $have -notcontains $_ })
    if (-not $missing.Count) {
        Write-Host "  TrustedHosts already covers: $($HostNames -join ', ')" -ForegroundColor DarkGray
        return $true
    }

    if (-not (Test-IsElevated)) {
        Write-Host "  TrustedHosts needs an elevated console. Run once as administrator:" -ForegroundColor Yellow
        Write-Host "    Set-Item WSMan:\localhost\Client\TrustedHosts -Value '$($missing -join ',')' -Concatenate -Force" -ForegroundColor Yellow
        return $false
    }

    try {
        Set-Item WSMan:\localhost\Client\TrustedHosts -Value ($missing -join ',') -Concatenate -Force -ErrorAction Stop
    }
    catch {
        Write-Host "  could not update TrustedHosts: $(($_.Exception.Message -split "`n")[0])" -ForegroundColor Red
        return $false
    }

    # Confirm rather than assume: a silent failure here shows up much later
    # as an authentication error against a completely unrelated domain.
    $after = Get-TrustedHostList
    $now = @()
    if ($after) { $now = @($after -split ',' | ForEach-Object { $_.Trim() }) }
    $stillMissing = @($HostNames | Where-Object { $now -notcontains $_ })

    if ($stillMissing.Count) {
        Write-Host "  TrustedHosts did not take these entries: $($stillMissing -join ', ')" -ForegroundColor Red
        Write-Host "  Current value: $after" -ForegroundColor DarkGray
        Write-Host "  A group policy may be enforcing the list. Check:" -ForegroundColor Yellow
        Write-Host "    Get-Item WSMan:\localhost\Client\TrustedHosts | Select Value, SourceOfValue" -ForegroundColor Yellow
        return $false
    }

    Write-Host "  TrustedHosts extended with: $($missing -join ', ')" -ForegroundColor Green
    return $true
}

function New-TargetSession {
    <#
        Opens a PSSession, retrying with a different authentication method
        when Kerberos fails. A workstation joined to another domain cannot
        get a Kerberos ticket for the target, but Negotiate falls back to
        NTLM and usually succeeds.
    #>
    param(
        [string]$Server,
        [System.Management.Automation.PSCredential]$Cred,
        [string]$Method = 'Negotiate'
    )

    $attempts = @($Method)
    foreach ($fallback in 'Negotiate', 'Default', 'Kerberos') {
        if ($attempts -notcontains $fallback) { $attempts += $fallback }
    }
    # Basic is deliberately absent: without HTTPS it sends the password in
    # clear text, and its failure message about unencrypted traffic used to
    # mask the real reason reported by the earlier attempts.
    Write-Verbose "auth order: $($attempts -join ', ')"

    $lastError = $null
    $thisError = $null
    foreach ($auth in $attempts) {
        try {
            $sp = @{ ComputerName = $Server; ErrorAction = 'Stop' }
            if ($Cred) {
                $sp['Credential'] = $Cred
                # Authentication cannot be specified without a credential
                if ($auth -ne 'Default') { $sp['Authentication'] = $auth }
            }
            $session = New-PSSession @sp
            if ($auth -ne $attempts[0]) {
                Write-Host "  connected using $auth" -ForegroundColor DarkGray
            }
            return $session
        }
        catch {
            # the first failure explains the cause; later ones are noise
            if (-not $lastError) { $lastError = $_.Exception.Message }
            $thisError = $_.Exception.Message
            # Do not pattern-match the message body: the Kerberos failure text
            # lists "the user name or password specified are invalid" merely as
            # one of its possible causes, which used to abort the fallback loop
            # on the very first attempt. Match the actual status codes instead.
            #   0x8009030C  logon failure, wrong credentials
            #   0x80090308  account restriction
            #   0x80090353  account locked out
            if ($thisError -match '0x8009030C|0x80090308|0x80090353') { $lastError = $thisError; break }
            if ($thisError -match 'Access is denied' -and $auth -ne 'Kerberos') { $lastError = $thisError; break }
        }
    }

    Write-Verbose "session failed: $lastError"
    $script:LastSessionError = $lastError
    return $null
}

function Test-SessionAlive {
    param($Session)
    if (-not $Session) { return $false }
    return ($Session.State -eq 'Opened' -and $Session.Availability -eq 'Available')
}

function Invoke-WithSession {
    <#
        Runs a script block in the session, reopening it when the link drops.
        The VPN to some controllers loses packets, and a broken session used
        to abort every remaining toolkit for that domain.
    #>
    param(
        [ref]$SessionRef,
        [string]$Server,
        [System.Management.Automation.PSCredential]$Cred,
        [string]$Method,
        [scriptblock]$Script,
        [object[]]$ArgumentList = @(),
        [int]$Retries = 2
    )

    for ($try = 1; $try -le ($Retries + 1); $try++) {
        if (-not (Test-SessionAlive $SessionRef.Value)) {
            if ($SessionRef.Value) {
                Write-Host "    session lost, reconnecting..." -ForegroundColor DarkYellow
                Remove-PSSession $SessionRef.Value -ErrorAction SilentlyContinue
            }
            $SessionRef.Value = New-TargetSession -Server $Server -Cred $Cred -Method $Method
            if (-not $SessionRef.Value) { throw "could not reopen the session to $Server" }
        }
        try {
            return Invoke-Command -Session $SessionRef.Value -ScriptBlock $Script -ArgumentList $ArgumentList -ErrorAction Stop
        }
        catch {
            $msg = $_.Exception.Message
            $recoverable = $msg -match 'session state|Broken|interrupted|command ID|not equal to Open|cannot be used'
            if (-not $recoverable -or $try -gt $Retries) { throw }
            Write-Host "    retry $try after: $(($msg -split "`n")[0])" -ForegroundColor DarkYellow
            Remove-PSSession $SessionRef.Value -ErrorAction SilentlyContinue
            $SessionRef.Value = $null
            Start-Sleep -Seconds (3 * $try)
        }
    }
}

# ---------------------------------------------------------------
# Targets come from $env:ADAUDIT_TARGETS, shared with deploy.ps1 and
# Fix-NlaDependency.ps1. Trusted = $false marks the domains with no trust
# to the management domain: Kerberos cannot work there, so those hosts need
# NTLM and an entry in TrustedHosts.
# ---------------------------------------------------------------
$targetsModule = Join-Path $here 'AuditTargets.psm1'
if (-not (Test-Path $targetsModule)) {
    throw "AuditTargets.psm1 not found next to this script."
}
Import-Module $targetsModule -Force -DisableNameChecking

$Targets = Get-AuditTargets
Write-Host "Targets: $($Targets.Count) domain(s) from `$env:ADAUDIT_TARGETS" -ForegroundColor DarkGray

if ($List) {
    Show-AuditTargets -Targets $Targets
    return
}

$selected = if ($All) { @($Targets.Keys) } else { @($Domain) }
foreach ($dom in $selected) {
    if (-not $Targets.Contains($dom)) {
        throw "Unknown domain '$dom'. Run .\run-remote.ps1 -list to see the table."
    }
}

$toolkits = if ($Only -contains 'all') { @('gpo', 'adhealth', 'adsecurity') } else { $Only }
$today = (Get-Date).ToString('yyyy-MM-dd')

Write-Host ""
Write-Host "Toolkits: $($toolkits -join ', ')" -ForegroundColor Cyan
Write-Host ("Analysis: " + $(if ($AnalyzeOnServer) { 'on the controller (no history there, so no comparison)' } else { 'here, comparing with the previous run' })) -ForegroundColor Cyan
Write-Host "Results:  $LocalRoot" -ForegroundColor Cyan

$results = New-Object System.Collections.Generic.List[object]
$reportData = New-Object System.Collections.Generic.List[object]

# ---------------------------------------------------------------
# TrustedHosts for the domains with no trust
# ---------------------------------------------------------------
$trustedHostsBefore = Get-TrustedHostList
$needNtlm = @()
foreach ($dom in $selected) {
    if ($Targets[$dom].Trusted -eq $false) {
        $needNtlm += $Targets[$dom].Server
        if ($Targets[$dom].Extra) { $needNtlm += $Targets[$dom].Extra }
    }
}
$needNtlm = @($needNtlm | Sort-Object -Unique)

if ($needNtlm.Count) {
    Write-Host ""
    Write-Host "No trust with: $(@($selected | Where-Object { $Targets[$_].Trusted -eq $false }) -join ', ')" -ForegroundColor DarkYellow
    Write-Host "These need NTLM, which WinRM allows only for TrustedHosts entries." -ForegroundColor DarkYellow
    if ($EnsureTrustedHosts) {
        if (-not (Add-TrustedHostEntry -HostNames $needNtlm)) {
            Write-Host "TrustedHosts could not be prepared - the untrusted domains will fail." -ForegroundColor Red
        }
    }
    else {
        $have = @()
        if ($trustedHostsBefore) { $have = @($trustedHostsBefore -split ',' | ForEach-Object { $_.Trim() }) }
        $missing = @($needNtlm | Where-Object { $have -notcontains $_ })
        if ($missing.Count) {
            Write-Host "Not listed yet: $($missing -join ', ')" -ForegroundColor DarkYellow
            Write-Host "Add them with -ensuretrustedhosts from an elevated console," -ForegroundColor DarkYellow
            Write-Host "or once by hand:" -ForegroundColor DarkYellow
            Write-Host "  Set-Item WSMan:\localhost\Client\TrustedHosts -Value '$($missing -join ',')' -Concatenate -Force" -ForegroundColor DarkYellow
        }
    }
}

# Reading the registry of a second host from inside a WinRM session needs
# credential delegation, which is off by default. The hardening section of
# Export-AdSecurity therefore sees only the controller it runs on. This is
# expected, not a fault: the note below stops it looking like one.
Write-Host ""
Write-Host "Note: host hardening is read only for the controller each toolkit runs on." -ForegroundColor DarkGray
Write-Host "      Other controllers and the CA report 'unauthorized' - that is credential" -ForegroundColor DarkGray
Write-Host "      delegation, not a permissions problem. Run the toolkit on those hosts" -ForegroundColor DarkGray
Write-Host "      directly to cover them." -ForegroundColor DarkGray

foreach ($dom in $selected) {
    $server = $Targets[$dom].Server
    $trusted = ($Targets[$dom].Trusted -ne $false)
    Write-Host ""
    Write-Host ("--- $dom  ->  $server " + ('-' * [Math]::Max(0, 28 - $dom.Length))) -ForegroundColor Cyan
    if (-not $trusted) { Write-Host "  no trust with the management domain, using NTLM" -ForegroundColor DarkGray }

    # map -> command line -> interactive prompt (username prefilled from
    # $env:ADAUDIT_TARGETS if it had one). Nothing is ever stored.
    $cred = Resolve-DomainCredential -Dom $dom -Server $server -Interactive

    $status = 'ok'
    $detail = ''
    $script:LastSessionError = $null

    # Check the port first: a closed 5985 is a firewall or a network profile
    # problem, not a credential one, and the message should say so.
    $portOpen = Test-NetConnection $server -Port 5985 -InformationLevel Quiet -WarningAction SilentlyContinue
    if (-not $portOpen) {
        Write-Host "  port 5985 is closed" -ForegroundColor Red
        Write-Host "  On the controller check the network profile - a DC showing Public" -ForegroundColor DarkYellow
        Write-Host "  only accepts WinRM from its own subnet:" -ForegroundColor DarkYellow
        Write-Host "    Get-NetConnectionProfile" -ForegroundColor DarkYellow
        Write-Host "    Restart-Service NlaSvc -Force" -ForegroundColor DarkYellow
        $results.Add([PSCustomObject]@{ Domain = $dom; Server = $server; Status = 'port closed'; Files = 0; Detail = 'WinRM 5985 unreachable' })
        continue
    }

    $session = New-TargetSession -Server $server -Cred $cred -Method $Authentication

    if (-not $session -and $PromptOnDenied) {
        Write-Host "  refused: $script:LastSessionError" -ForegroundColor DarkYellow
        Write-Host "  trying again with a different credential" -ForegroundColor DarkYellow
        $hint = "$($Targets[$dom].Username)"
        $msg = "Credentials for $dom ($server)"
        $cred = if ($hint) { Get-Credential -Message $msg -UserName $hint } else { Get-Credential -Message $msg }
        if ($cred) { $session = New-TargetSession -Server $server -Cred $cred -Method $Authentication }
    }

    if (-not $session) {
        Write-Host "  no session established" -ForegroundColor Red
        if ($script:LastSessionError) {
            Write-Host "  $(($script:LastSessionError -split "`n")[0])" -ForegroundColor DarkGray
        }
        if ("$script:LastSessionError" -match '0x80090311') {
            if (-not $trusted) {
                Write-Host "  Expected: there is no trust with $dom, so Kerberos cannot work." -ForegroundColor DarkYellow
                Write-Host "  NTLM needs this host in TrustedHosts. From an elevated console:" -ForegroundColor DarkYellow
                Write-Host "    Set-Item WSMan:\localhost\Client\TrustedHosts -Value '$server' -Concatenate -Force" -ForegroundColor DarkYellow
                Write-Host "  or rerun with -ensuretrustedhosts as administrator." -ForegroundColor DarkYellow
            }
            else {
                Write-Host "  Kerberos found no KDC although a trust is expected. Verify it:" -ForegroundColor DarkYellow
                Write-Host "    nltest /domain_trusts /all_trusts /v" -ForegroundColor DarkYellow
                Write-Host "    Resolve-DnsName -Type SRV _kerberos._tcp.$dom" -ForegroundColor DarkYellow
            }
        }
        else {
            Write-Host "  try again with -promptondenied, or check the username/password" -ForegroundColor DarkYellow
        }
        $results.Add([PSCustomObject]@{
                Domain = $dom; Server = $server; Status = 'no session'; Files = 0
                Detail = if ($script:LastSessionError) { ($script:LastSessionError -split "`n")[0] } else { '' }
            })
        continue
    }

    try {
        $remoteRoot = Join-Path $RemoteWork $dom

        $collectionLog = @()

        foreach ($kit in $toolkits) {
            Write-Host "    collecting $kit..." -ForegroundColor DarkGray
            $sw = [System.Diagnostics.Stopwatch]::StartNew()

            $out = Invoke-WithSession -SessionRef ([ref]$session) -Server $server -Cred $cred -Method $Authentication `
                -ArgumentList @($RemoteScripts, $kit, $dom, $server, $remoteRoot, (-not $AnalyzeOnServer)) -Script {
                param($scripts, $kit, $dom, $srv, $root, $skipAnalyze)
                Set-Location $scripts
                $wrapper = ".\run-$kit.ps1"
                if (-not (Test-Path $wrapper)) { throw "$wrapper not found on the controller - deploy first" }

                # Write-Host on the remote side goes to the information
                # stream, which WinRM forwards straight to the caller console
                # and never returns as data. Redirecting stream 6 into the
                # pipeline turns it into a value we can filter here instead
                # of watching it scroll past.
                # 6>&1 folds the information stream (Write-Host) into the
                # pipeline, 3>&1 the warnings. Without both, WinRM forwards
                # them straight to the caller console and no filtering here
                # can ever apply.
                if ($skipAnalyze) {
                    $log = & $wrapper -Domain $dom -Server $srv -Root $root -SkipAnalyze 6>&1 3>&1
                }
                else {
                    $log = & $wrapper -Domain $dom -Server $srv -Root $root 6>&1 3>&1
                }

                $log | ForEach-Object {
                    if ($_ -is [System.Management.Automation.WarningRecord]) { "WARNING: $($_.Message)" }
                    elseif ($_ -is [System.Management.Automation.ErrorRecord]) { "ERROR: $($_.Exception.Message)" }
                    else { "$_" }
                }
            }

            $sw.Stop()

            # Keep the full log for the report, show only the meaningful
            # lines here: counts, warnings and anything that failed.
            $collectionLog += @($out | ForEach-Object { "$_" })

            $notable = @($out | Where-Object {
                    "$_" -match 'COLLECTION INCOMPLETE|WARNING|FAILED|error|denied|not found|UNHANDLED'
                })
            foreach ($n in ($notable | Select-Object -First 8)) {
                Write-Host "      $n" -ForegroundColor DarkYellow
            }
            if ($notable.Count -gt 8) {
                Write-Host "      ... and $($notable.Count - 8) more, see the report" -ForegroundColor DarkYellow
            }

            Write-Host ("    {0} done in {1:N0}s" -f $kit, $sw.Elapsed.TotalSeconds) -ForegroundColor DarkGray
        }

        # ---------------------------------------------------------------
        # Bring the results home as ONE archive.
        #
        # Copying thirty files one by one meant thirty round trips over a
        # link that already loses packets, which took minutes per domain.
        # The controller packs everything into a single zip, that zip comes
        # back in one transfer, and it is unpacked locally.
        # ---------------------------------------------------------------
        $localDir = Join-Path (Join-Path $LocalRoot $dom) $today
        New-Item -ItemType Directory -Path $localDir -Force | Out-Null

        $archiveName = "$dom-$today-audit.zip"

        $pack = Invoke-WithSession -SessionRef ([ref]$session) -Server $server -Cred $cred -Method $Authentication `
            -ArgumentList @($remoteRoot, $archiveName) -Script {
            param($root, $name)

            $files = Get-ChildItem $root -Recurse -Filter *.csv -File -ErrorAction SilentlyContinue
            if (-not $files) { return [PSCustomObject]@{ Count = 0; Path = $null; Size = 0 } }

            # keep the archive outside the folder being compressed
            $zip = Join-Path $env:TEMP $name
            if (Test-Path $zip) { Remove-Item $zip -Force }
            Compress-Archive -Path $files.FullName -DestinationPath $zip -Force

            [PSCustomObject]@{
                Count = $files.Count
                Path  = $zip
                Size  = (Get-Item $zip).Length
            }
        }

        $copied = 0
        if (-not $pack -or $pack.Count -eq 0) {
            Write-Host "  nothing to collect" -ForegroundColor Yellow
            $detail = 'no files'
        }
        else {
            $kb = [math]::Round($pack.Size / 1KB, 1)
            Write-Host "  packed $($pack.Count) file(s) into $kb KB, transferring..." -ForegroundColor DarkGray

            $localZip = Join-Path $localDir $archiveName
            $got = $false

            # For a small archive the fastest route is straight through the
            # session as base64: one call, no separate file transfer channel.
            if ($pack.Size -lt 20MB) {
                try {
                    $b64 = Invoke-WithSession -SessionRef ([ref]$session) -Server $server -Cred $cred -Method $Authentication `
                        -ArgumentList @($pack.Path) -Script {
                        param($zip)
                        [Convert]::ToBase64String([IO.File]::ReadAllBytes($zip))
                    }
                    [IO.File]::WriteAllBytes($localZip, [Convert]::FromBase64String($b64))
                    $got = $true
                }
                catch {
                    Write-Host "    inline transfer failed, falling back to Copy-Item" -ForegroundColor DarkYellow
                }
            }

            if (-not $got) {
                for ($attempt = 1; $attempt -le 3 -and -not $got; $attempt++) {
                    try {
                        if (-not (Test-SessionAlive $session)) {
                            Remove-PSSession $session -ErrorAction SilentlyContinue
                            $session = New-TargetSession -Server $server -Cred $cred -Method $Authentication
                            if (-not $session) { break }
                        }
                        Copy-Item -FromSession $session -Path $pack.Path -Destination $localZip -Force -ErrorAction Stop
                        $got = $true
                    }
                    catch {
                        if ($attempt -eq 3) { Write-Warning "    could not transfer the archive: $(($_.Exception.Message -split "`n")[0])" }
                        else { Start-Sleep -Seconds 3 }
                    }
                }
            }

            if ($got) {
                try {
                    Expand-Archive -Path $localZip -DestinationPath $localDir -Force
                    $copied = @(Get-ChildItem $localDir -Filter *.csv -File).Count
                    Remove-Item $localZip -Force -ErrorAction SilentlyContinue
                    Write-Host "  collected $copied file(s) into $localDir" -ForegroundColor Green
                    $detail = "$copied files"

                    # ---------------------------------------------------
                    # Analyse here, where the history of previous runs is.
                    # ---------------------------------------------------
                    if ($AnalyzeOnServer) {
                        # nothing was captured, but the collection log is
                        # still worth putting in the report
                        $reportData.Add([PSCustomObject]@{
                                Domain       = $dom
                                DataPath     = $localDir
                                BaselinePath = $null
                                Sections     = @()
                            })
                    }
                    else {
                        # Baseline for the comparison: the previous dated
                        # folder for this domain, still on disk - folders
                        # are never deleted, so this always exists once a
                        # domain has been collected more than once.
                        $prevDir = Get-ChildItem (Join-Path $LocalRoot $dom) -Directory -ErrorAction SilentlyContinue |
                        Where-Object { $_.Name -match '^\d{4}-\d{2}-\d{2}$' -and $_.Name -ne $today } |
                        Sort-Object Name -Descending | Select-Object -First 1

                        $compareDir = $null
                        if ($prevDir) {
                            $compareDir = $prevDir.FullName
                            Write-Host "  comparing against $($prevDir.Name)" -ForegroundColor DarkGray
                        }
                        else { Write-Host "  no earlier run to compare with" -ForegroundColor DarkGray }

                        # Analyzer output is captured rather than printed:
                        # three reports across six domains is unreadable in a
                        # console. It all lands in the HTML report instead.
                        $sections = New-Object System.Collections.Generic.List[object]

                        $kits = @(
                            @{ Script = 'Analyze-GpoMap'; Name = 'Group Policy'; Probe = "$dom-gpo.csv" }
                            @{ Script = 'Analyze-AdHealth'; Name = 'AD Health'; Probe = "$dom-dcs.csv" }
                            @{ Script = 'Analyze-AdSecurity'; Name = 'AD Security'; Probe = "$dom-protection.csv" }
                        )

                        foreach ($kit in $kits) {
                            $anPath = Join-Path $here "$($kit.Script).ps1"
                            if (-not (Test-Path $anPath)) { continue }
                            if (-not (Test-Path (Join-Path $localDir $kit.Probe))) { continue }

                            $anArgs = @{ Path = $localDir; Domain = $dom }
                            if ($compareDir) { $anArgs['ComparePath'] = $compareDir }

                            Write-Host "    analysing $($kit.Name)..." -NoNewline -ForegroundColor DarkGray

                            if ($script:CanReport) {
                                $cap = Invoke-CapturedScript -Path $anPath -Arguments $anArgs
                                $sections.Add([PSCustomObject]@{
                                        Name     = $kit.Name
                                        Lines    = $cap.Lines
                                        Warnings = $cap.Warnings
                                        Error    = $cap.Error
                                    })

                                if ($cap.Error) {
                                    Write-Host " failed: $(($cap.Error -split "`n")[0])" -ForegroundColor Red
                                }
                                elseif ($cap.Count -eq 0) {
                                    Write-Host " no output captured" -ForegroundColor Yellow
                                }
                                else {
                                    $w = if ($cap.Warnings.Count) { ", $($cap.Warnings.Count) warning(s)" } else { '' }
                                    Write-Host " ok ($($cap.Count) lines$w)" -ForegroundColor Green
                                }
                            }
                            else {
                                try { & $anPath @anArgs | Out-Null; Write-Host " ok" -ForegroundColor Green }
                                catch { Write-Host " failed: $($_.Exception.Message)" -ForegroundColor Red }
                            }
                        }

                        # summarise on one line instead of dumping the reports
                        $sevCount = @{ high = 0; medium = 0; low = 0 }
                        foreach ($ff in @("$dom-findings.csv", "$dom-adhealth-findings.csv", "$dom-adsecurity-findings.csv")) {
                            $ffp = Join-Path $localDir $ff
                            if (-not (Test-Path $ffp)) { continue }
                            try {
                                foreach ($r in (Import-Csv $ffp)) {
                                    $k = "$($r.Severity)".ToLower()
                                    if ($sevCount.ContainsKey($k)) { $sevCount[$k]++ }
                                }
                            }
                            catch { }
                        }
                        $sevLine = "  findings: $($sevCount.high) high, $($sevCount.medium) medium, $($sevCount.low) low"
                        $sevColour = if ($sevCount.high -gt 0) { 'Red' } elseif ($sevCount.medium -gt 0) { 'Yellow' } else { 'Green' }
                        Write-Host $sevLine -ForegroundColor $sevColour

                        # the collection log is worth keeping too: it is the
                        # only place errors from the controller show up
                        if ($collectionLog.Count) {
                            $collLines = foreach ($cl in $collectionLog) {
                                $colour = 'Gray'
                                if ("$cl" -match 'WARNING|FAILED|error|denied|INCOMPLETE') { $colour = 'Yellow' }
                                elseif ("$cl" -match 'COLLECTION COMPLETE|Archive:') { $colour = 'Green' }
                                elseif ("$cl" -match '^\s*\[\d+/\d+\]') { $colour = 'Cyan' }
                                , @([PSCustomObject]@{ Text = "$cl"; Color = $colour })
                            }
                            $collWarn = @($collectionLog | Where-Object { "$_" -match '^WARNING: ' } |
                                ForEach-Object { "$_" -replace '^WARNING: ', '' })
                            $sections.Add([PSCustomObject]@{
                                    Name     = 'Collection log'
                                    Lines    = @($collLines)
                                    Warnings = $collWarn
                                    Error    = $null
                                })
                        }

                        # No database: the dated CSV folder just collected
                        # IS the persistent record, kept on disk forever as
                        # the baseline for the next run.
                        $reportData.Add([PSCustomObject]@{
                                Domain       = $dom
                                DataPath     = $localDir
                                BaselinePath = $(if ($prevDir) { $prevDir.FullName } else { $null })
                                Sections     = @($sections.ToArray())
                            })
                    }
                }
                catch {
                    Write-Host "  archive arrived but could not be unpacked: $($_.Exception.Message)" -ForegroundColor Red
                    Write-Host "  it is still here: $localZip" -ForegroundColor DarkYellow
                    $detail = 'archive not unpacked'
                    $status = 'partial'
                }
            }
            else {
                $detail = 'transfer failed'
                $status = 'partial'
            }
        }

        # ---------------------------------------------------------------
        # Clean up: the working folder, the archive in TEMP and the zips the
        # wrappers built. Nothing about the domain should stay on the host.
        # ---------------------------------------------------------------
        if (-not $KeepRemote) {
            try {
                $left = Invoke-WithSession -SessionRef ([ref]$session) -Server $server -Cred $cred -Method $Authentication `
                    -ArgumentList @($remoteRoot, $archiveName) -Script {
                    param($root, $name)
                    Remove-Item $root -Recurse -Force -ErrorAction SilentlyContinue
                    Remove-Item (Join-Path $env:TEMP $name) -Force -ErrorAction SilentlyContinue

                    # drop the parent folder too once the last domain is gone
                    $parent = Split-Path $root -Parent
                    if ((Test-Path $parent) -and -not (Get-ChildItem $parent -Force)) {
                        Remove-Item $parent -Force -ErrorAction SilentlyContinue
                    }

                    @(Get-ChildItem $root -Recurse -Force -ErrorAction SilentlyContinue).Count
                }
                if ($left) { Write-Host "  $left item(s) still on the controller" -ForegroundColor DarkYellow }
                else { Write-Host "  controller cleaned" -ForegroundColor DarkGray }
            }
            catch { Write-Warning "  could not clean up $remoteRoot on the controller" }
        }

        $results.Add([PSCustomObject]@{ Domain = $dom; Server = $server; Status = $status; Files = $copied; Detail = $detail })
    }
    catch {
        Write-Host "  $($_.Exception.Message)" -ForegroundColor Red
        $results.Add([PSCustomObject]@{ Domain = $dom; Server = $server; Status = 'failed'; Files = 0; Detail = $_.Exception.Message })
    }
    finally {
        if ($session) { Remove-PSSession $session -ErrorAction SilentlyContinue }
    }
}

if ($RestoreTrustedHosts) {
    if (Test-IsElevated) {
        try {
            if ($trustedHostsBefore) {
                Set-Item WSMan:\localhost\Client\TrustedHosts -Value $trustedHostsBefore -Force
            }
            else {
                Clear-Item WSMan:\localhost\Client\TrustedHosts -Force
            }
            Write-Host ""
            Write-Host "TrustedHosts restored to its previous value" -ForegroundColor DarkGray
        }
        catch { Write-Warning "Could not restore TrustedHosts: $($_.Exception.Message)" }
    }
    else { Write-Warning "TrustedHosts not restored: needs an elevated console" }
}

Write-Host ""
Write-Host ("=" * 60) -ForegroundColor Cyan
$results | Format-Table Domain, Server, Status, Files, Detail -AutoSize

$failed = @($results | Where-Object { $_.Status -ne 'ok' })
if ($failed.Count) {
    Write-Host "$($failed.Count) of $($results.Count) target(s) failed" -ForegroundColor Red
}
else {
    Write-Host "All $($results.Count) target(s) collected" -ForegroundColor Green
}

# Older versions of AuditCapture replaced Write-Host with a global proxy.
# If one is still installed from a previous session, drop it.
if (Test-Path function:global:Write-Host) {
    Remove-Item function:global:Write-Host -Force -ErrorAction SilentlyContinue
}

# ---------------------------------------------------------------
# HTML report
# ---------------------------------------------------------------
if (-not $NoReport -and $script:CanReport -and $reportData.Count) {
    if (-not $ReportPath) {
        $ReportPath = Join-Path $LocalRoot ("audit-report-$today.html")
    }
    try {
        $rep = New-AuditHtmlReport -Report @($reportData.ToArray()) -Path $ReportPath `
            -Title "Active Directory audit - $today" -Open:$OpenReport

        Write-Host ""
        Write-Host "Report: $($rep.Path)" -ForegroundColor Green
        $warnBit = ''
        if ($rep.PSObject.Properties.Name -contains 'Warnings' -and $rep.Warnings) {
            $warnBit = ", $($rep.Warnings) warning(s)"
        }
        Write-Host ("  $($rep.Domains) domain(s), $($rep.High) high, $($rep.Medium) medium, $($rep.Low) low$warnBit, $($rep.SizeKb) KB") -ForegroundColor DarkGray
        if ($rep.PSObject.Properties.Name -contains 'New' -and ($rep.New -or $rep.Resolved)) {
            $moveColour = if ($rep.New -gt 0) { 'Yellow' } else { 'Green' }
            Write-Host ("  since the previous run: $($rep.New) new, $($rep.Resolved) resolved") -ForegroundColor $moveColour
        }
        if (-not $OpenReport) { Write-Host "  open with: ii '$($rep.Path)'" -ForegroundColor DarkGray }
    }
    catch { Write-Warning "Could not build the report: $($_.Exception.Message)" }
}

Write-Host ""
Write-Host "Raw data and per-domain analysis:" -ForegroundColor DarkGray
Write-Host "  .\Analyze-GpoMap.ps1      -Path $LocalRoot\<domain>\$today" -ForegroundColor DarkGray
Write-Host "  .\Analyze-AdHealth.ps1    -Path $LocalRoot\<domain>\$today" -ForegroundColor DarkGray
Write-Host "  .\Analyze-AdSecurity.ps1  -Path $LocalRoot\<domain>\$today" -ForegroundColor DarkGray
Write-Host ""
