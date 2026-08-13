<#
    run-remote.ps1

    Runs the audit toolkit on each domain controller over WinRM and copies
    the results back. Far faster than driving the collectors over the
    network from a workstation: everything the scripts read is local to the
    controller, so a domain finishes in seconds instead of an hour.

    Targets come from the same table as deploy.ps1 - keep them in step.

    Usage:
        .\run-remote.ps1                       # default domain
        .\run-remote.ps1 -domain kkk.lo
        .\run-remote.ps1 -all
        .\run-remote.ps1 -all -only gpo        # one toolkit across every domain
        .\run-remote.ps1 -all -promptondenied
        .\run-remote.ps1 -list

    Results land in <LocalRoot>\<domain>\<date>\ on this machine.
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

    # Leave the working folder on the controller
    [switch]$KeepRemote
)

$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------
# Target table - mirror of the one in deploy.ps1
# ---------------------------------------------------------------
$Targets = [ordered]@{
    'nnn.lo'     = @{ Server = 'dc-nnn.nnn.lo'; Note = 'users: reten, conversion, sales' }
    'kkk.lo'     = @{ Server = 'dc-kkk.kkk.lo'; Note = 'scouts, operators - admin Anton' }
    'xxx.lo'     = @{ Server = 'dc-xxx.xxx.lo'; Note = 'admin Silver' }
    'ttt.lo'     = @{ Server = 'dc-ttt.ttt.lo'; Note = 'single DC, fault tolerant' }
    'a.lo'       = @{ Server = 'dc.a.lo'; Note = 'auth for OnlyOffice and Nextcloud' }
    'core64.com' = @{ Server = 'dc-dc1.core64.com'; Note = 'management domain' }
}

if ($List) {
    Write-Host ""
    Write-Host "Targets:" -ForegroundColor Cyan
    foreach ($k in $Targets.Keys) {
        Write-Host ("  {0,-12} {1,-24} {2}" -f $k, $Targets[$k].Server, $Targets[$k].Note)
    }
    Write-Host ""
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
Write-Host "Results:  $LocalRoot" -ForegroundColor Cyan

$results = New-Object System.Collections.Generic.List[object]

foreach ($dom in $selected) {
    $server = $Targets[$dom].Server
    Write-Host ""
    Write-Host ("--- $dom  ->  $server " + ('-' * [Math]::Max(0, 28 - $dom.Length))) -ForegroundColor Cyan

    $cred = $null
    if ($CredentialMap.ContainsKey($dom)) { $cred = $CredentialMap[$dom] }
    elseif ($Credential) { $cred = $Credential }

    $session = $null
    $status = 'ok'
    $detail = ''

    try {
        $sessionArgs = @{ ComputerName = $server; ErrorAction = 'Stop' }
        if ($cred) { $sessionArgs['Credential'] = $cred }
        $session = New-PSSession @sessionArgs
    }
    catch {
        if ($PromptOnDenied -and -not $cred) {
            Write-Host "  connection refused, asking for credentials" -ForegroundColor DarkYellow
            try {
                $cred = Get-Credential -Message "Credentials for $dom ($server)"
                $session = New-PSSession -ComputerName $server -Credential $cred -ErrorAction Stop
            }
            catch { $session = $null }
        }
    }

    if (-not $session) {
        Write-Host "  no WinRM session. Check the service and the firewall:" -ForegroundColor Red
        Write-Host "    Test-WSMan -ComputerName $server" -ForegroundColor DarkYellow
        $results.Add([PSCustomObject]@{ Domain = $dom; Server = $server; Status = 'no session'; Files = 0; Detail = '' })
        continue
    }

    try {
        $remoteRoot = Join-Path $RemoteWork $dom

        foreach ($kit in $toolkits) {
            Write-Host "  running $kit..." -ForegroundColor Yellow
            $sw = [System.Diagnostics.Stopwatch]::StartNew()

            $out = Invoke-Command -Session $session -ArgumentList $RemoteScripts, $kit, $dom, $server, $remoteRoot -ScriptBlock {
                param($scripts, $kit, $dom, $srv, $root)
                Set-Location $scripts
                $wrapper = ".\run-$kit.ps1"
                if (-not (Test-Path $wrapper)) { throw "$wrapper not found on the controller - deploy first" }
                & $wrapper -Domain $dom -Server $srv -Root $root
            }

            $sw.Stop()
            # keep only the lines worth seeing from here
            $out | Where-Object {
                "$_" -match 'COLLECTION|high|medium|RISK|DENY|WARNING|Error|Archive'
            } | Select-Object -First 20 | ForEach-Object {
                Write-Host "    $_" -ForegroundColor DarkGray
            }
            Write-Host ("    done in {0:N0}s" -f $sw.Elapsed.TotalSeconds) -ForegroundColor DarkGray
        }

        # bring the CSVs home
        $localDir = Join-Path (Join-Path $LocalRoot $dom) $today
        New-Item -ItemType Directory -Path $localDir -Force | Out-Null

        $remoteFiles = Invoke-Command -Session $session -ArgumentList $remoteRoot -ScriptBlock {
            param($root)
            Get-ChildItem $root -Recurse -Filter *.csv -File -ErrorAction SilentlyContinue |
                Select-Object -Expand FullName
        }

        $copied = 0
        foreach ($f in $remoteFiles) {
            try {
                Copy-Item -FromSession $session -Path $f -Destination $localDir -Force
                $copied++
            }
            catch { Write-Warning "    could not copy $f : $($_.Exception.Message)" }
        }

        Write-Host "  collected $copied file(s) into $localDir" -ForegroundColor Green
        $detail = "$copied files"

        if (-not $KeepRemote) {
            Invoke-Command -Session $session -ArgumentList $remoteRoot -ScriptBlock {
                param($root)
                Remove-Item $root -Recurse -Force -ErrorAction SilentlyContinue
            }
            Write-Host "  working folder removed from the controller" -ForegroundColor DarkGray
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

Write-Host ""
Write-Host "Analyse locally, no domain access needed:" -ForegroundColor DarkGray
Write-Host "  .\Analyze-GpoMap.ps1      -Path $LocalRoot\<domain>\$today" -ForegroundColor DarkGray
Write-Host "  .\Analyze-AdHealth.ps1    -Path $LocalRoot\<domain>\$today" -ForegroundColor DarkGray
Write-Host "  .\Analyze-AdSecurity.ps1  -Path $LocalRoot\<domain>\$today" -ForegroundColor DarkGray
Write-Host ""