<#
    Analyze-AdHealth.ps1  -  ANALYSIS ONLY

    Reads the CSV files produced by Export-AdHealth.ps1 and reports findings.
    Touches no domain controller: safe to run as often as you like.

    Sections:
        0. Data quality
        1. Domain controllers    - count, roles, RODC, stale, OS support
        2. FSMO                  - who holds what, are the holders alive
        3. Replication           - failures, stale partners
        4. Backup                - age of the last AD backup vs tombstone
        5. Sites and subnets     - unmapped subnets, empty sites, defaults
        6. Privileged access     - who is admin, stale and risky accounts
        7. Domain settings       - levels, password policy, krbtgt, recycle bin
        8. Comparison            - optional diff against a previous export

    Usage:
        .\Analyze-AdHealth.ps1 -Path c:\ad-export
        .\Analyze-AdHealth.ps1 -Path c:\ad-export\2026-08-12 -ComparePath c:\ad-export\2026-08-05
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Path,

    [string]$Domain,
    [string]$ComparePath,

    # Thresholds
    [int]$StaleLogonDays = 90,
    [int]$StalePasswordDays = 365,
    [int]$KrbtgtMaxAgeDays = 180,
    [int]$ReplStaleHours = 24,

    [switch]$NoCsv
)

$ErrorActionPreference = 'Stop'
$sw = [System.Diagnostics.Stopwatch]::StartNew()
$startedAt = Get-Date

# Operating systems past or near end of support
$EOL_PATTERNS = @(
    'Windows Server 2003', 'Windows Server 2008', 'Windows Server 2012'
)

function Import-Set {
    param([string]$Folder, [string]$Dom)
    if (-not (Test-Path $Folder)) { throw "Folder not found: $Folder" }
    if (-not $Dom) {
        $any = Get-ChildItem $Folder -Filter '*-dcs.csv' | Select-Object -First 1
        if (-not $any) { throw "No *-dcs.csv found in $Folder" }
        $Dom = $any.BaseName -replace '-dcs$', ''
    }
    $set = @{ Domain = $Dom }
    foreach ($part in 'dcs', 'fsmo', 'replication', 'backup', 'sites', 'subnets',
        'sitelinks', 'privileged', 'domaininfo', 'adhealth-meta') {
        $file = Join-Path $Folder "$Dom-$part.csv"
        if (Test-Path $file) {
            $rows = @(Import-Csv $file)
            # Out-Table writes a single "Empty" column when a section had no data
            if ($rows.Count -eq 0 -or ($rows[0].PSObject.Properties.Name -eq 'Empty')) { $rows = @() }
            $set[$part] = $rows
        }
        else { $set[$part] = @() }
    }
    return $set
}

function Write-Section {
    param([string]$Title)
    Write-Host ""
    Write-Host ("--- $Title " + ('-' * [Math]::Max(0, 48 - $Title.Length))) -ForegroundColor Cyan
}

function Write-Finding {
    param([string]$Text, [string]$Level = 'info')
    $color = switch ($Level) {
        'high' { 'Red' } 'warn' { 'Yellow' } 'ok' { 'Green' } default { 'Gray' }
    }
    Write-Host "  $Text" -ForegroundColor $color
}

$d = Import-Set -Folder $Path -Dom $Domain
$Domain = $d.Domain
$meta = if ($d.'adhealth-meta'.Count) { $d.'adhealth-meta'[0] } else { $null }
$info = if ($d.domaininfo.Count) { $d.domaininfo[0] } else { $null }

Write-Host "`n=== AD health analysis: $Domain ===" -ForegroundColor Cyan
if ($meta) { Write-Host "Collected: $($meta.CollectedAt) from $($meta.Server) by $($meta.CollectedBy)" -ForegroundColor DarkGray }
Write-Host "Source:    $Path" -ForegroundColor DarkGray

$findings = New-Object System.Collections.Generic.List[object]
function Add-Finding {
    param([string]$Area, [string]$Severity, [string]$Item, [string]$Detail)
    $findings.Add([PSCustomObject]@{ Area = $Area; Severity = $Severity; Item = $Item; Detail = $Detail })
}

# ---------------------------------------------------------------
# 0. Data quality
# ---------------------------------------------------------------
Write-Section 'Data quality'
foreach ($part in 'dcs', 'fsmo', 'sites', 'privileged', 'domaininfo') {
    if (-not $d[$part].Count) {
        Write-Finding "$part.csv is empty or missing" 'warn'
        Add-Finding 'DataQuality' 'medium' $part 'file empty or missing'
    }
}
if (-not $d.replication.Count) {
    Write-Finding "No replication data - repadmin was unavailable, run on a DC" 'warn'
}
if ($d.dcs.Count -and $d.replication.Count) { Write-Finding "All expected files present" 'ok' }

# ---------------------------------------------------------------
# 1. Domain controllers
# ---------------------------------------------------------------
Write-Section 'Domain controllers'

$dcs = $d.dcs
$writable = @($dcs | Where-Object { $_.IsRodc -ne 'True' })
$rodcs = @($dcs | Where-Object { $_.IsRodc -eq 'True' })
$gcs = @($dcs | Where-Object { $_.IsGlobalCatalog -eq 'True' })

Write-Finding "Total: $(@($dcs).Count)   writable: $($writable.Count)   RODC: $($rodcs.Count)   GC: $($gcs.Count)"
foreach ($dc in $dcs) {
    $tags = @()
    if ($dc.IsRodc -eq 'True') { $tags += 'RODC' }
    if ($dc.IsGlobalCatalog -eq 'True') { $tags += 'GC' }
    Write-Finding ("    {0,-22} site {1,-24} {2}  {3}" -f $dc.Name, $dc.Site, ($tags -join '+'), $dc.OperatingSystem)
}

if ($writable.Count -eq 1) {
    Write-Finding "SINGLE writable domain controller - no redundancy for this domain" 'high'
    Write-Finding "  A host failure, a bad update or a database corruption takes the" 'high'
    Write-Finding "  whole domain offline. Restore from backup is the only path back." 'high'
    Add-Finding 'Controllers' 'high' $Domain 'only one writable DC in the domain'
}
elseif ($writable.Count -eq 0) {
    Write-Finding "No writable domain controller found - check the collection" 'high'
}

if ($gcs.Count -eq 0) {
    Write-Finding "No global catalog in this domain" 'high'
    Add-Finding 'Controllers' 'high' $Domain 'no global catalog'
}

foreach ($dc in $dcs) {
    foreach ($p in $EOL_PATTERNS) {
        if ($dc.OperatingSystem -like "*$p*") {
            Write-Finding "    $($dc.Name): $($dc.OperatingSystem) is out of support" 'high'
            Add-Finding 'Controllers' 'high' $dc.Name "runs $($dc.OperatingSystem)"
        }
    }
    if ($dc.LastLogon) {
        try {
            $age = [int]((Get-Date) - [datetime]$dc.LastLogon).TotalDays
            if ($age -gt 30) {
                Write-Finding "    $($dc.Name): last logon $age days ago - is it still alive?" 'warn'
                Add-Finding 'Controllers' 'medium' $dc.Name "no logon for $age days"
            }
        }
        catch { }
    }
}

# ---------------------------------------------------------------
# 2. FSMO
# ---------------------------------------------------------------
Write-Section 'FSMO roles'

$dcNames = @($dcs.Name)
foreach ($f in $d.fsmo) {
    $known = $dcNames -contains $f.Holder
    Write-Finding ("    {0,-22} {1}{2}" -f $f.Role, $f.Holder, $(if (-not $known) { '   <-- not in the DC list' } else { '' })) `
    $(if ($known) { 'info' } else { 'high' })
    if (-not $known) { Add-Finding 'FSMO' 'high' $f.Role "holder $($f.Holder) is not a live DC" }
}

$holders = @($d.fsmo | Where-Object { $_.Holder } | Select-Object -Expand Holder -Unique)
if ($holders.Count -eq 1 -and $writable.Count -gt 1) {
    Write-Finding "All FSMO roles sit on one controller: $($holders[0])" 'warn'
    Write-Finding "  Workable, but its loss stops password changes, RID issuance and schema work." 'info'
    Add-Finding 'FSMO' 'medium' $holders[0] 'holds every FSMO role'
}

# ---------------------------------------------------------------
# 3. Replication
# ---------------------------------------------------------------
Write-Section 'Replication'

if ($d.replication.Count) {
    $failing = @($d.replication | Where-Object { [int]$_.Failures -gt 0 })
    Write-Finding "Partner links: $(@($d.replication).Count), failing: $($failing.Count)" `
    $(if ($failing.Count) { 'high' } else { 'ok' })

    foreach ($r in $failing) {
        Write-Finding "    $($r.DestinationDsa) <- $($r.SourceDsa)" 'high'
        Write-Finding "      partition: $($r.NamingContext)" 'high'
        Write-Finding "      failures: $($r.Failures), status: $($r.LastFailureStatus)" 'high'
        Add-Finding 'Replication' 'high' "$($r.DestinationDsa) <- $($r.SourceDsa)" `
            "$($r.Failures) failures, status $($r.LastFailureStatus)"
    }

    $stale = @()
    foreach ($r in $d.replication) {
        if (-not $r.LastSuccessTime) { continue }
        try {
            $t = [datetime]$r.LastSuccessTime
            $hrs = ((Get-Date) - $t).TotalHours
            if ($hrs -gt $ReplStaleHours) {
                $stale += [PSCustomObject]@{ Link = "$($r.DestinationDsa) <- $($r.SourceDsa)"; Hours = [int]$hrs; Nc = $r.NamingContext }
            }
        }
        catch { }
    }
    Write-Finding "Partners with no success in $ReplStaleHours+ hours: $($stale.Count)" `
    $(if ($stale.Count) { 'warn' } else { 'ok' })
    foreach ($s in $stale) {
        Write-Finding "    $($s.Link) - $($s.Hours)h ago  [$($s.Nc)]" 'warn'
        Add-Finding 'Replication' 'medium' $s.Link "no successful replication for $($s.Hours) hours"
    }
}
else { Write-Finding "No data" 'warn' }

# ---------------------------------------------------------------
# 4. Backup age
# ---------------------------------------------------------------
Write-Section 'AD backup'

$tombstone = if ($info -and $info.TombstoneLifetime) { [int]$info.TombstoneLifetime } else { 180 }
if ($d.backup.Count) {
    foreach ($b in $d.backup) {
        $age = $null
        try { $age = [int]((Get-Date) - [datetime]$b.LastBackup).TotalDays } catch { }
        if ($null -ne $age) {
            $lvl = if ($age -gt $tombstone) { 'high' } elseif ($age -gt 7) { 'warn' } else { 'ok' }
            Write-Finding "    $($b.Partition): $age days ago" $lvl
            if ($age -gt $tombstone) {
                Add-Finding 'Backup' 'high' $b.Partition "backup is $age days old, older than the $tombstone-day tombstone lifetime"
            }
            elseif ($age -gt 7) {
                Add-Finding 'Backup' 'medium' $b.Partition "backup is $age days old"
            }
        }
        else { Write-Finding "    $($b.Partition): $($b.LastBackup)" }
    }
    Write-Finding "  Tombstone lifetime is $tombstone days - a backup older than that cannot be restored." 'info'
}
else { Write-Finding "No backup data collected" 'warn' }

# ---------------------------------------------------------------
# 5. Sites and subnets
# ---------------------------------------------------------------
Write-Section 'Sites and subnets'

$sites = $d.sites
$subnets = $d.subnets

Write-Finding "Sites: $(@($sites).Count), subnets: $(@($subnets).Count), site links: $(@($d.sitelinks).Count)"
foreach ($s in $sites) {
    Write-Finding ("    {0,-30} DCs: {1,-3} subnets: {2}" -f $s.Site, $s.DcCount, $s.SubnetCount)
}

if (@($sites).Count -le 1 -and @($subnets).Count -eq 0) {
    Write-Finding "Only the default site exists and no subnets are defined." 'high'
    Write-Finding "  Clients cannot tell which DC is near them, so they authenticate" 'high'
    Write-Finding "  against an arbitrary one. On a network spread across countries this" 'high'
    Write-Finding "  shows up as slow logons that look like a client problem." 'high'
    Add-Finding 'Sites' 'high' $Domain 'no sites or subnets defined, clients pick DCs at random'
}

$noSubnet = @($sites | Where-Object { [int]$_.SubnetCount -eq 0 -and [int]$_.DcCount -gt 0 })
foreach ($s in $noSubnet) {
    Write-Finding "    site '$($s.Site)' has DCs but no subnets mapped to it" 'warn'
    Add-Finding 'Sites' 'medium' $s.Site 'site has no subnets'
}

$noDc = @($sites | Where-Object { [int]$_.DcCount -eq 0 })
foreach ($s in $noDc) {
    Write-Finding "    site '$($s.Site)' has no DC - clients there authenticate over the WAN" 'warn'
    Add-Finding 'Sites' 'medium' $s.Site 'site without a domain controller'
}

$orphanSubnets = @($subnets | Where-Object { -not $_.Site })
foreach ($s in $orphanSubnets) {
    Write-Finding "    subnet $($s.Subnet) is not assigned to any site" 'warn'
    Add-Finding 'Sites' 'medium' $s.Subnet 'subnet not linked to a site'
}

# ---------------------------------------------------------------
# 6. Privileged access
# ---------------------------------------------------------------
Write-Section 'Privileged access'

$priv = $d.privileged
$byGroup = $priv | Group-Object Group
foreach ($g in $byGroup) {
    $users = @($g.Group | Where-Object { $_.Class -eq 'user' })
    Write-Finding ("    {0,-30} {1} member(s)" -f $g.Name, @($g.Group).Count)
    foreach ($m in $g.Group) {
        $flags = @()
        if ($m.Enabled -ne 'True') { $flags += 'disabled' }
        if ($m.PasswordNeverExpires -eq 'True') { $flags += 'pwd never expires' }
        if ($m.PasswordAgeDays -and [int]$m.PasswordAgeDays -gt $StalePasswordDays) { $flags += "pwd $($m.PasswordAgeDays)d old" }
        if ($m.LastLogonDaysAgo -and [int]$m.LastLogonDaysAgo -gt $StaleLogonDays) { $flags += "idle $($m.LastLogonDaysAgo)d" }
        if (-not $m.LastLogon) { $flags += 'never logged on' }
        $note = if ($flags) { '   <-- ' + ($flags -join ', ') } else { '' }
        Write-Finding ("        {0,-24} {1}{2}" -f $m.Member, $m.Class, $note) `
        $(if ($flags) { 'warn' } else { 'info' })
    }
}

$distinct = @($priv | Select-Object -Expand Member -Unique)
Write-Finding "Distinct privileged principals: $($distinct.Count)"
if ($distinct.Count -gt 10) {
    Write-Finding "  That is a lot of standing privilege for one domain." 'warn'
    Add-Finding 'Privileged' 'medium' $Domain "$($distinct.Count) distinct privileged principals"
}

foreach ($m in ($priv | Where-Object { $_.LastLogonDaysAgo -and [int]$_.LastLogonDaysAgo -gt $StaleLogonDays })) {
    Add-Finding 'Privileged' 'high' $m.Member "admin account unused for $($m.LastLogonDaysAgo) days (group: $($m.Group))"
}
foreach ($m in ($priv | Where-Object { $_.PasswordNeverExpires -eq 'True' -and $_.Class -eq 'user' })) {
    Add-Finding 'Privileged' 'medium' $m.Member "privileged account with a non-expiring password (group: $($m.Group))"
}
foreach ($m in ($priv | Where-Object { $_.Enabled -ne 'True' -and $_.Class -eq 'user' })) {
    Add-Finding 'Privileged' 'high' $m.Member "DISABLED account still a member of $($m.Group) - re-enabling it restores full rights"
}
foreach ($m in ($priv | Where-Object { -not $_.LastLogon -and $_.Class -eq 'user' })) {
    Add-Finding 'Privileged' 'high' $m.Member "privileged account that has never logged on (group: $($m.Group))"
}

# Enterprise and Schema Admins should normally be empty outside upgrades
foreach ($gname in @('Enterprise Admins', 'Schema Admins')) {
    $g = $byGroup | Where-Object { $_.Name -eq $gname }
    if ($g -and @($g.Group | Where-Object { $_.Class -eq 'user' }).Count -gt 1) {
        $n = @($g.Group | Where-Object { $_.Class -eq 'user' }).Count
        Write-Finding "'$gname' holds $n user accounts - forest-wide rights are rarely needed day to day" 'high'
        Add-Finding 'Privileged' 'high' $gname "$n standing members in a forest-wide group"
    }
}

$opGroups = @('Account Operators', 'Server Operators', 'Print Operators', 'Backup Operators')
foreach ($g in $byGroup) {
    if ($opGroups -contains $g.Name -and @($g.Group).Count -gt 0) {
        Write-Finding "'$($g.Name)' is populated - these legacy groups grant more than they look like" 'warn'
        Add-Finding 'Privileged' 'medium' $g.Name "$(@($g.Group).Count) members in a legacy operator group"
    }
}

# ---------------------------------------------------------------
# 7. Domain settings
# ---------------------------------------------------------------
Write-Section 'Domain settings'

if ($info) {
    Write-Finding "Domain functional level: $($info.DomainFunctionLevel)   forest: $($info.ForestFunctionLevel)"
    Write-Finding "Recycle Bin enabled: $($info.RecycleBinEnabled)" `
    $(if ($info.RecycleBinEnabled -eq 'True') { 'ok' } else { 'warn' })
    if ($info.RecycleBinEnabled -ne 'True') {
        Write-Finding "  Without it, a deleted OU or user needs an authoritative restore." 'info'
        Add-Finding 'Domain' 'medium' $Domain 'AD Recycle Bin is not enabled'
    }

    Write-Finding "Password policy: min length $($info.MinPasswordLength), history $($info.PasswordHistory), max age $($info.MaxPasswordAgeDays) days"
    Write-Finding "Lockout: threshold $($info.LockoutThreshold), duration $($info.LockoutDurationMin) min"

    if ([int]$info.MinPasswordLength -lt 12) {
        Write-Finding "  Minimum length below 12 characters" 'warn'
        Add-Finding 'Domain' 'medium' $Domain "minimum password length is $($info.MinPasswordLength)"
    }
    if ([int]$info.LockoutThreshold -eq 0) {
        Write-Finding "  No account lockout at all - unlimited password guessing" 'high'
        Add-Finding 'Domain' 'high' $Domain 'account lockout threshold is 0'
    }

    if ($info.KrbtgtPasswordAgeDays) {
        $ka = [int]$info.KrbtgtPasswordAgeDays
        $lvl = if ($ka -gt $KrbtgtMaxAgeDays) { 'warn' } else { 'ok' }
        Write-Finding "krbtgt password age: $ka days (set $($info.KrbtgtPasswordSet))" $lvl
        if ($ka -gt $KrbtgtMaxAgeDays) {
            Write-Finding "  This key signs every Kerberos ticket in the domain." 'info'
            Add-Finding 'Domain' 'medium' 'krbtgt' "password is $ka days old"
        }
    }
}
else { Write-Finding "No domain settings collected" 'warn' }

# ---------------------------------------------------------------
# 8. Comparison
# ---------------------------------------------------------------
if ($ComparePath) {
    Write-Section 'Comparison with previous run'
    $p = Import-Set -Folder $ComparePath -Dom $Domain
    if ($p.'adhealth-meta'.Count) { Write-Finding "Baseline collected: $($p.'adhealth-meta'[0].CollectedAt)" }

    $oldDc = @($p.dcs.Name); $newDc = @($dcs.Name)
    foreach ($x in ($newDc | Where-Object { $oldDc -notcontains $_ })) { Write-Finding "    + DC $x" 'warn' }
    foreach ($x in ($oldDc | Where-Object { $newDc -notcontains $_ })) { Write-Finding "    - DC $x" 'high' }

    $oldPriv = @($p.privileged | ForEach-Object { "$($_.Group)|$($_.Member)" })
    $newPriv = @($priv | ForEach-Object { "$($_.Group)|$($_.Member)" })
    $added = @($newPriv | Where-Object { $oldPriv -notcontains $_ })
    $removed = @($oldPriv | Where-Object { $newPriv -notcontains $_ })
    Write-Finding "Privileged membership added:   $($added.Count)" $(if ($added.Count) { 'high' } else { 'ok' })
    foreach ($x in $added) {
        Write-Finding "    + $x" 'high'
        Add-Finding 'Privileged' 'high' $x 'added to a privileged group since the baseline'
    }
    Write-Finding "Privileged membership removed: $($removed.Count)"
    foreach ($x in $removed) { Write-Finding "    - $x" 'warn' }

    $oldFsmo = @{}
    foreach ($f in $p.fsmo) { $oldFsmo[$f.Role] = $f.Holder }
    foreach ($f in $d.fsmo) {
        if ($oldFsmo.ContainsKey($f.Role) -and $oldFsmo[$f.Role] -ne $f.Holder) {
            Write-Finding "    ~ FSMO $($f.Role): $($oldFsmo[$f.Role]) -> $($f.Holder)" 'warn'
            Add-Finding 'FSMO' 'medium' $f.Role "role moved from $($oldFsmo[$f.Role]) to $($f.Holder)"
        }
    }

    $oldSub = @($p.subnets.Subnet); $newSub = @($subnets.Subnet)
    foreach ($x in ($newSub | Where-Object { $oldSub -notcontains $_ })) { Write-Finding "    + subnet $x" }
    foreach ($x in ($oldSub | Where-Object { $newSub -notcontains $_ })) { Write-Finding "    - subnet $x" 'warn' }
}

# ---------------------------------------------------------------
# Output
# ---------------------------------------------------------------
if (-not $NoCsv -and $findings.Count) {
    $out = Join-Path $Path "$Domain-adhealth-findings.csv"
    $findings | Sort-Object Severity, Area, Item | Export-Csv $out -NoTypeInformation -Encoding UTF8
    Write-Host "`nFindings written to: $out" -ForegroundColor Green
}

$sw.Stop()
Write-Section 'Summary'
foreach ($sev in 'high', 'medium', 'low') {
    $n = @($findings | Where-Object { $_.Severity -eq $sev }).Count
    $lvl = switch ($sev) { 'high' { 'high' } 'medium' { 'warn' } default { 'info' } }
    Write-Finding ("{0,-8} {1}" -f $sev, $n) $lvl
}
Write-Host ""
Write-Host ("  Analyzed at:   " + $startedAt.ToString('yyyy-MM-dd HH:mm:ss'))
Write-Host ("  Total elapsed: " + [math]::Round($sw.Elapsed.TotalSeconds, 2) + " sec") -ForegroundColor Green
Write-Host ""