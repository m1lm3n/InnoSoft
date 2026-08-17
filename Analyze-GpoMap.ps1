<#
    Analyze-GpoMap.ps1  -  ANALYSIS ONLY

    Reads the CSV files produced by Export-GpoMap.ps1 and reports findings.
    Touches no domain controller: safe to run as often as you like.

    Sections:
        0. Data quality     - is the export complete, what cannot be judged
        1. Inventory
        2. Links            - unlinked policies, disabled links, enforced, blocks
        3. Filtering        - group filtering, inert policies, MS16-072 risk
        4. Deny exclusions  - Deny ACEs on Apply Group Policy
        5. Delegation       - who can edit policies besides the usual admins
        6. Hygiene          - orphaned SIDs, empty halves, version mismatch
        7. Comparison       - optional diff against a previous export

    Usage:
        .\Analyze-GpoMap.ps1 -Path C:\gpo-export
        .\Analyze-GpoMap.ps1 -Path C:\gpo-export -Domain kkk.lo
        .\Analyze-GpoMap.ps1 -Path C:\gpo-export\2026-08-11 -ComparePath C:\gpo-export\2026-08-04
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Path,

    [string]$Domain,
    [string]$ComparePath,
    [int]$StaleDays = 180,
    [switch]$NoCsv
)

$ErrorActionPreference = 'Stop'
$sw = [System.Diagnostics.Stopwatch]::StartNew()
$startedAt = Get-Date

$AUTH_USERS_SID = 'S-1-5-11'
$DOM_COMPUTERS_RID = '-515'

$STANDARD_EDITORS = @(
    'Domain Admins', 'Enterprise Admins', 'SYSTEM', 'Administrators',
    'ENTERPRISE DOMAIN CONTROLLERS', 'Group Policy Creator Owners'
)
# RIDs of built-in groups that legitimately hold edit rights
$STANDARD_EDITOR_RIDS = @('-512', '-519', '-520')

# ---------------------------------------------------------------
# Loading
# ---------------------------------------------------------------
function Import-Set {
    param([string]$Folder, [string]$Dom)

    if (-not (Test-Path $Folder)) { throw "Folder not found: $Folder" }

    if (-not $Dom) {
        $anyGpo = Get-ChildItem $Folder -Filter '*-gpo.csv' | Select-Object -First 1
        if (-not $anyGpo) { throw "No *-gpo.csv found in $Folder" }
        $Dom = $anyGpo.BaseName -replace '-gpo$', ''
    }

    $set = @{ Domain = $Dom; Folder = $Folder }
    foreach ($part in 'gpo', 'links', 'ou', 'permissions', 'applyaces', 'groupmembers', 'wmi', 'meta') {
        $file = Join-Path $Folder "$Dom-$part.csv"
        if (Test-Path $file) { $set[$part] = @(Import-Csv $file) } else { $set[$part] = @() }
    }
    if ($set['permissions'].Count -eq 0) {
        $legacy = Join-Path $Folder "$Dom-filtering.csv"
        if (Test-Path $legacy) { $set['permissions'] = @(Import-Csv $legacy) }
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

$gpos = $d.gpo
$links = $d.links | Where-Object DisplayName
$allTargets = $d.links
$perms = $d.permissions
$aces = $d.applyaces
$members = $d.groupmembers
$meta = if ($d.meta.Count) { $d.meta[0] } else { $null }
$domSid = $null
if ($meta -and $meta.PSObject.Properties.Name -contains 'DomainSid') { $domSid = $meta.DomainSid }
if (-not $domSid) {
    # meta.csv missing or older format: the most common S-1-5-21 prefix
    # across all ACLs is this domain
    $pref = $perms |
    Where-Object { $_.TrusteeSid -like 'S-1-5-21-*' } |
    ForEach-Object { ($_.TrusteeSid -split '-')[0..6] -join '-' } |
    Group-Object | Sort-Object Count -Descending
    if ($pref) { $domSid = $pref[0].Name }
}

Write-Host "`n=== GPO analysis: $Domain ===" -ForegroundColor Cyan
if ($meta) {
    Write-Host "Collected: $($meta.CollectedAt) from $($meta.Server) by $($meta.CollectedBy)" -ForegroundColor DarkGray
}
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

$covered = @($perms.Gpo | Sort-Object -Unique)
$noAcl = @($gpos | Where-Object { $covered -notcontains $_.DisplayName })
$dataComplete = ($noAcl.Count -eq 0)

if ($meta -and $meta.PSObject.Properties.Name -contains 'Complete') {
    Write-Finding "Export self-reported complete: $($meta.Complete)" $(if ($meta.Complete -eq 'True') { 'ok' } else { 'high' })
}
if ($dataComplete) {
    Write-Finding "ACL data present for all $(@($gpos).Count) policies" 'ok'
}
else {
    Write-Finding "ACL DATA MISSING for $($noAcl.Count) of $(@($gpos).Count) policies" 'high'
    Write-Finding "Filtering and delegation conclusions below EXCLUDE these:" 'high'
    foreach ($x in $noAcl) { Write-Finding "    $($x.DisplayName)" 'high' }
    Add-Finding 'DataQuality' 'high' 'incomplete export' "$($noAcl.Count) policies without ACL data"
}

if (-not $meta) {
    Write-Finding "meta.csv missing - domain SID derived from the ACL data" 'warn'
}
if (-not $domSid) {
    Write-Finding "Domain SID unknown - orphaned SID detection will be approximate" 'warn'
}
if ($aces.Count -eq 0) {
    Write-Finding "No applyaces.csv - Deny exclusions cannot be analysed" 'warn'
}

# ---------------------------------------------------------------
# 1. Inventory
# ---------------------------------------------------------------
Write-Section 'Inventory'
Write-Finding "Policies:     $(@($gpos).Count)"
Write-Finding "OUs:          $(@($d.ou).Count)"
Write-Finding "Active links: $(@($links).Count)"
Write-Finding "ACL entries:  $(@($perms).Count)"
Write-Finding "Apply ACEs:   $(@($aces).Count)"
Write-Finding "WMI filters:  $(@($d.wmi).Count)"

# ---------------------------------------------------------------
# 2. Links
# ---------------------------------------------------------------
Write-Section 'Links'

$linkedIds = @($links.GpoId | Sort-Object -Unique)
$orphans = $gpos | Where-Object { $linkedIds -notcontains $_.Id }
$disabledLinks = $links | Where-Object { $_.Enabled -eq 'False' }
$enforced = $links | Where-Object { $_.Enforced -eq 'True' }
$blocked = $allTargets | Where-Object { $_.InheritBlocked -eq 'True' } | Select-Object -Expand Target -Unique
$emptyOus = $allTargets | Where-Object { -not $_.DisplayName } | Select-Object -Expand Target -Unique

Write-Finding "Not linked anywhere: $(@($orphans).Count)" $(if (@($orphans).Count) { 'warn' } else { 'ok' })
foreach ($o in $orphans) {
    Write-Finding "    $($o.DisplayName)   (modified $($o.ModificationTime))"
    Add-Finding 'Links' 'low' $o.DisplayName 'not linked to any container'
}

Write-Finding "Disabled links: $(@($disabledLinks).Count)" $(if (@($disabledLinks).Count) { 'warn' } else { 'ok' })
foreach ($l in $disabledLinks) {
    Write-Finding "    $($l.DisplayName)   on $($l.Target)"
    Add-Finding 'Links' 'low' $l.DisplayName "link disabled on $($l.Target)"
}

Write-Finding "Enforced links: $(@($enforced).Count)"
Write-Finding "Inheritance blocked: $(@($blocked).Count)" $(if (@($blocked).Count) { 'warn' } else { 'ok' })
foreach ($b in $blocked) { Write-Finding "    $b" 'warn' }
Write-Finding "Containers with no links: $(@($emptyOus).Count)"

# ---------------------------------------------------------------
# helper: group composition
# ---------------------------------------------------------------
$groupKind = @{}
foreach ($grp in ($members | Group-Object GroupName)) {
    $classes = @($grp.Group | Select-Object -Expand MemberClass -Unique)
    $kind =
    if ($classes -contains 'builtin-not-enumerated') { 'builtin' }
    elseif ($classes -contains 'too-many') { 'large' }
    elseif ($classes -contains 'empty' -and $classes.Count -eq 1) { 'EMPTY' }
    elseif (($classes -contains 'user') -and ($classes -contains 'computer')) { 'mixed' }
    elseif ($classes -contains 'user') { 'users' }
    elseif ($classes -contains 'computer') { 'computers' }
    else { ($classes -join '/') }
    $groupKind[$grp.Name] = $kind
}
function Get-Kind { param([string]$Name) if ($groupKind[$Name]) { $groupKind[$Name] } else { '?' } }

$hasUserSide = @{}
$hasCompSide = @{}
foreach ($g in $gpos) {
    $hasUserSide[$g.DisplayName] = ([int]$g.UserVersionAD -gt 0)
    $hasCompSide[$g.DisplayName] = ([int]$g.ComputerVersionAD -gt 0)
}

# ---------------------------------------------------------------
# 3. Security filtering
# ---------------------------------------------------------------
Write-Section 'Security filtering'

$byGpo = $perms | Group-Object Gpo

$noApply = $byGpo | Where-Object { -not ($_.Group | Where-Object { $_.Applies -eq 'True' }) }
$groupFiltered = $byGpo | Where-Object {
    $ap = $_.Group | Where-Object { $_.Applies -eq 'True' }
    $ap -and -not ($ap | Where-Object { $_.TrusteeSid -eq $AUTH_USERS_SID })
}
$noRead = $byGpo | Where-Object {
    -not ($_.Group | Where-Object {
            $_.TrusteeSid -eq $AUTH_USERS_SID -or $_.TrusteeSid -like "*$DOM_COMPUTERS_RID"
        })
}
# A policy is only at MS16-072 risk if the COMPUTER cannot read it.
# Membership in the Apply group already grants Read, so when that group
# holds computer accounts the machine can fetch the user half itself.
function Test-ComputerCanRead {
    param($GpoGroup)
    $applying = $GpoGroup.Group | Where-Object { $_.Applies -eq 'True' }
    foreach ($a in $applying) {
        $k = Get-Kind $a.Trustee
        if ($k -eq 'computers' -or $k -eq 'mixed') { return $true }
        # Domain Computers and similar built-ins are computer principals
        if ($a.TrusteeSid -like "*$DOM_COMPUTERS_RID") { return $true }
    }
    return $false
}

$riskCandidates = $noRead | Where-Object { $hasUserSide[$_.Name] }
$ms16072 = $riskCandidates | Where-Object { -not (Test-ComputerCanRead $_) }
$coveredByGroup = $riskCandidates | Where-Object { Test-ComputerCanRead $_ }
$noReadCompOnly = $noRead | Where-Object { -not $hasUserSide[$_.Name] }

Write-Finding "Filtered to groups: $(@($groupFiltered).Count)"
foreach ($x in $groupFiltered) {
    $ap = $x.Group | Where-Object { $_.Applies -eq 'True' }
    $who = @($ap.Trustee) -join ', '
    $kinds = (@($ap.Trustee | ForEach-Object { Get-Kind $_ })) -join '/'
    $side = if ($hasUserSide[$x.Name] -and $hasCompSide[$x.Name]) { 'User+PC' }
    elseif ($hasUserSide[$x.Name]) { 'User' } else { 'PC' }
    Write-Finding ("    {0,-8} {1,-45} -> {2}  [{3}]" -f $side, $x.Name, $who, $kinds)
}

if ($noApply) {
    Write-Host ""
    Write-Finding "Inert policies (nobody has Apply): $(@($noApply).Count)" 'warn'
    foreach ($x in $noApply) {
        Write-Finding "    $($x.Name)" 'warn'
        Add-Finding 'Filtering' 'medium' $x.Name 'no Apply permission for any trustee'
    }
}

Write-Host ""
if ($ms16072) {
    Write-Finding "MS16-072 RISK: $(@($ms16072).Count)" 'high'
    Write-Finding "User-side settings exist, but neither Authenticated Users nor" 'high'
    Write-Finding "Domain Computers can read the policy. Since MS16-072 the user half" 'high'
    Write-Finding "is fetched in the COMPUTER context, so it silently fails to apply." 'high'
    Write-Finding "Fix: grant Authenticated Users Read WITHOUT Apply." 'high'
    foreach ($x in $ms16072) {
        $ap = $x.Group | Where-Object { $_.Applies -eq 'True' }
        $who = @($ap.Trustee) -join ', '
        $kinds = (@($ap.Trustee | ForEach-Object { Get-Kind $_ })) -join '/'
        $sev = if ($kinds -match 'user|mixed') { 'CONFIRMED' } else { 'check' }
        Write-Finding "    [$sev] $($x.Name)  ->  $who  [$kinds]" 'high'
        Add-Finding 'Filtering' 'high' $x.Name "MS16-072 ($sev): applies to $who [$kinds]"
    }
}
else { Write-Finding "MS16-072 risk: none" 'ok' }

if ($coveredByGroup) {
    Write-Host ""
    Write-Finding "No Read for Authenticated Users, but the Apply group holds computers"
    Write-Finding "so the machine can read the policy itself - not at risk:"
    foreach ($x in $coveredByGroup) {
        $ap = $x.Group | Where-Object { $_.Applies -eq 'True' }
        $who = @($ap.Trustee) -join ', '
        $kinds = (@($ap.Trustee | ForEach-Object { Get-Kind $_ })) -join '/'
        Write-Finding "    $($x.Name) -> $who [$kinds]"
    }
}

if ($noReadCompOnly) {
    Write-Host ""
    Write-Finding "No Read for Authenticated Users, computer-side only (not MS16-072):"
    foreach ($x in $noReadCompOnly) {
        $ap = $x.Group | Where-Object { $_.Applies -eq 'True' }
        $who = @($ap.Trustee) -join ', '
        $kind = (@($ap.Trustee | ForEach-Object { Get-Kind $_ })) -join '/'
        $flag = if ($kind -match 'users') { '  <-- group holds USERS, will not apply' } else { '' }
        Write-Finding "    $($x.Name) -> $who [$kind]$flag" $(if ($flag) { 'warn' } else { 'info' })
        if ($flag) { Add-Finding 'Filtering' 'high' $x.Name "computer policy applied to a user group: $who" }
    }
}

$emptyGroups = $groupKind.GetEnumerator() | Where-Object { $_.Value -eq 'EMPTY' }
if ($emptyGroups) {
    Write-Host ""
    Write-Finding "Filter groups with no members: $(@($emptyGroups).Count)" 'warn'
    foreach ($e in $emptyGroups) {
        Write-Finding "    $($e.Key)" 'warn'
        Add-Finding 'Filtering' 'medium' $e.Key 'filter group is empty'
    }
}

# ---------------------------------------------------------------
# 4. Deny exclusions
# ---------------------------------------------------------------
Write-Section 'Deny exclusions'

if ($aces.Count -eq 0) {
    Write-Finding "applyaces.csv not present - rerun Export-GpoMap.ps1" 'warn'
}
else {
    $denies = $aces | Where-Object { $_.AceType -eq 'Deny' }
    Write-Finding "Deny ACEs on Apply Group Policy: $(@($denies).Count)" $(if (@($denies).Count) { 'warn' } else { 'ok' })

    foreach ($grp in ($denies | Group-Object Trustee)) {
        $kind = Get-Kind $grp.Name
        $n = @($members | Where-Object { $_.GroupName -eq $grp.Name -and $_.MemberDn }).Count
        Write-Finding "  $($grp.Name)  [$kind, $n members]  denies:" 'warn'
        foreach ($x in $grp.Group) {
            $side = if ($hasUserSide[$x.Gpo] -and $hasCompSide[$x.Gpo]) { 'User+PC' }
            elseif ($hasUserSide[$x.Gpo]) { 'User' } else { 'PC' }
            Write-Finding ("      {0,-8} {1}" -f $side, $x.Gpo)
            Add-Finding 'DenyExclusion' 'low' $x.Gpo "Deny Apply for $($grp.Name) [$kind]"
        }

        # a user-only group denying a computer-side policy does nothing
        $compOnly = @($grp.Group | Where-Object { -not $hasUserSide[$_.Gpo] })
        if ($kind -eq 'users' -and $compOnly.Count) {
            Write-Finding "      NOTE: group holds users, but these policies are computer-side." 'high'
            Write-Finding "      The Deny has no effect - the exclusion is not working." 'high'
            foreach ($x in $compOnly) {
                Add-Finding 'DenyExclusion' 'high' $x.Gpo "Deny by user group $($grp.Name) has no effect on a computer policy"
            }
        }
        if ($kind -eq 'EMPTY') {
            Write-Finding "      NOTE: group is empty, the exclusion currently covers nobody." 'warn'
        }
    }

    # policies where a Deny exists but the group is not resolvable
    $unresolvedDeny = $denies | Where-Object { -not $_.Trustee }
    if ($unresolvedDeny) {
        Write-Finding "Deny ACEs with unresolved trustee: $(@($unresolvedDeny).Count)" 'warn'
        foreach ($x in $unresolvedDeny) { Write-Finding "    $($x.Gpo)  SID $($x.TrusteeSid)" 'warn' }
    }
}

# ---------------------------------------------------------------
# 5. Delegation
# ---------------------------------------------------------------
Write-Section 'Delegation'

function Test-StandardEditor {
    param($Row)
    if ($STANDARD_EDITORS -contains $Row.Trustee) { return $true }
    foreach ($rid in $STANDARD_EDITOR_RIDS) {
        if ($domSid -and $Row.TrusteeSid -eq "$domSid$rid") { return $true }
    }
    return $false
}

$editors = $perms |
Where-Object { $_.Permission -match 'Edit' -and -not (Test-StandardEditor $_) } |
Group-Object TrusteeSid

if ($editors) {
    Write-Finding "Non-standard trustees with edit rights: $(@($editors).Count)" 'warn'
    foreach ($e in $editors) {
        $name = @($e.Group.Trustee | Where-Object { $_ })[0]
        if (-not $name) { $name = "(unresolved) $($e.Name)" }
        $n = @($e.Group).Count
        Write-Finding "    $name  on $n policies" 'warn'
        Add-Finding 'Delegation' 'medium' $name "can edit $n policies"
    }
}
else { Write-Finding "Only standard admin groups can edit policies" 'ok' }

# ---------------------------------------------------------------
# 6. Hygiene
# ---------------------------------------------------------------
Write-Section 'Hygiene'

$unresolvedRows = $perms | Where-Object { -not $_.Trustee -or $_.Trustee -match '^S-1-' }
$foreign = @()
$localUnresolved = @()
foreach ($u in $unresolvedRows) {
    if ($domSid -and $u.TrusteeSid -like "$domSid*") { $localUnresolved += $u } else { $foreign += $u }
}

Write-Finding "ACE trustees from OTHER domains or truly orphaned: $(@($foreign).Count)" $(if (@($foreign).Count) { 'warn' } else { 'ok' })
foreach ($u in ($foreign | Select-Object Gpo, TrusteeSid -Unique)) {
    Write-Finding "    $($u.Gpo): $($u.TrusteeSid)" 'warn'
    Add-Finding 'Hygiene' 'medium' $u.Gpo "SID outside this domain in ACL: $($u.TrusteeSid)"
}

if ($localUnresolved.Count) {
    Write-Finding "Own-domain SIDs that did not resolve at collection time: $(@($localUnresolved).Count)" 'warn'
    Write-Finding "  These are NOT orphaned - the collector could not translate them." 'info'
    Write-Finding "  Rerun the export from a fresh runas /netonly window." 'info'
    Add-Finding 'DataQuality' 'low' 'name resolution' "$(@($localUnresolved).Count) own-domain SIDs unresolved"
}

# Users sitting in a group that only ever gates computer-side policies
# do nothing at all, but they make the group look like it excludes people.
$compOnlyGroups = @{}
foreach ($row in ($perms | Where-Object { $_.Applies -eq 'True' })) {
    if (-not $hasUserSide[$row.Gpo]) {
        if (-not $compOnlyGroups.ContainsKey($row.Trustee)) { $compOnlyGroups[$row.Trustee] = $true }
    }
    else { $compOnlyGroups[$row.Trustee] = $false }
}
foreach ($row in $aces) {
    if (-not $hasUserSide[$row.Gpo]) {
        if (-not $compOnlyGroups.ContainsKey($row.Trustee)) { $compOnlyGroups[$row.Trustee] = $true }
    }
    else { $compOnlyGroups[$row.Trustee] = $false }
}

$strayUsers = $members |
Where-Object { $_.MemberClass -eq 'user' -and $compOnlyGroups[$_.GroupName] -eq $true } |
Group-Object GroupName

Write-Finding "User accounts in computer-only filter groups: $(@($strayUsers).Count) groups" $(if (@($strayUsers).Count) { 'warn' } else { 'ok' })
foreach ($g in $strayUsers) {
    $who = (@($g.Group.MemberName) -join ', ')
    Write-Finding "    $($g.Name): $($g.Group.Count) user(s) - $who" 'warn'
    Write-Finding "      these accounts have no effect; the group only gates computer policies" 'info'
    Add-Finding 'Hygiene' 'medium' $g.Name "$($g.Group.Count) user accounts in a computer-only filter group"
}

$halfCandidates = $gpos | Where-Object {
    ($_.GpoStatus -eq 'AllSettingsEnabled') -and
    (([int]$_.UserVersionAD -eq 0) -or ([int]$_.ComputerVersionAD -eq 0))
}
Write-Finding "Halves that could be disabled: $(@($halfCandidates).Count)"
foreach ($h in $halfCandidates) {
    $side = if ([int]$h.UserVersionAD -eq 0) { 'User' } else { 'Computer' }
    Add-Finding 'Hygiene' 'low' $h.DisplayName "$side side is empty but still processed"
}

$mismatch = $gpos | Where-Object {
    $_.UserVersionAD -ne $_.UserVersionSysvol -or $_.ComputerVersionAD -ne $_.ComputerVersionSysvol
}
Write-Finding "AD / SYSVOL version mismatch: $(@($mismatch).Count)" $(if (@($mismatch).Count) { 'high' } else { 'ok' })
foreach ($x in $mismatch) {
    Write-Finding "    $($x.DisplayName)" 'high'
    Add-Finding 'Hygiene' 'high' $x.DisplayName 'SYSVOL replication problem'
}

$cutoff = (Get-Date).AddDays(-$StaleDays)
$stale = $gpos | Where-Object { try { [datetime]$_.ModificationTime -lt $cutoff } catch { $false } }
Write-Finding "Untouched for $StaleDays+ days: $(@($stale).Count)"
Write-Finding "Policies using a WMI filter: $(@($gpos | Where-Object WmiFilter).Count) of $(@($gpos).Count)"

# ---------------------------------------------------------------
# 7. Comparison
# ---------------------------------------------------------------
if ($ComparePath) {
    Write-Section 'Comparison with previous run'
    $p = Import-Set -Folder $ComparePath -Dom $Domain
    if ($p.meta.Count) { Write-Finding "Baseline collected: $($p.meta[0].CollectedAt)" }

    $oldNames = @($p.gpo.DisplayName); $newNames = @($gpos.DisplayName)
    $added = $newNames | Where-Object { $oldNames -notcontains $_ }
    $removed = $oldNames | Where-Object { $newNames -notcontains $_ }
    Write-Finding "Policies added:   $(@($added).Count)"
    foreach ($a in $added) { Write-Finding "    + $a" 'warn' }
    Write-Finding "Policies removed: $(@($removed).Count)"
    foreach ($r in $removed) { Write-Finding "    - $r" 'warn' }

    $oldVer = @{}
    foreach ($g in $p.gpo) { $oldVer[$g.DisplayName] = "$($g.UserVersionAD)/$($g.ComputerVersionAD)" }
    $changed = $gpos | Where-Object {
        $oldVer.ContainsKey($_.DisplayName) -and
        $oldVer[$_.DisplayName] -ne "$($_.UserVersionAD)/$($_.ComputerVersionAD)"
    }
    Write-Finding "Contents changed: $(@($changed).Count)"
    foreach ($c in $changed) {
        Write-Finding "    ~ $($c.DisplayName)  $($oldVer[$c.DisplayName]) -> $($c.UserVersionAD)/$($c.ComputerVersionAD)" 'warn'
    }

    # ---- links ----
    $oldLinks = @($p.links | Where-Object DisplayName | ForEach-Object { "$($_.Target)|$($_.DisplayName)" })
    $newLinks = @($links | ForEach-Object { "$($_.Target)|$($_.DisplayName)" })
    $linkAdd = @($newLinks | Where-Object { $oldLinks -notcontains $_ })
    $linkDel = @($oldLinks | Where-Object { $newLinks -notcontains $_ })
    Write-Finding "Links added:   $($linkAdd.Count)"
    foreach ($a in $linkAdd) { Write-Finding "    + $a" 'warn' }
    Write-Finding "Links removed: $($linkDel.Count)"
    foreach ($r in $linkDel) { Write-Finding "    - $r" 'warn' }

    # ---- permissions: EVERY permission level, not just Apply ----
    # A Read grant is invisible in an Apply-only diff, yet it decides
    # whether a user-side policy works at all (MS16-072).
    $oldPerm = @{}
    foreach ($x in $p.permissions) { $oldPerm["$($x.Gpo)|$($x.Trustee)"] = $x.Permission }
    $newPerm = @{}
    foreach ($x in $perms) { $newPerm["$($x.Gpo)|$($x.Trustee)"] = $x.Permission }

    $permAdd = @($newPerm.Keys | Where-Object { -not $oldPerm.ContainsKey($_) })
    $permDel = @($oldPerm.Keys | Where-Object { -not $newPerm.ContainsKey($_) })
    $permMod = @($newPerm.Keys | Where-Object {
            $oldPerm.ContainsKey($_) -and $oldPerm[$_] -ne $newPerm[$_]
        })

    Write-Finding "Permission entries added:   $($permAdd.Count)"
    foreach ($a in $permAdd) {
        $lvl = $newPerm[$a]
        $note = if ($lvl -match 'Apply') { ' <-- now applies' } else { '' }
        Write-Finding "    + $a = $lvl$note" 'warn'
    }
    Write-Finding "Permission entries removed: $($permDel.Count)"
    foreach ($r in $permDel) { Write-Finding "    - $r = $($oldPerm[$r])" 'warn' }
    Write-Finding "Permission levels changed:  $($permMod.Count)"
    foreach ($m in $permMod) {
        Write-Finding "    ~ $m : $($oldPerm[$m]) -> $($newPerm[$m])" 'warn'
    }

    # ---- deny ACEs ----
    if ($p.applyaces.Count -and $aces.Count) {
        $oldDeny = @($p.applyaces | Where-Object { $_.AceType -eq 'Deny' } | ForEach-Object { "$($_.Gpo)|$($_.Trustee)" })
        $newDeny = @($aces | Where-Object { $_.AceType -eq 'Deny' } | ForEach-Object { "$($_.Gpo)|$($_.Trustee)" })
        $denyAdd = @($newDeny | Where-Object { $oldDeny -notcontains $_ })
        $denyDel = @($oldDeny | Where-Object { $newDeny -notcontains $_ })
        Write-Finding "Deny ACEs added:   $($denyAdd.Count)"
        foreach ($a in $denyAdd) { Write-Finding "    + $a" 'warn' }
        Write-Finding "Deny ACEs removed: $($denyDel.Count)"
        foreach ($r in $denyDel) { Write-Finding "    - $r" 'warn' }
    }

    # ---- filter group membership ----
    if ($p.groupmembers.Count -and $members.Count) {
        $oldMem = @($p.groupmembers | Where-Object MemberDn | ForEach-Object { "$($_.GroupName)|$($_.MemberName)" })
        $newMem = @($members | Where-Object MemberDn | ForEach-Object { "$($_.GroupName)|$($_.MemberName)" })
        $memAdd = @($newMem | Where-Object { $oldMem -notcontains $_ })
        $memDel = @($oldMem | Where-Object { $newMem -notcontains $_ })
        if ($memAdd.Count -or $memDel.Count) {
            Write-Finding "Filter group membership changes: $($memAdd.Count + $memDel.Count)"
            foreach ($a in $memAdd) { Write-Finding "    + $a" 'warn' }
            foreach ($r in $memDel) { Write-Finding "    - $r" 'warn' }
        }
        else { Write-Finding "Filter group membership: unchanged" }
    }

    # ---- did any MS16-072 risk appear or clear? ----
    $oldByGpo = $p.permissions | Group-Object Gpo
    $oldUserSide = @{}
    foreach ($g in $p.gpo) { $oldUserSide[$g.DisplayName] = ([int]$g.UserVersionAD -gt 0) }
    $oldRisk = @($oldByGpo | Where-Object {
            $oldUserSide[$_.Name] -and -not ($_.Group | Where-Object {
                    $_.TrusteeSid -eq $AUTH_USERS_SID -or $_.TrusteeSid -like "*$DOM_COMPUTERS_RID"
                })
        } | Select-Object -Expand Name)
    $newRisk = @($ms16072 | Select-Object -Expand Name)
    $cleared = @($oldRisk | Where-Object { $newRisk -notcontains $_ })
    $appeared = @($newRisk | Where-Object { $oldRisk -notcontains $_ })
    if ($cleared) {
        Write-Finding "MS16-072 risk CLEARED since baseline: $($cleared.Count)" 'ok'
        foreach ($c in $cleared) { Write-Finding "    fixed: $c" 'ok' }
    }
    if ($appeared) {
        Write-Finding "MS16-072 risk APPEARED since baseline: $($appeared.Count)" 'high'
        foreach ($a in $appeared) { Write-Finding "    new: $a" 'high' }
        foreach ($a in $appeared) { Add-Finding 'Filtering' 'high' $a 'MS16-072 risk introduced since the baseline run' }
    }
}

# ---------------------------------------------------------------
# Output
# ---------------------------------------------------------------
if (-not $NoCsv -and $findings.Count) {
    $out = Join-Path $Path "$Domain-findings.csv"
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
if (-not $dataComplete) {
    Write-Host ""
    Write-Finding "REMINDER: the export was incomplete, treat the above as partial." 'high'
}
Write-Host ""
Write-Host ("  Analyzed at:   {0:yyyy-MM-dd HH:mm:ss}" -f $startedAt)
Write-Host ("  Total elapsed: {0:N2} sec" -f $sw.Elapsed.TotalSeconds) -ForegroundColor Green
Write-Host ""