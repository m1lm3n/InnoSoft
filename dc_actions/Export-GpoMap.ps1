<#
    Export-GpoMap.ps1

    Exports a GPO map for a domain: OU structure, policy links,
    WMI filters and an inventory of the policies themselves.

    Notes:
      - Does NOT require WinRM (no Invoke-Command)
      - Does NOT require the ActiveDirectory module (OUs are read via ADSI)
      - Works from a window started with runas /netonly

    Usage:
        .\Export-GpoMap.ps1
        .\Export-GpoMap.ps1 -Domain kkk.lo -Server dc-iiii.kkk.lo
#>

[CmdletBinding()]
param(
    [string]$Domain = 'nnn.lo',
    [string]$Server = 'dc-nnn.nnn.lo',
    [string]$OutDir = 'C:\gpo-export'
)

$ErrorActionPreference = 'Stop'
$sw = [System.Diagnostics.Stopwatch]::StartNew()
Import-Module GroupPolicy
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null

Write-Host "`n=== $Domain via $Server ===" -ForegroundColor Cyan

# ---------------------------------------------------------------
# Helper: directory search via ADSI
# ---------------------------------------------------------------
function Search-Directory {
    param(
        [string]$Base,
        [string]$Filter,
        [string[]]$Properties
    )
    $s = New-Object System.DirectoryServices.DirectorySearcher
    $s.SearchRoot = [ADSI]"LDAP://$Server/$Base"
    $s.Filter = $Filter
    $s.PageSize = 1000
    foreach ($p in $Properties) { [void]$s.PropertiesToLoad.Add($p) }
    $s.FindAll()
}

function Get-Prop {
    param($Result, [string]$Name)
    if ($Result.Properties[$Name].Count) { $Result.Properties[$Name][0] } else { $null }
}

$script:StepMarks = New-Object System.Collections.Generic.List[object]
function Write-Step {
    param([string]$Label)
    $script:StepMarks.Add([PSCustomObject]@{ Label = $Label; At = $sw.Elapsed })
    Write-Host ("`n{0}  [{1:mm\:ss}]" -f $Label, $sw.Elapsed) -ForegroundColor Yellow
}

# ---------------------------------------------------------------
# 1. Domain root
# ---------------------------------------------------------------
$rootDse = [ADSI]"LDAP://$Server/RootDSE"
$baseDn = $rootDse.defaultNamingContext[0]
Write-Host "Base DN: $baseDn"

# ---------------------------------------------------------------
# 2. OU structure
# ---------------------------------------------------------------
Write-Step "[1/5] OU structure..."

$ouResults = Search-Directory -Base $baseDn `
    -Filter '(objectClass=organizationalUnit)' `
    -Properties 'distinguishedname', 'name', 'description', 'gpoptions'

$ous = foreach ($r in $ouResults) {
    [PSCustomObject]@{
        DistinguishedName = Get-Prop $r 'distinguishedname'
        Name              = Get-Prop $r 'name'
        Description       = Get-Prop $r 'description'
        InheritBlocked    = ((Get-Prop $r 'gpoptions') -eq 1)
        Depth             = ([regex]::Matches((Get-Prop $r 'distinguishedname'), 'OU=')).Count
    }
}

$ous = $ous | Sort-Object DistinguishedName
$ous | Export-Csv (Join-Path $OutDir "$Domain-ou.csv") -NoTypeInformation -Encoding UTF8
Write-Host "  OUs found: $(@($ous).Count)"

# ---------------------------------------------------------------
# 3. Policy links: domain root + every OU
# ---------------------------------------------------------------
Write-Step "[2/5] Policy links..."

$targets = @($baseDn) + @($ous.DistinguishedName)
$links = New-Object System.Collections.Generic.List[object]
$i = 0

foreach ($t in $targets) {
    $i++
    Write-Progress -Activity 'Reading links' -Status $t -PercentComplete ($i * 100 / $targets.Count)
    try {
        $inh = Get-GPInheritance -Target $t -Domain $Domain -Server $Server
        foreach ($l in $inh.GpoLinks) {
            $links.Add([PSCustomObject]@{
                    Target         = $t
                    InheritBlocked = $inh.GpoInheritanceBlocked
                    Order          = $l.Order
                    DisplayName    = $l.DisplayName
                    Enabled        = $l.Enabled
                    Enforced       = $l.Enforced
                    GpoId          = $l.GpoId
                })
        }
    }
    catch {
        Write-Warning "$t : $($_.Exception.Message)"
    }
}
Write-Progress -Activity 'Reading links' -Completed

$links | Export-Csv (Join-Path $OutDir "$Domain-links.csv") -NoTypeInformation -Encoding UTF8
Write-Host "  links found: $($links.Count)"

# ---------------------------------------------------------------
# 4. WMI filters
# ---------------------------------------------------------------
Write-Step "[3/5] WMI filters..."

try {
    $wmiResults = Search-Directory -Base "CN=SOM,CN=WMIPolicy,CN=System,$baseDn" `
        -Filter '(objectClass=msWMI-Som)' `
        -Properties 'mswmi-name', 'mswmi-parm2'

    $wmi = foreach ($r in $wmiResults) {
        [PSCustomObject]@{
            Name  = Get-Prop $r 'mswmi-name'
            Query = Get-Prop $r 'mswmi-parm2'
        }
    }
    $wmi | Export-Csv (Join-Path $OutDir "$Domain-wmi.csv") -NoTypeInformation -Encoding UTF8
    Write-Host "  filters found: $(@($wmi).Count)"
}
catch {
    Write-Warning "WMI filters: $($_.Exception.Message)"
}

# ---------------------------------------------------------------
# 5. GPO inventory
# ---------------------------------------------------------------
Write-Step "[4/5] GPO inventory..."

$gpos = Get-GPO -All -Domain $Domain -Server $Server |
Select-Object DisplayName, Id, GpoStatus, CreationTime, ModificationTime,
@{N = 'Owner'; E = { $_.Owner } },
@{N = 'UserVersionAD'; E = { $_.User.DSVersion } },
@{N = 'UserVersionSysvol'; E = { $_.User.SysvolVersion } },
@{N = 'ComputerVersionAD'; E = { $_.Computer.DSVersion } },
@{N = 'ComputerVersionSysvol'; E = { $_.Computer.SysvolVersion } },
@{N = 'WmiFilter'; E = { $_.WmiFilter.Name } }

$gpos | Export-Csv (Join-Path $OutDir "$Domain-gpo.csv") -NoTypeInformation -Encoding UTF8
Write-Host "  policies found: $(@($gpos).Count)"

# ---------------------------------------------------------------
# 6. Summary
# ---------------------------------------------------------------
$linkedIds = $links.GpoId | Sort-Object -Unique
$orphans = $gpos | Where-Object { $_.Id -notin $linkedIds }
$empty = $gpos | Where-Object { $_.UserVersionAD -eq 0 -and $_.ComputerVersionAD -eq 0 }
$mismatch = $gpos | Where-Object {
    $_.UserVersionAD -ne $_.UserVersionSysvol -or
    $_.ComputerVersionAD -ne $_.ComputerVersionSysvol
}

Write-Host "`n--- Summary ---" -ForegroundColor Cyan
Write-Host "Total policies:           $(@($gpos).Count)"
Write-Host "Not linked anywhere:      $(@($orphans).Count)"
Write-Host "Empty (both versions 0):  $(@($empty).Count)"
Write-Host "AD / SYSVOL mismatch:     $(@($mismatch).Count)"

if ($orphans) {
    Write-Host "`nNot linked:" -ForegroundColor DarkYellow
    $orphans  | ForEach-Object { "  $($_.DisplayName)" }
}
if ($empty) {
    Write-Host "`nEmpty:" -ForegroundColor DarkYellow
    $empty    | ForEach-Object { "  $($_.DisplayName)" }
}
if ($mismatch) {
    Write-Host "`nVersion mismatch (SYSVOL replication problem):" -ForegroundColor Red
    $mismatch | ForEach-Object { "  $($_.DisplayName)" }
}

# ---------------------------------------------------------------
# 7. Security filtering (who actually gets each policy)
# ---------------------------------------------------------------
Write-Step "[5/5] Security filtering..."

$AUTH_USERS_SID = 'S-1-5-11'   # Authenticated Users
$DOM_COMPUTERS = '-515'       # Domain Computers (RID suffix)

$perms = New-Object System.Collections.Generic.List[object]
$j = 0

foreach ($g in $gpos) {
    $j++
    Write-Progress -Activity 'Reading permissions' -Status $g.DisplayName -PercentComplete ($j * 100 / @($gpos).Count)
    try {
        Get-GPPermission -Guid $g.Id -Domain $Domain -Server $Server -All | ForEach-Object {
            $perms.Add([PSCustomObject]@{
                    Gpo        = $g.DisplayName
                    GpoId      = $g.Id
                    Trustee    = $_.Trustee.Name
                    TrusteeSid = $_.Trustee.Sid.Value
                    SidType    = $_.Trustee.SidType
                    Permission = $_.Permission
                    Inherited  = $_.Inherited
                    Applies    = ($_.Permission -match 'Apply')
                })
        }
    }
    catch {
        Write-Warning "$($g.DisplayName) : $($_.Exception.Message)"
    }
}
Write-Progress -Activity 'Reading permissions' -Completed

$perms | Export-Csv (Join-Path $OutDir "$Domain-filtering.csv") -NoTypeInformation -Encoding UTF8
Write-Host "  permission entries: $($perms.Count)"

# --- filtering analysis ---
$byGpo = $perms | Group-Object Gpo

# Map policy name -> whether it carries any User-side settings.
# MS16-072 only affects the User half: computer policies are already
# retrieved in the computer's own security context.
$hasUserSide = @{}
foreach ($g in $gpos) {
    $hasUserSide[$g.DisplayName] = ([int]$g.UserVersionAD -gt 0)
}

# a) policies nobody can apply
$noApply = $byGpo | Where-Object { -not ($_.Group | Where-Object Applies) }

# b) policies filtered to specific groups (Authenticated Users lost Apply)
$groupFiltered = $byGpo | Where-Object {
    $applying = $_.Group | Where-Object Applies
    $applying -and -not ($applying | Where-Object { $_.TrusteeSid -eq $AUTH_USERS_SID })
}

# c) MS16-072: no Read for Authenticated Users / Domain Computers
#    AND the policy actually has User-side settings
$noRead = $byGpo | Where-Object {
    -not ($_.Group | Where-Object {
            $_.TrusteeSid -eq $AUTH_USERS_SID -or $_.TrusteeSid -like "*$DOM_COMPUTERS"
        })
}
$ms16072 = $noRead | Where-Object { $hasUserSide[$_.Name] }
$noReadCompOnly = $noRead | Where-Object { -not $hasUserSide[$_.Name] }

Write-Host "`n--- Filtering ---" -ForegroundColor Cyan
Write-Host "Filtered to specific groups:  $(@($groupFiltered).Count)"
Write-Host "Nobody can apply:             $(@($noApply).Count)"
Write-Host "MS16-072 risk (User side):    $(@($ms16072).Count)"
Write-Host "No Read, computer-only (ok):  $(@($noReadCompOnly).Count)"

if ($groupFiltered) {
    Write-Host "`nGroup-filtered policies:" -ForegroundColor DarkYellow
    foreach ($x in $groupFiltered) {
        $who = ($x.Group | Where-Object Applies | Select-Object -Expand Trustee) -join ', '
        $side = if ($hasUserSide[$x.Name]) { 'User+PC' } else { 'PC only' }
        Write-Host ("  {0,-8} {1}  ->  {2}" -f $side, $x.Name, $who)
    }
}
if ($noApply) {
    Write-Host "`nNo Apply permission for anyone (policy is inert):" -ForegroundColor DarkYellow
    $noApply | ForEach-Object { "  $($_.Name)" }
}
if ($ms16072) {
    Write-Host "`nMS16-072 RISK - policy has User-side settings but neither" -ForegroundColor Red
    Write-Host "Authenticated Users nor Domain Computers can read it." -ForegroundColor Red
    Write-Host "Since MS16-072 the User half is fetched in the COMPUTER context," -ForegroundColor Red
    Write-Host "so it silently fails even for users in the right group." -ForegroundColor Red
    Write-Host "Fix: grant Authenticated Users the Read permission WITHOUT Apply." -ForegroundColor Red
    foreach ($x in $ms16072) {
        $who = ($x.Group | Where-Object Applies | Select-Object -Expand Trustee) -join ', '
        Write-Host ("  {0}  ->  {1}" -f $x.Name, $who)
    }
}
if ($noReadCompOnly) {
    Write-Host "`nNo Read for Authenticated Users, but computer-side only - not affected" -ForegroundColor DarkGray
    Write-Host "by MS16-072. Verify the target group holds computer accounts:" -ForegroundColor DarkGray
    foreach ($x in $noReadCompOnly) {
        $who = ($x.Group | Where-Object Applies | Select-Object -Expand Trustee) -join ', '
        Write-Host ("  {0}  ->  {1}" -f $x.Name, $who) -ForegroundColor DarkGray
    }
}

# --- machine-readable summary of the filtering analysis ---
$analysis = foreach ($x in $byGpo) {
    $applying = $x.Group | Where-Object Applies
    [PSCustomObject]@{
        Gpo             = $x.Name
        AppliesTo       = ($applying | Select-Object -Expand Trustee) -join '; '
        HasUserSettings = [bool]$hasUserSide[$x.Name]
        AuthUsersApply  = [bool]($applying | Where-Object { $_.TrusteeSid -eq $AUTH_USERS_SID })
        AuthUsersRead   = [bool]($x.Group  | Where-Object { $_.TrusteeSid -eq $AUTH_USERS_SID })
        DomCompRead     = [bool]($x.Group  | Where-Object { $_.TrusteeSid -like "*$DOM_COMPUTERS" })
        Ms16072Risk     = [bool](($ms16072 | Select-Object -Expand Name) -contains $x.Name)
    }
}
$analysis | Sort-Object Gpo |
Export-Csv (Join-Path $OutDir "$Domain-filtering-analysis.csv") -NoTypeInformation -Encoding UTF8

# ---------------------------------------------------------------
# 8. Archive
# ---------------------------------------------------------------
$zip = "C:\gpo-map-$Domain.zip"
Compress-Archive -Path (Join-Path $OutDir '*.csv') -DestinationPath $zip -Force
Write-Host "`nDone. Archive: $zip" -ForegroundColor Green

$sw.Stop()

Write-Host "`n--- Timing ---" -ForegroundColor Cyan
for ($k = 0; $k -lt $script:StepMarks.Count; $k++) {
    $from = $script:StepMarks[$k].At
    $to = if ($k + 1 -lt $script:StepMarks.Count) { $script:StepMarks[$k + 1].At } else { $sw.Elapsed }
    Write-Host ("  {0,-30} {1:mm\:ss}" -f $script:StepMarks[$k].Label, ($to - $from))
}
Write-Host ("  {0,-30} {1:hh\:mm\:ss}" -f 'TOTAL', $sw.Elapsed) -ForegroundColor Green