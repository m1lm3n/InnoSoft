<#
    Export-GpoMap.ps1  -  COLLECTION ONLY

    Reads GPO data from a domain and writes it to CSV files.
    Does no analysis: run Analyze-GpoMap.ps1 against the output folder.

    Produces:
        <domain>-ou.csv             OU structure
        <domain>-links.csv          GPO links per container
        <domain>-wmi.csv            WMI filters
        <domain>-gpo.csv            GPO inventory
        <domain>-permissions.csv    Get-GPPermission view of every GPO ACL
        <domain>-applyaces.csv      raw Apply-Group-Policy ACEs, Allow AND Deny
        <domain>-groupmembers.csv   members of every group seen in an Apply ACE
        <domain>-meta.csv           run metadata, including completeness flag

    Why applyaces.csv exists:
        Get-GPPermission collapses non-standard ACLs into "GpoCustom" and
        cannot tell Allow from Deny. Exclusion groups are usually implemented
        as a Deny on Apply Group Policy, so the raw DACL is read separately.

    Notes:
      - Does NOT require WinRM (no Invoke-Command)
      - Does NOT require the ActiveDirectory module (ADSI only)
      - Works from a window started with runas /netonly.
        Open a FRESH window before a long run: an expiring Kerberos ticket
        is the usual cause of partial collections.

    Usage:
        .\Export-GpoMap.ps1
        .\Export-GpoMap.ps1 -Domain kkk.lo -Server dc-iiii.kkk.lo
        .\Export-GpoMap.ps1 -dated
        .\Export-GpoMap.ps1 -outdir c:\gpo-export -dated

    The -dated switch creates a yyyy-MM-dd subfolder by itself, so no date
    format has to be typed on the command line.
#>

[CmdletBinding()]
param(
    [string]$Domain = 'nnn.lo',
    [string]$Server = 'dc-nnn.nnn.lo',
    [string]$OutDir = 'C:\gpo-export',

    [int]$MaxGroupMembers = 500,
    [int]$Retries = 3,

    # Append a yyyy-MM-dd subfolder to OutDir automatically.
    # Saves typing a date format on a keyboard without Shift.
    [switch]$Dated,

    # Fail loudly instead of writing an incomplete data set
    [switch]$FailOnIncomplete,

    [switch]$NoZip
)

$ErrorActionPreference = 'Stop'
$sw = [System.Diagnostics.Stopwatch]::StartNew()
$startedAt = Get-Date

# Report the real failing line instead of a bare exception at the caller
trap {
    Write-Host ""
    Write-Host "UNHANDLED ERROR" -ForegroundColor Red
    Write-Host "  $($_.Exception.GetType().FullName): $($_.Exception.Message)" -ForegroundColor Red
    if ($_.InvocationInfo) {
        Write-Host "  at line $($_.InvocationInfo.ScriptLineNumber): $($_.InvocationInfo.Line.Trim())" -ForegroundColor Red
    }
    if ($_.ScriptStackTrace) {
        Write-Host "  stack:" -ForegroundColor DarkGray
        $_.ScriptStackTrace -split "`n" | ForEach-Object { Write-Host "    $_" -ForegroundColor DarkGray }
    }
    Write-Host "  CSV files already written to $OutDir are still valid." -ForegroundColor Yellow
    continue
}

# Extended right "Apply Group Policy"
$APPLY_GP_GUID = [guid]'edacfd8f-ffb3-11d1-b41d-00a0c968f939'

Import-Module GroupPolicy

if ($Dated) {
    $OutDir = Join-Path $OutDir (Get-Date).ToString('yyyy-MM-dd')
}
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null

Write-Host "`n=== GPO collection: $Domain via $Server ===" -ForegroundColor Cyan
Write-Host ("Started: {0:yyyy-MM-dd HH:mm:ss}" -f $startedAt) -ForegroundColor DarkGray
Write-Host "Output:  $OutDir" -ForegroundColor DarkGray

# ---------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------
function Invoke-WithRetry {
    param([scriptblock]$Script, [string]$What = 'operation', [int]$Attempts = $Retries)
    for ($a = 1; $a -le $Attempts; $a++) {
        try { return & $Script }
        catch {
            if ($a -eq $Attempts) {
                Write-Warning "FAILED after $a attempts - ${What}: $($_.Exception.Message)"
                throw
            }
            Write-Host "    retry $a/$Attempts - $What" -ForegroundColor DarkYellow
            Start-Sleep -Milliseconds (800 * $a)
        }
    }
}

function Search-Directory {
    param([string]$Base, [string]$Filter, [string[]]$Properties, [switch]$WithDacl)
    $s = New-Object System.DirectoryServices.DirectorySearcher
    $s.SearchRoot = [ADSI]"LDAP://$Server/$Base"
    $s.Filter = $Filter
    $s.PageSize = 1000
    if ($WithDacl) { $s.SecurityMasks = [System.DirectoryServices.SecurityMasks]::Dacl }
    foreach ($p in $Properties) { [void]$s.PropertiesToLoad.Add($p) }
    $s.FindAll()
}

function Get-Prop {
    param($Result, [string]$Name)
    if ($Result.Properties[$Name].Count) { $Result.Properties[$Name][0] } else { $null }
}

$script:StepMarks = New-Object System.Collections.Generic.List[object]
function Format-Span {
    # hh:mm:ss always, so runs longer than an hour are not misread
    param([TimeSpan]$Span)
    return ('{0:00}:{1:00}:{2:00}' -f [int]$Span.TotalHours, $Span.Minutes, $Span.Seconds)
}

function Write-Step {
    param([string]$Label)
    # close out the previous step with its duration
    if ($script:StepMarks.Count) {
        $last = $script:StepMarks[$script:StepMarks.Count - 1]
        Write-Host ("      took " + (Format-Span ($sw.Elapsed - $last.At))) -ForegroundColor DarkGray
    }
    $script:StepMarks.Add([PSCustomObject]@{ Label = $Label; At = $sw.Elapsed })
    Write-Host ("`n" + $Label + "   (elapsed so far " + (Format-Span $sw.Elapsed) + ")") -ForegroundColor Yellow
}

function Complete-LastStep {
    if ($script:StepMarks.Count) {
        $last = $script:StepMarks[$script:StepMarks.Count - 1]
        Write-Host ("      took " + (Format-Span ($sw.Elapsed - $last.At))) -ForegroundColor DarkGray
    }
}

function Out-Table {
    # Piping $null into Export-Csv throws, which used to abort a whole
    # section when a domain simply had none of that object type.
    param($Data, [string]$Suffix)
    $path = Join-Path $OutDir "$Domain-$Suffix.csv"
    $rows = @($Data | Where-Object { $null -ne $_ })
    if ($rows.Count) { $rows | Export-Csv $path -NoTypeInformation -Encoding UTF8 }
    else { Set-Content -Path $path -Value '"Empty"' -Encoding UTF8 }
    return $path
}

function ConvertTo-ByteArray {
    # The leading comma is essential: without it PowerShell unrolls the
    # array on output and the caller gets Object[] instead of byte[].
    param($Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [byte[]]) { return , $Value }
    $arr = New-Object byte[] $Value.Count
    for ($z = 0; $z -lt $Value.Count; $z++) { $arr[$z] = [byte]$Value[$z] }
    return , $arr
}

# SID -> name cache, filled as we go
$script:SidNames = @{}
function Resolve-Sid {
    param([string]$Sid)
    if ($script:SidNames.ContainsKey($Sid)) { return $script:SidNames[$Sid] }
    $name = $null
    try {
        $o = [ADSI]"LDAP://$Server/<SID=$Sid>"
        $name = @($o.Properties['sAMAccountName'])[0]
        if (-not $name) { $name = @($o.Properties['name'])[0] }
    }
    catch { $name = $null }
    if (-not $name) {
        try { $name = (New-Object System.Security.Principal.SecurityIdentifier($Sid)).Translate([System.Security.Principal.NTAccount]).Value }
        catch { $name = $null }
    }
    $script:SidNames[$Sid] = $name
    return $name
}

# ---------------------------------------------------------------
# Domain root and domain SID
# ---------------------------------------------------------------
$rootDse = [ADSI]"LDAP://$Server/RootDSE"
$baseDn = $rootDse.defaultNamingContext[0]

$domSid = $null
try {
    $domEntry = [ADSI]"LDAP://$Server/$baseDn"
    $sidBytes = ConvertTo-ByteArray $domEntry.Properties['objectSid'][0]
    # ::new() takes the byte[] as a single argument; New-Object -ArgumentList
    # would splat the array into separate constructor parameters.
    $domSid = [System.Security.Principal.SecurityIdentifier]::new($sidBytes, 0).Value
}
catch {
    Write-Warning "Could not read domain SID directly: $($_.Exception.Message)"
    Write-Warning "Will derive it from collected ACLs instead."
}

Write-Host "Base DN:    $baseDn" -ForegroundColor DarkGray
Write-Host "Domain SID: $domSid" -ForegroundColor DarkGray

# ---------------------------------------------------------------
# 1. OU structure
# ---------------------------------------------------------------
Write-Step "[1/7] OU structure"

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
[void](Out-Table $ous 'ou')
Write-Host "  OUs: $(@($ous).Count)"

# ---------------------------------------------------------------
# 2. Policy links
# ---------------------------------------------------------------
Write-Step "[2/7] Policy links"

$targets = @($baseDn) + @($ous.DistinguishedName)
$links = New-Object System.Collections.Generic.List[object]
$linkFailures = New-Object System.Collections.Generic.List[string]
$i = 0

foreach ($t in $targets) {
    $i++
    Write-Progress -Activity 'Reading links' -Status $t -PercentComplete ($i * 100 / $targets.Count)
    try {
        $inh = Invoke-WithRetry -What "links on $t" -Script {
            Get-GPInheritance -Target $t -Domain $Domain -Server $Server
        }
        if ($inh.GpoLinks.Count -eq 0) {
            $links.Add([PSCustomObject]@{
                Target = $t; InheritBlocked = $inh.GpoInheritanceBlocked
                Order = $null; DisplayName = $null; Enabled = $null
                Enforced = $null; GpoId = $null
            })
        }
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
    catch { $linkFailures.Add($t) }
}
Write-Progress -Activity 'Reading links' -Completed
[void](Out-Table $links 'links')
Write-Host "  link records: $($links.Count), failed containers: $($linkFailures.Count)"

# ---------------------------------------------------------------
# 3. WMI filters
# ---------------------------------------------------------------
Write-Step "[3/7] WMI filters"

$wmi = @()
try {
    $wmiResults = Search-Directory -Base "CN=SOM,CN=WMIPolicy,CN=System,$baseDn" `
        -Filter '(objectClass=msWMI-Som)' -Properties 'mswmi-name', 'mswmi-parm2'
    $wmi = foreach ($r in $wmiResults) {
        [PSCustomObject]@{ Name = Get-Prop $r 'mswmi-name'; Query = Get-Prop $r 'mswmi-parm2' }
    }
    [void](Out-Table $wmi 'wmi')
    Write-Host "  filters: $(@($wmi).Count)"
}
catch { Write-Warning "WMI filters: $($_.Exception.Message)" }

# ---------------------------------------------------------------
# 4. GPO inventory
# ---------------------------------------------------------------
Write-Step "[4/7] GPO inventory"

$gpos = Get-GPO -All -Domain $Domain -Server $Server |
    Select-Object DisplayName, Id, GpoStatus, CreationTime, ModificationTime,
        @{N = 'Owner'; E = { $_.Owner } },
        @{N = 'UserVersionAD'; E = { $_.User.DSVersion } },
        @{N = 'UserVersionSysvol'; E = { $_.User.SysvolVersion } },
        @{N = 'ComputerVersionAD'; E = { $_.Computer.DSVersion } },
        @{N = 'ComputerVersionSysvol'; E = { $_.Computer.SysvolVersion } },
        @{N = 'WmiFilter'; E = { $_.WmiFilter.Name } }

[void](Out-Table $gpos 'gpo')
Write-Host "  policies: $(@($gpos).Count)"

# ---------------------------------------------------------------
# 5. Permissions, with retry and a completeness pass
# ---------------------------------------------------------------
Write-Step "[5/7] Permissions"

$perms = New-Object System.Collections.Generic.List[object]
$permFailures = New-Object System.Collections.Generic.List[string]

function Read-GpoPermissions {
    param($Gpo)
    $rows = Invoke-WithRetry -What "permissions on $($Gpo.DisplayName)" -Script {
        Get-GPPermission -Guid $Gpo.Id -Domain $Domain -Server $Server -All
    }
    foreach ($p in $rows) {
        $perms.Add([PSCustomObject]@{
            Gpo        = $Gpo.DisplayName
            GpoId      = $Gpo.Id
            Trustee    = $p.Trustee.Name
            TrusteeSid = $p.Trustee.Sid.Value
            SidType    = $p.Trustee.SidType
            Permission = $p.Permission
            Inherited  = $p.Inherited
            Applies    = ($p.Permission -match 'Apply')
        })
    }
}

$j = 0
foreach ($g in $gpos) {
    $j++
    Write-Progress -Activity 'Reading permissions' -Status $g.DisplayName -PercentComplete ($j * 100 / @($gpos).Count)
    try { Read-GpoPermissions -Gpo $g }
    catch { $permFailures.Add($g.DisplayName) }
}
Write-Progress -Activity 'Reading permissions' -Completed

# second pass over whatever came back empty
$covered = @($perms.Gpo | Sort-Object -Unique)
$missing = $gpos | Where-Object { $covered -notcontains $_.DisplayName }

if ($missing) {
    Write-Host "  second pass over $(@($missing).Count) policies with no ACL data" -ForegroundColor DarkYellow
    Start-Sleep -Seconds 2
    foreach ($g in $missing) {
        try {
            Read-GpoPermissions -Gpo $g
            [void]$permFailures.Remove($g.DisplayName)
        }
        catch { if ($permFailures -notcontains $g.DisplayName) { $permFailures.Add($g.DisplayName) } }
    }
}

$covered = @($perms.Gpo | Sort-Object -Unique)
$stillMissing = @($gpos | Where-Object { $covered -notcontains $_.DisplayName })

# Fallback: the most common S-1-5-21 prefix in the ACLs is this domain
if (-not $domSid) {
    $prefixes = $perms |
        Where-Object { $_.TrusteeSid -like 'S-1-5-21-*' } |
        ForEach-Object { ($_.TrusteeSid -split '-')[0..6] -join '-' } |
        Group-Object | Sort-Object Count -Descending
    if ($prefixes) {
        $domSid = $prefixes[0].Name
        Write-Host "  domain SID derived from ACLs: $domSid" -ForegroundColor DarkYellow
    }
}

[void](Out-Table $perms 'permissions')
Write-Host "  ACL entries: $($perms.Count), policies covered: $(@($covered).Count)/$(@($gpos).Count)"

# ---------------------------------------------------------------
# 6. Raw Apply ACEs - the only way to see Deny
# ---------------------------------------------------------------
Write-Step "[6/7] Apply ACEs (Allow and Deny)"

$aces = New-Object System.Collections.Generic.List[object]
try {
    $gpcs = Search-Directory -Base "CN=Policies,CN=System,$baseDn" `
        -Filter '(objectClass=groupPolicyContainer)' `
        -Properties 'cn', 'displayname', 'ntsecuritydescriptor' -WithDacl

    foreach ($r in $gpcs) {
        $cn = Get-Prop $r 'cn'
        $dn = Get-Prop $r 'displayname'
        $raw = ConvertTo-ByteArray (Get-Prop $r 'ntsecuritydescriptor')
        if (-not $raw) { continue }

        $sd = New-Object System.DirectoryServices.ActiveDirectorySecurity
        $sd.SetSecurityDescriptorBinaryForm($raw)

        foreach ($ace in $sd.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) {
            if ($ace.ObjectType -ne $APPLY_GP_GUID) { continue }
            $sid = $ace.IdentityReference.Value
            $aces.Add([PSCustomObject]@{
                Gpo        = $dn
                GpoCn      = $cn
                TrusteeSid = $sid
                Trustee    = (Resolve-Sid $sid)
                AceType    = $ace.AccessControlType    # Allow / Deny
                Rights     = $ace.ActiveDirectoryRights
                Inherited  = $ace.IsInherited
            })
        }
    }
    [void](Out-Table $aces 'applyaces')
    $denies = @($aces | Where-Object { $_.AceType -eq 'Deny' })
    Write-Host "  Apply ACEs: $($aces.Count), of them Deny: $($denies.Count)"
    foreach ($d in $denies) { Write-Host "    DENY  $($d.Gpo)  ->  $($d.Trustee)" -ForegroundColor DarkYellow }
}
catch { Write-Warning "Apply ACEs: $($_.Exception.Message)" }

# ---------------------------------------------------------------
# 7. Membership of groups seen in Apply ACEs
# ---------------------------------------------------------------
Write-Step "[7/7] Group membership"

$skipRids = @('-512', '-513', '-515', '-516', '-518', '-519', '-520')
$skipSids = @('S-1-5-11', 'S-1-1-0', 'S-1-5-9', 'S-1-5-18')

$fromPerms = $perms | Where-Object { $_.Applies -and $_.SidType -eq 'Group' } |
    Select-Object @{N = 'Sid'; E = { $_.TrusteeSid } }, @{N = 'Name'; E = { $_.Trustee } }
$fromAces = $aces | Select-Object @{N = 'Sid'; E = { $_.TrusteeSid } }, @{N = 'Name'; E = { $_.Trustee } }
$applyGroups = @($fromPerms) + @($fromAces) | Sort-Object Sid -Unique

$members = New-Object System.Collections.Generic.List[object]
$k = 0
foreach ($grp in $applyGroups) {
    $k++
    $label = if ($grp.Name) { "$($grp.Name)" } else { "SID $($grp.Sid)" }
    Write-Progress -Activity 'Resolving groups' -Status $label -PercentComplete ($k * 100 / @($applyGroups).Count)

    $isBuiltin = ($skipSids -contains $grp.Sid) -or
                 (@($skipRids | Where-Object { $grp.Sid -like "*$_" }).Count -gt 0)
    if ($isBuiltin) {
        $members.Add([PSCustomObject]@{
            GroupName = $label; GroupSid = $grp.Sid; MemberDn = $null
            MemberName = $null; MemberClass = 'builtin-not-enumerated'
            Note = 'well-known group, skipped'
        })
        continue
    }

    try {
        $obj = [ADSI]"LDAP://$Server/<SID=$($grp.Sid)>"
        $memberDns = @($obj.Properties['member'])

        if ($memberDns.Count -eq 0) {
            $members.Add([PSCustomObject]@{
                GroupName = $grp.Name; GroupSid = $grp.Sid; MemberDn = $null
                MemberName = $null; MemberClass = 'empty'; Note = 'group has no members'
            })
            continue
        }
        if ($memberDns.Count -gt $MaxGroupMembers) {
            $members.Add([PSCustomObject]@{
                GroupName = $grp.Name; GroupSid = $grp.Sid; MemberDn = $null
                MemberName = $null; MemberClass = 'too-many'
                Note = "$($memberDns.Count) members, not enumerated"
            })
            continue
        }

        foreach ($dn in $memberDns) {
            try {
                $m = [ADSI]"LDAP://$Server/$dn"
                $members.Add([PSCustomObject]@{
                    GroupName   = $grp.Name
                    GroupSid    = $grp.Sid
                    MemberDn    = $dn
                    MemberName  = @($m.Properties['sAMAccountName'])[0]
                    MemberClass = @($m.Properties['objectClass'])[-1]
                    Note        = $null
                })
            }
            catch {
                $members.Add([PSCustomObject]@{
                    GroupName = $grp.Name; GroupSid = $grp.Sid; MemberDn = $dn
                    MemberName = $null; MemberClass = 'unresolved'; Note = $_.Exception.Message
                })
            }
        }
    }
    catch { Write-Warning "$($grp.Name) : $($_.Exception.Message)" }
}
Write-Progress -Activity 'Resolving groups' -Completed
[void](Out-Table $members 'groupmembers')
Write-Host "  groups: $(@($applyGroups).Count), member records: $($members.Count)"

# ---------------------------------------------------------------
# Metadata and completeness verdict
# ---------------------------------------------------------------
Complete-LastStep

$finishedAt = Get-Date
$complete = (@($stillMissing).Count -eq 0 -and @($linkFailures).Count -eq 0)

$missingNames = @($stillMissing | ForEach-Object { [string]$_.DisplayName })
$failedOus = @($linkFailures | ForEach-Object { [string]$_ })

# Built field by field: a single bad value would otherwise kill the whole
# object, and the exception alone does not say which property caused it.
$metaFields = [ordered]@{}
$metaSpec = @(
    @{ Name = 'Domain';         Get = { [string]$Domain } }
    @{ Name = 'Server';         Get = { [string]$Server } }
    @{ Name = 'BaseDn';         Get = { [string]$baseDn } }
    @{ Name = 'DomainSid';      Get = { [string]$domSid } }
    @{ Name = 'CollectedAt';    Get = { $startedAt.ToString('yyyy-MM-dd HH:mm:ss') } }
    @{ Name = 'FinishedAt';     Get = { $finishedAt.ToString('yyyy-MM-dd HH:mm:ss') } }
    @{ Name = 'ElapsedSec';     Get = { [double][math]::Round($sw.Elapsed.TotalSeconds, 1) } }
    @{ Name = 'CollectedBy';    Get = { [string]("$env:USERNAME on $env:COMPUTERNAME") } }
    @{ Name = 'OuCount';        Get = { [int]@($ous).Count } }
    @{ Name = 'LinkCount';      Get = { [int]@($links | Where-Object { $_.DisplayName }).Count } }
    @{ Name = 'GpoCount';       Get = { [int]@($gpos).Count } }
    @{ Name = 'PermCount';      Get = { [int]$perms.Count } }
    @{ Name = 'AceCount';       Get = { [int]$aces.Count } }
    @{ Name = 'GroupCount';     Get = { [int]@($applyGroups).Count } }
    @{ Name = 'Complete';       Get = { [bool]$complete } }
    @{ Name = 'MissingAclGpos'; Get = { [string]($missingNames -join '; ') } }
    @{ Name = 'FailedLinkOus';  Get = { [string]($failedOus -join '; ') } }
)

foreach ($f in $metaSpec) {
    try { $metaFields[$f.Name] = & $f.Get }
    catch {
        $metaFields[$f.Name] = 'ERROR'
        Write-Warning "meta field '$($f.Name)': $($_.Exception.Message)"
    }
}

$meta = [PSCustomObject]$metaFields
try { [void](Out-Table $meta 'meta') }
catch { Write-Warning "Could not write meta.csv: $($_.Exception.Message)" }

Write-Host ""
if ($complete) {
    Write-Host "COLLECTION COMPLETE - all $(@($gpos).Count) policies have ACL data" -ForegroundColor Green
}
else {
    Write-Host "COLLECTION INCOMPLETE" -ForegroundColor Red
    if ($stillMissing) {
        Write-Host "  no ACL data for $(@($stillMissing).Count) policies:" -ForegroundColor Red
        $stillMissing | ForEach-Object { Write-Host "    $($_.DisplayName)" -ForegroundColor Red }
    }
    if ($linkFailures.Count) {
        Write-Host "  links unreadable on $($linkFailures.Count) containers" -ForegroundColor Red
    }
    Write-Host "  Usual cause: an expiring Kerberos ticket in a runas /netonly window." -ForegroundColor Yellow
    Write-Host "  Open a fresh window and run again before trusting the analysis." -ForegroundColor Yellow
}

# ---------------------------------------------------------------
# Archive and timing
# ---------------------------------------------------------------
if (-not $NoZip) {
    try {
        $zip = "C:\gpo-map-$Domain.zip"
        Compress-Archive -Path (Join-Path $OutDir '*.csv') -DestinationPath $zip -Force
        Write-Host "`nArchive: $zip" -ForegroundColor Green
    }
    catch { Write-Warning "Could not build the archive: $($_.Exception.Message)" }
}

$sw.Stop()
try {
    Write-Host "`n--- Timing ---" -ForegroundColor Cyan
    for ($n = 0; $n -lt $script:StepMarks.Count; $n++) {
        $from = [TimeSpan]$script:StepMarks[$n].At
        $to = if ($n + 1 -lt $script:StepMarks.Count) { [TimeSpan]$script:StepMarks[$n + 1].At } else { $sw.Elapsed }
        $dur = $to - $from
        Write-Host ("  {0,-30} {1}" -f [string]$script:StepMarks[$n].Label, (Format-Span $dur))
    }
}
catch { Write-Warning "Timing table: $($_.Exception.Message)" }
Write-Host ""
Write-Host ("=" * 52) -ForegroundColor Cyan
Write-Host ("  Started:       " + $startedAt.ToString('yyyy-MM-dd HH:mm:ss'))
Write-Host ("  Finished:      " + $finishedAt.ToString('yyyy-MM-dd HH:mm:ss'))
Write-Host ("  Total elapsed: " + (Format-Span $sw.Elapsed) +
            "  (" + [math]::Round($sw.Elapsed.TotalMinutes, 1) + " min)") -ForegroundColor Green
Write-Host ("=" * 52) -ForegroundColor Cyan
Write-Host ""
Write-Host "Next step:  .\Analyze-GpoMap.ps1 -Path '$OutDir'" -ForegroundColor Cyan
Write-Host ""

if ($FailOnIncomplete -and -not $complete) { throw 'Collection incomplete - see the list above.' }