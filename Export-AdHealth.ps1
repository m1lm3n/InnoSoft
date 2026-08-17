<#
    Export-AdHealth.ps1  -  COLLECTION ONLY

    Collects the state of a domain: controllers, FSMO roles, replication,
    sites and subnets, privileged group membership, domain-wide settings.
    Does no analysis: run Analyze-AdHealth.ps1 against the output folder.

    Produces:
        <domain>-dcs.csv          domain controllers, incl. RODC flag
        <domain>-fsmo.csv         who holds each operations master role
        <domain>-replication.csv  repadmin /showrepl, one row per partner
        <domain>-backup.csv       age of the last AD backup per partition
        <domain>-sites.csv        sites, their DCs and subnet counts
        <domain>-subnets.csv      subnets and the site each maps to
        <domain>-sitelinks.csv    site links, cost and replication interval
        <domain>-privileged.csv   recursive membership of privileged groups
        <domain>-domaininfo.csv   functional levels, password policy, krbtgt
        <domain>-adhealth-meta.csv

    Notes:
      - ADSI only, the ActiveDirectory module is not required
      - repadmin is used for replication and backup age; it ships with the
        AD DS role, so run this on a domain controller for full output
      - everything is read-only

    Usage:
        .\Export-AdHealth.ps1
        .\Export-AdHealth.ps1 -Domain kkk.lo -Server dc-iiii.kkk.lo
        .\Export-AdHealth.ps1 -OutDir c:\ad-export\2026-08-12
#>

[CmdletBinding()]
param(
    [string]$Domain = 'nnn.lo',
    [string]$Server = 'dc-nnn.nnn.lo',
    [string]$OutDir = 'C:\ad-export',
    [switch]$NoZip
)

$ErrorActionPreference = 'Stop'
$sw = [System.Diagnostics.Stopwatch]::StartNew()
$startedAt = Get-Date

trap {
    Write-Host ""
    Write-Host "UNHANDLED ERROR" -ForegroundColor Red
    Write-Host "  $($_.Exception.GetType().FullName): $($_.Exception.Message)" -ForegroundColor Red
    if ($_.InvocationInfo) {
        Write-Host "  at line $($_.InvocationInfo.ScriptLineNumber): $($_.InvocationInfo.Line.Trim())" -ForegroundColor Red
    }
    Write-Host "  CSV files already written to $OutDir are still valid." -ForegroundColor Yellow
    continue
}

New-Item -ItemType Directory -Path $OutDir -Force | Out-Null

Write-Host "`n=== AD health collection: $Domain via $Server ===" -ForegroundColor Cyan
Write-Host ("Started: {0}" -f $startedAt.ToString('yyyy-MM-dd HH:mm:ss')) -ForegroundColor DarkGray
Write-Host "Output:  $OutDir" -ForegroundColor DarkGray

# ---------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------
function ConvertTo-ByteArray {
    # leading comma stops PowerShell unrolling the array on return
    param($Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [byte[]]) { return , $Value }
    $arr = New-Object byte[] $Value.Count
    for ($z = 0; $z -lt $Value.Count; $z++) { $arr[$z] = [byte]$Value[$z] }
    return , $arr
}

function Search-Directory {
    param([string]$Base, [string]$Filter, [string[]]$Properties, [string]$Scope = 'Subtree')
    $s = New-Object System.DirectoryServices.DirectorySearcher
    $s.SearchRoot = [ADSI]"LDAP://$Server/$Base"
    $s.Filter = $Filter
    $s.PageSize = 1000
    $s.SearchScope = $Scope
    foreach ($p in $Properties) { [void]$s.PropertiesToLoad.Add($p) }
    $s.FindAll()
}

function Get-Prop {
    param($Result, [string]$Name)
    if ($Result.Properties[$Name].Count) { $Result.Properties[$Name][0] } else { $null }
}

function ConvertFrom-ComLargeInteger {
    # [ADSI] hands back IADsLargeInteger COM objects for 64-bit attributes.
    # DirectorySearcher returns proper Int64, but bound objects do not.
    param($Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [int64]) { return $Value }
    try { return [int64]$Value }
    catch {
        try {
            $high = $Value.GetType().InvokeMember('HighPart', 'GetProperty', $null, $Value, $null)
            $low = $Value.GetType().InvokeMember('LowPart', 'GetProperty', $null, $Value, $null)
            return ([int64]$high -shl 32) -bor ([int64]$low -band 0xFFFFFFFFL)
        }
        catch { return $null }
    }
}

function ConvertFrom-AdInterval {
    # AD stores durations as negative 100-nanosecond intervals
    param($Value)
    $v = ConvertFrom-ComLargeInteger $Value
    if ($null -eq $v) { return $null }
    if ($v -eq 0 -or $v -eq -9223372036854775808) { return $null }
    return [TimeSpan]::FromTicks([math]::Abs($v))
}

function ConvertFrom-FileTimeSafe {
    param($Value)
    try {
        $v = ConvertFrom-ComLargeInteger $Value
        if ($null -eq $v -or $v -le 0) { return $null }
        return [datetime]::FromFileTimeUtc($v).ToLocalTime()
    }
    catch { return $null }
}

function Get-DnFromNtds {
    # "CN=NTDS Settings,CN=DC01,CN=Servers,CN=Site,..." -> DC01 / Site
    param([string]$Dn)
    if (-not $Dn) { return $null }
    $parts = $Dn -split ','
    $server = ($parts | Where-Object { $_ -like 'CN=*' })[1]
    $site = $null
    for ($i = 0; $i -lt $parts.Count; $i++) {
        if ($parts[$i] -eq 'CN=Servers' -and ($i + 1) -lt $parts.Count) { $site = $parts[$i + 1] }
    }
    return [PSCustomObject]@{
        Server = ($server -replace '^CN=', '')
        Site   = ($site -replace '^CN=', '')
    }
}

$script:StepMarks = New-Object System.Collections.Generic.List[object]
function Format-Span {
    param([TimeSpan]$Span)
    return ('{0:00}:{1:00}:{2:00}' -f [int]$Span.TotalHours, $Span.Minutes, $Span.Seconds)
}
function Write-Step {
    param([string]$Label)
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
    # A null pipeline input makes Export-Csv throw, so an empty result set
    # used to abort a whole section. Write a header-only file instead.
    param($Data, [string]$Suffix)
    $path = Join-Path $OutDir "$Domain-$Suffix.csv"
    $rows = @($Data | Where-Object { $null -ne $_ })
    if ($rows.Count) { $rows | Export-Csv $path -NoTypeInformation -Encoding UTF8 }
    else { Set-Content -Path $path -Value '"Empty"' -Encoding UTF8 }
    return $path
}

# ---------------------------------------------------------------
# Naming contexts
# ---------------------------------------------------------------
$rootDse = [ADSI]"LDAP://$Server/RootDSE"
$baseDn = $rootDse.defaultNamingContext[0]
$configDn = $rootDse.configurationNamingContext[0]
$schemaDn = $rootDse.schemaNamingContext[0]

$domSid = $null
try {
    $domEntry = [ADSI]"LDAP://$Server/$baseDn"
    $sidBytes = ConvertTo-ByteArray $domEntry.Properties['objectSid'][0]
    $domSid = [System.Security.Principal.SecurityIdentifier]::new($sidBytes, 0).Value
}
catch { Write-Warning "Could not read domain SID: $($_.Exception.Message)" }

Write-Host "Base DN:    $baseDn" -ForegroundColor DarkGray
Write-Host "Domain SID: $domSid" -ForegroundColor DarkGray

# ---------------------------------------------------------------
# 1. Domain controllers
# ---------------------------------------------------------------
Write-Step "[1/9] Domain controllers"

$dcs = @()
try {
    $ntds = Search-Directory -Base "CN=Sites,$configDn" `
        -Filter '(objectClass=nTDSDSA)' `
        -Properties 'distinguishedname', 'options', 'msds-behavior-version', 'invocationid'

    $dcs = foreach ($r in $ntds) {
        $dn = Get-Prop $r 'distinguishedname'
        $info = Get-DnFromNtds $dn
        $opts = [int](Get-Prop $r 'options')

        # server object one level up holds the DNS name
        $serverDn = ($dn -replace '^CN=NTDS Settings,', '')
        $srv = $null
        try {
            $srvEntry = [ADSI]"LDAP://$Server/$serverDn"
            $srv = @($srvEntry.Properties['dNSHostName'])[0]
        }
        catch { }

        # is this an RODC? the computer object carries the flag
        $isRodc = $false
        $osName = $null
        $lastLogon = $null
        try {
            $ref = @([ADSI]"LDAP://$Server/$serverDn").Properties['serverReference'][0]
            if ($ref) {
                $comp = [ADSI]"LDAP://$Server/$ref"
                $uac = [int]@($comp.Properties['userAccountControl'])[0]
                $isRodc = (($uac -band 0x4000000) -ne 0)   # PARTIAL_SECRETS_ACCOUNT
                $osName = @($comp.Properties['operatingSystem'])[0]
                $lastLogon = ConvertFrom-FileTimeSafe @($comp.Properties['lastLogonTimestamp'])[0]
            }
        }
        catch { }

        [PSCustomObject]@{
            Name          = $info.Server
            Site          = $info.Site
            DnsHostName   = $srv
            IsGlobalCatalog = (($opts -band 1) -ne 0)
            IsRodc        = $isRodc
            OperatingSystem = $osName
            LastLogon     = if ($lastLogon) { $lastLogon.ToString('yyyy-MM-dd HH:mm') } else { $null }
            DistinguishedName = $dn
        }
    }
    $dcs = $dcs | Sort-Object Site, Name
    [void](Out-Table $dcs 'dcs')
    Write-Host "  controllers: $(@($dcs).Count)  (RODC: $(@($dcs | Where-Object IsRodc).Count))"
}
catch { Write-Warning "Domain controllers: $($_.Exception.Message)" }

# ---------------------------------------------------------------
# 2. FSMO roles
# ---------------------------------------------------------------
Write-Step "[2/9] FSMO roles"

$fsmo = @()
try {
    $roleMap = @(
        @{ Role = 'Schema Master';        Dn = $schemaDn }
        @{ Role = 'Domain Naming Master'; Dn = "CN=Partitions,$configDn" }
        @{ Role = 'PDC Emulator';         Dn = $baseDn }
        @{ Role = 'RID Master';           Dn = "CN=RID Manager`$,CN=System,$baseDn" }
        @{ Role = 'Infrastructure Master'; Dn = "CN=Infrastructure,$baseDn" }
    )
    $fsmo = foreach ($m in $roleMap) {
        $holder = $null
        try {
            $e = [ADSI]"LDAP://$Server/$($m.Dn)"
            $owner = @($e.Properties['fSMORoleOwner'])[0]
            $holder = (Get-DnFromNtds $owner).Server
        }
        catch { }
        [PSCustomObject]@{ Role = $m.Role; Holder = $holder }
    }
    [void](Out-Table $fsmo 'fsmo')
    foreach ($f in $fsmo) { Write-Host ("  {0,-22} {1}" -f $f.Role, $f.Holder) }
}
catch { Write-Warning "FSMO: $($_.Exception.Message)" }

# ---------------------------------------------------------------
# 3. Replication (repadmin)
# ---------------------------------------------------------------
Write-Step "[3/9] Replication"

$repl = @()
$repadmin = Get-Command repadmin.exe -ErrorAction SilentlyContinue
if (-not $repadmin) {
    Write-Warning "repadmin.exe not found - run this on a domain controller for replication data"
}
else {
    try {
        $raw = & repadmin.exe /showrepl * /csv 2>&1
        $errLines = @($raw | Where-Object { "$_" -match 'error|Win32 Err|Server Down' })
        if ($errLines.Count) {
            foreach ($e in $errLines) { Write-Warning "repadmin: $e" }
            Write-Host "  some partners did not answer - usually a DC that is offline" -ForegroundColor DarkYellow
        }
        $parsed = @($raw | Where-Object { "$_" -match ',' }) | ConvertFrom-Csv
        $repl = foreach ($row in $parsed) {
            if ($row.'Showrepl_COLUMNS' -eq 'Showrepl_COLUMNS') { continue }
            [PSCustomObject]@{
                DestinationSite   = $row.'Destination DSA Site'
                DestinationDsa    = $row.'Destination DSA'
                NamingContext     = $row.'Naming Context'
                SourceSite        = $row.'Source DSA Site'
                SourceDsa         = $row.'Source DSA'
                Transport         = $row.'Transport Type'
                Failures          = $row.'Number of Failures'
                LastFailureTime   = $row.'Last Failure Time'
                LastSuccessTime   = $row.'Last Success Time'
                LastFailureStatus = $row.'Last Failure Status'
            }
        }
        [void](Out-Table $repl 'replication')
        $bad = @($repl | Where-Object { [int]$_.Failures -gt 0 })
        Write-Host "  links: $(@($repl).Count), with failures: $($bad.Count)" `
            -ForegroundColor $(if ($bad.Count) { 'Red' } else { 'Gray' })
        foreach ($b in $bad) {
            Write-Host "    FAIL $($b.DestinationDsa) <- $($b.SourceDsa) : $($b.LastFailureStatus)" -ForegroundColor Red
        }
    }
    catch { Write-Warning "Replication: $($_.Exception.Message)" }
}

# ---------------------------------------------------------------
# 4. Backup age
# ---------------------------------------------------------------
Write-Step "[4/9] AD backup age"

$backup = @()
if ($repadmin) {
    try {
        # repadmin prints the partition on one line, then a data line holding
        # the timestamp of the dSASignature attribute:
        #   DC=nnn,DC=lo
        #   6926322  <guid>  6926322 2026-08-12 03:09:05  369 dSASignature
        $out = & repadmin.exe /showbackup $Server 2>$null
        $currentNc = $null
        foreach ($line in $out) {
            $t = "$line".Trim()
            if ($t -match '^(DC=|CN=)\S') { $currentNc = $t; continue }
            if ($t -match '(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2})') {
                $stamp = $matches[1]
                $backup += [PSCustomObject]@{
                    Partition  = if ($currentNc) { $currentNc } else { 'unknown' }
                    LastBackup = $stamp
                }
                $currentNc = $null
            }
        }
        if (-not $backup) {
            $backup = @($out | Where-Object { "$_" -match '\S' } |
                ForEach-Object { [PSCustomObject]@{ Partition = 'raw'; LastBackup = "$_".Trim() } })
        }
        [void](Out-Table $backup 'backup')
        Write-Host "  backup records: $(@($backup).Count)"
    }
    catch { Write-Warning "Backup age: $($_.Exception.Message)" }
}

# ---------------------------------------------------------------
# 5. Sites, subnets, site links
# ---------------------------------------------------------------
Write-Step "[5/9] Sites and subnets"

$sites = @(); $subnets = @(); $siteLinks = @()
try {
    $siteRes = Search-Directory -Base "CN=Sites,$configDn" `
        -Filter '(objectClass=site)' -Properties 'name', 'distinguishedname', 'description'

    $subnetRes = Search-Directory -Base "CN=Subnets,CN=Sites,$configDn" `
        -Filter '(objectClass=subnet)' -Properties 'name', 'siteobject', 'description', 'location'

    $subnets = foreach ($r in $subnetRes) {
        $siteDn = Get-Prop $r 'siteobject'
        [PSCustomObject]@{
            Subnet      = Get-Prop $r 'name'
            Site        = if ($siteDn) { (($siteDn -split ',')[0] -replace '^CN=', '') } else { $null }
            Description = Get-Prop $r 'description'
            Location    = Get-Prop $r 'location'
        }
    }

    $sites = foreach ($r in $siteRes) {
        $n = Get-Prop $r 'name'
        [PSCustomObject]@{
            Site        = $n
            Description = Get-Prop $r 'description'
            DcCount     = @($dcs | Where-Object { $_.Site -eq $n }).Count
            SubnetCount = @($subnets | Where-Object { $_.Site -eq $n }).Count
        }
    }

    $linkRes = Search-Directory -Base "CN=Inter-Site Transports,CN=Sites,$configDn" `
        -Filter '(objectClass=siteLink)' -Properties 'name', 'cost', 'replinterval', 'sitelist'

    $siteLinks = foreach ($r in $linkRes) {
        $members = @($r.Properties['sitelist']) | ForEach-Object { ($_ -split ',')[0] -replace '^CN=', '' }
        [PSCustomObject]@{
            Name            = Get-Prop $r 'name'
            Cost            = Get-Prop $r 'cost'
            IntervalMinutes = Get-Prop $r 'replinterval'
            Sites           = ($members -join '; ')
        }
    }

    $sites = @($sites); $subnets = @($subnets); $siteLinks = @($siteLinks)
    [void](Out-Table $sites 'sites')
    [void](Out-Table $subnets 'subnets')
    [void](Out-Table $siteLinks 'sitelinks')
    Write-Host "  sites: $(@($sites).Count), subnets: $(@($subnets).Count), site links: $(@($siteLinks).Count)"
}
catch { Write-Warning "Sites: $($_.Exception.Message)" }

# ---------------------------------------------------------------
# 6. Privileged group membership (recursive)
# ---------------------------------------------------------------
Write-Step "[6/9] Privileged access"

$privileged = @()
try {
    $groupSpec = @(
        @{ Name = 'Domain Admins';               Sid = "$domSid-512" }
        @{ Name = 'Enterprise Admins';           Sid = "$domSid-519" }
        @{ Name = 'Schema Admins';               Sid = "$domSid-518" }
        @{ Name = 'Group Policy Creator Owners'; Sid = "$domSid-520" }
        @{ Name = 'Administrators';              Sid = 'S-1-5-32-544' }
        @{ Name = 'Account Operators';           Sid = 'S-1-5-32-548' }
        @{ Name = 'Server Operators';            Sid = 'S-1-5-32-549' }
        @{ Name = 'Backup Operators';            Sid = 'S-1-5-32-551' }
        @{ Name = 'Print Operators';             Sid = 'S-1-5-32-550' }
    )

    foreach ($g in $groupSpec) {
        $gDn = $null
        try {
            $gEntry = [ADSI]"LDAP://$Server/<SID=$($g.Sid)>"
            $gDn = @($gEntry.Properties['distinguishedName'])[0]
        }
        catch { }
        if (-not $gDn) { continue }

        # LDAP_MATCHING_RULE_IN_CHAIN walks nested groups for us
        $memRes = Search-Directory -Base $baseDn `
            -Filter "(memberOf:1.2.840.113556.1.4.1941:=$gDn)" `
            -Properties 'samaccountname', 'objectclass', 'useraccountcontrol', 'pwdlastset', 'lastlogontimestamp', 'admincount', 'distinguishedname'

        foreach ($m in $memRes) {
            $uac = [int](Get-Prop $m 'useraccountcontrol')
            $pwdSet = ConvertFrom-FileTimeSafe (Get-Prop $m 'pwdlastset')
            $lastOn = ConvertFrom-FileTimeSafe (Get-Prop $m 'lastlogontimestamp')
            $privileged += [PSCustomObject]@{
                Group            = $g.Name
                Member           = Get-Prop $m 'samaccountname'
                Class            = @($m.Properties['objectclass'])[-1]
                Enabled          = (($uac -band 2) -eq 0)
                PasswordNeverExpires = (($uac -band 65536) -ne 0)
                AdminCount       = Get-Prop $m 'admincount'
                PasswordLastSet  = if ($pwdSet) { $pwdSet.ToString('yyyy-MM-dd') } else { $null }
                PasswordAgeDays  = if ($pwdSet) { [int]((Get-Date) - $pwdSet).TotalDays } else { $null }
                LastLogon        = if ($lastOn) { $lastOn.ToString('yyyy-MM-dd') } else { $null }
                LastLogonDaysAgo = if ($lastOn) { [int]((Get-Date) - $lastOn).TotalDays } else { $null }
                DistinguishedName = Get-Prop $m 'distinguishedname'
            }
        }
    }
    [void](Out-Table $privileged 'privileged')
    $uniq = @($privileged | Select-Object Member -Unique).Count
    Write-Host "  privileged entries: $(@($privileged).Count), distinct principals: $uniq"
}
catch { Write-Warning "Privileged access: $($_.Exception.Message)" }

# ---------------------------------------------------------------
# 7. Domain-wide settings
# ---------------------------------------------------------------
Write-Step "[7/9] Domain settings"

$domainInfo = $null
try {
    $krbtgtPwd = $null
    try {
        $k = Search-Directory -Base $baseDn -Filter '(samaccountname=krbtgt)' -Properties 'pwdlastset'
        $krbtgtPwd = ConvertFrom-FileTimeSafe (Get-Prop $k[0] 'pwdlastset')
    }
    catch { }

    $recycleBin = $false
    try {
        $feat = Search-Directory -Base "CN=Partitions,$configDn" `
            -Filter '(objectClass=crossRefContainer)' -Properties 'msds-enabledfeature'
        $recycleBin = (@($feat[0].Properties['msds-enabledfeature']) -join ';') -match 'Recycle Bin'
    }
    catch { }

    $tombstone = $null
    try {
        $ds = Search-Directory -Base "CN=Directory Service,CN=Windows NT,CN=Services,$configDn" `
            -Filter '(objectClass=*)' -Scope 'Base' -Properties 'tombstonelifetime'
        $tombstone = Get-Prop $ds[0] 'tombstonelifetime'
        if (-not $tombstone) { $tombstone = 180 }   # AD default when unset
    }
    catch { }

    $forestLevel = $null
    try {
        $part = Search-Directory -Base "CN=Partitions,$configDn" `
            -Filter '(objectClass=*)' -Scope 'Base' -Properties 'msds-behavior-version'
        $forestLevel = Get-Prop $part[0] 'msds-behavior-version'
    }
    catch { }

    # DirectorySearcher returns Int64 for these, unlike a bound [ADSI] object
    $domRes = Search-Directory -Base $baseDn -Filter '(objectClass=domainDNS)' -Scope 'Base' `
        -Properties 'maxpwdage', 'minpwdage', 'lockoutduration', 'minpwdlength',
                    'pwdhistorylength', 'lockoutthreshold', 'msds-behavior-version'
    $dr = $domRes[0]

    $maxPwdAge = ConvertFrom-AdInterval (Get-Prop $dr 'maxpwdage')
    $minPwdAge = ConvertFrom-AdInterval (Get-Prop $dr 'minpwdage')
    $lockDur   = ConvertFrom-AdInterval (Get-Prop $dr 'lockoutduration')

    $domainInfo = [PSCustomObject]@{
        Domain              = $Domain
        DomainSid           = $domSid
        DomainFunctionLevel = Get-Prop $dr 'msds-behavior-version'
        ForestFunctionLevel = $forestLevel
        RecycleBinEnabled   = $recycleBin
        TombstoneLifetime   = $tombstone
        MaxPasswordAgeDays  = if ($maxPwdAge) { [int]$maxPwdAge.TotalDays } else { 'never' }
        MinPasswordAgeDays  = if ($minPwdAge) { [int]$minPwdAge.TotalDays } else { 0 }
        MinPasswordLength   = Get-Prop $dr 'minpwdlength'
        PasswordHistory     = Get-Prop $dr 'pwdhistorylength'
        LockoutThreshold    = Get-Prop $dr 'lockoutthreshold'
        LockoutDurationMin  = if ($lockDur) { [int]$lockDur.TotalMinutes } else { 0 }
        KrbtgtPasswordSet   = if ($krbtgtPwd) { $krbtgtPwd.ToString('yyyy-MM-dd') } else { $null }
        KrbtgtPasswordAgeDays = if ($krbtgtPwd) { [int]((Get-Date) - $krbtgtPwd).TotalDays } else { $null }
    }
    [void](Out-Table $domainInfo 'domaininfo')
    Write-Host "  domain level: $($domainInfo.DomainFunctionLevel), forest level: $($domainInfo.ForestFunctionLevel)"
    Write-Host "  krbtgt password age: $($domainInfo.KrbtgtPasswordAgeDays) days"
}
catch { Write-Warning "Domain settings: $($_.Exception.Message)" }

# ---------------------------------------------------------------
# 8. Kerberos delegation
# ---------------------------------------------------------------
Write-Step "[8/9] Kerberos delegation"

$delegation = New-Object System.Collections.Generic.List[object]
try {
    # userAccountControl bits that matter here
    $UAC_TRUSTED_FOR_DELEGATION = 0x80000      # unconstrained
    $UAC_TRUSTED_TO_AUTH        = 0x1000000    # protocol transition (S4U2Self)
    $UAC_NOT_DELEGATED          = 0x100000     # "sensitive, cannot be delegated"
    $UAC_SERVER_TRUST           = 0x2000       # domain controller

    $delRes = Search-Directory -Base $baseDn `
        -Filter '(|(userAccountControl:1.2.840.113556.1.4.803:=524288)(msDS-AllowedToDelegateTo=*)(userAccountControl:1.2.840.113556.1.4.803:=16777216)(msDS-AllowedToActOnBehalfOfOtherIdentity=*))' `
        -Properties 'samaccountname', 'objectclass', 'useraccountcontrol', 'distinguishedname',
                    'msds-allowedtodelegateto', 'msds-allowedtoactonbehalfofotheridentity',
                    'serviceprincipalname', 'pwdlastset'

    foreach ($r in $delRes) {
        $uac = [int](Get-Prop $r 'useraccountcontrol')
        # A writable DC has SERVER_TRUST_ACCOUNT; an RODC instead carries
        # PARTIAL_SECRETS_ACCOUNT, so checking only the first flag makes
        # every RODC look like a plain member server with delegation.
        $isDc = ((($uac -band $UAC_SERVER_TRUST) -ne 0) -or (($uac -band 0x4000000) -ne 0))

        # A DirectorySearcher result exposes every requested property, so
        # .Count alone is not proof the attribute holds anything. Filter for
        # real values, otherwise every DC looks constrained with no targets.
        $allowedTo = @($r.Properties['msds-allowedtodelegateto'] | Where-Object { "$_".Trim() })
        $rbcdRaw = @($r.Properties['msds-allowedtoactonbehalfofotheridentity'] | Where-Object { $_ })

        $type = @()
        if (($uac -band $UAC_TRUSTED_FOR_DELEGATION) -ne 0) { $type += 'Unconstrained' }
        if ($allowedTo.Count) {
            if (($uac -band $UAC_TRUSTED_TO_AUTH) -ne 0) { $type += 'Constrained+ProtocolTransition' }
            else { $type += 'Constrained' }
        }
        elseif (($uac -band $UAC_TRUSTED_TO_AUTH) -ne 0) {
            # protocol transition set without any target service
            $type += 'ProtocolTransition (no targets)'
        }
        if ($rbcdRaw.Count) { $type += 'ResourceBased' }
        if (-not $type) { continue }

        # RBCD stores a security descriptor; pull out who is allowed
        $rbcdWho = $null
        try {
            $raw = if ($rbcdRaw.Count) { ConvertTo-ByteArray $rbcdRaw[0] } else { $null }
            if ($raw) {
                $sd = New-Object System.DirectoryServices.ActiveDirectorySecurity
                $sd.SetSecurityDescriptorBinaryForm($raw)
                $sids = @($sd.GetAccessRules($true, $false, [System.Security.Principal.SecurityIdentifier]) |
                    ForEach-Object { $_.IdentityReference.Value }) | Sort-Object -Unique
                $rbcdWho = ($sids -join '; ')
            }
        }
        catch { }

        $delegation.Add([PSCustomObject]@{
            Name          = Get-Prop $r 'samaccountname'
            Class         = @($r.Properties['objectclass'])[-1]
            IsDomainController = $isDc
            DelegationType = ($type -join ', ')
            AllowedTo     = ($allowedTo -join '; ')
            RbcdAllowedFrom = $rbcdWho
            Spn           = (@($r.Properties['serviceprincipalname']) -join '; ')
            Sensitive     = (($uac -band $UAC_NOT_DELEGATED) -ne 0)
            Enabled       = (($uac -band 2) -eq 0)
            DistinguishedName = Get-Prop $r 'distinguishedname'
        })
    }

    [void](Out-Table $delegation 'delegation')
    $unc = @($delegation | Where-Object { $_.DelegationType -match 'Unconstrained' -and -not $_.IsDomainController })
    Write-Host "  delegation objects: $($delegation.Count)  (unconstrained outside DCs: $($unc.Count))" `
        -ForegroundColor $(if ($unc.Count) { 'Red' } else { 'Gray' })
    foreach ($u in $unc) { Write-Host "    UNCONSTRAINED  $($u.Name)  [$($u.Class)]" -ForegroundColor Red }
}
catch { Write-Warning "Delegation: $($_.Exception.Message)" }

# ---------------------------------------------------------------
# 9. Service accounts, SPNs and weak Kerberos settings
# ---------------------------------------------------------------
Write-Step "[9/9] Service accounts and SPNs"

$spnAccounts = New-Object System.Collections.Generic.List[object]
try {
    $UAC_DONT_REQ_PREAUTH = 0x400000   # AS-REP roastable
    $UAC_REVERSIBLE       = 0x80       # password stored reversibly
    $UAC_DONT_EXPIRE      = 0x10000

    # user objects only: computer SPNs are normal and not roastable in practice
    # krbtgt and the RODC krbtgt_* clones carry a system SPN by design and
    # cannot be changed; leaving them in only produces noise.
    $spnRes = Search-Directory -Base $baseDn `
        -Filter '(&(objectCategory=person)(objectClass=user)(!(samAccountName=krbtgt))(!(samAccountName=krbtgt_*))(|(servicePrincipalName=*)(userAccountControl:1.2.840.113556.1.4.803:=4194304)(userAccountControl:1.2.840.113556.1.4.803:=128)))' `
        -Properties 'samaccountname', 'useraccountcontrol', 'serviceprincipalname', 'pwdlastset',
                    'lastlogontimestamp', 'admincount', 'msds-supportedencryptiontypes',
                    'distinguishedname', 'description', 'memberof'

    foreach ($r in $spnRes) {
        $uac = [int](Get-Prop $r 'useraccountcontrol')
        $pwdSet = ConvertFrom-FileTimeSafe (Get-Prop $r 'pwdlastset')
        $lastOn = ConvertFrom-FileTimeSafe (Get-Prop $r 'lastlogontimestamp')
        $enc = Get-Prop $r 'msds-supportedencryptiontypes'

        # 0 or unset means the default set, which still allows RC4
        $encNames = @()
        if ($null -ne $enc) {
            $e = [int]$enc
            if ($e -band 1) { $encNames += 'DES-CRC' }
            if ($e -band 2) { $encNames += 'DES-MD5' }
            if ($e -band 4) { $encNames += 'RC4' }
            if ($e -band 8) { $encNames += 'AES128' }
            if ($e -band 16) { $encNames += 'AES256' }
        }

        $spns = @($r.Properties['serviceprincipalname'])

        $spnAccounts.Add([PSCustomObject]@{
            Name            = Get-Prop $r 'samaccountname'
            Description     = Get-Prop $r 'description'
            SpnCount        = $spns.Count
            Spn             = ($spns -join '; ')
            Enabled         = (($uac -band 2) -eq 0)
            PasswordNeverExpires = (($uac -band $UAC_DONT_EXPIRE) -ne 0)
            NoPreauth       = (($uac -band $UAC_DONT_REQ_PREAUTH) -ne 0)
            ReversiblePassword = (($uac -band $UAC_REVERSIBLE) -ne 0)
            AdminCount      = Get-Prop $r 'admincount'
            EncryptionTypes = if ($encNames) { $encNames -join ',' } else { 'default (RC4 allowed)' }
            PasswordLastSet = if ($pwdSet) { $pwdSet.ToString('yyyy-MM-dd') } else { $null }
            PasswordAgeDays = if ($pwdSet) { [int]((Get-Date) - $pwdSet).TotalDays } else { $null }
            LastLogonDaysAgo = if ($lastOn) { [int]((Get-Date) - $lastOn).TotalDays } else { $null }
            MemberOf        = (@($r.Properties['memberof']) | ForEach-Object { ($_ -split ',')[0] -replace '^CN=', '' }) -join '; '
            DistinguishedName = Get-Prop $r 'distinguishedname'
        })
    }

    [void](Out-Table $spnAccounts 'spn')
    $roastable = @($spnAccounts | Where-Object { $_.SpnCount -gt 0 -and $_.Enabled })
    $asrep = @($spnAccounts | Where-Object { $_.NoPreauth })
    $rev = @($spnAccounts | Where-Object { $_.ReversiblePassword })
    Write-Host "  accounts with SPN: $($roastable.Count), without preauth: $($asrep.Count), reversible password: $($rev.Count)"
    foreach ($a in $asrep) { Write-Host "    NO PREAUTH  $($a.Name)" -ForegroundColor Red }
    foreach ($a in $rev) { Write-Host "    REVERSIBLE  $($a.Name)" -ForegroundColor Red }
}
catch { Write-Warning "Service accounts: $($_.Exception.Message)" }

# ---------------------------------------------------------------
# Metadata
# ---------------------------------------------------------------
Complete-LastStep
$finishedAt = Get-Date

$metaFields = [ordered]@{}
$metaSpec = @(
    @{ Name = 'Domain';       Get = { [string]$Domain } }
    @{ Name = 'Server';       Get = { [string]$Server } }
    @{ Name = 'BaseDn';       Get = { [string]$baseDn } }
    @{ Name = 'DomainSid';    Get = { [string]$domSid } }
    @{ Name = 'CollectedAt';  Get = { $startedAt.ToString('yyyy-MM-dd HH:mm:ss') } }
    @{ Name = 'FinishedAt';   Get = { $finishedAt.ToString('yyyy-MM-dd HH:mm:ss') } }
    @{ Name = 'ElapsedSec';   Get = { [double][math]::Round($sw.Elapsed.TotalSeconds, 1) } }
    @{ Name = 'CollectedBy';  Get = { [string]("$env:USERNAME on $env:COMPUTERNAME") } }
    @{ Name = 'DcCount';      Get = { [int]@($dcs).Count } }
    @{ Name = 'SiteCount';    Get = { [int]@($sites).Count } }
    @{ Name = 'SubnetCount';  Get = { [int]@($subnets).Count } }
    @{ Name = 'ReplLinks';    Get = { [int]@($repl).Count } }
    @{ Name = 'PrivEntries';  Get = { [int]@($privileged).Count } }
    @{ Name = 'DelegationObjects'; Get = { [int]$delegation.Count } }
    @{ Name = 'SpnAccounts';  Get = { [int]$spnAccounts.Count } }
    @{ Name = 'RepadminUsed'; Get = { [bool]$repadmin } }
)
foreach ($f in $metaSpec) {
    try { $metaFields[$f.Name] = & $f.Get }
    catch {
        $metaFields[$f.Name] = 'ERROR'
        Write-Warning "meta field '$($f.Name)': $($_.Exception.Message)"
    }
}
try { [void](Out-Table ([PSCustomObject]$metaFields) 'adhealth-meta') }
catch { Write-Warning "Could not write meta: $($_.Exception.Message)" }

# ---------------------------------------------------------------
# Archive and timing
# ---------------------------------------------------------------
if (-not $NoZip) {
    try {
        $zip = Join-Path (Split-Path $OutDir -Parent) ("ad-$Domain-" + (Get-Date).ToString('yyyy-MM-dd') + ".zip")
        $files = Get-ChildItem $OutDir -Filter *.csv -File
        if ($files) {
            Compress-Archive -Path $files.FullName -DestinationPath $zip -Force
            Write-Host "`nArchive: $zip" -ForegroundColor Green
        }
    }
    catch { Write-Warning "Archive: $($_.Exception.Message)" }
}

$sw.Stop()
Write-Host ""
Write-Host ("=" * 52) -ForegroundColor Cyan
Write-Host ("  Started:       " + $startedAt.ToString('yyyy-MM-dd HH:mm:ss'))
Write-Host ("  Finished:      " + $finishedAt.ToString('yyyy-MM-dd HH:mm:ss'))
Write-Host ("  Total elapsed: " + (Format-Span $sw.Elapsed)) -ForegroundColor Green
Write-Host ("=" * 52) -ForegroundColor Cyan
Write-Host ""
Write-Host "Next step:  .\Analyze-AdHealth.ps1 -Path '$OutDir'" -ForegroundColor Cyan
Write-Host ""