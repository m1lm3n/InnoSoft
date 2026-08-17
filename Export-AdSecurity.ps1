<#
    Export-AdSecurity.ps1  -  COLLECTION ONLY

    Second-tier audit: the things that rarely get looked at until they are
    used against you. Run Analyze-AdSecurity.ps1 against the output folder.

    Produces:
        <domain>-ca.csv            certification authorities in the forest
        <domain>-templates.csv     certificate templates and who may enrol
        <domain>-laps.csv          LAPS coverage per computer
        <domain>-protection.csv    sensitive flag / Protected Users per admin
        <domain>-computers.csv     computer inventory, OS and staleness
        <domain>-dcconfig.csv      SMB and LDAP signing, NTLM level, spooler
        <domain>-adsecurity-meta.csv

    Notes:
      - ADSI only for directory data; no ActiveDirectory module needed
      - DC hardening needs the remote registry service, or run on a DC
      - everything is read-only. Certificate PRIVATE keys are never touched,
        only the template definitions stored in the configuration partition

    Usage:
        .\Export-AdSecurity.ps1
        .\Export-AdSecurity.ps1 -Domain kkk.lo -Server dc-iiii.kkk.lo
#>

[CmdletBinding()]
param(
    [string]$Domain = 'nnn.lo',
    [string]$Server = 'dc-nnn.nnn.lo',
    [string]$OutDir = 'C:\ad-export',
    [int]$StaleComputerDays = 90,

    # Additional hosts to probe for hardening settings alongside the DCs.
    # The CA is the obvious one: it is not a domain controller, so it never
    # appears in OU=Domain Controllers, yet it holds the flags that decide
    # whether certificate templates can be bypassed entirely.
    [string[]]$ExtraHosts = @(),

    [switch]$SkipDcConfig,
    [switch]$SkipCaConfig,
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

Write-Host "`n=== AD security collection: $Domain via $Server ===" -ForegroundColor Cyan
Write-Host ("Started: {0}" -f $startedAt.ToString('yyyy-MM-dd HH:mm:ss')) -ForegroundColor DarkGray

# ---------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------
function ConvertTo-ByteArray {
    param($Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [byte[]]) { return , $Value }
    $arr = New-Object byte[] $Value.Count
    for ($z = 0; $z -lt $Value.Count; $z++) { $arr[$z] = [byte]$Value[$z] }
    return , $arr
}

function ConvertFrom-ComLargeInteger {
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

function ConvertFrom-FileTimeSafe {
    param($Value)
    try {
        $v = ConvertFrom-ComLargeInteger $Value
        if ($null -eq $v -or $v -le 0) { return $null }
        return [datetime]::FromFileTimeUtc($v).ToLocalTime()
    }
    catch { return $null }
}

function Search-Directory {
    param([string]$Base, [string]$Filter, [string[]]$Properties, [string]$Scope = 'Subtree', [switch]$WithDacl)
    $s = New-Object System.DirectoryServices.DirectorySearcher
    $s.SearchRoot = [ADSI]"LDAP://$Server/$Base"
    $s.Filter = $Filter
    $s.PageSize = 1000
    $s.SearchScope = $Scope
    if ($WithDacl) { $s.SecurityMasks = [System.DirectoryServices.SecurityMasks]::Dacl }
    foreach ($p in $Properties) { [void]$s.PropertiesToLoad.Add($p) }
    $s.FindAll()
}

function Get-Prop {
    param($Result, [string]$Name)
    if ($Result.Properties[$Name].Count) { $Result.Properties[$Name][0] } else { $null }
}

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
    catch { }
    if (-not $name) {
        try { $name = (New-Object System.Security.Principal.SecurityIdentifier($Sid)).Translate([System.Security.Principal.NTAccount]).Value }
        catch { $name = $Sid }
    }
    $script:SidNames[$Sid] = $name
    return $name
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
$pkiDn = "CN=Public Key Services,CN=Services,$configDn"

$domSid = $null
try {
    $domEntry = [ADSI]"LDAP://$Server/$baseDn"
    $sidBytes = ConvertTo-ByteArray $domEntry.Properties['objectSid'][0]
    $domSid = [System.Security.Principal.SecurityIdentifier]::new($sidBytes, 0).Value
}
catch { }

Write-Host "Base DN: $baseDn" -ForegroundColor DarkGray

# Extended rights that matter on a certificate template
$RIGHT_ENROLL = [guid]'0e10c968-78fb-11d2-90d4-00c04f79dc55'
$RIGHT_AUTOENROLL = [guid]'a05b8cc2-17bc-4802-a710-e7c15ab866a2'

# Principals that should never hold enrolment on a sensitive template
$BROAD_SIDS = @('S-1-5-11', 'S-1-1-0', 'S-1-5-7')          # Authenticated Users, Everyone, Anonymous
$BROAD_RIDS = @('-513', '-515', '-514')                     # Domain Users, Domain Computers, Domain Guests

# ---------------------------------------------------------------
# 1. Certification authorities
# ---------------------------------------------------------------
Write-Step "[1/7] Certification authorities"

$cas = @()
try {
    $caRes = Search-Directory -Base "CN=Enrollment Services,$pkiDn" `
        -Filter '(objectClass=pKIEnrollmentService)' `
        -Properties 'cn', 'dnshostname', 'certificatetemplates', 'cacertificatedn', 'whencreated'

    $cas = foreach ($r in $caRes) {
        [PSCustomObject]@{
            Name          = Get-Prop $r 'cn'
            DnsHostName   = Get-Prop $r 'dnshostname'
            SubjectDn     = Get-Prop $r 'cacertificatedn'
            Created       = Get-Prop $r 'whencreated'
            TemplateCount = @($r.Properties['certificatetemplates']).Count
            Templates     = (@($r.Properties['certificatetemplates']) -join '; ')
        }
    }
    [void](Out-Table $cas 'ca')
    Write-Host "  CAs: $(@($cas).Count)"
    foreach ($c in $cas) { Write-Host "    $($c.Name) on $($c.DnsHostName), $($c.TemplateCount) published template(s)" }
}
catch { Write-Warning "CAs: $($_.Exception.Message)" }

# ---------------------------------------------------------------
# 2. Certificate templates
# ---------------------------------------------------------------
Write-Step "[2/7] Certificate templates"

$templates = New-Object System.Collections.Generic.List[object]
try {
    $published = @()
    foreach ($c in $cas) { $published += @($c.Templates -split '; ') }
    $published = @($published | Where-Object { $_ } | Sort-Object -Unique)

    $tplRes = Search-Directory -Base "CN=Certificate Templates,$pkiDn" `
        -Filter '(objectClass=pKICertificateTemplate)' `
        -Properties 'cn', 'displayname', 'mspki-certificate-name-flag', 'mspki-enrollment-flag',
                    'mspki-ra-signature', 'pkiextendedkeyusage', 'mspki-certificate-application-policy',
                    'ntsecuritydescriptor', 'whenchanged' -WithDacl

    foreach ($r in $tplRes) {
        $cn = Get-Prop $r 'cn'
        $nameFlag = [int](Get-Prop $r 'mspki-certificate-name-flag')
        $enrollFlag = [int](Get-Prop $r 'mspki-enrollment-flag')
        $raSig = [int](Get-Prop $r 'mspki-ra-signature')

        $ekus = @($r.Properties['pkiextendedkeyusage']) + @($r.Properties['mspki-certificate-application-policy'])
        $ekus = @($ekus | Where-Object { $_ } | Sort-Object -Unique)

        # 0x1 = ENROLLEE_SUPPLIES_SUBJECT: the requester chooses the identity
        $suppliesSubject = (($nameFlag -band 0x1) -ne 0)
        # 0x2 = PEND_ALL_REQUESTS: an operator must approve
        $managerApproval = (($enrollFlag -band 0x2) -ne 0)

        # EKUs that let a certificate be used to log on as somebody
        $authEkus = @('1.3.6.1.5.5.7.3.2', '1.3.6.1.5.2.3.4', '1.3.6.1.4.1.311.20.2.2', '2.5.29.37.0')
        $allowsAuth = $false
        if ($ekus.Count -eq 0) { $allowsAuth = $true }   # no EKU means any purpose
        foreach ($e in $ekus) { if ($authEkus -contains $e) { $allowsAuth = $true } }

        # who may enrol, and who may edit the template
        $enrollees = @(); $writers = @()
        try {
            $raw = ConvertTo-ByteArray (Get-Prop $r 'ntsecuritydescriptor')
            if ($raw) {
                $sd = New-Object System.DirectoryServices.ActiveDirectorySecurity
                $sd.SetSecurityDescriptorBinaryForm($raw)
                foreach ($ace in $sd.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) {
                    if ($ace.AccessControlType -ne 'Allow') { continue }
                    $sid = $ace.IdentityReference.Value
                    $rights = "$($ace.ActiveDirectoryRights)"
                    if ($ace.ObjectType -eq $RIGHT_ENROLL -or $ace.ObjectType -eq $RIGHT_AUTOENROLL) {
                        $enrollees += $sid
                    }
                    elseif ($rights -match 'GenericAll|WriteDacl|WriteOwner|WriteProperty') {
                        $writers += $sid
                    }
                }
            }
        }
        catch { }

        $enrollees = @($enrollees | Sort-Object -Unique)
        $writers = @($writers | Sort-Object -Unique)

        $broadEnroll = @($enrollees | Where-Object {
            $s = $_
            ($BROAD_SIDS -contains $s) -or (@($BROAD_RIDS | Where-Object { $s -like "*$_" }).Count -gt 0)
        })

        $templates.Add([PSCustomObject]@{
            Name             = $cn
            DisplayName      = Get-Prop $r 'displayname'
            Published        = ($published -contains $cn)
            SuppliesSubject  = $suppliesSubject
            ManagerApproval  = $managerApproval
            RaSignatures     = $raSig
            AllowsAuthentication = $allowsAuth
            Ekus             = ($ekus -join '; ')
            EnrolleeSids     = ($enrollees -join '; ')
            Enrollees        = (@($enrollees | ForEach-Object { Resolve-Sid $_ }) -join '; ')
            BroadEnrollment  = ($broadEnroll.Count -gt 0)
            BroadEnrollees   = (@($broadEnroll | ForEach-Object { Resolve-Sid $_ }) -join '; ')
            Writers          = (@($writers | ForEach-Object { Resolve-Sid $_ }) -join '; ')
            WhenChanged      = Get-Prop $r 'whenchanged'
        })
    }

    [void](Out-Table $templates 'templates')
    $risky = @($templates | Where-Object {
        $_.Published -and $_.SuppliesSubject -and $_.AllowsAuthentication -and
        -not $_.ManagerApproval -and $_.RaSignatures -eq 0 -and $_.BroadEnrollment
    })
    Write-Host "  templates: $($templates.Count), published: $(@($templates | Where-Object Published).Count)"
    Write-Host "  templates allowing subject choice + auth + open enrolment: $($risky.Count)" `
        -ForegroundColor $(if ($risky.Count) { 'Red' } else { 'Gray' })
    foreach ($t in $risky) { Write-Host "    RISKY  $($t.Name)  ->  $($t.BroadEnrollees)" -ForegroundColor Red }
}
catch { Write-Warning "Templates: $($_.Exception.Message)" }

# ---------------------------------------------------------------
# 3. LAPS coverage
# ---------------------------------------------------------------
Write-Step "[3/7] LAPS coverage"

$laps = New-Object System.Collections.Generic.List[object]
try {
    # Windows LAPS uses msLAPS-*, legacy Microsoft LAPS uses ms-Mcs-AdmPwd*.
    # Only expiry timestamps are read here, never a password value.
    $compRes = Search-Directory -Base $baseDn `
        -Filter '(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=8192)))' `
        -Properties 'samaccountname', 'operatingsystem', 'lastlogontimestamp', 'useraccountcontrol',
                    'mslaps-passwordexpirationtime', 'ms-mcs-admpwdexpirationtime', 'distinguishedname'

    foreach ($r in $compRes) {
        $uac = [int](Get-Prop $r 'useraccountcontrol')
        $newLaps = ConvertFrom-FileTimeSafe (Get-Prop $r 'mslaps-passwordexpirationtime')
        $oldLaps = ConvertFrom-FileTimeSafe (Get-Prop $r 'ms-mcs-admpwdexpirationtime')
        $lastOn = ConvertFrom-FileTimeSafe (Get-Prop $r 'lastlogontimestamp')

        $flavour = if ($newLaps) { 'Windows LAPS' } elseif ($oldLaps) { 'Legacy LAPS' } else { 'none' }
        $expiry = if ($newLaps) { $newLaps } else { $oldLaps }

        $laps.Add([PSCustomObject]@{
            Computer        = Get-Prop $r 'samaccountname'
            OperatingSystem = Get-Prop $r 'operatingsystem'
            LapsFlavour     = $flavour
            PasswordExpires = if ($expiry) { $expiry.ToString('yyyy-MM-dd') } else { $null }
            ExpiredDaysAgo  = if ($expiry -and $expiry -lt (Get-Date)) { [int]((Get-Date) - $expiry).TotalDays } else { $null }
            Enabled         = (($uac -band 2) -eq 0)
            LastLogonDaysAgo = if ($lastOn) { [int]((Get-Date) - $lastOn).TotalDays } else { $null }
            DistinguishedName = Get-Prop $r 'distinguishedname'
        })
    }

    [void](Out-Table $laps 'laps')
    $covered = @($laps | Where-Object { $_.LapsFlavour -ne 'none' })
    $active = @($laps | Where-Object { $_.Enabled -and ($null -eq $_.LastLogonDaysAgo -or $_.LastLogonDaysAgo -le $StaleComputerDays) })
    Write-Host "  computers: $($laps.Count), active: $($active.Count), with LAPS: $($covered.Count)"
}
catch { Write-Warning "LAPS: $($_.Exception.Message)" }

# ---------------------------------------------------------------
# 4. Protection of privileged accounts
# ---------------------------------------------------------------
Write-Step "[4/7] Privileged account protection"

$protection = New-Object System.Collections.Generic.List[object]
try {
    $UAC_NOT_DELEGATED = 0x100000

    $protUsersDn = $null
    try {
        $pu = [ADSI]"LDAP://$Server/<SID=$domSid-525>"     # Protected Users
        $protUsersDn = @($pu.Properties['distinguishedName'])[0]
    }
    catch { }

    $protUsersMembers = @()
    if ($protUsersDn) {
        try {
            $pm = Search-Directory -Base $baseDn `
                -Filter "(memberOf:1.2.840.113556.1.4.1941:=$protUsersDn)" -Properties 'samaccountname'
            $protUsersMembers = @($pm | ForEach-Object { Get-Prop $_ 'samaccountname' })
        }
        catch { }
    }

    # every account flagged as privileged by AdminSDHolder
    $admRes = Search-Directory -Base $baseDn `
        -Filter '(&(objectCategory=person)(objectClass=user)(adminCount=1))' `
        -Properties 'samaccountname', 'useraccountcontrol', 'admincount', 'lastlogontimestamp',
                    'pwdlastset', 'distinguishedname'

    foreach ($r in $admRes) {
        $uac = [int](Get-Prop $r 'useraccountcontrol')
        $name = Get-Prop $r 'samaccountname'
        $lastOn = ConvertFrom-FileTimeSafe (Get-Prop $r 'lastlogontimestamp')
        $protection.Add([PSCustomObject]@{
            Account            = $name
            Enabled            = (($uac -band 2) -eq 0)
            SensitiveNoDelegate = (($uac -band $UAC_NOT_DELEGATED) -ne 0)
            InProtectedUsers   = ($protUsersMembers -contains $name)
            LastLogonDaysAgo   = if ($lastOn) { [int]((Get-Date) - $lastOn).TotalDays } else { $null }
            DistinguishedName  = Get-Prop $r 'distinguishedname'
        })
    }

    [void](Out-Table $protection 'protection')
    $unprot = @($protection | Where-Object { -not $_.SensitiveNoDelegate -and -not $_.InProtectedUsers })
    Write-Host "  privileged accounts: $($protection.Count), Protected Users members: $($protUsersMembers.Count)"
    Write-Host "  neither sensitive nor protected: $($unprot.Count)" `
        -ForegroundColor $(if ($unprot.Count) { 'Yellow' } else { 'Gray' })
}
catch { Write-Warning "Protection: $($_.Exception.Message)" }

# ---------------------------------------------------------------
# 5. Computer inventory
# ---------------------------------------------------------------
Write-Step "[5/7] Computer inventory"

$computers = @()
try {
    $computers = $laps | Select-Object Computer, OperatingSystem, Enabled, LastLogonDaysAgo, DistinguishedName
    [void](Out-Table $computers 'computers')
    $byOs = $laps | Group-Object OperatingSystem | Sort-Object Count -Descending
    foreach ($o in $byOs) {
        $label = if ($o.Name) { $o.Name } else { '(not set)' }
        Write-Host ("    {0,-45} {1}" -f $label, $o.Count)
    }
}
catch { Write-Warning "Computers: $($_.Exception.Message)" }

# ---------------------------------------------------------------
# 6. Domain controller hardening
# ---------------------------------------------------------------
Write-Step "[6/7] Domain controller hardening"

$dcConfig = New-Object System.Collections.Generic.List[object]
if ($SkipDcConfig) { Write-Host "  skipped by request" -ForegroundColor DarkGray }
else {
    try {
        $dcRes = Search-Directory -Base "OU=Domain Controllers,$baseDn" `
            -Filter '(objectCategory=computer)' -Properties 'dnshostname'
        $dcHosts = @($dcRes | ForEach-Object { Get-Prop $_ 'dnshostname' } | Where-Object { $_ })

        # CAs are picked up automatically, plus anything passed in by hand
        $caHosts = @($cas | ForEach-Object { $_.DnsHostName } | Where-Object { $_ })
        $probeList = @()
        foreach ($h in $dcHosts) { $probeList += [PSCustomObject]@{ Host = $h; Role = 'DomainController' } }
        foreach ($h in $caHosts) {
            if ($dcHosts -notcontains $h) { $probeList += [PSCustomObject]@{ Host = $h; Role = 'CertificationAuthority' } }
        }
        foreach ($h in $ExtraHosts) {
            if (@($probeList.Host) -notcontains $h) { $probeList += [PSCustomObject]@{ Host = $h; Role = 'Extra' } }
        }

        foreach ($entry in $probeList) {
            $h = $entry.Host
            $row = [ordered]@{
                DomainController      = $h
                Role                  = $entry.Role
                SmbSigningRequired    = $null
                LdapServerIntegrity   = $null
                LdapChannelBinding    = $null
                LmCompatibilityLevel  = $null
                PrintSpoolerRunning   = $null
                Error                 = $null
            }
            try {
                $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $h)

                $k1 = $reg.OpenSubKey('SYSTEM\CurrentControlSet\Services\LanManServer\Parameters')
                if ($k1) { $row.SmbSigningRequired = $k1.GetValue('requiresecuritysignature') }

                $k2 = $reg.OpenSubKey('SYSTEM\CurrentControlSet\Services\NTDS\Parameters')
                if ($k2) {
                    $row.LdapServerIntegrity = $k2.GetValue('LDAPServerIntegrity')
                    $row.LdapChannelBinding = $k2.GetValue('LdapEnforceChannelBinding')
                }

                $k3 = $reg.OpenSubKey('SYSTEM\CurrentControlSet\Control\Lsa')
                if ($k3) { $row.LmCompatibilityLevel = $k3.GetValue('LmCompatibilityLevel') }

                $reg.Close()
            }
            catch { $row.Error = $_.Exception.Message }

            try {
                $svc = Get-Service -ComputerName $h -Name Spooler -ErrorAction Stop
                $row.PrintSpoolerRunning = ($svc.Status -eq 'Running')
            }
            catch { }

            $dcConfig.Add([PSCustomObject]$row)
        }

        [void](Out-Table $dcConfig 'dcconfig')
        Write-Host "  hosts probed: $($dcConfig.Count)  (DC: $(@($dcConfig | Where-Object { $_.Role -eq 'DomainController' }).Count), CA: $(@($dcConfig | Where-Object { $_.Role -eq 'CertificationAuthority' }).Count))"
        foreach ($c in $dcConfig) {
            if ($c.Error) { Write-Host "    $($c.DomainController): $($c.Error)" -ForegroundColor DarkYellow }
        }
    }
    catch { Write-Warning "DC config: $($_.Exception.Message)" }
}

# ---------------------------------------------------------------
# 7. Certification authority configuration
# ---------------------------------------------------------------
Write-Step "[7/7] CA configuration"

$caConfig = New-Object System.Collections.Generic.List[object]
if ($SkipCaConfig) { Write-Host "  skipped by request" -ForegroundColor DarkGray }
elseif (-not @($cas).Count) { Write-Host "  no CA to probe" -ForegroundColor DarkGray }
else {
    foreach ($c in $cas) {
        $h = $c.DnsHostName
        if (-not $h) { continue }

        $row = [ordered]@{
            CaName          = $c.Name
            CaHost          = $h
            EditFlags       = $null
            SanBypass       = $null      # EDITF_ATTRIBUTESUBJECTALTNAME2
            AuditFilter     = $null
            RequestDisposition = $null
            Officers        = $null
            Enrollers       = $null
            Error           = $null
        }

        # The policy module flags live in the registry on the CA itself.
        # EDITF_ATTRIBUTESUBJECTALTNAME2 lets any requester attach an
        # arbitrary alternative name, which defeats template restrictions.
        try {
            $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $h)
            $caRoot = $reg.OpenSubKey('SYSTEM\CurrentControlSet\Services\CertSvc\Configuration')
            if ($caRoot) {
                foreach ($sub in $caRoot.GetSubKeyNames()) {
                    $k = $caRoot.OpenSubKey($sub)
                    if (-not $k) { continue }
                    $audit = $k.GetValue('AuditFilter')
                    if ($null -ne $audit) { $row.AuditFilter = $audit }

                    $pol = $k.OpenSubKey('PolicyModules\CertificateAuthority_MicrosoftDefault.Policy')
                    if ($pol) {
                        $ef = $pol.GetValue('EditFlags')
                        if ($null -ne $ef) {
                            $row.EditFlags = $ef
                            # 0x00040000 = EDITF_ATTRIBUTESUBJECTALTNAME2
                            $row.SanBypass = ((([int]$ef) -band 0x00040000) -ne 0)
                        }
                        $rd = $pol.GetValue('RequestDisposition')
                        if ($null -ne $rd) { $row.RequestDisposition = $rd }
                    }
                }
            }
            $reg.Close()
        }
        catch { $row.Error = $_.Exception.Message }

        # Who may manage the CA. Needs certutil, which lives on the CA and on
        # any machine with the AD CS tools installed.
        try {
            $certutil = Get-Command certutil.exe -ErrorAction SilentlyContinue
            if ($certutil) {
                $sec = & certutil.exe -config "$h\$($c.Name)" -getreg CA\Security 2>$null
                $txt = ($sec | Out-String)
                $officers = [regex]::Matches($txt, 'Allow.*Manage CA.*?\s+([^\r\n]+)') |
                    ForEach-Object { $_.Groups[1].Value.Trim() }
                if ($officers) { $row.Officers = ($officers -join '; ') }
            }
        }
        catch { }

        $caConfig.Add([PSCustomObject]$row)
    }

    [void](Out-Table $caConfig 'caconfig')
    Write-Host "  CAs probed: $($caConfig.Count)"
    foreach ($c in $caConfig) {
        if ($c.Error) {
            Write-Host "    $($c.CaHost): $($c.Error)" -ForegroundColor DarkYellow
            Write-Host "    run on the CA itself:  certutil -getreg policy\EditFlags" -ForegroundColor DarkYellow
        }
        elseif ($c.SanBypass -eq $true) {
            Write-Host "    SAN BYPASS ENABLED on $($c.CaHost) - any request can claim any identity" -ForegroundColor Red
        }
        else {
            Write-Host "    $($c.CaHost): EditFlags $($c.EditFlags), SAN bypass $($c.SanBypass), audit filter $($c.AuditFilter)"
        }
    }
}

# ---------------------------------------------------------------
# Metadata
# ---------------------------------------------------------------
Complete-LastStep
$finishedAt = Get-Date

$metaFields = [ordered]@{}
$metaSpec = @(
    @{ Name = 'Domain';        Get = { [string]$Domain } }
    @{ Name = 'Server';        Get = { [string]$Server } }
    @{ Name = 'DomainSid';     Get = { [string]$domSid } }
    @{ Name = 'CollectedAt';   Get = { $startedAt.ToString('yyyy-MM-dd HH:mm:ss') } }
    @{ Name = 'FinishedAt';    Get = { $finishedAt.ToString('yyyy-MM-dd HH:mm:ss') } }
    @{ Name = 'ElapsedSec';    Get = { [double][math]::Round($sw.Elapsed.TotalSeconds, 1) } }
    @{ Name = 'CollectedBy';   Get = { [string]("$env:USERNAME on $env:COMPUTERNAME") } }
    @{ Name = 'CaCount';       Get = { [int]@($cas).Count } }
    @{ Name = 'TemplateCount'; Get = { [int]$templates.Count } }
    @{ Name = 'ComputerCount'; Get = { [int]$laps.Count } }
    @{ Name = 'AdminCount';    Get = { [int]$protection.Count } }
    @{ Name = 'DcProbed';      Get = { [int]$dcConfig.Count } }
    @{ Name = 'CaProbed';      Get = { [int]$caConfig.Count } }
)
foreach ($f in $metaSpec) {
    try { $metaFields[$f.Name] = & $f.Get }
    catch { $metaFields[$f.Name] = 'ERROR'; Write-Warning "meta field '$($f.Name)': $($_.Exception.Message)" }
}
try { [void](Out-Table ([PSCustomObject]$metaFields) 'adsecurity-meta') }
catch { Write-Warning "Could not write meta: $($_.Exception.Message)" }

if (-not $NoZip) {
    try {
        $zip = Join-Path (Split-Path $OutDir -Parent) ("adsec-$Domain-" + (Get-Date).ToString('yyyy-MM-dd') + ".zip")
        $files = Get-ChildItem $OutDir -Filter *.csv -File
        if ($files) { Compress-Archive -Path $files.FullName -DestinationPath $zip -Force }
        Write-Host "`nArchive: $zip" -ForegroundColor Green
    }
    catch { Write-Warning "Archive: $($_.Exception.Message)" }
}

$sw.Stop()
Write-Host ""
Write-Host ("=" * 52) -ForegroundColor Cyan
Write-Host ("  Total elapsed: " + (Format-Span $sw.Elapsed)) -ForegroundColor Green
Write-Host ("=" * 52) -ForegroundColor Cyan
Write-Host ""
Write-Host "Next step:  .\Analyze-AdSecurity.ps1 -Path '$OutDir'" -ForegroundColor Cyan
Write-Host ""