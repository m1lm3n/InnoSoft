<#
    Analyze-AdSecurity.ps1  -  ANALYSIS ONLY

    Reads the CSV files produced by Export-AdSecurity.ps1 and reports findings.
    Touches no domain controller.

    Sections:
        1. Certification authorities
        2. Certificate templates  - the ESC-style misconfigurations
        3. LAPS coverage
        4. Privileged account protection
        5. Computer inventory     - stale objects, unsupported systems
        6. DC hardening           - SMB and LDAP signing, NTLM, spooler
        7. Comparison             - optional diff against a previous export

    Usage:
        .\Analyze-AdSecurity.ps1 -Path c:\ad-export
        .\Analyze-AdSecurity.ps1 -Path c:\ad-export\2026-08-12 -ComparePath c:\ad-export\2026-08-05
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Path,

    [string]$Domain,
    [string]$ComparePath,
    [int]$StaleComputerDays = 90,

    # Accounts already known to be domain admins. Passing them in stops
    # template write rights held by an existing admin from being reported
    # as an extra privilege. Use the names from the AD health export.
    [string[]]$PrivilegedAccounts = @(),

    [switch]$NoCsv
)

$ErrorActionPreference = 'Stop'
$sw = [System.Diagnostics.Stopwatch]::StartNew()

$EOL_OS = @(
    'Windows 7', 'Windows 8', 'Windows XP', 'Windows Vista',
    'Server 2003', 'Server 2008', 'Server 2012'
)

function Import-Set {
    param([string]$Folder, [string]$Dom)
    if (-not (Test-Path $Folder)) { throw "Folder not found: $Folder" }
    if (-not $Dom) {
        $any = Get-ChildItem $Folder -Filter '*-templates.csv' | Select-Object -First 1
        if (-not $any) { throw "No *-templates.csv found in $Folder" }
        $Dom = $any.BaseName -replace '-templates$', ''
    }
    $set = @{ Domain = $Dom }
    foreach ($part in 'ca', 'caconfig', 'templates', 'laps', 'protection', 'computers',
                      'dcconfig', 'adsecurity-meta') {
        $file = Join-Path $Folder "$Dom-$part.csv"
        if (Test-Path $file) {
            $rows = @(Import-Csv $file)
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
    $color = switch ($Level) { 'high' { 'Red' } 'warn' { 'Yellow' } 'ok' { 'Green' } default { 'Gray' } }
    Write-Host "  $Text" -ForegroundColor $color
}

$d = Import-Set -Folder $Path -Dom $Domain
$Domain = $d.Domain
$meta = if ($d.'adsecurity-meta'.Count) { $d.'adsecurity-meta'[0] } else { $null }

Write-Host "`n=== AD security analysis: $Domain ===" -ForegroundColor Cyan
if ($meta) { Write-Host "Collected: $($meta.CollectedAt) from $($meta.Server) by $($meta.CollectedBy)" -ForegroundColor DarkGray }

$findings = New-Object System.Collections.Generic.List[object]
function Add-Finding {
    param([string]$Area, [string]$Severity, [string]$Item, [string]$Detail)
    $findings.Add([PSCustomObject]@{ Area = $Area; Severity = $Severity; Item = $Item; Detail = $Detail })
}

# ---------------------------------------------------------------
# 1. Certification authorities
# ---------------------------------------------------------------
Write-Section 'Certification authorities'

if (-not $d.ca.Count) {
    Write-Finding "No enterprise CA found in this forest" 'ok'
    Write-Finding "  Nothing to misconfigure here, but check whether certificates come" 'info'
    Write-Finding "  from somewhere else - a standalone CA leaves no trace in AD." 'info'
}
else {
    foreach ($c in $d.ca) {
        Write-Finding "$($c.Name) on $($c.DnsHostName)"
        Write-Finding "    subject:   $($c.SubjectDn)"
        Write-Finding "    published: $($c.TemplateCount) template(s)"
    }
}

# ---------------------------------------------------------------
# 1b. CA configuration
# ---------------------------------------------------------------
if ($d.caconfig.Count) {
    Write-Section 'CA configuration'
    foreach ($c in $d.caconfig) {
        Write-Finding "$($c.CaName) on $($c.CaHost)"
        if ($c.Error) {
            Write-Finding "    could not read the registry: $($c.Error)" 'warn'
            Write-Finding "    run on the CA:  certutil -getreg policy\EditFlags" 'info'
            Add-Finding 'CaConfig' 'medium' $c.CaName 'CA registry unreadable, check EditFlags by hand'
            continue
        }

        if ($c.SanBypass -eq 'True') {
            Write-Finding "    EDITF_ATTRIBUTESUBJECTALTNAME2: ENABLED" 'high'
            Write-Finding "    Any request may attach an arbitrary alternative name, so every" 'high'
            Write-Finding "    template that issues an authentication certificate becomes an" 'high'
            Write-Finding "    escalation path regardless of how carefully it is configured." 'high'
            Write-Finding "    Fix:  certutil -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2" 'info'
            Write-Finding "    then restart certsvc. Check first what relies on it." 'info'
            Add-Finding 'CaConfig' 'high' $c.CaName 'EDITF_ATTRIBUTESUBJECTALTNAME2 is enabled'
        }
        elseif ($c.SanBypass -eq 'False') {
            Write-Finding "    EDITF_ATTRIBUTESUBJECTALTNAME2: off" 'ok'
        }

        # AuditFilter 127 means every event category is audited
        if ($c.AuditFilter) {
            $af = [int]$c.AuditFilter
            Write-Finding "    audit filter: $af" $(if ($af -eq 127) { 'ok' } else { 'warn' })
            if ($af -ne 127) {
                Add-Finding 'CaConfig' 'medium' $c.CaName "CA auditing is partial (filter $af, full is 127)"
            }
        }
        else {
            Write-Finding "    audit filter: not set - certificate issuance is not audited" 'warn'
            Add-Finding 'CaConfig' 'medium' $c.CaName 'CA auditing is not configured'
        }

        # 1 = issue immediately, 0 = pend for approval
        if ($c.RequestDisposition) {
            Write-Finding "    request disposition: $($c.RequestDisposition)"
        }
        if ($c.Officers) { Write-Finding "    CA managers: $($c.Officers)" }
    }
}

# ---------------------------------------------------------------
# 2. Certificate templates
# ---------------------------------------------------------------
Write-Section 'Certificate templates'

$tpl = $d.templates
if (-not $tpl.Count) {
    Write-Finding "No templates collected" 'info'
}
else {
    $pub = @($tpl | Where-Object { $_.Published -eq 'True' })
    Write-Finding "Templates in the forest: $($tpl.Count), published by a CA: $($pub.Count)"

    # The classic escalation: the requester names the identity, the certificate
    # can be used to authenticate, and nobody has to approve the request.
    $esc1 = @($pub | Where-Object {
        $_.SuppliesSubject -eq 'True' -and
        $_.AllowsAuthentication -eq 'True' -and
        $_.ManagerApproval -ne 'True' -and
        [int]$_.RaSignatures -eq 0 -and
        $_.BroadEnrollment -eq 'True'
    })

    if ($esc1.Count) {
        Write-Host ""
        Write-Finding "TEMPLATE ESCALATION PATH: $($esc1.Count)" 'high'
        Write-Finding "  These published templates let the requester choose the subject, produce" 'high'
        Write-Finding "  a certificate usable for authentication, need no approval, and can be" 'high'
        Write-Finding "  enrolled by a broad group. Any domain user can then request a" 'high'
        Write-Finding "  certificate naming a domain admin and log in as them." 'high'
        foreach ($t in $esc1) {
            Write-Finding "    $($t.Name)  -  enrollable by: $($t.BroadEnrollees)" 'high'
            Add-Finding 'Certificates' 'high' $t.Name "subject choice + auth EKU + no approval, open to $($t.BroadEnrollees)"
        }
        Write-Finding "  Fix: require manager approval, drop ENROLLEE_SUPPLIES_SUBJECT, or" 'info'
        Write-Finding "  restrict enrolment to a named group." 'info'
    }
    else { Write-Finding "No template combines subject choice with open enrolment" 'ok' }

    # A template with no EKU, or the any-purpose EKU, is usable for anything.
    # Only interesting when someone outside the admin groups can enrol:
    # SubCA and similar built-ins are admin-only by design.
    $anyPurpose = @($pub | Where-Object {
        ($_.Ekus -match '2\.5\.29\.37\.0' -or -not $_.Ekus) -and $_.BroadEnrollment -eq 'True'
    })
    $anyPurposeAdmin = @($pub | Where-Object {
        ($_.Ekus -match '2\.5\.29\.37\.0' -or -not $_.Ekus) -and $_.BroadEnrollment -ne 'True'
    })
    if ($anyPurpose.Count) {
        Write-Host ""
        Write-Finding "Templates valid for any purpose, open enrolment: $($anyPurpose.Count)" 'high'
        foreach ($t in $anyPurpose) {
            Write-Finding "    $($t.Name)  enrollable by: $($t.Enrollees)" 'high'
            Add-Finding 'Certificates' 'high' $t.Name "any-purpose EKU enrollable by $($t.BroadEnrollees)"
        }
    }
    if ($anyPurposeAdmin.Count) {
        Write-Finding "Any-purpose templates limited to admins (expected): $($anyPurposeAdmin.Count)"
        foreach ($t in $anyPurposeAdmin) { Write-Finding "    $($t.Name) -> $($t.Enrollees)" }
    }

    # Write access on a template is as good as owning it
    # Write access on a template is as good as owning it, but only counts
    # when the holder is not already a domain administrator.
    $adminNames = @('Domain Admins', 'Enterprise Admins', 'Administrators', 'SYSTEM',
                    'Schema Admins', 'ENTERPRISE DOMAIN CONTROLLERS')
    if ($PrivilegedAccounts) { $adminNames += $PrivilegedAccounts }

    $writable = @()
    foreach ($t in $tpl) {
        if (-not $t.Writers) { continue }
        $who = @("$($t.Writers)" -split ';' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
        $extra = @($who | Where-Object { $adminNames -notcontains $_ })
        if ($extra.Count) {
            $writable += [PSCustomObject]@{ Name = $t.Name; Extra = ($extra -join '; ') }
        }
    }
    if ($writable.Count) {
        Write-Host ""
        Write-Finding "Templates writable outside the admin groups: $($writable.Count)" 'high'
        Write-Finding "  Whoever can edit a template can turn it into the escalation path above." 'info'
        foreach ($t in $writable) {
            Write-Finding "    $($t.Name)  writable by: $($t.Extra)" 'high'
            Add-Finding 'Certificates' 'high' $t.Name "editable by $($t.Extra)"
        }
    }
    else { Write-Finding "No template is writable outside the admin groups" 'ok' }

    Write-Host ""
    Write-Finding "Note: the CA flag EDITF_ATTRIBUTESUBJECTALTNAME2 is not visible from AD." 'info'
    Write-Finding "It lets any request add an alternative identity regardless of template." 'info'
    Write-Finding "Check on each CA with: certutil -getreg policy\EditFlags" 'info'
}

# ---------------------------------------------------------------
# 3. LAPS coverage
# ---------------------------------------------------------------
Write-Section 'LAPS coverage'

$laps = $d.laps
if (-not $laps.Count) {
    Write-Finding "No computer data collected" 'warn'
}
else {
    $active = @($laps | Where-Object {
        $_.Enabled -eq 'True' -and
        ($null -eq $_.LastLogonDaysAgo -or $_.LastLogonDaysAgo -eq '' -or [int]$_.LastLogonDaysAgo -le $StaleComputerDays)
    })
    $covered = @($active | Where-Object { $_.LapsFlavour -ne 'none' })
    $missing = @($active | Where-Object { $_.LapsFlavour -eq 'none' })
    $expired = @($covered | Where-Object { $_.ExpiredDaysAgo -and [int]$_.ExpiredDaysAgo -gt 7 })

    $pct = if ($active.Count) { [math]::Round(100 * $covered.Count / $active.Count, 1) } else { 0 }
    Write-Finding "Active computers: $($active.Count), with LAPS: $($covered.Count)  ($pct%)" `
        $(if ($pct -ge 90) { 'ok' } elseif ($pct -eq 0) { 'high' } else { 'warn' })

    if ($covered.Count -eq 0) {
        Write-Finding "  No machine has a LAPS-managed local administrator password." 'high'
        Write-Finding "  That means the local admin password is either identical everywhere or" 'high'
        Write-Finding "  set by hand. One recovered hash then opens every machine at once." 'high'
        Add-Finding 'LAPS' 'high' $Domain 'no computer has a LAPS managed password'
    }
    elseif ($missing.Count) {
        Write-Finding "  Active computers without LAPS: $($missing.Count)" 'warn'
        foreach ($m in ($missing | Select-Object -First 20)) {
            Write-Finding "    $($m.Computer)  [$($m.OperatingSystem)]"
        }
        if ($missing.Count -gt 20) { Write-Finding "    ... and $($missing.Count - 20) more" }
        Add-Finding 'LAPS' 'medium' $Domain "$($missing.Count) active computers without LAPS"
    }

    if ($expired.Count) {
        Write-Finding "  Passwords past their rotation date by over a week: $($expired.Count)" 'warn'
        Write-Finding "  Usually means the machine stopped talking to the domain." 'info'
        foreach ($e in ($expired | Select-Object -First 10)) {
            Write-Finding "    $($e.Computer) - $($e.ExpiredDaysAgo) days overdue" 'warn'
        }
        Add-Finding 'LAPS' 'medium' $Domain "$($expired.Count) machines with an overdue LAPS password"
    }
}

# ---------------------------------------------------------------
# 4. Privileged account protection
# ---------------------------------------------------------------
Write-Section 'Privileged account protection'

$prot = $d.protection
if (-not $prot.Count) {
    Write-Finding "No privileged accounts collected" 'warn'
}
else {
    $inProtected = @($prot | Where-Object { $_.InProtectedUsers -eq 'True' })
    $sensitive = @($prot | Where-Object { $_.SensitiveNoDelegate -eq 'True' })
    $neither = @($prot | Where-Object { $_.SensitiveNoDelegate -ne 'True' -and $_.InProtectedUsers -ne 'True' -and $_.Enabled -eq 'True' })

    Write-Finding "Accounts flagged by AdminSDHolder: $($prot.Count)"
    Write-Finding "  in Protected Users: $($inProtected.Count)"
    Write-Finding "  marked sensitive and not delegatable: $($sensitive.Count)"

    if ($neither.Count) {
        Write-Host ""
        Write-Finding "Unprotected privileged accounts: $($neither.Count)" 'high'
        Write-Finding "  A ticket for these can be forwarded by any host trusted for delegation," 'high'
        Write-Finding "  and their credentials can be cached on ordinary workstations." 'high'
        foreach ($p in $neither) {
            Write-Finding "    $($p.Account)" 'high'
            Add-Finding 'AccountProtection' 'high' $p.Account 'privileged account is neither sensitive nor in Protected Users'
        }
        Write-Finding "  Fix: add them to Protected Users, or set the sensitive flag. Test first:" 'info'
        Write-Finding "  Protected Users forbids NTLM and unconstrained delegation for its members." 'info'
    }
    else { Write-Finding "Every enabled privileged account is protected" 'ok' }
}

# ---------------------------------------------------------------
# 5. Computer inventory
# ---------------------------------------------------------------
Write-Section 'Computer inventory'

$comp = if ($d.computers.Count) { $d.computers } else { $laps }
if ($comp.Count) {
    $enabled = @($comp | Where-Object { $_.Enabled -eq 'True' })
    $stale = @($enabled | Where-Object { $_.LastLogonDaysAgo -and [int]$_.LastLogonDaysAgo -gt $StaleComputerDays })

    Write-Finding "Computers: $($comp.Count), enabled: $($enabled.Count), stale over $StaleComputerDays days: $($stale.Count)"

    $byOs = $comp | Group-Object OperatingSystem | Sort-Object Count -Descending
    foreach ($o in $byOs) {
        $label = if ($o.Name) { $o.Name } else { '(not set)' }
        $eol = $false
        foreach ($p in $EOL_OS) { if ($label -like "*$p*") { $eol = $true } }
        Write-Finding ("    {0,-45} {1}" -f $label, $o.Count) $(if ($eol) { 'high' } else { 'info' })
        if ($eol) { Add-Finding 'Computers' 'high' $label "$($o.Count) machines on an unsupported system" }
    }

    if ($stale.Count) {
        Write-Finding "  Stale computer objects clutter the directory and keep working credentials." 'warn'
        Add-Finding 'Computers' 'low' $Domain "$($stale.Count) computer objects unused for over $StaleComputerDays days"
    }
}

# ---------------------------------------------------------------
# 6. DC hardening
# ---------------------------------------------------------------
Write-Section 'Domain controller hardening'

$dcc = $d.dcconfig
if (-not $dcc.Count) {
    Write-Finding "No data - the remote registry service is usually the reason" 'warn'
}
else {
    foreach ($c in $dcc) {
        $role = if ($c.Role) { " [$($c.Role)]" } else { '' }
        Write-Finding "$($c.DomainController)$role"
        if ($c.Error) {
            Write-Finding "    could not read: $($c.Error)" 'warn'
            continue
        }

        # SMB signing: 1 = required
        $smb = $c.SmbSigningRequired
        Write-Finding "    SMB signing required:   $smb" $(if ($smb -eq '1') { 'ok' } else { 'high' })
        if ($smb -ne '1') {
            Add-Finding 'DcHardening' 'high' $c.DomainController 'SMB signing is not required'
        }

        # LDAPServerIntegrity: 2 = signing required
        $ldap = $c.LdapServerIntegrity
        Write-Finding "    LDAP signing required:  $ldap" $(if ($ldap -eq '2') { 'ok' } else { 'high' })
        if ($ldap -ne '2') {
            Add-Finding 'DcHardening' 'high' $c.DomainController 'LDAP signing is not enforced'
        }

        # LdapEnforceChannelBinding: 2 = always
        $cb = $c.LdapChannelBinding
        Write-Finding "    LDAP channel binding:   $cb" $(if ($cb -eq '2') { 'ok' } else { 'warn' })
        if ($cb -ne '2') {
            Add-Finding 'DcHardening' 'medium' $c.DomainController 'LDAP channel binding is not enforced'
        }

        # LmCompatibilityLevel: 5 = NTLMv2 only
        $lm = $c.LmCompatibilityLevel
        Write-Finding "    LM compatibility level: $lm" $(if ($lm -eq '5') { 'ok' } else { 'warn' })
        if ($lm -and $lm -ne '5') {
            Add-Finding 'DcHardening' 'medium' $c.DomainController "LmCompatibilityLevel is $lm, not 5"
        }

        # The spooler on a DC is a well known relay target
        if ($c.PrintSpoolerRunning -eq 'True') {
            $what = if ($c.Role -eq 'CertificationAuthority') { 'a certification authority' } else { 'a domain controller' }
            Write-Finding "    Print Spooler:          running" 'high'
            Add-Finding 'DcHardening' 'high' $c.DomainController "Print Spooler is running on $what"
        }
        elseif ($c.PrintSpoolerRunning -eq 'False') {
            Write-Finding "    Print Spooler:          stopped" 'ok'
        }
    }
}

# ---------------------------------------------------------------
# 7. Comparison
# ---------------------------------------------------------------
if ($ComparePath) {
    Write-Section 'Comparison with previous run'
    $p = Import-Set -Folder $ComparePath -Dom $Domain
    if ($p.'adsecurity-meta'.Count) { Write-Finding "Baseline collected: $($p.'adsecurity-meta'[0].CollectedAt)" }

    $oldT = @($p.templates | ForEach-Object { "$($_.Name)|$($_.Enrollees)" })
    $newT = @($tpl | ForEach-Object { "$($_.Name)|$($_.Enrollees)" })
    foreach ($x in ($newT | Where-Object { $oldT -notcontains $_ })) {
        Write-Finding "    + template/enrolment $x" 'high'
        Add-Finding 'Certificates' 'high' $x 'template or its enrolment rights changed since the baseline'
    }
    foreach ($x in ($oldT | Where-Object { $newT -notcontains $_ })) { Write-Finding "    - template/enrolment $x" 'warn' }

    # --- hardening state: the whole point of running this twice ---
    $oldCfg = @{}
    foreach ($x in $p.dcconfig) { $oldCfg[$x.DomainController] = $x }
    $cfgChanges = 0
    foreach ($n in $dcc) {
        if (-not $oldCfg.ContainsKey($n.DomainController)) {
            Write-Finding "    + host $($n.DomainController)" 'warn'
            continue
        }
        $o = $oldCfg[$n.DomainController]
        foreach ($field in 'SmbSigningRequired', 'LdapServerIntegrity', 'LdapChannelBinding',
                           'LmCompatibilityLevel', 'PrintSpoolerRunning') {
            $ov = "$($o.$field)"; $nv = "$($n.$field)"
            if ($ov -ne $nv) {
                $cfgChanges++
                # spooler stopping is an improvement, starting is not
                $better = ($field -eq 'PrintSpoolerRunning' -and $nv -eq 'False') -or
                          ($field -ne 'PrintSpoolerRunning' -and $nv -gt $ov)
                $lvl = if ($better) { 'ok' } else { 'high' }
                Write-Finding "    ~ $($n.DomainController) $field : '$ov' -> '$nv'" $lvl
                if (-not $better) {
                    Add-Finding 'DcHardening' 'high' $n.DomainController "$field weakened: $ov -> $nv"
                }
            }
        }
    }
    Write-Finding "Hardening settings changed: $cfgChanges" $(if ($cfgChanges) { 'warn' } else { 'ok' })

    # --- privileged account protection ---
    $oldProt = @{}
    foreach ($x in $p.protection) { $oldProt[$x.Account] = $x }
    foreach ($n in $prot) {
        if (-not $oldProt.ContainsKey($n.Account)) {
            Write-Finding "    + privileged account $($n.Account)" 'high'
            Add-Finding 'AccountProtection' 'high' $n.Account 'newly flagged as privileged since the baseline'
            continue
        }
        $o = $oldProt[$n.Account]
        if ($o.InProtectedUsers -ne $n.InProtectedUsers -or $o.SensitiveNoDelegate -ne $n.SensitiveNoDelegate) {
            Write-Finding "    ~ $($n.Account) protection changed: protected $($o.InProtectedUsers)->$($n.InProtectedUsers), sensitive $($o.SensitiveNoDelegate)->$($n.SensitiveNoDelegate)" 'warn'
        }
    }
    foreach ($o in $p.protection) {
        if (-not (@($prot.Account) -contains $o.Account)) { Write-Finding "    - privileged account $($o.Account)" }
    }

    # --- LAPS coverage trend ---
    $oldCov = @($p.laps | Where-Object { $_.LapsFlavour -ne 'none' }).Count
    $newCov = @($laps | Where-Object { $_.LapsFlavour -ne 'none' }).Count
    if ($oldCov -ne $newCov) {
        $lvl = if ($newCov -gt $oldCov) { 'ok' } else { 'high' }
        Write-Finding "LAPS coverage: $oldCov -> $newCov computers" $lvl
    }

    # --- CA flags ---
    if ($p.caconfig.Count -and $d.caconfig.Count) {
        $oldCa = @{}
        foreach ($x in $p.caconfig) { $oldCa[$x.CaName] = $x }
        foreach ($n in $d.caconfig) {
            if ($oldCa.ContainsKey($n.CaName) -and $oldCa[$n.CaName].SanBypass -ne $n.SanBypass) {
                Write-Finding "    ~ $($n.CaName) SAN bypass: $($oldCa[$n.CaName].SanBypass) -> $($n.SanBypass)" 'high'
                Add-Finding 'CaConfig' 'high' $n.CaName "EDITF_ATTRIBUTESUBJECTALTNAME2 changed to $($n.SanBypass)"
            }
        }
    }

    # --- computers ---
    $oldC = @($p.computers.Computer); $newC = @($comp.Computer)
    Write-Finding "Computers added: $(@($newC | Where-Object { $oldC -notcontains $_ }).Count)"
    Write-Finding "Computers removed: $(@($oldC | Where-Object { $newC -notcontains $_ }).Count)"
}

# ---------------------------------------------------------------
# Output
# ---------------------------------------------------------------
if (-not $NoCsv -and $findings.Count) {
    $out = Join-Path $Path "$Domain-adsecurity-findings.csv"
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
Write-Host ("  Total elapsed: " + [math]::Round($sw.Elapsed.TotalSeconds, 2) + " sec") -ForegroundColor Green
Write-Host ""