<#
    AuditDb.psm1

    Makes MS SQL Server the durable store for audit runs, replacing the
    dated CSV folders (C:\audit\<domain>\<date>\*.csv) that used to be kept
    forever. Everything talks to SQL through plain ADO.NET
    (System.Data.SqlClient), which ships with PowerShell 5.1 / .NET
    Framework, so there is no module to install on the server that will run
    this daily.

    Why rehydration instead of teaching the analyzers SQL
        Analyze-AdHealth.ps1, Analyze-AdSecurity.ps1 and Analyze-GpoMap.ps1
        each carry several hundred lines of severity rules and ad hoc
        diff-against-baseline logic keyed off the raw CSV columns. Rather
        than rewrite that, a domain's previous run is pulled back out of
        SQL as the exact same CSV files the collectors would have written
        (Export-RunToCsvFolder), and the analyzers run completely
        unmodified against "today's fresh folder" + "yesterday's rehydrated
        folder", exactly the two-path contract they already have.

    Round-trip safety
        Every fact-table data column is NVARCHAR (sized generously, or MAX
        for semicolon-joined list/DN columns) and copied byte-for-byte in
        both directions - SqlBulkCopy straight from the string properties
        Import-Csv already gave us, Export-RunToCsvFolder straight back out
        with Export-Csv. RunId is the only INT anywhere in these tables.
        Deliberately not clever: counts, bools and dates all still look
        like plain ints/bools/dates in the CSVs, but they carry sentinels
        ('never', blank, raw repadmin-formatted text) inconsistently enough
        across the ~28 files that typing any of them strictly in SQL risks
        a rehydrated folder an analyzer would parse differently from the
        original. NVARCHAR everywhere makes that impossible by
        construction, at the cost of no native numeric/date queries in SQL
        - acceptable since the analyzers, not SQL, own all of that logic.

    The "Empty" sentinel
        Export-*.ps1's Out-Table writes a single line containing the text
        `"Empty"` (via Set-Content) when a section has zero rows, because
        Export-Csv throws on null pipeline input. Import-Csv parses that
        one-line file as a header with no data rows, i.e. zero rows -
        exactly what Import-Set in each analyzer expects. Rehydration
        reproduces that same one-line file with the same Set-Content call
        for any table that has zero rows for the RunId being rehydrated.

    Usage
        Import-Module .\AuditDb.psm1
        Test-AuditDbConnection
        $prev = Get-PreviousRunId -Domain 'nnn.lo'
        if ($prev) { Export-RunToCsvFolder -RunId $prev.RunId -Domain 'nnn.lo' -OutDir $tmp }
        $run = Save-AuditRun -Domain 'nnn.lo' -Server 'dc-nnn.nnn.lo' -RunDate (Get-Date) -DataPath $localDir
#>

# ---------------------------------------------------------------
# Schema: the single source of truth for CREATE TABLE, CSV -> SQL
# loading and SQL -> CSV rehydration.
#
# Suffix   the file name suffix Export-*.ps1 uses: "$Domain-$Suffix.csv"
# Table    the SQL table it loads into
# Max      columns stored as NVARCHAR(MAX) instead of NVARCHAR(400):
#          distinguished names, semicolon-joined lists, free text that can
#          run long
# Alias    SQL column name -> CSV column name, only where the CSV's own
#          column would otherwise collide with the RunId/Domain tag columns
#          every fact table carries (only domaininfo.csv's own "Domain"
#          column needs this)
# ---------------------------------------------------------------
$script:FactTables = [ordered]@{
    'AdHealth_Dcs'          = @{ Toolkit = 'adhealth'; Suffix = 'dcs'
        Columns = 'Name', 'Site', 'DnsHostName', 'IsGlobalCatalog', 'IsRodc', 'OperatingSystem', 'LastLogon', 'DistinguishedName'
        Max     = 'DistinguishedName' }
    'AdHealth_Fsmo'         = @{ Toolkit = 'adhealth'; Suffix = 'fsmo'
        Columns = 'Role', 'Holder'; Max = @() }
    'AdHealth_Replication'  = @{ Toolkit = 'adhealth'; Suffix = 'replication'
        Columns = 'DestinationSite', 'DestinationDsa', 'NamingContext', 'SourceSite', 'SourceDsa', 'Transport', 'Failures', 'LastFailureTime', 'LastSuccessTime', 'LastFailureStatus'
        Max     = 'NamingContext', 'LastFailureStatus' }
    'AdHealth_Backup'       = @{ Toolkit = 'adhealth'; Suffix = 'backup'
        Columns = 'Partition', 'LastBackup'; Max = 'Partition' }
    'AdHealth_Sites'        = @{ Toolkit = 'adhealth'; Suffix = 'sites'
        Columns = 'Site', 'Description', 'DcCount', 'SubnetCount'; Max = @() }
    'AdHealth_Subnets'      = @{ Toolkit = 'adhealth'; Suffix = 'subnets'
        Columns = 'Subnet', 'Site', 'Description', 'Location'; Max = @() }
    'AdHealth_SiteLinks'    = @{ Toolkit = 'adhealth'; Suffix = 'sitelinks'
        Columns = 'Name', 'Cost', 'IntervalMinutes', 'Sites'; Max = 'Sites' }
    'AdHealth_Privileged'   = @{ Toolkit = 'adhealth'; Suffix = 'privileged'
        Columns = 'Group', 'Member', 'Class', 'Enabled', 'PasswordNeverExpires', 'AdminCount', 'PasswordLastSet', 'PasswordAgeDays', 'LastLogon', 'LastLogonDaysAgo', 'DistinguishedName'
        Max     = 'DistinguishedName' }
    'AdHealth_DomainInfo'   = @{ Toolkit = 'adhealth'; Suffix = 'domaininfo'
        Columns = 'Domain', 'DomainSid', 'DomainFunctionLevel', 'ForestFunctionLevel', 'RecycleBinEnabled', 'TombstoneLifetime', 'MaxPasswordAgeDays', 'MinPasswordAgeDays', 'MinPasswordLength', 'PasswordHistory', 'LockoutThreshold', 'LockoutDurationMin', 'KrbtgtPasswordSet', 'KrbtgtPasswordAgeDays'
        Max     = @(); Alias = @{ 'Domain' = 'DomainFqdn' } }
    'AdHealth_Delegation'   = @{ Toolkit = 'adhealth'; Suffix = 'delegation'
        Columns = 'Name', 'Class', 'IsDomainController', 'DelegationType', 'AllowedTo', 'RbcdAllowedFrom', 'Spn', 'Sensitive', 'Enabled', 'DistinguishedName'
        Max     = 'AllowedTo', 'RbcdAllowedFrom', 'Spn', 'DistinguishedName' }
    'AdHealth_Spn'          = @{ Toolkit = 'adhealth'; Suffix = 'spn'
        Columns = 'Name', 'Description', 'SpnCount', 'Spn', 'Enabled', 'PasswordNeverExpires', 'NoPreauth', 'ReversiblePassword', 'AdminCount', 'EncryptionTypes', 'PasswordLastSet', 'PasswordAgeDays', 'LastLogonDaysAgo', 'MemberOf', 'DistinguishedName'
        Max     = 'Spn', 'MemberOf', 'DistinguishedName' }

    'AdSecurity_Ca'         = @{ Toolkit = 'adsecurity'; Suffix = 'ca'
        Columns = 'Name', 'DnsHostName', 'SubjectDn', 'Created', 'TemplateCount', 'Templates'
        Max     = 'SubjectDn', 'Templates' }
    'AdSecurity_Templates'  = @{ Toolkit = 'adsecurity'; Suffix = 'templates'
        Columns = 'Name', 'DisplayName', 'Published', 'SuppliesSubject', 'ManagerApproval', 'RaSignatures', 'AllowsAuthentication', 'Ekus', 'EnrolleeSids', 'Enrollees', 'BroadEnrollment', 'BroadEnrollees', 'Writers', 'WhenChanged'
        Max     = 'Ekus', 'EnrolleeSids', 'Enrollees', 'BroadEnrollees', 'Writers' }
    'AdSecurity_Laps'       = @{ Toolkit = 'adsecurity'; Suffix = 'laps'
        Columns = 'Computer', 'OperatingSystem', 'LapsFlavour', 'PasswordExpires', 'ExpiredDaysAgo', 'Enabled', 'LastLogonDaysAgo', 'DistinguishedName'
        Max     = 'DistinguishedName' }
    'AdSecurity_Protection' = @{ Toolkit = 'adsecurity'; Suffix = 'protection'
        Columns = 'Account', 'Enabled', 'SensitiveNoDelegate', 'InProtectedUsers', 'LastLogonDaysAgo', 'DistinguishedName'
        Max     = 'DistinguishedName' }
    'AdSecurity_Computers'  = @{ Toolkit = 'adsecurity'; Suffix = 'computers'
        Columns = 'Computer', 'OperatingSystem', 'Enabled', 'LastLogonDaysAgo', 'DistinguishedName'
        Max     = 'DistinguishedName' }
    'AdSecurity_DcConfig'   = @{ Toolkit = 'adsecurity'; Suffix = 'dcconfig'
        Columns = 'DomainController', 'Role', 'SmbSigningRequired', 'LdapServerIntegrity', 'LdapChannelBinding', 'LmCompatibilityLevel', 'PrintSpoolerRunning', 'Error'
        Max     = @() }
    'AdSecurity_CaConfig'   = @{ Toolkit = 'adsecurity'; Suffix = 'caconfig'
        Columns = 'CaName', 'CaHost', 'EditFlags', 'SanBypass', 'AuditFilter', 'RequestDisposition', 'Officers', 'Error'
        Max     = 'Officers' }

    'Gpo_Ou'                = @{ Toolkit = 'gpo'; Suffix = 'ou'
        Columns = 'DistinguishedName', 'Name', 'Description', 'InheritBlocked', 'Depth'
        Max     = 'DistinguishedName' }
    'Gpo_Links'             = @{ Toolkit = 'gpo'; Suffix = 'links'
        Columns = 'Target', 'InheritBlocked', 'Order', 'DisplayName', 'Enabled', 'Enforced', 'GpoId'
        Max     = 'Target' }
    'Gpo_Wmi'               = @{ Toolkit = 'gpo'; Suffix = 'wmi'
        Columns = 'Name', 'Query'; Max = 'Query' }
    'Gpo_Gpo'               = @{ Toolkit = 'gpo'; Suffix = 'gpo'
        Columns = 'DisplayName', 'Id', 'GpoStatus', 'CreationTime', 'ModificationTime', 'Owner', 'UserVersionAD', 'UserVersionSysvol', 'ComputerVersionAD', 'ComputerVersionSysvol', 'WmiFilter'
        Max     = @() }
    'Gpo_Permissions'       = @{ Toolkit = 'gpo'; Suffix = 'permissions'
        Columns = 'Gpo', 'GpoId', 'Trustee', 'TrusteeSid', 'SidType', 'Permission', 'Inherited', 'Applies'
        Max     = @() }
    'Gpo_ApplyAces'         = @{ Toolkit = 'gpo'; Suffix = 'applyaces'
        Columns = 'Gpo', 'GpoCn', 'TrusteeSid', 'Trustee', 'AceType', 'Rights', 'Inherited'
        Max     = 'Rights' }
    'Gpo_GroupMembers'      = @{ Toolkit = 'gpo'; Suffix = 'groupmembers'
        Columns = 'GroupName', 'GroupSid', 'MemberDn', 'MemberName', 'MemberClass', 'Note'
        Max     = 'MemberDn' }
}

# Single-row-per-run metadata files: Suffix -> Toolkit. Loaded as key/value
# pairs into RunMeta rather than their own fact table, since their columns
# are just whatever the collector happened to compute that run.
$script:MetaSuffixes = @{
    'adhealth-meta'   = 'adhealth'
    'adsecurity-meta' = 'adsecurity'
    'meta'            = 'gpo'
}

# Analyzer output: Suffix -> the "Source" label AuditHtml.psm1 already uses.
$script:FindingsSuffixes = @{
    'findings'            = 'Group Policy'
    'adhealth-findings'   = 'AD Health'
    'adsecurity-findings' = 'AD Security'
}

# Order Get-MetaForDomain's CSV-path fallback already relies on: gpo meta
# first, then adhealth, then adsecurity, first non-empty value per key wins.
$script:MetaToolkitOrder = 'gpo', 'adhealth', 'adsecurity'

$script:ReservedColumnNames = 'Order', 'Group'

function Format-SqlIdent {
    # Brackets the handful of column names that collide with T-SQL
    # keywords. Only needed in raw SQL text - ADO.NET metadata (DataTable
    # columns, SqlBulkCopy mappings) is not affected by this.
    param([string]$Name)
    if ($script:ReservedColumnNames -contains $Name) { return "[$Name]" }
    return $Name
}

# ---------------------------------------------------------------
# Configuration and connections
# ---------------------------------------------------------------
function Get-AuditDbConfig {
    [CmdletBinding()]
    param(
        [string]$Path = (Join-Path $PSScriptRoot 'db.psd1'),
        [string]$CredentialPath = (Join-Path $env:USERPROFILE '.dc_actions\creds\_db.cred.xml')
    )

    if (-not (Test-Path $Path)) { throw "db.psd1 not found at $Path. It must sit next to the scripts." }
    try { $cfg = Import-PowerShellDataFile -Path $Path -ErrorAction Stop }
    catch { throw "db.psd1 could not be parsed: $($_.Exception.Message)" }

    if (-not $cfg.Contains('SqlServer') -or -not $cfg['SqlServer']) { throw "db.psd1: SqlServer is required" }
    if (-not $cfg.Contains('Database') -or -not $cfg['Database']) { throw "db.psd1: Database is required" }
    if (-not $cfg.Contains('ConnectTimeoutSec')) { $cfg['ConnectTimeoutSec'] = 15 }
    if (-not $cfg.Contains('CommandTimeoutSec')) { $cfg['CommandTimeoutSec'] = 120 }

    if (-not (Test-Path $CredentialPath)) {
        throw "No SQL login stored at $CredentialPath. Run: .\Initialize-AuditDatabase.ps1 -SetCredential"
    }
    try { $cred = Import-Clixml -Path $CredentialPath }
    catch { throw "Stored SQL login at $CredentialPath is unusable (different account or machine?): $($_.Exception.Message)" }

    $cfg['Credential'] = $cred
    return $cfg
}

function Get-AuditDbConnectionString {
    param([hashtable]$Config)
    $user = $Config.Credential.UserName
    $plain = $Config.Credential.GetNetworkCredential().Password
    # Encrypt=False/TrustServerCertificate=True: everything is localhost by
    # design (see targets.psd1's header - this mirrors that "all on one
    # box" assumption), so there is no network hop to protect against.
    return ("Server={0};Database={1};User ID={2};Password={3};Connect Timeout={4};Encrypt=False;TrustServerCertificate=True;" -f `
            $Config.SqlServer, $Config.Database, $user, $plain, $Config.ConnectTimeoutSec)
}

function New-AuditDbConnection {
    [CmdletBinding()]
    param([hashtable]$Config)
    if (-not $Config) { $Config = Get-AuditDbConfig }
    $connStr = Get-AuditDbConnectionString -Config $Config
    $conn = New-Object System.Data.SqlClient.SqlConnection($connStr)
    $conn.Open()
    return [PSCustomObject]@{ Connection = $conn; Config = $Config }
}

function Test-AuditDbConnection {
    [CmdletBinding()]
    param()
    try {
        $ctx = New-AuditDbConnection
        try {
            $cmd = $ctx.Connection.CreateCommand()
            $cmd.CommandText = 'SELECT 1'
            [void]$cmd.ExecuteScalar()
            return $true
        }
        finally { $ctx.Connection.Close() }
    }
    catch {
        Write-Warning "SQL Server unreachable: $($_.Exception.Message)"
        return $false
    }
}

# ---------------------------------------------------------------
# Schema creation - idempotent, safe to re-run after adding a table
# ---------------------------------------------------------------
function Initialize-AuditDatabaseSchema {
    [CmdletBinding()]
    param([hashtable]$Config)

    $ctx = New-AuditDbConnection -Config $Config
    try {
        $conn = $ctx.Connection

        function Invoke-Ddl {
            param([string]$Sql)
            $cmd = $conn.CreateCommand()
            $cmd.CommandTimeout = 120
            $cmd.CommandText = $Sql
            [void]$cmd.ExecuteNonQuery()
        }

        Invoke-Ddl @"
IF OBJECT_ID('dbo.Runs') IS NULL
BEGIN
    CREATE TABLE dbo.Runs (
        RunId      INT IDENTITY(1,1) PRIMARY KEY,
        Domain     NVARCHAR(64)   NOT NULL,
        Server     NVARCHAR(256)  NULL,
        RunDate    DATE           NOT NULL,
        StartedAt  DATETIME2(0)   NOT NULL DEFAULT SYSUTCDATETIME(),
        FinishedAt DATETIME2(0)   NULL,
        Status     NVARCHAR(20)   NOT NULL DEFAULT 'running',
        Detail     NVARCHAR(1000) NULL
    );
    CREATE NONCLUSTERED INDEX IX_Runs_Domain_Status ON dbo.Runs (Domain, Status, RunId DESC);
END
"@

        Invoke-Ddl @"
IF OBJECT_ID('dbo.RunMeta') IS NULL
BEGIN
    CREATE TABLE dbo.RunMeta (
        RunId     INT           NOT NULL REFERENCES dbo.Runs(RunId),
        Toolkit   NVARCHAR(20)  NOT NULL,
        MetaKey   NVARCHAR(100) NOT NULL,
        MetaValue NVARCHAR(MAX) NULL,
        CONSTRAINT PK_RunMeta PRIMARY KEY (RunId, Toolkit, MetaKey)
    );
END
"@

        Invoke-Ddl @"
IF OBJECT_ID('dbo.Findings') IS NULL
BEGIN
    CREATE TABLE dbo.Findings (
        FindingId BIGINT IDENTITY(1,1) PRIMARY KEY,
        RunId     INT            NOT NULL REFERENCES dbo.Runs(RunId),
        Domain    NVARCHAR(64)   NOT NULL,
        Source    NVARCHAR(40)   NOT NULL,
        Area      NVARCHAR(100)  NOT NULL,
        Severity  NVARCHAR(10)   NOT NULL,
        Item      NVARCHAR(1000) NOT NULL,
        Detail    NVARCHAR(MAX)  NULL
    );
    CREATE NONCLUSTERED INDEX IX_Findings_RunId ON dbo.Findings (RunId);
    CREATE NONCLUSTERED INDEX IX_Findings_DedupKey ON dbo.Findings (RunId, Source, Area, Item);
END
"@

        foreach ($tableName in $script:FactTables.Keys) {
            $def = $script:FactTables[$tableName]
            $colSql = New-Object System.Collections.Generic.List[string]
            foreach ($col in $def.Columns) {
                $sqlCol = if ($def.Alias -and $def.Alias.Contains($col)) { $def.Alias[$col] } else { $col }
                # Every data column is NVARCHAR (see this module's header):
                # RunId is the only INT in these tables, so the string a
                # collector wrote is always exactly the string SqlBulkCopy
                # loads and Export-RunToCsvFolder later hands back.
                $type = if (@($def.Max) -contains $col) { 'NVARCHAR(MAX)' } else { 'NVARCHAR(400)' }
                $colSql.Add("$(Format-SqlIdent $sqlCol) $type NULL")
            }
            $ddl = @"
IF OBJECT_ID('dbo.$tableName') IS NULL
BEGIN
    CREATE TABLE dbo.$tableName (
        FactId BIGINT IDENTITY(1,1) PRIMARY KEY,
        RunId  INT          NOT NULL REFERENCES dbo.Runs(RunId),
        Domain NVARCHAR(64) NOT NULL,
        $($colSql -join ",`n        ")
    );
    CREATE NONCLUSTERED INDEX IX_$($tableName)_RunId ON dbo.$tableName (RunId);
END
"@
            Invoke-Ddl $ddl
        }

        Write-Verbose "Schema present/created: Runs, RunMeta, Findings, $($script:FactTables.Count) fact tables"
    }
    finally { $ctx.Connection.Close() }
}

# ---------------------------------------------------------------
# CSV -> SQL
# ---------------------------------------------------------------
function Test-EmptySentinel {
    # Mirrors Import-Set's own check in every Analyze-*.ps1: a file whose
    # only column is "Empty" (or that parsed to zero rows at all) means the
    # collector found nothing for that section.
    param($Rows)
    $rows = @($Rows)
    if ($rows.Count -eq 0) { return $true }
    return ($rows[0].PSObject.Properties.Name -eq 'Empty')
}

function ConvertTo-FactDataTable {
    param([string]$TableName, [hashtable]$Def, [object[]]$Rows, [int]$RunId, [string]$Domain)

    $dt = New-Object System.Data.DataTable
    [void]$dt.Columns.Add('RunId', [int])
    [void]$dt.Columns.Add('Domain', [string])
    foreach ($col in $Def.Columns) {
        $sqlCol = if ($Def.Alias -and $Def.Alias.Contains($col)) { $Def.Alias[$col] } else { $col }
        [void]$dt.Columns.Add($sqlCol, [string])
    }

    foreach ($row in $Rows) {
        $dr = $dt.NewRow()
        $dr['RunId'] = $RunId
        $dr['Domain'] = $Domain
        foreach ($col in $Def.Columns) {
            $sqlCol = if ($Def.Alias -and $Def.Alias.Contains($col)) { $Def.Alias[$col] } else { $col }
            $val = $row.$col
            $dr[$sqlCol] = if ($null -eq $val -or $val -eq '') { [DBNull]::Value } else { [string]$val }
        }
        $dt.Rows.Add($dr)
    }
    return , $dt
}

function Import-FactTableRows {
    param($Connection, $Transaction, [string]$TableName, [System.Data.DataTable]$DataTable, [int]$CommandTimeoutSec)
    if ($DataTable.Rows.Count -eq 0) { return }
    $bulk = New-Object System.Data.SqlClient.SqlBulkCopy($Connection, [System.Data.SqlClient.SqlBulkCopyOptions]::Default, $Transaction)
    $bulk.DestinationTableName = "dbo.$TableName"
    $bulk.BulkCopyTimeout = $CommandTimeoutSec
    foreach ($col in $DataTable.Columns) { [void]$bulk.ColumnMappings.Add($col.ColumnName, $col.ColumnName) }
    $bulk.WriteToServer($DataTable)
}

function Import-RunMetaRows {
    param($Connection, $Transaction, [int]$RunId, [string]$Toolkit, $MetaRow)
    if ($null -eq $MetaRow) { return }
    $cmd = $Connection.CreateCommand()
    $cmd.Transaction = $Transaction
    $cmd.CommandText = 'INSERT INTO dbo.RunMeta (RunId, Toolkit, MetaKey, MetaValue) VALUES (@r, @t, @k, @v)'
    [void]$cmd.Parameters.Add('@r', [System.Data.SqlDbType]::Int)
    [void]$cmd.Parameters.Add('@t', [System.Data.SqlDbType]::NVarChar, 20)
    [void]$cmd.Parameters.Add('@k', [System.Data.SqlDbType]::NVarChar, 100)
    [void]$cmd.Parameters.Add('@v', [System.Data.SqlDbType]::NVarChar, -1)
    foreach ($p in $MetaRow.PSObject.Properties) {
        $cmd.Parameters['@r'].Value = $RunId
        $cmd.Parameters['@t'].Value = $Toolkit
        $cmd.Parameters['@k'].Value = $p.Name
        $cmd.Parameters['@v'].Value = if ($null -eq $p.Value -or $p.Value -eq '') { [DBNull]::Value } else { [string]$p.Value }
        [void]$cmd.ExecuteNonQuery()
    }
}

function Import-FindingsRows {
    param($Connection, $Transaction, [int]$RunId, [string]$Domain, [string]$Source, [object[]]$Rows, [int]$CommandTimeoutSec)
    $rows = @($Rows) | Where-Object { -not (Test-EmptySentinel @($_)) }
    if (-not $rows.Count) { return }

    $dt = New-Object System.Data.DataTable
    foreach ($c in 'RunId', 'Domain', 'Source', 'Area', 'Severity', 'Item', 'Detail') { [void]$dt.Columns.Add($c, [string]) }
    foreach ($r in $rows) {
        $dr = $dt.NewRow()
        $dr['RunId'] = $RunId
        $dr['Domain'] = $Domain
        $dr['Source'] = $Source
        $dr['Area'] = [string]$r.Area
        $dr['Severity'] = "$($r.Severity)".ToLower()
        $dr['Item'] = [string]$r.Item
        $dr['Detail'] = if ($null -eq $r.Detail) { [DBNull]::Value } else { [string]$r.Detail }
        $dt.Rows.Add($dr)
    }
    $bulk = New-Object System.Data.SqlClient.SqlBulkCopy($Connection, [System.Data.SqlClient.SqlBulkCopyOptions]::Default, $Transaction)
    $bulk.DestinationTableName = 'dbo.Findings'
    $bulk.BulkCopyTimeout = $CommandTimeoutSec
    foreach ($col in $dt.Columns) { [void]$bulk.ColumnMappings.Add($col.ColumnName, $col.ColumnName) }
    $bulk.WriteToServer($dt)
}

function Save-AuditRun {
    <#
        .SYNOPSIS
        Loads one domain's freshly-collected CSV folder (and, if present,
        its three *-findings.csv analyzer outputs) into SQL as a single
        RunId, inside one transaction: either everything for this domain
        lands, or nothing does.

        .PARAMETER DataPath
        The local dated folder run-remote.ps1 just unpacked - the same
        folder the analyzers were pointed at with -Path.

        .OUTPUTS
        PSCustomObject with RunId and Status. Throws on failure; the caller
        is expected to catch it, keep DataPath on disk, and carry on.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Domain,
        [string]$Server,
        [Parameter(Mandatory = $true)][datetime]$RunDate,
        [Parameter(Mandatory = $true)][string]$DataPath,
        [hashtable]$Config
    )

    if (-not (Test-Path $DataPath)) { throw "DataPath not found: $DataPath" }
    if (-not $Config) { $Config = Get-AuditDbConfig }

    $ctx = New-AuditDbConnection -Config $Config
    $conn = $ctx.Connection
    $timeout = [int]$Config.CommandTimeoutSec
    $runId = $null

    try {
        $insertCmd = $conn.CreateCommand()
        $insertCmd.CommandText = @"
INSERT INTO dbo.Runs (Domain, Server, RunDate, Status)
OUTPUT INSERTED.RunId
VALUES (@d, @s, @rd, 'running')
"@
        [void]$insertCmd.Parameters.AddWithValue('@d', $Domain)
        [void]$insertCmd.Parameters.AddWithValue('@s', $(if ($Server) { $Server } else { [DBNull]::Value }))
        [void]$insertCmd.Parameters.AddWithValue('@rd', $RunDate.Date)
        $runId = [int]$insertCmd.ExecuteScalar()
    }
    catch {
        $conn.Close()
        throw "Could not create a Runs row for $Domain : $($_.Exception.Message)"
    }

    $tx = $conn.BeginTransaction()
    try {
        # One writer per domain at a time. A second overlapping run for the
        # same domain (manual run stacked on the scheduled task) fails fast
        # here instead of racing on RunId ordering or a half-loaded table.
        $lockCmd = $conn.CreateCommand()
        $lockCmd.Transaction = $tx
        $lockCmd.CommandText = 'DECLARE @r INT; EXEC @r = sp_getapplock @Resource = @res, @LockMode = N''Exclusive'', @LockOwner = N''Transaction'', @LockTimeout = 30000; SELECT @r'
        [void]$lockCmd.Parameters.AddWithValue('@res', "auditrun_$Domain")
        $lockResult = [int]$lockCmd.ExecuteScalar()
        if ($lockResult -lt 0) { throw "Could not acquire the load lock for $Domain (code $lockResult) - another run may be in progress" }

        $csvFiles = Get-ChildItem -Path $DataPath -Filter "$Domain-*.csv" -File
        $prefix = "$Domain-"
        $tableBySuffix = @{}
        foreach ($t in $script:FactTables.Keys) { $tableBySuffix[$script:FactTables[$t].Suffix] = $t }

        foreach ($file in $csvFiles) {
            $suffix = $file.BaseName.Substring($prefix.Length)

            if ($tableBySuffix.Contains($suffix)) {
                $tableName = $tableBySuffix[$suffix]
                $def = $script:FactTables[$tableName]
                $rows = @(Import-Csv $file.FullName)
                if (-not (Test-EmptySentinel $rows)) {
                    $dt = ConvertTo-FactDataTable -TableName $tableName -Def $def -Rows $rows -RunId $runId -Domain $Domain
                    Import-FactTableRows -Connection $conn -Transaction $tx -TableName $tableName -DataTable $dt -CommandTimeoutSec $timeout
                }
            }
            elseif ($script:MetaSuffixes.Contains($suffix)) {
                $rows = @(Import-Csv $file.FullName)
                if (-not (Test-EmptySentinel $rows)) {
                    Import-RunMetaRows -Connection $conn -Transaction $tx -RunId $runId -Toolkit $script:MetaSuffixes[$suffix] -MetaRow $rows[0]
                }
            }
            elseif ($script:FindingsSuffixes.Contains($suffix)) {
                $rows = @(Import-Csv $file.FullName)
                Import-FindingsRows -Connection $conn -Transaction $tx -RunId $runId -Domain $Domain -Source $script:FindingsSuffixes[$suffix] -Rows $rows -CommandTimeoutSec $timeout
            }
            # anything else (e.g. a legacy -filtering.csv) is not part of
            # the known schema and is skipped rather than guessed at
        }

        $doneCmd = $conn.CreateCommand()
        $doneCmd.Transaction = $tx
        $doneCmd.CommandText = "UPDATE dbo.Runs SET Status = 'ok', FinishedAt = SYSUTCDATETIME() WHERE RunId = @r"
        [void]$doneCmd.Parameters.AddWithValue('@r', $runId)
        [void]$doneCmd.ExecuteNonQuery()

        $tx.Commit()
        return [PSCustomObject]@{ RunId = $runId; Status = 'ok' }
    }
    catch {
        try { $tx.Rollback() } catch { }
        $msg = $_.Exception.Message
        try {
            $failCmd = $conn.CreateCommand()
            $failCmd.CommandText = "UPDATE dbo.Runs SET Status = 'failed', Detail = @d, FinishedAt = SYSUTCDATETIME() WHERE RunId = @r"
            [void]$failCmd.Parameters.AddWithValue('@d', $msg.Substring(0, [Math]::Min(999, $msg.Length)))
            [void]$failCmd.Parameters.AddWithValue('@r', $runId)
            [void]$failCmd.ExecuteNonQuery()
        }
        catch { Write-Warning "Also failed to mark RunId $runId as failed: $($_.Exception.Message)" }
        throw "Loading $Domain into SQL failed (RunId $runId marked failed): $msg"
    }
    finally { $conn.Close() }
}

# ---------------------------------------------------------------
# SQL -> CSV (baseline rehydration)
# ---------------------------------------------------------------
function Get-PreviousRunId {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Domain, [hashtable]$Config)
    if (-not $Config) { $Config = Get-AuditDbConfig }
    $ctx = New-AuditDbConnection -Config $Config
    try {
        $cmd = $ctx.Connection.CreateCommand()
        $cmd.CommandText = "SELECT TOP 1 RunId, RunDate FROM dbo.Runs WHERE Domain = @d AND Status = 'ok' ORDER BY RunId DESC"
        [void]$cmd.Parameters.AddWithValue('@d', $Domain)
        $reader = $cmd.ExecuteReader()
        try {
            if ($reader.Read()) {
                return [PSCustomObject]@{ RunId = [int]$reader['RunId']; RunDate = [datetime]$reader['RunDate'] }
            }
            return $null
        }
        finally { $reader.Close() }
    }
    finally { $ctx.Connection.Close() }
}

function Write-RehydratedCsv {
    param([string]$Path, [System.Collections.Generic.List[object]]$Rows)
    if ($Rows.Count -eq 0) {
        # byte-identical to Out-Table's own empty-section output
        Set-Content -Path $Path -Value '"Empty"' -Encoding UTF8
    }
    else {
        $Rows.ToArray() | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8
    }
}

function Export-RunToCsvFolder {
    <#
        .SYNOPSIS
        Re-creates the CSV folder a given RunId came from, so an analyzer
        can use it as -ComparePath exactly as if the original dated folder
        had never been deleted.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][int]$RunId,
        [Parameter(Mandatory = $true)][string]$Domain,
        [Parameter(Mandatory = $true)][string]$OutDir,
        [hashtable]$Config
    )
    if (-not $Config) { $Config = Get-AuditDbConfig }
    if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir -Force | Out-Null }

    $ctx = New-AuditDbConnection -Config $Config
    try {
        $conn = $ctx.Connection

        foreach ($tableName in $script:FactTables.Keys) {
            $def = $script:FactTables[$tableName]
            $selectCols = foreach ($col in $def.Columns) {
                $sqlCol = if ($def.Alias -and $def.Alias.Contains($col)) { $def.Alias[$col] } else { $col }
                "$(Format-SqlIdent $sqlCol) AS $(Format-SqlIdent $col)"
            }
            $cmd = $conn.CreateCommand()
            $cmd.CommandText = "SELECT $($selectCols -join ', ') FROM dbo.$tableName WHERE RunId = @r"
            [void]$cmd.Parameters.AddWithValue('@r', $RunId)

            $rows = New-Object System.Collections.Generic.List[object]
            $reader = $cmd.ExecuteReader()
            try {
                while ($reader.Read()) {
                    $obj = [ordered]@{}
                    foreach ($col in $def.Columns) {
                        $v = $reader[$col]
                        $obj[$col] = if ($v -is [DBNull]) { '' } else { [string]$v }
                    }
                    $rows.Add([PSCustomObject]$obj)
                }
            }
            finally { $reader.Close() }

            Write-RehydratedCsv -Path (Join-Path $OutDir "$Domain-$($def.Suffix).csv") -Rows $rows
        }

        foreach ($suffix in $script:MetaSuffixes.Keys) {
            $toolkit = $script:MetaSuffixes[$suffix]
            $cmd = $conn.CreateCommand()
            $cmd.CommandText = 'SELECT MetaKey, MetaValue FROM dbo.RunMeta WHERE RunId = @r AND Toolkit = @t'
            [void]$cmd.Parameters.AddWithValue('@r', $RunId)
            [void]$cmd.Parameters.AddWithValue('@t', $toolkit)

            $obj = [ordered]@{}
            $reader = $cmd.ExecuteReader()
            try { while ($reader.Read()) { $obj[[string]$reader['MetaKey']] = [string]$reader['MetaValue'] } }
            finally { $reader.Close() }

            $rows = New-Object System.Collections.Generic.List[object]
            if ($obj.Count) { $rows.Add([PSCustomObject]$obj) }
            Write-RehydratedCsv -Path (Join-Path $OutDir "$Domain-$suffix.csv") -Rows $rows
        }
    }
    finally { $ctx.Connection.Close() }
}

# ---------------------------------------------------------------
# Read paths for AuditHtml.psm1
# ---------------------------------------------------------------
function Get-FindingsFromDb {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][int]$RunId, [hashtable]$Config)
    if (-not $Config) { $Config = Get-AuditDbConfig }
    $ctx = New-AuditDbConnection -Config $Config
    try {
        $cmd = $ctx.Connection.CreateCommand()
        $cmd.CommandText = 'SELECT Source, Area, Severity, Item, Detail FROM dbo.Findings WHERE RunId = @r'
        [void]$cmd.Parameters.AddWithValue('@r', $RunId)
        $rows = New-Object System.Collections.Generic.List[object]
        $reader = $cmd.ExecuteReader()
        try {
            while ($reader.Read()) {
                $rows.Add([PSCustomObject]@{
                        Source   = [string]$reader['Source']
                        Area     = [string]$reader['Area']
                        Severity = "$($reader['Severity'])".ToLower()
                        Item     = [string]$reader['Item']
                        Detail   = $(if ($reader['Detail'] -is [DBNull]) { '' } else { [string]$reader['Detail'] })
                    })
            }
        }
        finally { $reader.Close() }
        return , @($rows.ToArray())
    }
    finally { $ctx.Connection.Close() }
}

function Get-RunMetaFromDb {
    # Mirrors Get-MetaForDomain's own semantics: gpo meta, then adhealth,
    # then adsecurity, first non-empty value per key wins.
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][int]$RunId, [hashtable]$Config)
    if (-not $Config) { $Config = Get-AuditDbConfig }
    $ctx = New-AuditDbConnection -Config $Config
    try {
        $cmd = $ctx.Connection.CreateCommand()
        $cmd.CommandText = 'SELECT Toolkit, MetaKey, MetaValue FROM dbo.RunMeta WHERE RunId = @r'
        [void]$cmd.Parameters.AddWithValue('@r', $RunId)
        $byToolkit = @{}
        $reader = $cmd.ExecuteReader()
        try {
            while ($reader.Read()) {
                $tk = [string]$reader['Toolkit']
                if (-not $byToolkit.Contains($tk)) { $byToolkit[$tk] = @{} }
                $byToolkit[$tk][[string]$reader['MetaKey']] = $(if ($reader['MetaValue'] -is [DBNull]) { '' } else { [string]$reader['MetaValue'] })
            }
        }
        finally { $reader.Close() }

        $out = [ordered]@{}
        foreach ($tk in $script:MetaToolkitOrder) {
            if (-not $byToolkit.Contains($tk)) { continue }
            foreach ($k in $byToolkit[$tk].Keys) {
                $v = $byToolkit[$tk][$k]
                if ($v -and -not $out.Contains($k)) { $out[$k] = $v }
            }
        }
        return $out
    }
    finally { $ctx.Connection.Close() }
}

Export-ModuleMember -Function `
    Get-AuditDbConfig, Test-AuditDbConnection, Initialize-AuditDatabaseSchema, `
    Save-AuditRun, Get-PreviousRunId, Export-RunToCsvFolder, `
    Get-FindingsFromDb, Get-RunMetaFromDb
