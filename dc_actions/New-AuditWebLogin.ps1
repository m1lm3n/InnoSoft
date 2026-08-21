<#
    New-AuditWebLogin.ps1

    Provisions the backend's SQL login - ad_audit_web by default - with the
    scoped permissions decided for it (see project_web_architecture_plan):
    read access to the whole database (it needs to read Findings/Runs, the
    collector's tables, via Dapper) but write access ONLY to the cfg schema
    it owns (Targets, DomainCredentials, AuditLog). It must never be able to
    alter the audit-history tables the PowerShell collector writes - that
    separation is the entire point of having two logins instead of one.

    Same DBA-run, sysadmin-once pattern as New-AuditDatabaseLogin.ps1 - see
    that script's header for the SQL Server setup prerequisite. Run this
    after that one; it assumes the AdAudit database and ad_audit_svc
    already exist.

    Schema creation/migrations for the cfg tables themselves are NOT done
    here and not done by ad_audit_web at runtime - EF Core Migrations are
    applied separately using a trusted (Windows Integrated) connection, by
    whoever is deploying. ad_audit_web only ever gets DML rights
    (SELECT/INSERT/UPDATE/DELETE), never CREATE/ALTER - keeps "who can
    change the schema" and "what the running app can do" cleanly separate.

    Usage
        .\New-AuditWebLogin.ps1
        .\New-AuditWebLogin.ps1 -ResetPassword
#>

[CmdletBinding()]
param(
    [string]$SqlServer,
    [string]$Database,
    [string]$LoginName = 'ad_audit_web',
    [string]$Schema = 'cfg',

    [System.Security.SecureString]$Password,
    [switch]$ResetPassword,
    [System.Management.Automation.PSCredential]$AdminCredential,

    [string]$DbConfigPath
)

$ErrorActionPreference = 'Stop'

if (-not $DbConfigPath) { $DbConfigPath = Join-Path $PSScriptRoot 'db.psd1' }

if (-not $SqlServer -or -not $Database) {
    if (-not (Test-Path $DbConfigPath)) { throw "db.psd1 not found at $DbConfigPath and -SqlServer/-Database not given." }
    $dbCfg = Import-PowerShellDataFile -Path $DbConfigPath
    if (-not $SqlServer) { $SqlServer = $dbCfg.SqlServer }
    if (-not $Database) { $Database = $dbCfg.Database }
}

function New-StrongPassword {
    param([int]$Length = 20)
    $upper = 'ABCDEFGHJKLMNPQRSTUVWXYZ'; $lower = 'abcdefghijkmnpqrstuvwxyz'
    $digit = '23456789'; $punct = '!@#$%^&*-_=+'
    $all = $upper + $lower + $digit + $punct
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    function Get-RandomChar { param([string]$Set)
        $len = $Set.Length; $limit = 256 - (256 % $len); $b = [byte[]]::new(1)
        do { $rng.GetBytes($b) } while ($b[0] -ge $limit)
        return $Set[$b[0] % $len]
    }
    $chars = [System.Collections.Generic.List[char]]::new()
    $chars.Add((Get-RandomChar $upper)); $chars.Add((Get-RandomChar $lower))
    $chars.Add((Get-RandomChar $digit)); $chars.Add((Get-RandomChar $punct))
    while ($chars.Count -lt $Length) { $chars.Add((Get-RandomChar $all)) }
    for ($i = $chars.Count - 1; $i -gt 0; $i--) {
        $b = [byte[]]::new(1); $limit = 256 - (256 % ($i + 1))
        do { $rng.GetBytes($b) } while ($b[0] -ge $limit)
        $j = $b[0] % ($i + 1); $tmp = $chars[$i]; $chars[$i] = $chars[$j]; $chars[$j] = $tmp
    }
    -join $chars
}

$generatedPassword = $null
if (-not $Password) {
    $generatedPassword = New-StrongPassword
    $Password = ConvertTo-SecureString -String $generatedPassword -AsPlainText -Force
}
$plainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto(
    [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password))

function New-AdminConnection {
    param([string]$InitialCatalog = 'master')
    $csb = New-Object System.Text.StringBuilder
    [void]$csb.Append("Server=$SqlServer;Database=$InitialCatalog;Connect Timeout=15;")
    if ($AdminCredential) {
        [void]$csb.Append("User ID=$($AdminCredential.UserName);Password=$($AdminCredential.GetNetworkCredential().Password);")
    }
    else { [void]$csb.Append("Integrated Security=True;") }
    [void]$csb.Append("Encrypt=False;TrustServerCertificate=True;")
    $conn = New-Object System.Data.SqlClient.SqlConnection($csb.ToString())
    $conn.Open()
    return $conn
}

Write-Host ""
Write-Host "Server:   $SqlServer" -ForegroundColor Cyan
Write-Host "Database: $Database" -ForegroundColor Cyan
Write-Host "Login:    $LoginName" -ForegroundColor Cyan
Write-Host "Schema:   $Schema (read/write) + whole database (read-only)" -ForegroundColor Cyan
Write-Host ""

# ---------------------------------------------------------------
# 1. Login (master)
# ---------------------------------------------------------------
$conn = New-AdminConnection -InitialCatalog 'master'
try {
    $cmd = $conn.CreateCommand()
    $cmd.CommandText = 'SELECT SUSER_ID(@login)'
    [void]$cmd.Parameters.AddWithValue('@login', $LoginName)
    $loginExists = $cmd.ExecuteScalar()
    $loginExists = -not ($loginExists -is [DBNull] -or $null -eq $loginExists)

    if (-not $loginExists) {
        $create = $conn.CreateCommand()
        $create.CommandText = @'
DECLARE @login sysname = @loginname;
DECLARE @pwd sysname = @password;
DECLARE @sql nvarchar(max) = N'CREATE LOGIN ' + QUOTENAME(@login) +
    N' WITH PASSWORD = ' + QUOTENAME(@pwd, '''') + N', CHECK_POLICY = ON, CHECK_EXPIRATION = OFF';
EXEC(@sql);
'@
        [void]$create.Parameters.AddWithValue('@loginname', $LoginName)
        [void]$create.Parameters.AddWithValue('@password', $plainPassword)
        [void]$create.ExecuteNonQuery()
        Write-Host "  created login $LoginName" -ForegroundColor Green
    }
    elseif ($ResetPassword) {
        $alter = $conn.CreateCommand()
        $alter.CommandText = @'
DECLARE @login sysname = @loginname;
DECLARE @pwd sysname = @password;
DECLARE @sql nvarchar(max) = N'ALTER LOGIN ' + QUOTENAME(@login) + N' WITH PASSWORD = ' + QUOTENAME(@pwd, '''');
EXEC(@sql);
'@
        [void]$alter.Parameters.AddWithValue('@loginname', $LoginName)
        [void]$alter.Parameters.AddWithValue('@password', $plainPassword)
        [void]$alter.ExecuteNonQuery()
        Write-Host "  password reset for $LoginName" -ForegroundColor Green
    }
    else {
        Write-Host "  login $LoginName already exists, password left unchanged (use -ResetPassword to change it)" -ForegroundColor DarkGray
        $generatedPassword = $null
    }
}
finally { $conn.Close() }

# ---------------------------------------------------------------
# 2. User + schema + scoped grants (AdAudit)
# ---------------------------------------------------------------
$conn = New-AdminConnection -InitialCatalog $Database
try {
    $cmd = $conn.CreateCommand()
    $cmd.CommandText = 'SELECT USER_ID(@login)'
    [void]$cmd.Parameters.AddWithValue('@login', $LoginName)
    $userExists = $cmd.ExecuteScalar()
    $userExists = -not ($userExists -is [DBNull] -or $null -eq $userExists)

    if (-not $userExists) {
        $create = $conn.CreateCommand()
        $create.CommandText = @'
DECLARE @n sysname = @loginname;
DECLARE @sql nvarchar(max) = N'CREATE USER ' + QUOTENAME(@n) + N' FOR LOGIN ' + QUOTENAME(@n);
EXEC(@sql);
'@
        [void]$create.Parameters.AddWithValue('@loginname', $LoginName)
        [void]$create.ExecuteNonQuery()
        Write-Host "  created database user $LoginName" -ForegroundColor Green
    }
    else {
        Write-Host "  database user $LoginName already exists" -ForegroundColor DarkGray
    }

    # db_datareader: needs to read Findings/Runs/fact tables (Dapper), and
    # everything in the cfg schema too - the scoped grant below only ADDS
    # write, read already covers the whole database via this role.
    $chk = $conn.CreateCommand()
    $chk.CommandText = 'SELECT IS_ROLEMEMBER(@role, @login)'
    [void]$chk.Parameters.AddWithValue('@role', 'db_datareader')
    [void]$chk.Parameters.AddWithValue('@login', $LoginName)
    $isMember = $chk.ExecuteScalar()
    if ($isMember -isnot [int] -or $isMember -ne 1) {
        $add = $conn.CreateCommand()
        $add.CommandText = @'
DECLARE @n sysname = @loginname;
DECLARE @sql nvarchar(max) = N'ALTER ROLE db_datareader ADD MEMBER ' + QUOTENAME(@n);
EXEC(@sql);
'@
        [void]$add.Parameters.AddWithValue('@loginname', $LoginName)
        [void]$add.ExecuteNonQuery()
        Write-Host "  added to db_datareader" -ForegroundColor Green
    }
    else {
        Write-Host "  already a member of db_datareader" -ForegroundColor DarkGray
    }

    # Create the cfg schema if EF Migrations haven't run yet, so the grant
    # below has something to attach to - Migrations owning the schema
    # afterwards is fine, GRANT on a schema doesn't require owning it.
    $schemaCmd = $conn.CreateCommand()
    $schemaCmd.CommandText = @'
DECLARE @s sysname = @schema;
IF SCHEMA_ID(@s) IS NULL
BEGIN
    DECLARE @sql nvarchar(max) = N'CREATE SCHEMA ' + QUOTENAME(@s);
    EXEC(@sql);
END
'@
    [void]$schemaCmd.Parameters.AddWithValue('@schema', $Schema)
    [void]$schemaCmd.ExecuteNonQuery()

    $grantCmd = $conn.CreateCommand()
    $grantCmd.CommandText = @'
DECLARE @s sysname = @schema;
DECLARE @n sysname = @loginname;
DECLARE @sql nvarchar(max) = N'GRANT SELECT, INSERT, UPDATE, DELETE ON SCHEMA::' + QUOTENAME(@s) + N' TO ' + QUOTENAME(@n);
EXEC(@sql);
'@
    [void]$grantCmd.Parameters.AddWithValue('@schema', $Schema)
    [void]$grantCmd.Parameters.AddWithValue('@loginname', $LoginName)
    [void]$grantCmd.ExecuteNonQuery()
    Write-Host "  granted SELECT/INSERT/UPDATE/DELETE on schema $Schema" -ForegroundColor Green
}
finally { $conn.Close() }

if ($generatedPassword) {
    Write-Host ""
    Write-Host "Generated password (shown once, not stored anywhere by this script):" -ForegroundColor Yellow
    Write-Host "  $generatedPassword" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Done." -ForegroundColor Cyan
Write-Host ""
