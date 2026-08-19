<#
    New-AuditDatabaseLogin.ps1

    One-time, DBA-run provisioning step: creates the AdAudit database and a
    dedicated, least-privilege SQL login for it (ad_audit_svc by default).
    This is the manual prerequisite Initialize-AuditDatabase.ps1's header
    describes - running it here instead of by hand in SSMS keeps it
    idempotent and repeatable.

    Needs sysadmin rights the first time (creating a database and a login
    is not something the ad_audit_svc login itself can ever be granted, by
    design - it only ever gets db_datareader/db_datawriter/db_ddladmin on
    the one database it owns). By default this connects with the current
    Windows account via Integrated Security, which is sysadmin on a fresh
    SQL Server Express install for whoever ran the installer. Pass
    -AdminCredential for a SQL login (e.g. sa) instead.

    This script only provisions the SQL-side login - it does not store the
    password anywhere. Run it once as whoever administers SQL Server, then
    have whoever will actually run run-remote.ps1 (the scheduled task
    account) run:

        .\Initialize-AuditDatabase.ps1 -SetCredential

    entering the same login/password, so the DPAPI-encrypted store is
    created under the account that needs to read it later. Running that
    step from this script would encrypt the credential for the wrong
    account whenever the DBA and the scheduled task are not the same user.

    Usage
        .\New-AuditDatabaseLogin.ps1
        .\New-AuditDatabaseLogin.ps1 -SqlServer 'localhost\SQLEXPRESS'
        .\New-AuditDatabaseLogin.ps1 -LoginName 'ad_audit_svc' -Password (Read-Host -AsSecureString)
        .\New-AuditDatabaseLogin.ps1 -ResetPassword
        .\New-AuditDatabaseLogin.ps1 -AdminCredential (Get-Credential sa)
#>

[CmdletBinding()]
param(
    [string]$SqlServer,
    [string]$Database,
    [string]$LoginName = 'ad_audit_svc',

    # Leave unset to have a strong password generated and printed once.
    [System.Security.SecureString]$Password,

    # Change the password on an already-existing login instead of leaving
    # it untouched.
    [switch]$ResetPassword,

    # SQL login with sysadmin rights, instead of the current Windows account
    [System.Management.Automation.PSCredential]$AdminCredential,

    # No $PSScriptRoot-based default here: with [CmdletBinding()], PSScriptRoot
    # is empty during param default evaluation when invoked via -File from an
    # external process (confirmed PowerShell 5.1 quirk). Resolved below.
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
    # CHECK_POLICY = ON below enforces the Windows password policy, so this
    # guarantees at least one of each character class rather than hoping a
    # purely random string happens to qualify. Rejection sampling avoids
    # modulo bias; everything - character picks and the final shuffle -
    # comes from the same CSPRNG, not the non-cryptographic Get-Random.
    param([int]$Length = 20)
    $upper = 'ABCDEFGHJKLMNPQRSTUVWXYZ'
    $lower = 'abcdefghijkmnpqrstuvwxyz'
    $digit = '23456789'
    $punct = '!@#$%^&*-_=+'
    $all = $upper + $lower + $digit + $punct
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()

    function Get-RandomChar {
        param([string]$Set)
        $len = $Set.Length
        $limit = 256 - (256 % $len)
        $b = [byte[]]::new(1)
        do { $rng.GetBytes($b) } while ($b[0] -ge $limit)
        return $Set[$b[0] % $len]
    }

    $chars = [System.Collections.Generic.List[char]]::new()
    $chars.Add((Get-RandomChar $upper))
    $chars.Add((Get-RandomChar $lower))
    $chars.Add((Get-RandomChar $digit))
    $chars.Add((Get-RandomChar $punct))
    while ($chars.Count -lt $Length) { $chars.Add((Get-RandomChar $all)) }

    for ($i = $chars.Count - 1; $i -gt 0; $i--) {
        $b = [byte[]]::new(1)
        $limit = 256 - (256 % ($i + 1))
        do { $rng.GetBytes($b) } while ($b[0] -ge $limit)
        $j = $b[0] % ($i + 1)
        $tmp = $chars[$i]; $chars[$i] = $chars[$j]; $chars[$j] = $tmp
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
    else {
        [void]$csb.Append("Integrated Security=True;")
    }
    [void]$csb.Append("Encrypt=False;TrustServerCertificate=True;")
    $conn = New-Object System.Data.SqlClient.SqlConnection($csb.ToString())
    $conn.Open()
    return $conn
}

Write-Host ""
Write-Host "Server:   $SqlServer" -ForegroundColor Cyan
Write-Host "Database: $Database" -ForegroundColor Cyan
Write-Host "Login:    $LoginName" -ForegroundColor Cyan
Write-Host ""

# ---------------------------------------------------------------
# 1. Database - CREATE DATABASE must be the only statement in its batch,
#    so this runs on its own before anything else.
# ---------------------------------------------------------------
$conn = New-AdminConnection -InitialCatalog 'master'
try {
    $cmd = $conn.CreateCommand()
    $cmd.CommandText = 'SELECT DB_ID(@db)'
    [void]$cmd.Parameters.AddWithValue('@db', $Database)
    $exists = $cmd.ExecuteScalar()

    if ($exists -is [DBNull] -or $null -eq $exists) {
        $create = $conn.CreateCommand()
        # Database names cannot be parameterized in DDL; QUOTENAME defends
        # against a name that needs bracket-escaping, not against injection
        # from an untrusted source - this value comes from db.psd1 or an
        # operator-supplied parameter, never from collected AD data.
        #
        # EXEC('literal' + expr) only accepts a variable or a literal after
        # the '+' - not a function call - so QUOTENAME(@n) has to be
        # resolved into its own variable first, then EXEC'd as a bare
        # variable. Building it inline (EXEC('...' + QUOTENAME(@n))) is a
        # parse error: "Incorrect syntax near 'QUOTENAME'".
        $create.CommandText = @'
DECLARE @n sysname = @dbname;
DECLARE @sql nvarchar(max) = N'CREATE DATABASE ' + QUOTENAME(@n);
EXEC(@sql);
'@
        [void]$create.Parameters.AddWithValue('@dbname', $Database)
        [void]$create.ExecuteNonQuery()
        Write-Host "  created database $Database" -ForegroundColor Green
    }
    else {
        Write-Host "  database $Database already exists" -ForegroundColor DarkGray
    }

    # ---------------------------------------------------------------
    # 2. Login. CREATE/ALTER LOGIN's PASSWORD clause has its own hand-rolled
    #    grammar that - unlike ordinary DML - does not accept a bound
    #    sp_executesql parameter there at all ("Incorrect syntax near
    #    '@pwd'", even though @pwd is a validly declared parameter). The
    #    documented way around that is QUOTENAME(@pwd, '''') - the standard
    #    quote-and-double-embedded-quotes escape for building a safe string
    #    literal in dynamic SQL - and only that is a good idea to place
    #    into @sql, not the identifier concatenation trick used for
    #    CREATE DATABASE/CREATE USER above.
    # ---------------------------------------------------------------
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
# 3. User + least-privilege roles, scoped to the AdAudit database only:
#    db_datareader/db_datawriter for the day-to-day load, db_ddladmin so
#    Initialize-AuditDatabaseSchema's own CREATE TABLE statements can run.
#    Nothing here grants anything outside this one database.
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

    foreach ($role in 'db_datareader', 'db_datawriter', 'db_ddladmin') {
        $chk = $conn.CreateCommand()
        $chk.CommandText = 'SELECT IS_ROLEMEMBER(@role, @login)'
        [void]$chk.Parameters.AddWithValue('@role', $role)
        [void]$chk.Parameters.AddWithValue('@login', $LoginName)
        $isMember = $chk.ExecuteScalar()

        if ($isMember -isnot [int] -or $isMember -ne 1) {
            $add = $conn.CreateCommand()
            $add.CommandText = @"
DECLARE @n sysname = @loginname;
DECLARE @sql nvarchar(max) = N'ALTER ROLE $role ADD MEMBER ' + QUOTENAME(@n);
EXEC(@sql);
"@
            [void]$add.Parameters.AddWithValue('@loginname', $LoginName)
            [void]$add.ExecuteNonQuery()
            Write-Host "  added to $role" -ForegroundColor Green
        }
        else {
            Write-Host "  already a member of $role" -ForegroundColor DarkGray
        }
    }
}
finally { $conn.Close() }

if ($generatedPassword) {
    Write-Host ""
    Write-Host "Generated password (shown once, not stored anywhere by this script):" -ForegroundColor Yellow
    Write-Host "  $generatedPassword" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Done. Next, as whoever will run run-remote.ps1:" -ForegroundColor Cyan
Write-Host "  .\Initialize-AuditDatabase.ps1 -SetCredential" -ForegroundColor Cyan
Write-Host "  .\Initialize-AuditDatabase.ps1" -ForegroundColor Cyan
Write-Host ""
