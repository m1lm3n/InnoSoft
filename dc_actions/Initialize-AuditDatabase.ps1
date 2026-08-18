<#
    Initialize-AuditDatabase.ps1

    One-time (and safely re-runnable) setup for the SQL Server database
    that now holds every audit run - see AuditDb.psm1's header for why the
    dated CSV folders are no longer the durable store.

    Manual prerequisite, done once by whoever administers the server
    run-remote.ps1 runs on (not automated here - it needs an interactive
    session and elevated rights this script cannot assume it has):

        1. Install SQL Server Express (or any edition) on that machine.
           https://www.microsoft.com/sql-server/sql-server-downloads
        2. During setup, or afterwards via SSMS, enable
           "SQL Server and Windows Authentication mode" and restart the
           SQL Server service.
        3. Create the database and a dedicated, least-privilege login:

               CREATE DATABASE AdAudit;
               GO
               CREATE LOGIN ad_audit_svc WITH PASSWORD = '<a strong password>';
               GO
               USE AdAudit;
               CREATE USER ad_audit_svc FOR LOGIN ad_audit_svc;
               ALTER ROLE db_datareader ADD MEMBER ad_audit_svc;
               ALTER ROLE db_datawriter ADD MEMBER ad_audit_svc;
               ALTER ROLE db_ddladmin   ADD MEMBER ad_audit_svc;
               GO

           db_ddladmin is only needed so this script's own idempotent
           CREATE TABLE statements can run; it is not sysadmin, and the
           login has no access outside the AdAudit database.

    After that, from this folder:

        .\Initialize-AuditDatabase.ps1 -SetCredential   # once, prompts for
                                                         # the SQL login above
        .\Initialize-AuditDatabase.ps1                  # creates/updates
                                                         # the schema

    Both are idempotent: re-running either is harmless. Adjust db.psd1
    first if SqlServer/Database differ from the defaults ('localhost' /
    'AdAudit').

    The credential is stored the same way run-remote.ps1 stores domain
    credentials: DPAPI-encrypted via Export-Clixml, readable only by the
    Windows account that saved it, on the machine that saved it.
#>

[CmdletBinding()]
param(
    [string]$DbConfigPath = (Join-Path $PSScriptRoot 'db.psd1'),

    [string]$CredentialPath = (Join-Path $env:USERPROFILE '.dc_actions\creds\_db.cred.xml'),

    # Prompt for the SQL login, verify it, store it encrypted, then exit
    [switch]$SetCredential
)

$ErrorActionPreference = 'Stop'

$dbModule = Join-Path $PSScriptRoot 'AuditDb.psm1'
if (-not (Test-Path $dbModule)) { throw "AuditDb.psm1 not found next to this script." }
Import-Module $dbModule -Force -DisableNameChecking

if (-not (Test-Path $DbConfigPath)) { throw "db.psd1 not found at $DbConfigPath." }
try { $dbCfg = Import-PowerShellDataFile -Path $DbConfigPath -ErrorAction Stop }
catch { throw "db.psd1 could not be parsed: $($_.Exception.Message)" }

if ($SetCredential) {
    Write-Host ""
    Write-Host "SQL login for $($dbCfg.SqlServer) / $($dbCfg.Database)" -ForegroundColor Cyan
    $cred = Get-Credential -Message "SQL Server login (e.g. ad_audit_svc)"
    if (-not $cred) { Write-Host "  skipped" -ForegroundColor DarkGray; return }

    $storeDir = Split-Path $CredentialPath -Parent
    if (-not (Test-Path $storeDir)) { New-Item -ItemType Directory -Path $storeDir -Force | Out-Null }
    $cred | Export-Clixml -Path $CredentialPath -Force
    Write-Host "  stored: $CredentialPath" -ForegroundColor DarkGray

    if (Test-AuditDbConnection) {
        Write-Host "  verified against $($dbCfg.SqlServer)" -ForegroundColor Green
    }
    else {
        Write-Host "  saved, but the connection test failed - see the warning above" -ForegroundColor Yellow
    }
    Write-Host ""
    return
}

Write-Host ""
Write-Host "Server:   $($dbCfg.SqlServer)" -ForegroundColor Cyan
Write-Host "Database: $($dbCfg.Database)" -ForegroundColor Cyan

if (-not (Test-Path $CredentialPath)) {
    throw "No SQL login stored yet. Run: .\Initialize-AuditDatabase.ps1 -SetCredential"
}

if (-not (Test-AuditDbConnection)) {
    throw "Could not connect to $($dbCfg.SqlServer)/$($dbCfg.Database). Confirm the database exists and the login has access (see this script's header for the one-time DBA setup)."
}

Write-Host "Connected. Creating/verifying schema..." -ForegroundColor DarkGray
Initialize-AuditDatabaseSchema
Write-Host "Schema ready." -ForegroundColor Green
Write-Host ""
