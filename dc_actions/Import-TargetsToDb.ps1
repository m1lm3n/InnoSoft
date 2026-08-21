<#
    Import-TargetsToDb.ps1

    One-time migration: reads targets.psd1 + the existing per-domain DPAPI
    credential store (the same one run-remote.ps1 -SetCredential fills) and
    writes them into cfg.Targets / cfg.DomainCredentials, encrypting each
    password through AdAudit.CredentialHelper.exe (Data Protection, see
    AdAudit.Shared/Crypto/DomainCredentialProtector.cs) instead of leaving
    it as DPAPI.

    Deliberately connects with a trusted (Windows Integrated) connection,
    not ad_audit_web - this is a one-off admin-run migration, not something
    that runs unattended, and the account running it needs to be able to
    read the OLD per-domain .cred.xml files too, which are DPAPI-tied to
    whoever is running this script interactively right now.

    Safe to re-run: a domain already present in cfg.Targets (matched by
    Domain) is skipped, not duplicated.

    Usage
        .\Import-TargetsToDb.ps1
        .\Import-TargetsToDb.ps1 -WhatIf
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$SqlServer,
    [string]$Database,
    [string]$TargetsFile,
    [string]$CredentialStore = (Join-Path $env:USERPROFILE '.dc_actions\creds'),
    [string]$CredentialHelperPath
)

$ErrorActionPreference = 'Stop'

if (-not $SqlServer -or -not $Database) {
    $dbCfgPath = Join-Path $PSScriptRoot 'db.psd1'
    if (Test-Path $dbCfgPath) {
        $dbCfg = Import-PowerShellDataFile -Path $dbCfgPath
        if (-not $SqlServer) { $SqlServer = $dbCfg.SqlServer }
        if (-not $Database) { $Database = $dbCfg.Database }
    }
}
if (-not $SqlServer) { $SqlServer = 'localhost' }
if (-not $Database) { $Database = 'AdAudit' }

if (-not $CredentialHelperPath) {
    $CredentialHelperPath = Join-Path $PSScriptRoot '..\src\AdAudit.CredentialHelper\bin\Debug\net10.0-windows\AdAudit.CredentialHelper.exe'
}
if (-not (Test-Path $CredentialHelperPath)) {
    throw "AdAudit.CredentialHelper.exe not found at $CredentialHelperPath - build src\AdAudit.CredentialHelper first, or pass -CredentialHelperPath."
}

$targetsModule = Join-Path $PSScriptRoot 'AuditTargets.psm1'
Import-Module $targetsModule -Force -DisableNameChecking
$Targets = Get-AuditTargets -Path $TargetsFile

function Protect-Password {
    # The leading comma on return is load-bearing: without it PowerShell
    # unrolls the byte[] into a System.Object[] of boxed System.Byte
    # elements when it crosses the function boundary, which
    # SqlParameter.AddWithValue cannot bind to a varbinary column
    # ("No mapping exists from object type System.Object[]..." - confirmed
    # by inspecting the returned array's actual type, same class of bug as
    # AuditHtml.psm1's earlier double-array-wrap, opposite direction).
    param([Guid]$TargetId, [string]$PlainPassword)
    $b64 = $PlainPassword | & $CredentialHelperPath encrypt --target-id $TargetId
    if ($LASTEXITCODE -ne 0) { throw "CredentialHelper encrypt failed for $TargetId (exit $LASTEXITCODE)" }
    return , [Convert]::FromBase64String($b64)
}

$conn = New-Object System.Data.SqlClient.SqlConnection(
    "Server=$SqlServer;Database=$Database;Integrated Security=True;Encrypt=False;TrustServerCertificate=True;")
$conn.Open()

try {
    $imported = 0
    $skipped = 0

    foreach ($domain in $Targets.Keys) {
        $entry = $Targets[$domain]

        $existsCmd = $conn.CreateCommand()
        $existsCmd.CommandText = 'SELECT Id FROM cfg.Targets WHERE Domain = @d'
        [void]$existsCmd.Parameters.AddWithValue('@d', $domain)
        $existingId = $existsCmd.ExecuteScalar()

        if ($existingId -and $existingId -isnot [DBNull]) {
            Write-Host "  $domain already in cfg.Targets, skipping" -ForegroundColor DarkGray
            $skipped++
            continue
        }

        $credPath = Join-Path $CredentialStore ("$($domain -replace '[^\w\.\-]', '_').cred.xml")
        if (-not (Test-Path $credPath)) {
            Write-Host "  $domain has no stored credential at $credPath, skipping (add it later via the UI)" -ForegroundColor Yellow
            continue
        }
        $cred = Import-Clixml -Path $credPath
        $plainPassword = $cred.GetNetworkCredential().Password

        $targetId = [Guid]::NewGuid()

        if (-not $PSCmdlet.ShouldProcess($domain, "insert into cfg.Targets/cfg.DomainCredentials")) { continue }

        $tx = $conn.BeginTransaction()
        try {
            $insTarget = $conn.CreateCommand()
            $insTarget.Transaction = $tx
            $insTarget.CommandText = @'
INSERT INTO cfg.Targets (Id, Domain, Server, Trusted, Note, CreatedAt, UpdatedAt)
VALUES (@id, @domain, @server, @trusted, @note, SYSDATETIMEOFFSET(), SYSDATETIMEOFFSET())
'@
            [void]$insTarget.Parameters.AddWithValue('@id', $targetId)
            [void]$insTarget.Parameters.AddWithValue('@domain', $domain)
            [void]$insTarget.Parameters.AddWithValue('@server', $entry.Server)
            [void]$insTarget.Parameters.AddWithValue('@trusted', [bool]$entry.Trusted)
            [void]$insTarget.Parameters.AddWithValue('@note', $(if ($entry.Note) { $entry.Note } else { [DBNull]::Value }))
            [void]$insTarget.ExecuteNonQuery()

            foreach ($extra in @($entry.Extra)) {
                if (-not $extra) { continue }
                $insExtra = $conn.CreateCommand()
                $insExtra.Transaction = $tx
                $insExtra.CommandText = 'INSERT INTO cfg.TargetExtraServers (Id, TargetId, ServerName) VALUES (@id, @tid, @s)'
                [void]$insExtra.Parameters.AddWithValue('@id', [Guid]::NewGuid())
                [void]$insExtra.Parameters.AddWithValue('@tid', $targetId)
                [void]$insExtra.Parameters.AddWithValue('@s', $extra)
                [void]$insExtra.ExecuteNonQuery()
            }

            $encryptedPassword = Protect-Password -TargetId $targetId -PlainPassword $plainPassword

            $insCred = $conn.CreateCommand()
            $insCred.Transaction = $tx
            $insCred.CommandText = @'
INSERT INTO cfg.DomainCredentials (Id, TargetId, Username, EncryptedPassword, UpdatedAt)
VALUES (@id, @tid, @user, @pwd, SYSDATETIMEOFFSET())
'@
            [void]$insCred.Parameters.AddWithValue('@id', [Guid]::NewGuid())
            [void]$insCred.Parameters.AddWithValue('@tid', $targetId)
            [void]$insCred.Parameters.AddWithValue('@user', $cred.UserName)
            [void]$insCred.Parameters.AddWithValue('@pwd', $encryptedPassword)
            [void]$insCred.ExecuteNonQuery()

            $insLog = $conn.CreateCommand()
            $insLog.Transaction = $tx
            $insLog.CommandText = @'
INSERT INTO cfg.AuditLogEntries (Id, Timestamp, Actor, Action, TargetDomain, Detail)
VALUES (@id, SYSDATETIMEOFFSET(), @actor, @action, @domain, @detail)
'@
            [void]$insLog.Parameters.AddWithValue('@id', [Guid]::NewGuid())
            [void]$insLog.Parameters.AddWithValue('@actor', "$env:USERDOMAIN\$env:USERNAME (Import-TargetsToDb.ps1)")
            [void]$insLog.Parameters.AddWithValue('@action', 'TargetImported')
            [void]$insLog.Parameters.AddWithValue('@domain', $domain)
            [void]$insLog.Parameters.AddWithValue('@detail', "Migrated from targets.psd1 + $credPath")
            [void]$insLog.ExecuteNonQuery()

            $tx.Commit()
            Write-Host "  imported $domain (TargetId $targetId)" -ForegroundColor Green
            $imported++

            # Never leave the plaintext password sitting in a variable
            # longer than it has to.
            $plainPassword = $null
        }
        catch {
            $tx.Rollback()
            Write-Host "  FAILED to import $domain : $($_.Exception.Message)" -ForegroundColor Red
        }
    }

    Write-Host ""
    Write-Host "Imported: $imported, skipped: $skipped" -ForegroundColor Cyan
}
finally { $conn.Close() }
