<#
    db.psd1

    Non-secret connection settings for the audit database. Sibling to
    targets.psd1: public configuration lives here, the SQL login itself
    lives in the same DPAPI-encrypted store run-remote.ps1 already uses for
    domain credentials (see Initialize-AuditDatabase.ps1 -SetCredential),
    never in this file.

    SqlServer          instance to connect to. Everything runs on the same
                        machine as the scripts (see targets.psd1's Server
                        field for the same "one box" pattern), so this is
                        normally 'localhost' or 'localhost\<instance name>'
                        if SQL Server Express was installed as a named
                        instance.
    Database            database name. Initialize-AuditDatabase.ps1 expects
                        it to already exist (see that script's header for
                        the one-time setup a DBA runs by hand).
    ConnectTimeoutSec     SQL connection timeout.
    CommandTimeoutSec     bulk-load timeout; a run touches ~28 tables so this
                          is generous by default.
    CredentialHelperPath  path to AdAudit.CredentialHelper.exe, used to
                          decrypt cfg.DomainCredentials rows (see
                          Get-DomainCredentialFromDb in AuditDb.psm1) -
                          Windows PowerShell 5.1 cannot load the .NET
                          assembly that does the actual decryption
                          in-process (different runtime), so this console
                          exe is launched as a child process instead. The
                          default assumes the dev build layout
                          (..\src\AdAudit.CredentialHelper\bin\Debug\...);
                          point this at wherever it's actually published on
                          a real deployment.

    This is a data file: it may only contain a hash table literal, no code.
#>

@{
    SqlServer            = 'localhost'
    Database             = 'AdAudit'
    ConnectTimeoutSec    = 15
    CommandTimeoutSec    = 120
    CredentialHelperPath = '..\src\AdAudit.CredentialHelper\bin\Debug\net10.0-windows\AdAudit.CredentialHelper.exe'
}
