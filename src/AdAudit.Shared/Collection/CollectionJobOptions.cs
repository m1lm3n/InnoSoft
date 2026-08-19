using System.Security;

namespace AdAudit.Shared.Collection;

/// <summary>
/// Parameters for one run-remote.ps1 invocation.
///
/// RunAsUserName/RunAsDomain/RunAsPassword are for local dev testing under
/// the svc_adaudit account specifically - e.g. to validate a DPAPI-tied
/// keyring/credential path even when the developer is logged in as a
/// different Windows account. In production the backend already runs *as*
/// svc_adaudit (as a Windows Service), so the child process inherits that
/// identity for free and these should be left null.
/// </summary>
public sealed class CollectionJobOptions
{
    public required string ScriptPath { get; init; }
    public required string Domain { get; init; }
    public string PowerShellExecutable { get; init; } = "powershell.exe";
    public string? WorkingDirectory { get; init; }

    public string? RunAsUserName { get; init; }
    public string? RunAsDomain { get; init; }
    public SecureString? RunAsPassword { get; init; }
}
