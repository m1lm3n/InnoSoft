using System.Text;
using Microsoft.AspNetCore.DataProtection;

namespace AdAudit.Shared.Crypto;

/// <summary>
/// Where the shared Data Protection keyring lives and what it's called -
/// both AdAudit.Web (DI-registered IDataProtectionProvider) and
/// AdAudit.CredentialHelper (this class's standalone constructor) must
/// agree on both values exactly, or they end up with incompatible
/// keyrings. Both processes also need to run as svc_adaudit for either to
/// actually be able to read the DPAPI-protected keys on disk.
/// </summary>
public static class DataProtectionSettings
{
    public const string ApplicationName = "AdAudit";
    public const string KeyringPath = @"C:\ProgramData\AdAudit\keys";
}

/// <summary>
/// Encrypts/decrypts one domain's stored credential. Purpose-chained on
/// the target's own id, so ciphertext from one domain can never be
/// swapped into another domain's row and decrypt successfully - the
/// property the original hand-rolled AAD design was after, provided here
/// by Data Protection's purpose strings instead (see
/// project_web_architecture_plan memory for why the hand-rolled
/// HKDF/AES-GCM version was dropped in favour of this).
/// </summary>
public sealed class DomainCredentialProtector
{
    private const string Purpose = "AdAudit.DomainCredential.Password";
    private readonly IDataProtectionProvider _provider;

    /// <summary>Standalone use - AdAudit.CredentialHelper (a plain console exe PowerShell launches as a child process), not run through ASP.NET Core DI.</summary>
    public DomainCredentialProtector() : this(CreateStandaloneProvider()) { }

    /// <summary>DI use from AdAudit.Web - inject the IDataProtectionProvider AddDataProtection() already registers, so there is exactly one configuration of folder+app name in the whole solution.</summary>
    public DomainCredentialProtector(IDataProtectionProvider provider)
    {
        _provider = provider;
    }

    private static IDataProtectionProvider CreateStandaloneProvider() =>
        DataProtectionProvider.Create(
            new DirectoryInfo(DataProtectionSettings.KeyringPath),
            builder => builder.SetApplicationName(DataProtectionSettings.ApplicationName));

    public byte[] Protect(Guid targetId, string plainPassword)
    {
        var protector = _provider.CreateProtector(Purpose, targetId.ToString());
        return protector.Protect(Encoding.UTF8.GetBytes(plainPassword));
    }

    public string Unprotect(Guid targetId, byte[] encrypted)
    {
        var protector = _provider.CreateProtector(Purpose, targetId.ToString());
        return Encoding.UTF8.GetString(protector.Unprotect(encrypted));
    }
}
