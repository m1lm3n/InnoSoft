namespace AdAudit.Data;

/// <summary>
/// One domain's collection credential. Username is plain (not a secret);
/// EncryptedPassword is an ASP.NET Core Data Protection payload, never
/// plaintext - see AdAudit.Shared's credential-protection wrapper for how
/// it's produced/consumed. The purpose chain used to protect it is derived
/// from TargetId, which is why that FK is immutable in practice even
/// though nothing enforces that at the database level.
/// </summary>
public sealed class DomainCredential
{
    public Guid Id { get; set; }
    public Guid TargetId { get; set; }

    public required string Username { get; set; }
    public required byte[] EncryptedPassword { get; set; }

    public DateTimeOffset UpdatedAt { get; set; }
}
