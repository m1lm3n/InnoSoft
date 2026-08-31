namespace AdAudit.Data;

/// <summary>
/// A login for this app's own UI - separate from AD domain credentials
/// (DomainCredential) and separate from Windows accounts. Password is a
/// PasswordHasher&lt;object&gt; hash (ASP.NET Core Identity's hasher, used
/// standalone without the rest of Identity), never plaintext.
/// </summary>
public sealed class WebUser
{
    public Guid Id { get; set; }
    public required string Username { get; set; }
    public required string PasswordHash { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
}
