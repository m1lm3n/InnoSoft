using AdAudit.Data;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace AdAudit.Web.Services;

/// <summary>
/// Validates a login form's username/password against cfg.WebUsers - a
/// login local to this app, separate from AD domain credentials and from
/// Windows accounts. Replaces an earlier AD-bind (System.DirectoryServices)
/// approach that got tangled up with a Blazor SSR antiforgery issue mid-debug;
/// this is the simpler thing that actually works. Uses
/// PasswordHasher&lt;object&gt; standalone (ASP.NET Core Identity's hasher
/// algorithm, without pulling in the rest of Identity).
/// </summary>
public sealed class WebUserValidator(AdAuditDbContext db)
{
    private static readonly PasswordHasher<object> Hasher = new();

    public async Task<bool> ValidateAsync(string username, string password)
    {
        if (string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(password)) return false;

        var user = await db.WebUsers.AsNoTracking().FirstOrDefaultAsync(u => u.Username == username);
        if (user is null) return false;

        return Hasher.VerifyHashedPassword(new object(), user.PasswordHash, password) != PasswordVerificationResult.Failed;
    }
}
