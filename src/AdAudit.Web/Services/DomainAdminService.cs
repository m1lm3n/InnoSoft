using AdAudit.Data;
using AdAudit.Shared.Crypto;
using Microsoft.EntityFrameworkCore;

namespace AdAudit.Web.Services;

/// <summary>
/// CRUD for cfg.Targets/cfg.DomainCredentials plus the audit-log write that
/// goes with every change, per Phase 2 of ROADMAP.md. Scoped, not
/// singleton - shares the request/circuit-scoped AdAuditDbContext instead
/// of holding one open indefinitely.
/// </summary>
public sealed class DomainAdminService(AdAuditDbContext db, DomainCredentialProtector protector)
{
    public Task<List<Target>> ListAsync(CancellationToken ct = default) =>
        db.Targets.AsNoTracking()
            .Include(t => t.ExtraServers)
            .Include(t => t.Credential)
            .OrderBy(t => t.Domain)
            .ToListAsync(ct);

    public Task<Target?> GetAsync(Guid id, CancellationToken ct = default) =>
        db.Targets.AsNoTracking()
            .Include(t => t.ExtraServers)
            .Include(t => t.Credential)
            .FirstOrDefaultAsync(t => t.Id == id, ct);

    /// <summary>Server-side only - decrypted for a "test connection" call, never sent back to the browser as a displayed value.</summary>
    public async Task<string?> GetStoredPasswordAsync(Guid targetId, CancellationToken ct = default)
    {
        var cred = await db.DomainCredentials.AsNoTracking().FirstOrDefaultAsync(c => c.TargetId == targetId, ct);
        return cred is null ? null : protector.Unprotect(targetId, cred.EncryptedPassword);
    }

    public async Task<Guid> SaveTargetAsync(
        Guid? id, string domain, string server, bool trusted, string? note,
        IReadOnlyList<string> extraServers, string actor, CancellationToken ct = default)
    {
        Target target;
        string action;

        if (id is { } existingId)
        {
            target = await db.Targets.Include(t => t.ExtraServers).FirstOrDefaultAsync(t => t.Id == existingId, ct)
                ?? throw new InvalidOperationException($"Target {existingId} not found.");
            target.Domain = domain;
            target.Server = server;
            target.Trusted = trusted;
            target.Note = note;
            target.UpdatedAt = DateTimeOffset.UtcNow;
            db.TargetExtraServers.RemoveRange(target.ExtraServers);
            target.ExtraServers = extraServers.Select(s => new TargetExtraServer { TargetId = existingId, ServerName = s }).ToList();
            action = "target.update";
        }
        else
        {
            target = new Target
            {
                Id = Guid.NewGuid(),
                Domain = domain,
                Server = server,
                Trusted = trusted,
                Note = note,
                CreatedAt = DateTimeOffset.UtcNow,
                UpdatedAt = DateTimeOffset.UtcNow,
            };
            target.ExtraServers = extraServers.Select(s => new TargetExtraServer { TargetId = target.Id, ServerName = s }).ToList();
            db.Targets.Add(target);
            action = "target.create";
        }

        db.AuditLogEntries.Add(new AuditLogEntry
        {
            Id = Guid.NewGuid(),
            Timestamp = DateTimeOffset.UtcNow,
            Actor = actor,
            Action = action,
            TargetDomain = domain,
            Detail = $"server={server}; trusted={trusted}; extraServers={extraServers.Count}",
        });

        await db.SaveChangesAsync(ct);
        return target.Id;
    }

    /// <summary>Write-only by construction: the caller only ever passes a freshly-typed password in, this never returns one out.</summary>
    public async Task SetCredentialAsync(Guid targetId, string username, string plainPassword, string actor, CancellationToken ct = default)
    {
        var target = await db.Targets.Include(t => t.Credential).FirstOrDefaultAsync(t => t.Id == targetId, ct)
            ?? throw new InvalidOperationException($"Target {targetId} not found.");

        var encrypted = protector.Protect(targetId, plainPassword);

        if (target.Credential is { } existing)
        {
            existing.Username = username;
            existing.EncryptedPassword = encrypted;
            existing.UpdatedAt = DateTimeOffset.UtcNow;
        }
        else
        {
            db.DomainCredentials.Add(new DomainCredential
            {
                Id = Guid.NewGuid(),
                TargetId = targetId,
                Username = username,
                EncryptedPassword = encrypted,
                UpdatedAt = DateTimeOffset.UtcNow,
            });
        }

        db.AuditLogEntries.Add(new AuditLogEntry
        {
            Id = Guid.NewGuid(),
            Timestamp = DateTimeOffset.UtcNow,
            Actor = actor,
            Action = "credential.set",
            TargetDomain = target.Domain,
            Detail = $"username={username}", // the password itself is never logged
        });

        await db.SaveChangesAsync(ct);
    }

    public async Task DeleteAsync(Guid id, string actor, CancellationToken ct = default)
    {
        var target = await db.Targets.FirstOrDefaultAsync(t => t.Id == id, ct);
        if (target is null) return;

        db.AuditLogEntries.Add(new AuditLogEntry
        {
            Id = Guid.NewGuid(),
            Timestamp = DateTimeOffset.UtcNow,
            Actor = actor,
            Action = "target.delete",
            TargetDomain = target.Domain,
        });

        db.Targets.Remove(target); // cascades to ExtraServers/Credential (see AdAuditDbContext)
        await db.SaveChangesAsync(ct);
    }
}
