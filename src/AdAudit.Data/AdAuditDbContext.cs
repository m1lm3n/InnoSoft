using Microsoft.EntityFrameworkCore;

namespace AdAudit.Data;

/// <summary>
/// Owns exactly the cfg schema (Targets/DomainCredentials/AuditLog) - never
/// Findings/Runs/RunMeta/the collector's fact tables, which PowerShell owns
/// and writes via raw ADO.NET/SqlBulkCopy (AuditDb.psm1). Keeping this
/// DbContext scoped to cfg is what makes the ad_audit_web SQL login's
/// narrow permissions (db_datareader + DML only on cfg, see
/// New-AuditWebLogin.ps1) actually sufficient for everything EF does here.
/// </summary>
public sealed class AdAuditDbContext(DbContextOptions<AdAuditDbContext> options) : DbContext(options)
{
    public DbSet<Target> Targets => Set<Target>();
    public DbSet<TargetExtraServer> TargetExtraServers => Set<TargetExtraServer>();
    public DbSet<DomainCredential> DomainCredentials => Set<DomainCredential>();
    public DbSet<AuditLogEntry> AuditLogEntries => Set<AuditLogEntry>();
    public DbSet<WebUser> WebUsers => Set<WebUser>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.HasDefaultSchema("cfg");

        modelBuilder.Entity<Target>(e =>
        {
            e.HasIndex(t => t.Domain).IsUnique();
            e.Property(t => t.Domain).HasMaxLength(64);
            e.Property(t => t.Server).HasMaxLength(256);
            e.Property(t => t.Note).HasMaxLength(1000);

            e.HasMany(t => t.ExtraServers)
                .WithOne()
                .HasForeignKey(x => x.TargetId)
                .OnDelete(DeleteBehavior.Cascade);

            e.HasOne(t => t.Credential)
                .WithOne()
                .HasForeignKey<DomainCredential>(c => c.TargetId)
                .OnDelete(DeleteBehavior.Cascade);
        });

        modelBuilder.Entity<TargetExtraServer>(e =>
        {
            e.Property(x => x.ServerName).HasMaxLength(256);
        });

        modelBuilder.Entity<DomainCredential>(e =>
        {
            e.HasIndex(c => c.TargetId).IsUnique();
            e.Property(c => c.Username).HasMaxLength(256);
        });

        modelBuilder.Entity<AuditLogEntry>(e =>
        {
            e.Property(a => a.Actor).HasMaxLength(256);
            e.Property(a => a.Action).HasMaxLength(100);
            e.Property(a => a.TargetDomain).HasMaxLength(64);
            e.Property(a => a.Detail).HasMaxLength(2000);
            e.HasIndex(a => a.Timestamp);
        });

        modelBuilder.Entity<WebUser>(e =>
        {
            e.HasIndex(u => u.Username).IsUnique();
            e.Property(u => u.Username).HasMaxLength(256);
            e.Property(u => u.PasswordHash).HasMaxLength(512);
        });
    }
}
