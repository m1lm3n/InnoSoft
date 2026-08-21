using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace AdAudit.Data;

/// <summary>
/// Used only by `dotnet ef migrations add`/`dotnet ef database update` at
/// design/deploy time - never by the running app. Deliberately uses a
/// trusted (Windows Integrated) connection as whoever is running the CLI,
/// not the ad_audit_web login: applying migrations needs CREATE/ALTER
/// rights on the cfg schema, and ad_audit_web intentionally only ever gets
/// DML (see New-AuditWebLogin.ps1) - schema changes and "what the running
/// app can do" stay on two different credentials on purpose.
/// </summary>
public sealed class AdAuditDbContextFactory : IDesignTimeDbContextFactory<AdAuditDbContext>
{
    public AdAuditDbContext CreateDbContext(string[] args)
    {
        var connectionString = Environment.GetEnvironmentVariable("ADAUDIT_MIGRATION_CONNECTION")
            ?? "Server=localhost;Database=AdAudit;Integrated Security=True;Encrypt=False;TrustServerCertificate=True;";

        var optionsBuilder = new DbContextOptionsBuilder<AdAuditDbContext>();
        optionsBuilder.UseSqlServer(connectionString);
        return new AdAuditDbContext(optionsBuilder.Options);
    }
}
