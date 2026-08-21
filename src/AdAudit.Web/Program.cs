using AdAudit.Data;
using AdAudit.Shared.Collection;
using AdAudit.Shared.Crypto;
using AdAudit.Web.Components;
using AdAudit.Web.Hubs;
using AdAudit.Web.Services;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents();

builder.Services.AddSignalR();
builder.Services.AddSingleton<CollectionJobRunner>();
builder.Services.AddSingleton<CollectionBroadcastService>();

// cfg schema only (Targets/DomainCredentials/AuditLog) via the scoped
// ad_audit_web login - see New-AuditWebLogin.ps1. Connection string comes
// from user-secrets locally (`dotnet user-secrets set ConnectionStrings:AdAuditWeb ...`)
// or real config/secret storage in production - never committed to appsettings.json.
builder.Services.AddDbContext<AdAuditDbContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("AdAuditWeb")
        ?? throw new InvalidOperationException("ConnectionStrings:AdAuditWeb is not configured.")));

// Root key DPAPI-protected on disk (System.Security.Cryptography.ProtectedData
// under the hood on Windows - the same primitive PowerShell's Export-Clixml
// uses), keyring shared with the PowerShell collector via the same folder +
// application name so both sides can decrypt what the other encrypted. Both
// processes need to run as svc_adaudit for that sharing to actually work.
builder.Services.AddDataProtection()
    .SetApplicationName(DataProtectionSettings.ApplicationName)
    .PersistKeysToFileSystem(new DirectoryInfo(DataProtectionSettings.KeyringPath));
builder.Services.AddSingleton<DomainCredentialProtector>();

var app = builder.Build();

// First-pass fix for "what happens to an in-flight job if the backend
// restarts": kill every tracked child process on shutdown so nothing gets
// orphaned. Does not yet handle resuming a job cut off mid-collection, or
// noticing a previous crashed run's leftover process on startup -
// deliberately deferred, see project_web_architecture_plan memory.
app.Lifetime.ApplicationStopping.Register(() =>
{
    app.Services.GetRequiredService<CollectionJobRunner>().KillAll();
});

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error", createScopeForErrors: true);
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}
app.UseStatusCodePagesWithReExecute("/not-found", createScopeForStatusCodePages: true);
app.UseHttpsRedirection();

app.UseAntiforgery();

app.MapStaticAssets();
app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode();
app.MapHub<CollectionHub>("/hubs/collection");

app.Run();
