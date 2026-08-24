using AdAudit.Data;
using AdAudit.Shared.Collection;
using AdAudit.Shared.Crypto;
using AdAudit.Web.Components;
using AdAudit.Web.Hubs;
using AdAudit.Web.Services;
using Microsoft.AspNetCore.Authentication.Negotiate;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;
using System.Threading.RateLimiting;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents();

builder.Services.AddSignalR();

// Windows Integrated Auth (Kerberos/NTLM) against this box's own AD - no
// external IdP for this deployment. See Phase 3 in ROADMAP.md /
// project_web_architecture_plan memory for why Negotiate over OIDC: this
// box is already domain-joined with real AD domains to authenticate
// against, no separate IdP to stand up or maintain.
//
// Enforcement (the fallback policy requiring auth on every endpoint) is
// DISABLED for now - 2026-08-24, hit real friction getting Chrome to do
// transparent Negotiate SSO against 127.0.0.1 (needs an AuthServerAllowlist
// browser policy) plus a separate per-account dev-cert mismatch on HTTPS,
// stacked on top of each other mid-debugging. Re-enable the
// FallbackPolicy block below once both are sorted out calmly - the
// services are still registered so nothing about the setup needs
// redoing, just the requirement itself is off.
builder.Services.AddAuthentication(NegotiateDefaults.AuthenticationScheme)
    .AddNegotiate();
builder.Services.AddAuthorization();
builder.Services.AddCascadingAuthenticationState();

// Global backstop against a runaway client (a stuck reconnect loop, a
// misbehaving script) - partitioned by the authenticated Windows account,
// not remote IP, since every request on this box arrives from 127.0.0.1
// regardless of who's actually behind it. Not a replacement for
// DomainConnectionTester's own per-target AD-lockout cooldown (Phase 2) -
// that one exists because *any* rate of repeated bad credentials against a
// real DC is dangerous, independent of overall request volume.
builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    options.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(httpContext =>
        RateLimitPartition.GetFixedWindowLimiter(
            partitionKey: httpContext.User.Identity?.Name ?? "anonymous",
            factory: _ => new FixedWindowRateLimiterOptions
            {
                Window = TimeSpan.FromSeconds(10),
                PermitLimit = 200,
                QueueLimit = 0,
            }));
});
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
    .PersistKeysToFileSystem(new DirectoryInfo(DataProtectionSettings.KeyringPath))
    .ProtectKeysWithDpapi();
builder.Services.AddSingleton<DomainCredentialProtector>();
builder.Services.AddScoped<DomainAdminService>();
builder.Services.AddSingleton<DomainConnectionTester>();

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

app.UseAuthentication();
app.UseAuthorization();
app.UseRateLimiter();

app.UseAntiforgery();

app.MapStaticAssets();
app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode();
app.MapHub<CollectionHub>("/hubs/collection");

app.Run();
