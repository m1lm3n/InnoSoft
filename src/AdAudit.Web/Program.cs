using AdAudit.Data;
using AdAudit.Shared.Collection;
using AdAudit.Shared.Crypto;
using AdAudit.Web.Components;
using AdAudit.Web.Hubs;
using AdAudit.Web.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Threading.RateLimiting;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents();

builder.Services.AddSignalR();

// Cookie login against cfg.WebUsers (own login, not AD/Windows) -
// 2026-08-24: originally tried Negotiate/Windows-SSO, then AD-bind
// (System.DirectoryServices) form login; both got tangled in real friction
// (Chrome's AuthServerAllowlist policy, a per-Windows-account dev-cert
// mismatch, then a Blazor-SSR-form antiforgery issue) mid-debug. This is
// the version that actually works: a plain form posting to a hand-written
// minimal API endpoint below, no framework form machinery to fight. See
// Phase 3 in ROADMAP.md.
builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.LoginPath = "/Account/Login";
        options.AccessDeniedPath = "/Account/Login";
        options.ExpireTimeSpan = TimeSpan.FromHours(8);
        options.SlidingExpiration = true;
    });
builder.Services.AddAuthorization(options =>
{
    options.FallbackPolicy = new AuthorizationPolicyBuilder()
        .RequireAuthenticatedUser()
        .Build();
});
builder.Services.AddCascadingAuthenticationState();
builder.Services.AddScoped<WebUserValidator>();

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

// First-run seed: create a single 'root' login with a random password if
// cfg.WebUsers is empty, and print the password once to the console -
// there's no signup flow, this is the only way in on a fresh database.
// Change the password later by updating cfg.WebUsers directly (PasswordHasher<object>.HashPassword).
using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<AdAuditDbContext>();
    if (!db.WebUsers.Any())
    {
        var password = Convert.ToBase64String(RandomNumberGenerator.GetBytes(18));
        db.WebUsers.Add(new WebUser
        {
            Id = Guid.NewGuid(),
            Username = "root",
            PasswordHash = new PasswordHasher<object>().HashPassword(new object(), password),
            CreatedAt = DateTimeOffset.UtcNow,
        });
        db.SaveChanges();
        Console.WriteLine("============================================================");
        Console.WriteLine("[AdAudit] No web users found - created 'root'.");
        Console.WriteLine($"[AdAudit] Password: {password}");
        Console.WriteLine("[AdAudit] Shown once - save it now.");
        Console.WriteLine("============================================================");
    }
}

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

app.MapStaticAssets().AllowAnonymous();
app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode();
app.MapHub<CollectionHub>("/hubs/collection");

// Logout CSRF is low-severity (worst case: someone gets force-logged-out),
// so this skips the antiforgery-token plumbing a plain (non-EditForm) HTML
// <form> would otherwise need - the login form itself, which actually
// matters, goes through EditForm's own antiforgery handling instead.
// Plain (non-EditForm) HTML form -> hand-written endpoint, deliberately
// bypassing Blazor's SSR EditForm/antiforgery machinery, which is where the
// previous attempt at this got stuck. Login CSRF here just means an
// attacker could trick a victim into logging into the *attacker's* account -
// not a meaningful risk for this app - so antiforgery is skipped the same
// way as /Account/Logout, for the same reason.
app.MapPost("/Account/DoLogin", async (HttpContext ctx, WebUserValidator validator) =>
{
    var form = await ctx.Request.ReadFormAsync();
    var username = form["username"].ToString();
    var password = form["password"].ToString();
    var returnUrl = form["returnUrl"].ToString();

    if (!await validator.ValidateAsync(username, password))
    {
        var back = $"/Account/Login?error=1&ReturnUrl={Uri.EscapeDataString(returnUrl)}";
        return Results.LocalRedirect(back);
    }

    var identity = new ClaimsIdentity(
        [new Claim(ClaimTypes.Name, username)],
        CookieAuthenticationDefaults.AuthenticationScheme);
    await ctx.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, new ClaimsPrincipal(identity));

    return Results.LocalRedirect(string.IsNullOrEmpty(returnUrl) ? "/domains" : returnUrl);
}).DisableAntiforgery().AllowAnonymous();

app.MapPost("/Account/Logout", async (HttpContext ctx) =>
{
    await ctx.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
    return Results.LocalRedirect("/Account/Login");
}).DisableAntiforgery();

app.Run();
