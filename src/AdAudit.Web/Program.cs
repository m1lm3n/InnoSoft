using AdAudit.Shared.Collection;
using AdAudit.Web.Components;
using AdAudit.Web.Hubs;
using AdAudit.Web.Services;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents();

builder.Services.AddSignalR();
builder.Services.AddSingleton<CollectionJobRunner>();
builder.Services.AddSingleton<CollectionBroadcastService>();

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
