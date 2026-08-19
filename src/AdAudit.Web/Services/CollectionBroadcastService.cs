using AdAudit.Shared.Collection;
using AdAudit.Web.Hubs;
using Microsoft.AspNetCore.SignalR;

namespace AdAudit.Web.Services;

/// <summary>
/// Thin glue between the framework-agnostic CollectionJobRunner
/// (AdAudit.Shared, also loadable from PowerShell) and SignalR. Starts a
/// job, then forwards its output to the job's SignalR group as it arrives.
/// </summary>
public sealed class CollectionBroadcastService(
    CollectionJobRunner runner,
    IHubContext<CollectionHub> hub,
    IConfiguration config,
    IHostEnvironment env,
    ILogger<CollectionBroadcastService> logger)
{
    public CollectionJob StartJob(string domain)
    {
        var configuredPath = config["Collection:ScriptPath"]
            ?? throw new InvalidOperationException("Collection:ScriptPath is not configured.");
        // Resolved against ContentRootPath, not the process's current
        // directory - CWD varies depending on how the host was launched
        // (dotnet run vs a Windows Service vs a scheduled task), ContentRootPath does not.
        var scriptPath = Path.GetFullPath(Path.Combine(env.ContentRootPath, configuredPath));

        var options = new CollectionJobOptions
        {
            ScriptPath = scriptPath,
            Domain = domain,
        };

        var job = runner.Start(options);
        var group = CollectionHub.GroupName(job.Id);

        job.LineReceived += line =>
        {
            // fire-and-forget on purpose: a slow/disconnected client must
            // never block or fail the collection itself
            _ = hub.Clients.Group(group).SendAsync("LineReceived", line)
                .ContinueWith(t =>
                {
                    if (t.IsFaulted)
                    {
                        logger.LogWarning(t.Exception, "Failed to broadcast a line for job {JobId}", job.Id);
                    }
                }, TaskScheduler.Default);
        };

        job.Completion.ContinueWith(t =>
        {
            _ = hub.Clients.Group(group).SendAsync("JobFinished", job.Status.ToString());
        }, TaskScheduler.Default);

        logger.LogInformation("Started collection job {JobId} for domain {Domain}", job.Id, domain);
        return job;
    }
}
