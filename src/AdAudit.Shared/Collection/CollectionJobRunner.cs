using System.Collections.Concurrent;
using System.Runtime.Versioning;

namespace AdAudit.Shared.Collection;

/// <summary>
/// Tracks every CollectionJob currently running so something (a shutdown
/// hook, an admin "cancel" button, a health page) can find and kill them.
///
/// This is the first pass at the "what happens to an in-flight job if the
/// backend restarts" problem - KillAll() on ApplicationStopping stops the
/// most obvious failure mode (an orphaned powershell.exe nobody can see or
/// clean up), but does not yet handle resuming/retrying a job that got cut
/// off mid-collection, or noticing on startup that a *previous* crashed
/// process is still alive. Deliberately deferred until this is exercised
/// for real - see project_web_architecture_plan memory.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class CollectionJobRunner
{
    private readonly ConcurrentDictionary<Guid, CollectionJob> _jobs = new();

    public IReadOnlyCollection<CollectionJob> RunningJobs => _jobs.Values.ToArray();

    public CollectionJob Start(CollectionJobOptions options)
    {
        var job = new CollectionJob(options);
        _jobs[job.Id] = job;

        // fire-and-forget cleanup once the process exits, regardless of how
        job.Completion.ContinueWith(completedTask =>
        {
            _jobs.TryRemove(job.Id, out _);
        }, TaskScheduler.Default);

        job.Start();
        return job;
    }

    public bool TryGet(Guid id, out CollectionJob? job) => _jobs.TryGetValue(id, out job);

    public void KillAll()
    {
        foreach (var job in _jobs.Values)
        {
            job.Kill();
        }
    }
}
