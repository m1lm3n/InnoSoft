using System.Diagnostics;
using System.Runtime.Versioning;

namespace AdAudit.Shared.Collection;

/// <summary>
/// One run-remote.ps1 invocation, running as a child process. Streams each
/// stdout/stderr line as it arrives via LineReceived rather than buffering
/// the whole run - a single domain already takes 10-30+ seconds in
/// practice, and the UI (Blazor Interactive Server, over SignalR) is meant
/// to show it live.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class CollectionJob : IDisposable
{
    private readonly Process _process;
    private readonly TaskCompletionSource<int> _completionSource = new();
    private int _status = (int)CollectionJobStatus.Running;

    public Guid Id { get; } = Guid.NewGuid();
    public string Domain { get; }
    public DateTimeOffset StartedAt { get; } = DateTimeOffset.UtcNow;

    public CollectionJobStatus Status => (CollectionJobStatus)_status;

    /// <summary>Fires from a ThreadPool thread - callers marshal to their own context (e.g. a SignalR hub context call) as needed.</summary>
    public event Action<CollectionJobLine>? LineReceived;

    public Task<int> Completion => _completionSource.Task;

    internal CollectionJob(CollectionJobOptions options)
    {
        Domain = options.Domain;

        var psi = new ProcessStartInfo
        {
            FileName = options.PowerShellExecutable,
            WorkingDirectory = options.WorkingDirectory
                ?? Path.GetDirectoryName(Path.GetFullPath(options.ScriptPath))
                ?? Environment.CurrentDirectory,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        };
        psi.ArgumentList.Add("-NoProfile");
        psi.ArgumentList.Add("-NonInteractive");
        psi.ArgumentList.Add("-ExecutionPolicy");
        psi.ArgumentList.Add("Bypass");
        psi.ArgumentList.Add("-File");
        psi.ArgumentList.Add(options.ScriptPath);
        psi.ArgumentList.Add("-Domain");
        psi.ArgumentList.Add(options.Domain);

        if (options.RunAsUserName is not null)
        {
            psi.UserName = options.RunAsUserName;
            psi.Domain = options.RunAsDomain;
            psi.Password = options.RunAsPassword;
            // Needed so the launched process gets a real profile - without
            // it DPAPI-protected data tied to that account (the whole
            // point of running under svc_adaudit) is not reliably
            // accessible, and neither is anything else profile-scoped.
            psi.LoadUserProfile = true;
        }

        _process = new Process { StartInfo = psi, EnableRaisingEvents = true };
        _process.OutputDataReceived += (_, e) => OnLine(isError: false, e.Data);
        _process.ErrorDataReceived += (_, e) => OnLine(isError: true, e.Data);
        _process.Exited += OnExited;
    }

    internal void Start()
    {
        _process.Start();
        _process.BeginOutputReadLine();
        _process.BeginErrorReadLine();
    }

    private void OnLine(bool isError, string? text)
    {
        if (text is null) return; // null marks end-of-stream, not a blank line
        LineReceived?.Invoke(new CollectionJobLine(DateTimeOffset.UtcNow, isError, text));
    }

    private void OnExited(object? sender, EventArgs e)
    {
        var killed = Interlocked.CompareExchange(ref _status, 0, 0) == (int)CollectionJobStatus.Killed;
        int exitCode;
        try { exitCode = _process.ExitCode; }
        catch { exitCode = -1; }

        if (!killed)
        {
            Interlocked.Exchange(ref _status, (int)(exitCode == 0 ? CollectionJobStatus.Completed : CollectionJobStatus.Failed));
        }
        _completionSource.TrySetResult(exitCode);
    }

    /// <summary>
    /// Kills the whole process tree, not just the immediate powershell.exe -
    /// otherwise a mid-collection kill can leave a child process (or the
    /// PowerShell session's own children) running orphaned.
    /// </summary>
    public void Kill()
    {
        Interlocked.Exchange(ref _status, (int)CollectionJobStatus.Killed);
        try
        {
            if (!_process.HasExited) _process.Kill(entireProcessTree: true);
        }
        catch
        {
            // already exited between the check and the call - not an error
        }
    }

    public void Dispose() => _process.Dispose();
}
