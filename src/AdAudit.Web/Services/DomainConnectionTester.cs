using System.Collections.Concurrent;
using System.Diagnostics;
using System.Text;

namespace AdAudit.Web.Services;

/// <summary>
/// Runs dc_actions/Test-DomainConnection.ps1 as a child process (same
/// "PowerShell as a proven boundary" pattern as CollectionBroadcastService/
/// AdAudit.CredentialHelper) and enforces a per-target cooldown - this
/// specifically tests AD credentials against a real DC, so hammering the
/// button risks a real account lockout, not just backend load. Singleton:
/// the cooldown state has to survive across requests/circuits, not reset
/// per Blazor circuit like a scoped service would.
/// </summary>
public sealed class DomainConnectionTester(IConfiguration config, IHostEnvironment env, ILogger<DomainConnectionTester> logger)
{
    private static readonly TimeSpan Cooldown = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan ProcessTimeout = TimeSpan.FromSeconds(30);

    private readonly ConcurrentDictionary<Guid, DateTimeOffset> _lastAttempt = new();

    public TimeSpan? GetCooldownRemaining(Guid targetId)
    {
        if (_lastAttempt.TryGetValue(targetId, out var last))
        {
            var remaining = Cooldown - (DateTimeOffset.UtcNow - last);
            if (remaining > TimeSpan.Zero) return remaining;
        }
        return null;
    }

    public async Task<(bool Success, string Message)> TestAsync(
        Guid targetId, string server, string username, string plainPassword, CancellationToken ct = default)
    {
        var remaining = GetCooldownRemaining(targetId);
        if (remaining is { } r)
        {
            return (false, $"Please wait {Math.Ceiling(r.TotalSeconds)}s before testing this domain again - avoids hammering the DC with repeated bad-credential attempts.");
        }
        _lastAttempt[targetId] = DateTimeOffset.UtcNow;

        var configuredPath = config["Collection:TestConnectionScriptPath"]
            ?? throw new InvalidOperationException("Collection:TestConnectionScriptPath is not configured.");
        var scriptPath = Path.GetFullPath(Path.Combine(env.ContentRootPath, configuredPath));

        var psi = new ProcessStartInfo
        {
            FileName = "powershell.exe",
            WorkingDirectory = Path.GetDirectoryName(scriptPath),
            UseShellExecute = false,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
            StandardInputEncoding = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false),
        };
        psi.ArgumentList.Add("-NoProfile");
        psi.ArgumentList.Add("-NonInteractive");
        psi.ArgumentList.Add("-ExecutionPolicy");
        psi.ArgumentList.Add("Bypass");
        psi.ArgumentList.Add("-File");
        psi.ArgumentList.Add(scriptPath);
        psi.ArgumentList.Add("-Server");
        psi.ArgumentList.Add(server);
        psi.ArgumentList.Add("-Username");
        psi.ArgumentList.Add(username);

        using var process = new Process { StartInfo = psi };
        process.Start();

        // Secret via stdin only - never a CLI argument (visible in process
        // listings), same convention as AdAudit.CredentialHelper.
        await process.StandardInput.WriteAsync(plainPassword);
        process.StandardInput.Close();

        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeoutCts.CancelAfter(ProcessTimeout);

        var stdoutTask = process.StandardOutput.ReadToEndAsync(timeoutCts.Token);
        var stderrTask = process.StandardError.ReadToEndAsync(timeoutCts.Token);

        try
        {
            await process.WaitForExitAsync(timeoutCts.Token);
        }
        catch (OperationCanceledException)
        {
            try { process.Kill(entireProcessTree: true); } catch { /* already exited */ }
            logger.LogWarning("Test-DomainConnection timed out for {Server}", server);
            return (false, $"Timed out after {ProcessTimeout.TotalSeconds:0}s waiting for a response - the target may be unreachable.");
        }

        var stdout = (await stdoutTask).Trim();
        var stderr = (await stderrTask).Trim();

        logger.LogInformation("Test-DomainConnection for {Server} exited {Code}", server, process.ExitCode);

        if (process.ExitCode == 0 && stdout.StartsWith("OK:", StringComparison.Ordinal))
        {
            return (true, stdout);
        }

        var message = stdout.Length > 0 ? stdout : (stderr.Length > 0 ? stderr : "Connection test failed (no output).");
        return (false, message);
    }
}
