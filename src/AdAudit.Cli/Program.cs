using System.Security;
using AdAudit.Shared.Collection;

// Quick manual test harness for CollectionJobRunner, and a genuinely useful
// "run one collection job from the command line" ops tool going forward.
//
// Usage:
//   dotnet run -- <domain> [--script <path-to-run-remote.ps1>] [--runas <user>] [--runas-domain <domain>] [--runas-password-env <VARNAME>]
//
// --runas exercises the alternate-credential launch path. Password comes
// from an interactive masked prompt by default; --runas-password-env reads
// it from the named environment variable instead, for non-interactive/
// scripted runs - an env var isn't visible in a process listing the way a
// plain CLI arg would be, but it is still readable by anything with enough
// privilege to inspect this process's environment block, so treat it as
// "fine for local testing," not as secret-safe for anything that matters.

string domain = args.Length > 0 && !args[0].StartsWith("--") ? args[0] : "a.lo";

string? scriptPath = GetOption(args, "--script");
scriptPath ??= Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "..", "dc_actions", "run-remote.ps1"));

string? runAsUser = GetOption(args, "--runas");
string? runAsDomain = GetOption(args, "--runas-domain");
string? runAsPasswordEnvVar = GetOption(args, "--runas-password-env");

if (!File.Exists(scriptPath))
{
    Console.Error.WriteLine($"Script not found: {scriptPath}");
    Console.Error.WriteLine("Pass --script <path> explicitly if the default guess is wrong.");
    return 2;
}

SecureString? runAsPassword = null;
if (runAsUser is not null)
{
    if (runAsPasswordEnvVar is not null)
    {
        var plain = Environment.GetEnvironmentVariable(runAsPasswordEnvVar)
            ?? throw new InvalidOperationException($"Environment variable {runAsPasswordEnvVar} is not set.");
        runAsPassword = new SecureString();
        foreach (var c in plain) runAsPassword.AppendChar(c);
        runAsPassword.MakeReadOnly();
    }
    else
    {
        Console.Write($"Password for {runAsDomain}\\{runAsUser}: ");
        runAsPassword = ReadPasswordMasked();
        Console.WriteLine();
    }
}

var options = new CollectionJobOptions
{
    ScriptPath = scriptPath,
    Domain = domain,
    RunAsUserName = runAsUser,
    RunAsDomain = runAsDomain,
    RunAsPassword = runAsPassword,
};

Console.WriteLine($"Script:  {scriptPath}");
Console.WriteLine($"Domain:  {domain}");
Console.WriteLine($"Identity: {(runAsUser is null ? "inherited (current process identity)" : $"{runAsDomain}\\{runAsUser}")}");
Console.WriteLine(new string('-', 60));

var runner = new CollectionJobRunner();
var job = runner.Start(options);

job.LineReceived += line =>
{
    var prevColor = Console.ForegroundColor;
    Console.ForegroundColor = line.IsError ? ConsoleColor.Yellow : ConsoleColor.Gray;
    Console.WriteLine($"[{line.Timestamp:HH:mm:ss}] {line.Text}");
    Console.ForegroundColor = prevColor;
};

// Ctrl+C kills the child process tree too, instead of leaving it running
// after this harness exits - the exact orphan scenario the shutdown hook
// in the real host needs to cover as well.
Console.CancelKeyPress += (_, e) =>
{
    e.Cancel = true;
    Console.WriteLine("\n-- cancelling, killing process tree --");
    job.Kill();
};

int exitCode = await job.Completion;
Console.WriteLine(new string('-', 60));
Console.WriteLine($"Status: {job.Status}, exit code: {exitCode}");
return exitCode;

static string? GetOption(string[] a, string name)
{
    for (int i = 0; i < a.Length - 1; i++)
    {
        if (a[i] == name) return a[i + 1];
    }
    return null;
}

static SecureString ReadPasswordMasked()
{
    var pwd = new SecureString();
    ConsoleKeyInfo key;
    while ((key = Console.ReadKey(intercept: true)).Key != ConsoleKey.Enter)
    {
        if (key.Key == ConsoleKey.Backspace)
        {
            if (pwd.Length > 0) pwd.RemoveAt(pwd.Length - 1);
            continue;
        }
        if (!char.IsControl(key.KeyChar))
        {
            pwd.AppendChar(key.KeyChar);
        }
    }
    pwd.MakeReadOnly();
    return pwd;
}
