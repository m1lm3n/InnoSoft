using AdAudit.Shared.Crypto;

// Bridges the runtime gap between AdAudit.Web (modern .NET, can use
// AdAudit.Shared's DomainCredentialProtector directly via DI) and
// Windows PowerShell 5.1 (.NET Framework - cannot load a net10.0 assembly
// via Add-Type at all, confirmed empirically: BadImageFormatException/
// loader exceptions, not a theoretical concern). PowerShell launches this
// as a child process instead, same pattern already proven for
// run-remote.ps1 via CollectionJobRunner.
//
// Usage:
//   AdAudit.CredentialHelper.exe encrypt --target-id <guid>   (password on stdin, base64 ciphertext on stdout)
//   AdAudit.CredentialHelper.exe decrypt --target-id <guid>   (base64 ciphertext on stdin, password on stdout)
//
// stdin/stdout only for anything secret - never a command-line argument
// (visible in process listings) and never an environment variable beyond
// what a caller explicitly chooses for their own testing. Every other
// message goes to stderr, so stdout is always exactly the one value a
// caller wants to capture, nothing else mixed in.

if (args.Length < 1)
{
    Console.Error.WriteLine("Usage: encrypt --target-id <guid> | decrypt --target-id <guid>");
    return 2;
}

var mode = args[0];
var targetIdArg = GetOption(args, "--target-id");
if (targetIdArg is null || !Guid.TryParse(targetIdArg, out var targetId))
{
    Console.Error.WriteLine("Missing or invalid --target-id <guid>");
    return 2;
}

try
{
    var protector = new DomainCredentialProtector();

    switch (mode)
    {
        case "encrypt":
            {
                var plain = ReadStdin();
                var encrypted = protector.Protect(targetId, plain);
                Console.Out.Write(Convert.ToBase64String(encrypted));
                return 0;
            }
        case "decrypt":
            {
                var base64 = ReadStdin();
                var encrypted = Convert.FromBase64String(base64);
                var plain = protector.Unprotect(targetId, encrypted);
                Console.Out.Write(plain);
                return 0;
            }
        default:
            Console.Error.WriteLine($"Unknown mode '{mode}', expected encrypt|decrypt");
            return 2;
    }
}
catch (Exception ex)
{
    // Deliberately no ex.ToString()/stack trace on stdout or stderr here
    // beyond the message - this runs against real credentials, keep
    // whatever ends up in a log as small as possible.
    Console.Error.WriteLine($"{mode} failed: {ex.Message}");
    return 1;
}

static string? GetOption(string[] a, string name)
{
    for (int i = 0; i < a.Length - 1; i++)
    {
        if (a[i] == name) return a[i + 1];
    }
    return null;
}

/// <summary>
/// Reads stdin as raw bytes and decodes it ourselves instead of trusting
/// Console.In - confirmed empirically that Windows PowerShell 5.1 prepends
/// a UTF-8 BOM (EF BB BF) to whatever it pipes into a native process's
/// stdin, and Console.In does not reliably strip it for redirected input
/// (depends on Console.InputEncoding, which is not guaranteed to be UTF-8
/// here). Left un-stripped, those 3 bytes decode as garbage leading
/// characters under most encodings, which broke base64 parsing outright.
/// Stripping the BOM by hand and decoding as UTF-8 explicitly works
/// regardless of what the caller (PowerShell, a shell, this exe itself)
/// has its console encoding set to.
/// </summary>
static string ReadStdin()
{
    using var stdin = Console.OpenStandardInput();
    using var ms = new MemoryStream();
    stdin.CopyTo(ms);
    var bytes = ms.ToArray();

    var utf8Bom = System.Text.Encoding.UTF8.GetPreamble();
    var start = bytes.Length >= utf8Bom.Length && bytes.AsSpan(0, utf8Bom.Length).SequenceEqual(utf8Bom)
        ? utf8Bom.Length
        : 0;

    return System.Text.Encoding.UTF8.GetString(bytes, start, bytes.Length - start).Trim();
}
