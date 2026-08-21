namespace AdAudit.Data;

/// <summary>
/// Replaces targets.psd1's per-domain entries: a domain and the DC address
/// the toolkit talks to. Mirrors targets.psd1's Server/Trusted/Note fields;
/// its "Extra" list becomes TargetExtraServer rows instead of an inline array.
/// </summary>
public sealed class Target
{
    public Guid Id { get; set; }

    /// <summary>e.g. "a.lo" - the domain the collectors already key everything on.</summary>
    public required string Domain { get; set; }

    /// <summary>Primary DC FQDN the toolkit deploys to and collects from.</summary>
    public required string Server { get; set; }

    /// <summary>False when there is no AD trust to the management domain - collectors need NTLM/TrustedHosts for these.</summary>
    public bool Trusted { get; set; } = true;

    public string? Note { get; set; }

    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }

    public List<TargetExtraServer> ExtraServers { get; set; } = [];
    public DomainCredential? Credential { get; set; }
}
