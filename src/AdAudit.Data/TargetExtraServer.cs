namespace AdAudit.Data;

/// <summary>One additional DC in a domain, beyond Target.Server - targets.psd1's "Extra" list, normalized.</summary>
public sealed class TargetExtraServer
{
    public Guid Id { get; set; }
    public Guid TargetId { get; set; }
    public required string ServerName { get; set; }
}
