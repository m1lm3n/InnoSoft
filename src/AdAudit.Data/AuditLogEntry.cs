namespace AdAudit.Data;

/// <summary>
/// The tool auditing itself: who added/changed/removed a domain credential,
/// and when - separate from the AD-findings audit trail this tool produces
/// about the domains it's pointed at. No auth exists yet, so Actor is
/// whatever identity was available at the time (Windows identity for now,
/// an authenticated user once auth lands) - never left blank.
/// </summary>
public sealed class AuditLogEntry
{
    public Guid Id { get; set; }
    public DateTimeOffset Timestamp { get; set; }
    public required string Actor { get; set; }
    public required string Action { get; set; }
    public string? TargetDomain { get; set; }
    public string? Detail { get; set; }
}
