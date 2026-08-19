namespace AdAudit.Shared.Collection;

public sealed record CollectionJobLine(DateTimeOffset Timestamp, bool IsError, string Text);

public enum CollectionJobStatus
{
    Running,
    Completed,
    Failed,
    Killed,
}
