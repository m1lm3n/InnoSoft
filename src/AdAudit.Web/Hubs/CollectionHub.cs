using Microsoft.AspNetCore.SignalR;

namespace AdAudit.Web.Hubs;

/// <summary>
/// Broadcasts a running collection job's output to whoever is watching -
/// not just the browser tab that started it. Deliberately a real SignalR
/// hub rather than component-local state: Blazor Server's own circuit
/// could show live output to the page that clicked the button with no hub
/// at all, but a hub lets any number of tabs/users watch the same job, and
/// gives any future non-Blazor client (the CLI, a future API consumer) the
/// same live feed over a standard WebSocket connection.
/// </summary>
public sealed class CollectionHub : Hub
{
    public Task JoinJob(Guid jobId) =>
        Groups.AddToGroupAsync(Context.ConnectionId, GroupName(jobId));

    public Task LeaveJob(Guid jobId) =>
        Groups.RemoveFromGroupAsync(Context.ConnectionId, GroupName(jobId));

    public static string GroupName(Guid jobId) => $"job:{jobId}";
}
