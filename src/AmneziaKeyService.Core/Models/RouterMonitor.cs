using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;

namespace AmneziaKeyService.Core.Models;

public class RouterMonitor
{
    [BsonId, BsonRepresentation(BsonType.ObjectId)]
    public string Id { get; set; } = ObjectId.GenerateNewId().ToString();
    public string Name { get; set; } = "";
    public string UserId { get; set; } = "";
    public string ServerId { get; set; } = "";
    public string ProtocolId { get; set; } = "";
    public string KeyId { get; set; } = ObjectId.GenerateNewId().ToString();
    public string ProvisionEventId { get; set; } = ObjectId.GenerateNewId().ToString();
    public bool ProvisionDispatched { get; set; }
    public string? CreatedByUserId { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public bool Archived { get; set; }
    public bool Paused { get; set; }
    public bool NotificationsEnabled { get; set; } = true;
    public int OfflineAfterSeconds { get; set; } = 240;
    public long Version { get; set; }
    // Invalidates queued notifications when recipient/preferences change.
    public long DeliveryGeneration { get; set; }
    public string State { get; set; } = RouterStates.Waiting;
    public DateTime StateSince { get; set; } = DateTime.UtcNow;
    public DateTime? LastCheckedAt { get; set; }
    public DateTime? LastHandshakeAt { get; set; }
    public DateTime? OutageStartedAt { get; set; }
    public string? Detail { get; set; }
    // Transactional outbox: state and transitions are one Mongo document write.
    public List<RouterTransition> PendingHistory { get; set; } = [];
}

public class RouterTransition
{
    [BsonId]
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public string RouterId { get; set; } = "";
    public string RouterName { get; set; } = "";
    public string UserId { get; set; } = "";
    public long DeliveryGeneration { get; set; }
    public DateTime At { get; set; }
    public string State { get; set; } = "";
    public string? Detail { get; set; }
    public DateTime? LastHandshakeAt { get; set; }
    public double? OutageSeconds { get; set; }
    public string DeliveryStatus { get; set; } = "skipped";
    public DateTime AvailableAt { get; set; }
    public int Attempts { get; set; }
    public string? LeaseOwner { get; set; }
    public DateTime? LeaseUntil { get; set; }
    public string? DeliveryError { get; set; }
    public DateTime? SentAt { get; set; }
}

public static class RouterStates
{
    public const string Waiting = "waiting", Online = "online", Offline = "offline",
        Unknown = "unknown", Setup = "setup", Paused = "paused";
    public const int StaleAfterSeconds = 120;

    public static string Effective(RouterMonitor router, DateTime now)
        => router.Paused ? Paused
            : router.LastCheckedAt is { } at && now - at > TimeSpan.FromSeconds(StaleAfterSeconds)
                ? Unknown : router.State;

    public static string Label(string state) => state switch
    {
        Waiting => "Ожидает подключения", Online => "На связи", Offline => "Нет связи",
        Unknown => "Нет данных мониторинга", Setup => "Требуется настройка", Paused => "На паузе",
        "test" => "Проверка уведомлений", _ => state
    };
}

public static class RouterMonitorRules
{
    public static bool CanDeliver(RouterMonitor? router, RouterTransition item, DateTime now)
        => router is { Archived: false } && router.UserId == item.UserId
            && router.DeliveryGeneration == item.DeliveryGeneration
            && (item.State == "test" || (!router.Paused && router.NotificationsEnabled
                && RouterStates.Effective(router, now) == item.State && router.StateSince <= item.At.AddMilliseconds(1)));

    public static bool CanReceive(User? user)
        => user is { IsActive: true, Status: UserStatuses.Active, TelegramId: > 0 };

    public static void Observe(RouterMonitor router, string state, DateTime? handshake, string? detail, DateTime now)
    {
        // A missed polling window is an observation gap, never a measured outage.
        if (!router.Paused && router.LastCheckedAt is { } checkedAt
            && now - checkedAt > TimeSpan.FromSeconds(RouterStates.StaleAfterSeconds))
            Transition(router, RouterStates.Unknown, "Перерыв в наблюдении", checkedAt.AddSeconds(RouterStates.StaleAfterSeconds));

        router.LastCheckedAt = now;
        if (handshake is { } h) router.LastHandshakeAt = h;
        Transition(router, router.Paused ? RouterStates.Paused : state, detail, now);
    }

    public static string ConnectionState(RouterMonitor router, DateTime? handshake, DateTime now)
    {
        if (handshake > now.AddSeconds(30)) return RouterStates.Unknown;
        if (handshake is { } h && now - h <= TimeSpan.FromSeconds(router.OfflineAfterSeconds))
            return RouterStates.Online;
        return router.LastHandshakeAt is null && handshake is null ? RouterStates.Waiting : RouterStates.Offline;
    }

    public static void Transition(RouterMonitor router, string state, string? detail, DateTime now)
    {
        router.Detail = detail;
        if (router.State == state) return;
        var previous = router.State;
        var duration = state == RouterStates.Online && previous == RouterStates.Offline && router.OutageStartedAt is { } start
            ? Math.Max(0, (now - start).TotalSeconds) : (double?)null;
        router.OutageStartedAt = state == RouterStates.Offline ? now : null;
        router.State = state;
        router.StateSince = now;
        router.PendingHistory.Add(new RouterTransition
        {
            RouterId = router.Id, RouterName = router.Name, UserId = router.UserId,
            DeliveryGeneration = router.DeliveryGeneration, At = now, State = state,
            Detail = detail, LastHandshakeAt = router.LastHandshakeAt, OutageSeconds = duration,
            // First connection is useful too. Errors are visible in the panel, not "power off" alerts.
            DeliveryStatus = router.NotificationsEnabled && state is RouterStates.Online or RouterStates.Offline ? "pending" : "skipped",
            AvailableAt = now.AddSeconds(30)
        });
    }
}
