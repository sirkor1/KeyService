using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;

namespace AmneziaKeyService.Core.Models;

[BsonIgnoreExtraElements]
public class NotificationCampaign
{
    [BsonId]
    [BsonRepresentation(BsonType.ObjectId)]
    public string Id { get; set; } = default!;

    [BsonElement("title")]
    public string Title { get; set; } = default!;

    [BsonElement("text")]
    public string Text { get; set; } = default!;

    [BsonElement("disableNotification")]
    public bool DisableNotification { get; set; }

    [BsonElement("status")]
    public string Status { get; set; } = NotificationCampaignStatuses.Queued;

    [BsonElement("createdByUserId")]
    public string? CreatedByUserId { get; set; }

    [BsonElement("createdAt")]
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    [BsonElement("startedAt")]
    public DateTime? StartedAt { get; set; }

    [BsonElement("finishedAt")]
    public DateTime? FinishedAt { get; set; }

    [BsonElement("totalCount")]
    public long TotalCount { get; set; }

    [BsonElement("sentCount")]
    public long SentCount { get; set; }

    [BsonElement("failedCount")]
    public long FailedCount { get; set; }

    [BsonElement("skippedCount")]
    public long SkippedCount { get; set; }

    [BsonElement("error")]
    public string? Error { get; set; }

    public bool IsTerminal => NotificationCampaignStatuses.Terminal.Contains(Status);
}

[BsonIgnoreExtraElements]
public class NotificationDelivery
{
    [BsonId]
    [BsonRepresentation(BsonType.ObjectId)]
    public string Id { get; set; } = default!;

    [BsonElement("campaignId")]
    public string CampaignId { get; set; } = default!;

    [BsonElement("userId")]
    public string UserId { get; set; } = default!;

    [BsonElement("telegramId")]
    public long TelegramId { get; set; }

    [BsonElement("status")]
    public string Status { get; set; } = NotificationDeliveryStatuses.Pending;

    [BsonElement("attempt")]
    public int Attempt { get; set; }

    [BsonElement("availableAt")]
    public DateTime AvailableAt { get; set; } = DateTime.UtcNow;

    [BsonElement("lease")]
    public EventLease? Lease { get; set; }

    [BsonElement("sentAt")]
    public DateTime? SentAt { get; set; }

    [BsonElement("telegramMessageId")]
    public int? TelegramMessageId { get; set; }

    [BsonElement("errorCode")]
    public int? ErrorCode { get; set; }

    [BsonElement("error")]
    public string? Error { get; set; }
}

public static class NotificationCampaignStatuses
{
    public const string Queued = "queued";
    public const string Running = "running";
    public const string Completed = "completed";
    public const string Canceled = "canceled";
    public const string Failed = "failed";

    public static readonly string[] Active = [Queued, Running];
    public static readonly string[] Terminal = [Completed, Canceled, Failed];
}

public static class NotificationDeliveryStatuses
{
    public const string Pending = "pending";
    public const string Sending = "sending";
    public const string Retry = "retry";
    public const string Sent = "sent";
    public const string Failed = "failed";
    public const string Canceled = "canceled";
}

public class NotificationOptions
{
    public bool Enabled { get; set; } = true;
    public int PollIntervalMilliseconds { get; set; } = 500;
    public int StartupDelaySeconds { get; set; } = 5;
    public int BatchSize { get; set; } = 10;
    public int MessagesPerSecond { get; set; } = 20;
    public int MaxAttempts { get; set; } = 5;
    public int LeaseTtlSeconds { get; set; } = 60;
}
