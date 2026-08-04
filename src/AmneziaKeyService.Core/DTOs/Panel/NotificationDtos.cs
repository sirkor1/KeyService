using AmneziaKeyService.Core.Models;

namespace AmneziaKeyService.Core.DTOs.Panel;

public record NotificationCampaignDto(
    string Id,
    string Title,
    string Text,
    bool DisableNotification,
    string Status,
    long TotalCount,
    long SentCount,
    long FailedCount,
    long SkippedCount,
    string? Error,
    DateTime CreatedAt,
    DateTime? StartedAt,
    DateTime? FinishedAt)
{
    public static NotificationCampaignDto From(NotificationCampaign value) => new(
        value.Id,
        value.Title,
        value.Text,
        value.DisableNotification,
        value.Status,
        value.TotalCount,
        value.SentCount,
        value.FailedCount,
        value.SkippedCount,
        value.Error,
        value.CreatedAt,
        value.StartedAt,
        value.FinishedAt);
}

public record CreateNotificationCampaignRequest(
    string? Title,
    string? Text,
    bool DisableNotification = false);

public record NotificationAudienceDto(long RecipientCount);
