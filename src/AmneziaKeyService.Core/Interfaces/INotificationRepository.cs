using AmneziaKeyService.Core.DTOs;
using AmneziaKeyService.Core.Models;

namespace AmneziaKeyService.Core.Interfaces;

public interface INotificationRepository
{
    Task<NotificationCampaign> CreateAsync(
        NotificationCampaign campaign,
        IReadOnlyCollection<User> recipients,
        CancellationToken ct = default);

    Task<NotificationCampaign?> GetCampaignAsync(string id, CancellationToken ct = default);
    Task<Paged<NotificationCampaign>> SearchCampaignsAsync(
        NotificationCampaignQuery query, CancellationToken ct = default);

    Task<bool> CancelAsync(string campaignId, CancellationToken ct = default);

    Task<NotificationDelivery?> ClaimNextAsync(
        string owner, TimeSpan leaseTtl, CancellationToken ct = default);

    Task<bool> MarkSentAsync(
        NotificationDelivery delivery, string owner, int telegramMessageId,
        CancellationToken ct = default);

    Task<bool> MarkRetryAsync(
        NotificationDelivery delivery, string owner, DateTime availableAt,
        int? errorCode, string error, CancellationToken ct = default);

    Task<bool> MarkFailedAsync(
        NotificationDelivery delivery, string owner, int? errorCode, string error,
        CancellationToken ct = default);

    Task<bool> MarkCanceledAsync(
        NotificationDelivery delivery, string owner, CancellationToken ct = default);
}

public record NotificationCampaignQuery(
    string? Status = null,
    int? Page = null,
    int? PageSize = null)
{
    public PageRequest Paging => new(Page, PageSize);
}
