using AmneziaKeyService.Core.DTOs;
using AmneziaKeyService.Core.Interfaces;
using AmneziaKeyService.Core.Models;
using Microsoft.Extensions.Options;
using MongoDB.Bson;
using MongoDB.Driver;

namespace AmneziaKeyService.Infrastructure.Repositories;

public class NotificationRepository : INotificationRepository
{
    private readonly IMongoCollection<NotificationCampaign> _campaigns;
    private readonly IMongoCollection<NotificationDelivery> _deliveries;

    public NotificationRepository(IMongoClient mongo, IOptions<MongoDbOptions> options)
    {
        var db = mongo.GetDatabase(options.Value.DatabaseName);
        _campaigns = db.GetCollection<NotificationCampaign>(options.Value.NotificationCampaignsCollection);
        _deliveries = db.GetCollection<NotificationDelivery>(options.Value.NotificationDeliveriesCollection);
    }

    public async Task<NotificationCampaign> CreateAsync(
        NotificationCampaign campaign,
        IReadOnlyCollection<User> recipients,
        CancellationToken ct = default)
    {
        campaign.Id = ObjectId.GenerateNewId().ToString();
        campaign.TotalCount = recipients.Count;
        campaign.Status = recipients.Count == 0
            ? NotificationCampaignStatuses.Completed
            : NotificationCampaignStatuses.Running;
        campaign.StartedAt = recipients.Count == 0 ? null : DateTime.UtcNow;
        campaign.FinishedAt = recipients.Count == 0 ? DateTime.UtcNow : null;

        await _campaigns.InsertOneAsync(campaign, cancellationToken: ct);

        if (recipients.Count == 0) return campaign;

        var deliveries = recipients
            .Where(x => x.TelegramId.HasValue)
            .Select(x => new NotificationDelivery
            {
                Id = ObjectId.GenerateNewId().ToString(),
                CampaignId = campaign.Id,
                UserId = x.Id,
                TelegramId = x.TelegramId!.Value
            })
            .ToList();

        try
        {
            await _deliveries.InsertManyAsync(
                deliveries,
                new InsertManyOptions { IsOrdered = false },
                ct);
        }
        catch (Exception ex)
        {
            await _campaigns.UpdateOneAsync(
                x => x.Id == campaign.Id,
                Builders<NotificationCampaign>.Update
                    .Set(x => x.Status, NotificationCampaignStatuses.Failed)
                    .Set(x => x.Error, "Не удалось подготовить очередь получателей.")
                    .Set(x => x.FinishedAt, DateTime.UtcNow),
                cancellationToken: CancellationToken.None);
            throw new InvalidOperationException("Не удалось подготовить очередь получателей.", ex);
        }

        return campaign;
    }

    public async Task<NotificationCampaign?> GetCampaignAsync(
        string id, CancellationToken ct = default)
    {
        if (!ObjectId.TryParse(id, out _)) return null;
        return await _campaigns.Find(x => x.Id == id).FirstOrDefaultAsync(ct);
    }

    public async Task<Paged<NotificationCampaign>> SearchCampaignsAsync(
        NotificationCampaignQuery query, CancellationToken ct = default)
    {
        var filter = string.IsNullOrWhiteSpace(query.Status)
            ? Builders<NotificationCampaign>.Filter.Empty
            : Builders<NotificationCampaign>.Filter.Eq(x => x.Status, query.Status);
        var paging = query.Paging;
        var total = await _campaigns.CountDocumentsAsync(filter, cancellationToken: ct);
        var items = await _campaigns.Find(filter)
            .SortByDescending(x => x.CreatedAt)
            .Skip(paging.Skip)
            .Limit(paging.PageSize)
            .ToListAsync(ct);
        return new Paged<NotificationCampaign>(items, total, paging.Page, paging.PageSize);
    }

    public async Task<bool> CancelAsync(string campaignId, CancellationToken ct = default)
    {
        if (!ObjectId.TryParse(campaignId, out _)) return false;

        var campaignResult = await _campaigns.UpdateOneAsync(
            x => x.Id == campaignId && NotificationCampaignStatuses.Active.Contains(x.Status),
            Builders<NotificationCampaign>.Update
                .Set(x => x.Status, NotificationCampaignStatuses.Canceled)
                .Set(x => x.FinishedAt, DateTime.UtcNow),
            cancellationToken: ct);
        if (campaignResult.ModifiedCount == 0) return false;

        var b = Builders<NotificationDelivery>.Filter;
        var deliveries = await _deliveries.UpdateManyAsync(
            b.And(
                b.Eq(x => x.CampaignId, campaignId),
                b.In(x => x.Status, new[]
                {
                    NotificationDeliveryStatuses.Pending,
                    NotificationDeliveryStatuses.Retry
                })),
            Builders<NotificationDelivery>.Update
                .Set(x => x.Status, NotificationDeliveryStatuses.Canceled)
                .Unset(x => x.Lease),
            cancellationToken: ct);

        if (deliveries.ModifiedCount > 0)
            await IncrementCampaignAsync(campaignId, skipped: deliveries.ModifiedCount, ct: ct);

        return true;
    }

    public async Task<NotificationDelivery?> ClaimNextAsync(
        string owner, TimeSpan leaseTtl, CancellationToken ct = default)
    {
        var now = DateTime.UtcNow;
        var b = Builders<NotificationDelivery>.Filter;
        var available = b.And(
            b.In(x => x.Status, new[]
            {
                NotificationDeliveryStatuses.Pending,
                NotificationDeliveryStatuses.Retry
            }),
            b.Lte(x => x.AvailableAt, now));
        var expired = b.And(
            b.Eq(x => x.Status, NotificationDeliveryStatuses.Sending),
            b.Lte("lease.until", now));

        return await _deliveries.FindOneAndUpdateAsync(
            b.Or(available, expired),
            Builders<NotificationDelivery>.Update
                .Set(x => x.Status, NotificationDeliveryStatuses.Sending)
                .Set(x => x.Lease, new EventLease { Owner = owner, Until = now + leaseTtl })
                .Inc(x => x.Attempt, 1)
                .Unset(x => x.ErrorCode)
                .Unset(x => x.Error),
            new FindOneAndUpdateOptions<NotificationDelivery>
            {
                ReturnDocument = ReturnDocument.After,
                Sort = Builders<NotificationDelivery>.Sort.Ascending(x => x.AvailableAt)
            },
            ct);
    }

    public async Task<bool> MarkSentAsync(
        NotificationDelivery delivery, string owner, int telegramMessageId,
        CancellationToken ct = default)
    {
        var changed = await FinishDeliveryAsync(
            delivery, owner,
            Builders<NotificationDelivery>.Update
                .Set(x => x.Status, NotificationDeliveryStatuses.Sent)
                .Set(x => x.SentAt, DateTime.UtcNow)
                .Set(x => x.TelegramMessageId, telegramMessageId)
                .Unset(x => x.Lease),
            ct);
        if (changed) await IncrementCampaignAsync(delivery.CampaignId, sent: 1, ct: ct);
        return changed;
    }

    public Task<bool> MarkRetryAsync(
        NotificationDelivery delivery, string owner, DateTime availableAt,
        int? errorCode, string error, CancellationToken ct = default)
        => FinishDeliveryAsync(
            delivery, owner,
            Builders<NotificationDelivery>.Update
                .Set(x => x.Status, NotificationDeliveryStatuses.Retry)
                .Set(x => x.AvailableAt, availableAt)
                .Set(x => x.ErrorCode, errorCode)
                .Set(x => x.Error, SafeError(error))
                .Unset(x => x.Lease),
            ct);

    public async Task<bool> MarkFailedAsync(
        NotificationDelivery delivery, string owner, int? errorCode, string error,
        CancellationToken ct = default)
    {
        var changed = await FinishDeliveryAsync(
            delivery, owner,
            Builders<NotificationDelivery>.Update
                .Set(x => x.Status, NotificationDeliveryStatuses.Failed)
                .Set(x => x.ErrorCode, errorCode)
                .Set(x => x.Error, SafeError(error))
                .Unset(x => x.Lease),
            ct);
        if (changed) await IncrementCampaignAsync(delivery.CampaignId, failed: 1, ct: ct);
        return changed;
    }

    public async Task<bool> MarkCanceledAsync(
        NotificationDelivery delivery, string owner, CancellationToken ct = default)
    {
        var changed = await FinishDeliveryAsync(
            delivery, owner,
            Builders<NotificationDelivery>.Update
                .Set(x => x.Status, NotificationDeliveryStatuses.Canceled)
                .Unset(x => x.Lease),
            ct);
        if (changed) await IncrementCampaignAsync(delivery.CampaignId, skipped: 1, ct: ct);
        return changed;
    }

    private async Task<bool> FinishDeliveryAsync(
        NotificationDelivery delivery,
        string owner,
        UpdateDefinition<NotificationDelivery> update,
        CancellationToken ct)
    {
        var b = Builders<NotificationDelivery>.Filter;
        var result = await _deliveries.UpdateOneAsync(
            b.And(
                b.Eq(x => x.Id, delivery.Id),
                b.Eq(x => x.Status, NotificationDeliveryStatuses.Sending),
                b.Eq("lease.owner", owner)),
            update,
            cancellationToken: ct);
        return result.ModifiedCount > 0;
    }

    private async Task IncrementCampaignAsync(
        string campaignId,
        long sent = 0,
        long failed = 0,
        long skipped = 0,
        CancellationToken ct = default)
    {
        var update = Builders<NotificationCampaign>.Update.Combine(
            Builders<NotificationCampaign>.Update.Inc(x => x.SentCount, sent),
            Builders<NotificationCampaign>.Update.Inc(x => x.FailedCount, failed),
            Builders<NotificationCampaign>.Update.Inc(x => x.SkippedCount, skipped));

        await _campaigns.UpdateOneAsync(x => x.Id == campaignId, update, cancellationToken: ct);
        var campaign = await _campaigns.Find(x => x.Id == campaignId).FirstOrDefaultAsync(ct);
        if (campaign is null || campaign.IsTerminal ||
            campaign.SentCount + campaign.FailedCount + campaign.SkippedCount < campaign.TotalCount)
            return;

        await _campaigns.UpdateOneAsync(
            x => x.Id == campaignId && x.Status == NotificationCampaignStatuses.Running,
            Builders<NotificationCampaign>.Update
                .Set(x => x.Status, NotificationCampaignStatuses.Completed)
                .Set(x => x.FinishedAt, DateTime.UtcNow),
            cancellationToken: ct);
    }

    private static string SafeError(string error)
        => error.Length <= 500 ? error : error[..500];
}
