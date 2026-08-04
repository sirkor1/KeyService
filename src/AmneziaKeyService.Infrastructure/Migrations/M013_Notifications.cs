using AmneziaKeyService.Core.Models;
using Microsoft.Extensions.Options;
using MongoDB.Driver;

namespace AmneziaKeyService.Infrastructure.Migrations;

public sealed class M013_Notifications : IMongoMigration
{
    private readonly MongoDbOptions _options;

    public M013_Notifications(IOptions<MongoDbOptions> options) => _options = options.Value;

    public string Id => "013_notifications";

    public async Task ApplyAsync(IMongoDatabase db, CancellationToken ct)
    {
        var campaigns = db.GetCollection<NotificationCampaign>(_options.NotificationCampaignsCollection);
        var campaignKeys = Builders<NotificationCampaign>.IndexKeys;
        await campaigns.Indexes.CreateManyAsync(new[]
        {
            new CreateIndexModel<NotificationCampaign>(campaignKeys.Descending(x => x.CreatedAt)),
            new CreateIndexModel<NotificationCampaign>(campaignKeys.Ascending(x => x.Status).Descending(x => x.CreatedAt))
        }, ct);

        var deliveries = db.GetCollection<NotificationDelivery>(_options.NotificationDeliveriesCollection);
        var deliveryKeys = Builders<NotificationDelivery>.IndexKeys;
        await deliveries.Indexes.CreateManyAsync(new[]
        {
            new CreateIndexModel<NotificationDelivery>(
                deliveryKeys.Ascending(x => x.CampaignId).Ascending(x => x.UserId),
                new CreateIndexOptions { Unique = true }),
            new CreateIndexModel<NotificationDelivery>(
                deliveryKeys.Ascending(x => x.Status).Ascending(x => x.AvailableAt)),
            new CreateIndexModel<NotificationDelivery>(
                deliveryKeys.Ascending(x => x.CampaignId).Ascending(x => x.Status)),
            new CreateIndexModel<NotificationDelivery>(deliveryKeys.Ascending("lease.until"))
        }, ct);
    }
}
