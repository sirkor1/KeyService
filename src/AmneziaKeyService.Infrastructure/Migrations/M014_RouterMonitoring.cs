using AmneziaKeyService.Core.Models;
using MongoDB.Driver;

namespace AmneziaKeyService.Infrastructure.Migrations;

public sealed class M014_RouterMonitoring : IMongoMigration
{
    public string Id => "014_router_monitoring";
    public async Task ApplyAsync(IMongoDatabase db, CancellationToken ct)
    {
        var routers = db.GetCollection<RouterMonitor>("router_monitors");
        await routers.Indexes.CreateManyAsync(new[]
        {
            new CreateIndexModel<RouterMonitor>(Builders<RouterMonitor>.IndexKeys.Ascending(x => x.KeyId), new CreateIndexOptions { Unique = true }),
            new CreateIndexModel<RouterMonitor>(Builders<RouterMonitor>.IndexKeys.Ascending(x => x.UserId).Ascending(x => x.Archived))
        }, ct);
        var history = db.GetCollection<RouterTransition>("router_history");
        await history.Indexes.CreateManyAsync(new[]
        {
            new CreateIndexModel<RouterTransition>(Builders<RouterTransition>.IndexKeys.Ascending(x => x.RouterId).Descending(x => x.At)),
            new CreateIndexModel<RouterTransition>(Builders<RouterTransition>.IndexKeys.Ascending(x => x.DeliveryStatus).Ascending(x => x.AvailableAt)),
            new CreateIndexModel<RouterTransition>(Builders<RouterTransition>.IndexKeys.Ascending(x => x.LeaseUntil))
        }, ct);
    }
}
