using AmneziaKeyService.Core.Models;
using Microsoft.Extensions.Options;
using MongoDB.Bson;
using MongoDB.Driver;

namespace AmneziaKeyService.Infrastructure.Repositories;

public sealed class RouterMonitorRepository
{
    private readonly IMongoCollection<RouterMonitor> _routers;
    private readonly IMongoCollection<RouterTransition> _history;
    private readonly IMongoCollection<DomainEvent> _events;

    public RouterMonitorRepository(IMongoClient mongo, IOptions<MongoDbOptions> options)
    {
        var db = mongo.GetDatabase(options.Value.DatabaseName);
        _routers = db.GetCollection<RouterMonitor>("router_monitors");
        _history = db.GetCollection<RouterTransition>("router_history");
        _events = db.GetCollection<DomainEvent>(options.Value.DomainEventsCollection);
    }

    public Task<List<RouterMonitor>> ListAsync(CancellationToken ct, bool includeArchived = false)
        => _routers.Find(x => includeArchived || !x.Archived).SortBy(x => x.Name).ToListAsync(ct);
    public Task<List<RouterMonitor>> ForUserAsync(string userId, CancellationToken ct)
        => _routers.Find(x => !x.Archived && x.UserId == userId).SortBy(x => x.Name).ToListAsync(ct);
    public async Task<RouterMonitor?> GetAsync(string id, CancellationToken ct)
        => !ObjectId.TryParse(id, out _) ? null : await _routers.Find(x => x.Id == id).FirstOrDefaultAsync(ct);
    public Task CreateAsync(RouterMonitor router, CancellationToken ct)
        => _routers.InsertOneAsync(router, cancellationToken: ct);

    public async Task<bool> SaveAsync(RouterMonitor router, CancellationToken ct)
    {
        var expected = router.Version;
        router.Version++;
        var result = await _routers.ReplaceOneAsync(x => x.Id == router.Id && x.Version == expected, router, cancellationToken: ct);
        return result.ModifiedCount == 1;
    }

    // Idempotent relay: a crash between history insert and acknowledgement is harmless.
    public async Task FlushAsync(RouterMonitor router, CancellationToken ct)
    {
        foreach (var item in router.PendingHistory)
        {
            try { await _history.InsertOneAsync(item, cancellationToken: ct); }
            catch (MongoWriteException ex) when (ex.WriteError.Category == ServerErrorCategory.DuplicateKey) { }
            await _routers.UpdateOneAsync(x => x.Id == router.Id,
                Builders<RouterMonitor>.Update.PullFilter(x => x.PendingHistory, h => h.Id == item.Id).Inc(x => x.Version, 1), cancellationToken: ct);
        }
    }

    // The persisted router is also an outbox for key provisioning; no HTTP/queue dual-write gap.
    public async Task EnsureProvisionAsync(RouterMonitor router, CancellationToken ct)
    {
        if (router.Archived || router.ProvisionDispatched) return;
        var payload = new KeyIssuePayload(router.KeyId, router.ServerId, router.UserId, false,
            router.ProtocolId, null, router.Name, "Наблюдение за роутером", null, null,
            "router", router.CreatedByUserId, null);
        var evt = new DomainEvent
        {
            Id = router.ProvisionEventId, Type = DomainEventTypes.KeyIssue, Payload = payload.ToBsonDocument(),
            PartitionKey = router.ServerId, CorrelationId = router.KeyId, ActorUserId = router.CreatedByUserId
        };
        try { await _events.InsertOneAsync(evt, cancellationToken: ct); }
        catch (MongoWriteException ex) when (ex.WriteError.Category == ServerErrorCategory.DuplicateKey) { }
        // Events expire after 30 days. Remember dispatch independently, or TTL cleanup
        // could accidentally issue a second peer for the same router.
        await _routers.UpdateOneAsync(x => x.Id == router.Id && !x.ProvisionDispatched,
            Builders<RouterMonitor>.Update.Set(x => x.ProvisionDispatched, true).Inc(x => x.Version, 1), cancellationToken: ct);
    }

    public Task<List<RouterTransition>> HistoryAsync(string id, CancellationToken ct, int limit = 100)
        => _history.Find(x => x.RouterId == id).SortByDescending(x => x.At).Limit(limit).ToListAsync(ct);

    public Task<RouterTransition?> ClaimDeliveryAsync(string owner, CancellationToken ct)
    {
        var now = DateTime.UtcNow;
        return _history.FindOneAndUpdateAsync(x =>
            (x.DeliveryStatus == "pending" && x.AvailableAt <= now || x.DeliveryStatus == "sending" && x.LeaseUntil < now),
            Builders<RouterTransition>.Update.Set(x => x.DeliveryStatus, "sending")
                .Set(x => x.LeaseOwner, owner).Set(x => x.LeaseUntil, now.AddMinutes(2)).Inc(x => x.Attempts, 1),
            new FindOneAndUpdateOptions<RouterTransition> { ReturnDocument = ReturnDocument.After, Sort = Builders<RouterTransition>.Sort.Ascending(x => x.At) }, ct)!;
    }

    public Task CompleteDeliveryAsync(RouterTransition item, string owner, string status, string? error, int retrySeconds, CancellationToken ct)
        => _history.UpdateOneAsync(x => x.Id == item.Id && x.LeaseOwner == owner && x.DeliveryStatus == "sending",
            Builders<RouterTransition>.Update.Set(x => x.DeliveryStatus, status).Set(x => x.DeliveryError, error)
                .Set(x => x.AvailableAt, DateTime.UtcNow.AddSeconds(retrySeconds)).Set(x => x.LeaseUntil, null)
                .Set(x => x.SentAt, status == "sent" ? DateTime.UtcNow : (DateTime?)null), cancellationToken: ct);
}
