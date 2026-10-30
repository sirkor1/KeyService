using AmneziaKeyService.Core.DTOs;
using AmneziaKeyService.Core.Interfaces;
using AmneziaKeyService.Core.Models;
using Microsoft.Extensions.Options;
using MongoDB.Bson;
using MongoDB.Driver;

namespace AmneziaKeyService.Infrastructure.Repositories;

public class SubscriptionRepository : ISubscriptionRepository
{
    private readonly IMongoCollection<Subscription> _collection;

    public SubscriptionRepository(IMongoClient mongo, IOptions<MongoDbOptions> opts)
    {
        var db = mongo.GetDatabase(opts.Value.DatabaseName);
        _collection = db.GetCollection<Subscription>(opts.Value.SubscriptionsCollection);
        // Индексы создаёт миграция 016.
    }

    public async Task<Subscription?> FindByIdAsync(string id, CancellationToken ct = default)
    {
        // Невалидный ObjectId — «не найдено»: id приходит из URL.
        if (!ObjectId.TryParse(id, out _)) return null;
        return await _collection.Find(x => x.Id == id).FirstOrDefaultAsync(ct);
    }

    public Task<Subscription?> FindByTokenHashAsync(string tokenHash, CancellationToken ct = default)
        => _collection.Find(x => x.TokenHash == tokenHash).FirstOrDefaultAsync(ct)!;

    public Task<Subscription?> FindActiveByUserAsync(string userId, CancellationToken ct = default)
    {
        if (!ObjectId.TryParse(userId, out _)) return Task.FromResult<Subscription?>(null);
        return _collection.Find(x => x.UserId == userId && x.Status == SubscriptionStatuses.Active)
            .FirstOrDefaultAsync(ct)!;
    }

    public Task<Subscription?> FindLatestByUserAsync(string userId, CancellationToken ct = default)
    {
        if (!ObjectId.TryParse(userId, out _)) return Task.FromResult<Subscription?>(null);
        // _id во вторичном ключе: при равных createdAt (миллисекунды) порядок всё равно детерминирован.
        return _collection.Find(x => x.UserId == userId)
            .SortByDescending(x => x.CreatedAt).ThenByDescending(x => x.Id)
            .FirstOrDefaultAsync(ct)!;
    }

    public async Task<List<Subscription>> FindByIdsAsync(IEnumerable<string> ids, CancellationToken ct = default)
    {
        var valid = ids.Where(i => ObjectId.TryParse(i, out _)).Distinct().ToList();
        if (valid.Count == 0) return [];
        return await _collection.Find(Builders<Subscription>.Filter.In(x => x.Id, valid)).ToListAsync(ct);
    }

    public async Task<bool> TryCreateAsync(Subscription subscription, CancellationToken ct = default)
    {
        try
        {
            await _collection.InsertOneAsync(subscription, cancellationToken: ct);
            return true;
        }
        catch (MongoWriteException ex) when (ex.WriteError?.Category == ServerErrorCategory.DuplicateKey)
        {
            return false;
        }
    }

    public async Task<Paged<Subscription>> SearchAsync(SubscriptionQuery query, CancellationToken ct = default)
    {
        var b = Builders<Subscription>.Filter;
        var filters = new List<FilterDefinition<Subscription>>();

        var search = new List<FilterDefinition<Subscription>>();
        if (query.Id is not null && ObjectId.TryParse(query.Id, out _)) search.Add(b.Eq(x => x.Id, query.Id));
        if (query.UserIds is { Count: > 0 }) search.Add(b.In(x => x.UserId, query.UserIds));

        // Поиск задан, но искать нечем (ни подходящего id, ни пользователей) — это пустой
        // результат, а не «всё подряд».
        if (query.Id is not null || query.UserIds is not null)
        {
            if (search.Count == 0) return Paged<Subscription>.Empty(query.Paging.Page, query.Paging.PageSize);
            filters.Add(b.Or(search));
        }

        if (!string.IsNullOrWhiteSpace(query.Status))
            filters.Add(b.Eq(x => x.Status, query.Status));

        var filter = filters.Count == 0 ? FilterDefinition<Subscription>.Empty : b.And(filters);
        var paging = query.Paging;

        var total = await _collection.CountDocumentsAsync(filter, cancellationToken: ct);
        var items = await _collection.Find(filter)
            .SortByDescending(x => x.CreatedAt)
            .Skip(paging.Skip)
            .Limit(paging.PageSize)
            .ToListAsync(ct);

        return new Paged<Subscription>(items, total, paging.Page, paging.PageSize);
    }

    public Task<List<Subscription>> FindDesiredAsync(DateTime now, CancellationToken ct = default)
    {
        var b = Builders<Subscription>.Filter;
        return _collection.Find(b.And(
                b.Eq(x => x.Status, SubscriptionStatuses.Active),
                b.Or(b.Eq(x => x.ExpiresAt, null), b.Gt(x => x.ExpiresAt, now))))
            .ToListAsync(ct);
    }

    public Task<List<Subscription>> FindEnforcementCandidatesAsync(DateTime now, CancellationToken ct = default)
    {
        var b = Builders<Subscription>.Filter;

        var expired = b.And(b.Ne(x => x.ExpiresAt, null), b.Lte(x => x.ExpiresAt, now));

        // Сумма двух полей против третьего выражается только через $expr; отсутствующий
        // trafficLimitBytes даёт false на первом условии. Так же устроен отбор ключей.
        var overQuota = new BsonDocumentFilterDefinition<Subscription>(new BsonDocument("$expr",
            new BsonDocument("$and", new BsonArray
            {
                new BsonDocument("$ne", new BsonArray { "$trafficLimitBytes", BsonNull.Value }),
                new BsonDocument("$gte", new BsonArray
                {
                    new BsonDocument("$add", new BsonArray
                    {
                        new BsonDocument("$ifNull", new BsonArray { "$usage.rxBytes", 0 }),
                        new BsonDocument("$ifNull", new BsonArray { "$usage.txBytes", 0 }),
                    }),
                    "$trafficLimitBytes",
                }),
            })));

        return _collection.Find(b.And(
                b.Eq(x => x.Status, SubscriptionStatuses.Active),
                b.Or(expired, overQuota)))
            .ToListAsync(ct);
    }

    public async Task<bool> TryRevokeAsync(string id, string reason, DateTime now, CancellationToken ct = default)
    {
        var b = Builders<Subscription>.Filter;
        var result = await _collection.UpdateOneAsync(
            b.Eq(x => x.Id, id) & b.Eq(x => x.Status, SubscriptionStatuses.Active),
            Builders<Subscription>.Update
                .Set(x => x.Status, SubscriptionStatuses.Revoked)
                .Set(x => x.RevokeReason, reason)
                .Set(x => x.RevokedAt, now),
            cancellationToken: ct);
        return result.ModifiedCount == 1;
    }

    public async Task<bool> TryReplaceCredentialsAsync(
        string id, string tokenHash, EncryptedValue tokenEncrypted, string xrayUuid, DateTime now,
        CancellationToken ct = default)
    {
        var b = Builders<Subscription>.Filter;
        var result = await _collection.UpdateOneAsync(
            b.Eq(x => x.Id, id) & b.Eq(x => x.Status, SubscriptionStatuses.Active),
            Builders<Subscription>.Update
                .Set(x => x.TokenHash, tokenHash)
                .Set(x => x.TokenEncrypted, tokenEncrypted)
                .Set(x => x.XrayUuid, xrayUuid)
                .Set(x => x.TokenRotatedAt, now),
            cancellationToken: ct);
        return result.ModifiedCount == 1;
    }

    public async Task<bool> TryUpdateLimitsAsync(
        string id, DateTime? expiresAt, long? trafficLimitBytes, CancellationToken ct = default)
    {
        var b = Builders<Subscription>.Filter;
        var result = await _collection.UpdateOneAsync(
            b.Eq(x => x.Id, id) & b.Eq(x => x.Status, SubscriptionStatuses.Active),
            Builders<Subscription>.Update
                .Set(x => x.ExpiresAt, expiresAt)
                .Set(x => x.TrafficLimitBytes, trafficLimitBytes),
            cancellationToken: ct);
        // MatchedCount, а не ModifiedCount: повторная отправка тех же границ — не ошибка.
        return result.MatchedCount == 1;
    }

    public Task ApplyUsageAsync(IReadOnlyCollection<SubscriptionUsageUpdate> updates, CancellationToken ct = default)
    {
        if (updates.Count == 0) return Task.CompletedTask;

        var writes = new List<WriteModel<Subscription>>(updates.Count);
        foreach (var u in updates)
        {
            // Приращение и новые сырые значения — одним обновлением документа: записанные
            // раздельно, они при сбое между операциями задвоили бы или потеряли приращение.
            var update = Builders<Subscription>.Update
                .Inc(x => x.Usage.RxBytes, u.RxDelta)
                .Inc(x => x.Usage.TxBytes, u.TxDelta)
                .Set($"rawByNode.{u.ServerId}", new SubscriptionNodeRaw { Rx = u.RxRaw, Tx = u.TxRaw });

            // lastSeenAt — «когда последний раз шёл трафик», а не «когда опрашивали».
            if (u.RxDelta > 0 || u.TxDelta > 0)
                update = update.Set(x => x.Usage.LastSeenAt, u.SeenAt);

            writes.Add(new UpdateOneModel<Subscription>(
                Builders<Subscription>.Filter.Eq(x => x.Id, u.SubscriptionId), update));
        }

        return _collection.BulkWriteAsync(writes, new BulkWriteOptions { IsOrdered = false }, ct);
    }
}
