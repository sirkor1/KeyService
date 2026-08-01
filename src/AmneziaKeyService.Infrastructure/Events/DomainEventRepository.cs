using AmneziaKeyService.Core.Interfaces;
using AmneziaKeyService.Core.Models;
using Microsoft.Extensions.Options;
using MongoDB.Bson;
using MongoDB.Driver;

namespace AmneziaKeyService.Infrastructure.Events;

/// <summary>
/// Очередь работ поверх коллекции domain_events.
///
/// Захват — один <c>findOneAndUpdate</c>: он атомарен на уровне документа
/// даже на standalone-развёртывании, где нет ни транзакций, ни change streams.
/// Больше очереди ничего и не нужно — вся конкуренция сводится к тому, чтобы
/// два процесса не забрали одно событие.
/// </summary>
public class DomainEventRepository : IDomainEventRepository
{
    private readonly IMongoCollection<DomainEvent> _events;

    public DomainEventRepository(IMongoClient mongo, IOptions<MongoDbOptions> opts)
    {
        var db = mongo.GetDatabase(opts.Value.DatabaseName);
        _events = db.GetCollection<DomainEvent>(opts.Value.DomainEventsCollection);
        // Индексы создаёт миграция 010.
    }

    public async Task<DomainEvent> PublishAsync(
        string type,
        object payload,
        string? partitionKey = null,
        string? correlationId = null,
        string? actorUserId = null,
        CancellationToken ct = default)
    {
        var evt = new DomainEvent
        {
            Type          = type,
            Payload       = payload.ToBsonDocument(payload.GetType()),
            PartitionKey  = partitionKey,
            CorrelationId = correlationId,
            ActorUserId   = actorUserId,
            Status        = DomainEventStatuses.Pending,
            AvailableAt   = DateTime.UtcNow,
        };

        await _events.InsertOneAsync(evt, cancellationToken: ct);
        return evt;
    }

    public async Task<DomainEvent?> GetByIdAsync(string id, CancellationToken ct = default)
    {
        // Невалидный ObjectId — это «не найдено», а не ошибка: id приходит из URL.
        if (!ObjectId.TryParse(id, out _)) return null;
        return await _events.Find(x => x.Id == id).FirstOrDefaultAsync(ct);
    }

    public Task<DomainEvent?> ClaimAsync(
        IReadOnlyCollection<string> types, string owner, TimeSpan leaseTtl, CancellationToken ct = default)
    {
        if (types.Count == 0) return Task.FromResult<DomainEvent?>(null);

        var now = DateTime.UtcNow;
        var b = Builders<DomainEvent>.Filter;

        var filter = b.And(
            b.In(x => x.Type, types),
            b.Eq(x => x.Status, DomainEventStatuses.Pending),
            b.Lte(x => x.AvailableAt, now));

        var update = Builders<DomainEvent>.Update
            .Set(x => x.Status, DomainEventStatuses.Claimed)
            .Set(x => x.Lease, new EventLease { Owner = owner, Until = now + leaseTtl })
            .Set(x => x.StartedAt, now)
            .Inc(x => x.Attempt, 1);

        return _events.FindOneAndUpdateAsync(filter, update,
            new FindOneAndUpdateOptions<DomainEvent>
            {
                // Первым — то, что дольше ждало: иначе событие с большим
                // backoff могло бы не дождаться очереди никогда.
                Sort           = Builders<DomainEvent>.Sort.Ascending(x => x.AvailableAt),
                ReturnDocument = ReturnDocument.After,
            }, ct)!;
    }

    public async Task<bool> RenewLeaseAsync(
        string id, string owner, TimeSpan leaseTtl, CancellationToken ct = default)
    {
        var b = Builders<DomainEvent>.Filter;

        // Владелец в фильтре обязателен: если аренду успел перехватить жнец
        // и отдать другому процессу, продлевать её нельзя — иначе два
        // обработчика считали бы себя хозяевами одного события.
        var result = await _events.UpdateOneAsync(
            b.And(
                b.Eq(x => x.Id, id),
                b.Eq(x => x.Status, DomainEventStatuses.Claimed),
                b.Eq("lease.owner", owner)),
            Builders<DomainEvent>.Update.Set(x => x.Lease!.Until, DateTime.UtcNow + leaseTtl),
            cancellationToken: ct);

        return result.MatchedCount > 0;
    }

    public Task RequeueAsync(
        string id, DateTime availableAt, bool countsAsAttempt, CancellationToken ct = default)
    {
        var update = Builders<DomainEvent>.Update
            .Set(x => x.Status, DomainEventStatuses.Pending)
            .Set(x => x.AvailableAt, availableAt)
            .Set(x => x.Lease, null)
            .Set(x => x.StartedAt, null);

        // Захват увеличил счётчик попыток авансом. Если работа так и не
        // началась — партиция была занята, — аванс надо вернуть, иначе
        // загруженный узел исчерпал бы попытки события, которое не пробовали.
        if (!countsAsAttempt) update = update.Inc(x => x.Attempt, -1);

        return _events.UpdateOneAsync(
            Builders<DomainEvent>.Filter.Eq(x => x.Id, id), update, cancellationToken: ct);
    }

    public Task CompleteAsync(string id, BsonDocument? result, CancellationToken ct = default)
        => _events.UpdateOneAsync(
            Builders<DomainEvent>.Filter.Eq(x => x.Id, id),
            Builders<DomainEvent>.Update
                .Set(x => x.Status, DomainEventStatuses.Succeeded)
                .Set(x => x.Result, result)
                .Set(x => x.Error, null)
                .Set(x => x.Lease, null)
                .Set(x => x.FinishedAt, DateTime.UtcNow),
            cancellationToken: ct);

    public Task FailAsync(string id, string error, CancellationToken ct = default)
        => _events.UpdateOneAsync(
            Builders<DomainEvent>.Filter.Eq(x => x.Id, id),
            Builders<DomainEvent>.Update
                .Set(x => x.Status, DomainEventStatuses.Failed)
                .Set(x => x.Error, error)
                .Set(x => x.Lease, null)
                .Set(x => x.FinishedAt, DateTime.UtcNow),
            cancellationToken: ct);

    public Task<List<DomainEvent>> FindExpiredAsync(
        IReadOnlyCollection<string> types, int limit, CancellationToken ct = default)
    {
        if (types.Count == 0) return Task.FromResult(new List<DomainEvent>());

        var b = Builders<DomainEvent>.Filter;

        return _events.Find(b.And(
                b.In(x => x.Type, types),
                b.Eq(x => x.Status, DomainEventStatuses.Claimed),
                b.Lt("lease.until", DateTime.UtcNow)))
            .Limit(Math.Clamp(limit, 1, 500))
            .ToListAsync(ct);
    }
}
