using AmneziaKeyService.Core.Interfaces;
using AmneziaKeyService.Core.Models;
using Microsoft.Extensions.Options;
using MongoDB.Driver;

namespace AmneziaKeyService.Infrastructure.Events;

/// <summary>
/// Именованные аренды поверх коллекции leases.
///
/// Взятие аренды — upsert с условием в фильтре. Приём стандартный и опирается
/// на то, что уникальность <c>_id</c> обеспечивает сама база: если документ
/// существует, но принадлежит другому владельцу, фильтр не совпадает, Mongo
/// пытается вставить новый документ с тем же <c>_id</c> и получает E11000.
/// Дубликат ключа здесь — не ошибка, а ответ «занято».
/// </summary>
public class LeaseRepository : ILeaseRepository
{
    private readonly IMongoCollection<Lease> _leases;

    public LeaseRepository(IMongoClient mongo, IOptions<MongoDbOptions> opts)
    {
        var db = mongo.GetDatabase(opts.Value.DatabaseName);
        _leases = db.GetCollection<Lease>(opts.Value.LeasesCollection);
        // Индекс уборки создаёт миграция 010.
    }

    public async Task<bool> TryAcquireAsync(
        string key, string owner, TimeSpan ttl, CancellationToken ct = default)
    {
        var now = DateTime.UtcNow;
        var b = Builders<Lease>.Filter;

        // Свободна, если срок истёк, — либо уже наша: повторное взятие
        // своей же аренды должно быть безобидным.
        var filter = b.And(
            b.Eq(x => x.Id, key),
            b.Or(b.Lt(x => x.Until, now), b.Eq(x => x.Owner, owner)));

        var update = Builders<Lease>.Update
            .Set(x => x.Owner, owner)
            .Set(x => x.Until, now + ttl);

        try
        {
            await _leases.UpdateOneAsync(
                filter, update, new UpdateOptions { IsUpsert = true }, ct);

            return true;
        }
        catch (MongoWriteException ex)
            when (ex.WriteError?.Category == ServerErrorCategory.DuplicateKey)
        {
            // Документ есть, но держит его кто-то другой, и срок не вышел.
            return false;
        }
    }

    public async Task<bool> RenewAsync(
        string key, string owner, TimeSpan ttl, CancellationToken ct = default)
    {
        var b = Builders<Lease>.Filter;

        // Без upsert: продлевать нечего, если аренды больше нет — значит
        // её отобрали, и держатель обязан об этом узнать.
        var result = await _leases.UpdateOneAsync(
            b.And(b.Eq(x => x.Id, key), b.Eq(x => x.Owner, owner)),
            Builders<Lease>.Update.Set(x => x.Until, DateTime.UtcNow + ttl),
            cancellationToken: ct);

        return result.MatchedCount > 0;
    }

    public Task ReleaseAsync(string key, string owner, CancellationToken ct = default)
    {
        var b = Builders<Lease>.Filter;

        // Владелец в фильтре: отпускать чужую аренду нельзя даже по ошибке —
        // это пустило бы второго исполнителя на занятый узел.
        return _leases.DeleteOneAsync(
            b.And(b.Eq(x => x.Id, key), b.Eq(x => x.Owner, owner)), ct);
    }
}
