using AmneziaKeyService.Core.Interfaces;
using AmneziaKeyService.Core.Models;
using Microsoft.Extensions.Options;
using MongoDB.Driver;

namespace AmneziaKeyService.Infrastructure.Repositories;

public class UsageRepository : IUsageRepository
{
    /// <summary>
    /// Сколько живут срезы. Сутки сверх года: годовой отчёт должен видеть
    /// целиком тот же месяц прошлого года, а не начинаться с обрубка.
    /// </summary>
    private static readonly TimeSpan Retention = TimeSpan.FromDays(400);

    private readonly IMongoCollection<KeyUsageDaily> _keyUsage;
    private readonly IMongoCollection<ServerUsageDaily> _serverUsage;
    private readonly IMongoCollection<ServerHealthDaily> _serverHealth;

    public UsageRepository(IMongoClient mongo, IOptions<MongoDbOptions> opts)
    {
        var db = mongo.GetDatabase(opts.Value.DatabaseName);
        _keyUsage     = db.GetCollection<KeyUsageDaily>(opts.Value.KeyUsageDailyCollection);
        _serverUsage  = db.GetCollection<ServerUsageDaily>(opts.Value.ServerUsageDailyCollection);
        _serverHealth = db.GetCollection<ServerHealthDaily>(opts.Value.ServerHealthDailyCollection);
        // Индексы создаёт миграция 009.
    }

    public Task IncrementKeysAsync(
        IReadOnlyCollection<UsageDelta> deltas, DateOnly day, CancellationToken ct = default)
    {
        var writes = new List<WriteModel<KeyUsageDaily>>(deltas.Count);
        var date   = UsageDailyKey.Format(day);
        var expire = ExpireAt(day);

        foreach (var d in deltas)
        {
            if (d.IsEmpty) continue;

            var id = UsageDailyKey.For(d.KeyId, d.ServerId, day);

            writes.Add(new UpdateOneModel<KeyUsageDaily>(
                Builders<KeyUsageDaily>.Filter.Eq(x => x.Id, id),
                Builders<KeyUsageDaily>.Update
                    .Inc(x => x.RxBytes, d.RxBytes)
                    .Inc(x => x.TxBytes, d.TxBytes)
                    .SetOnInsert(x => x.KeyId, d.KeyId)
                    .SetOnInsert(x => x.ServerId, d.ServerId)
                    .SetOnInsert(x => x.Date, date)
                    .SetOnInsert(x => x.ExpireAt, expire))
            {
                IsUpsert = true,
            });
        }

        if (writes.Count == 0) return Task.CompletedTask;

        // Порядок не важен, а неупорядоченная запись не останавливается
        // на первой ошибке — один сбойный ключ не должен терять остальные.
        return _keyUsage.BulkWriteAsync(writes, new BulkWriteOptions { IsOrdered = false }, ct);
    }

    public Task IncrementServerAsync(
        string serverId, DateOnly day, long rxBytes, long txBytes, CancellationToken ct = default)
    {
        if (rxBytes == 0 && txBytes == 0) return Task.CompletedTask;

        return _serverUsage.UpdateOneAsync(
            Builders<ServerUsageDaily>.Filter.Eq(x => x.Id, UsageDailyKey.For(serverId, day)),
            Builders<ServerUsageDaily>.Update
                .Inc(x => x.RxBytes, rxBytes)
                .Inc(x => x.TxBytes, txBytes)
                .SetOnInsert(x => x.ServerId, serverId)
                .SetOnInsert(x => x.Date, UsageDailyKey.Format(day))
                .SetOnInsert(x => x.ExpireAt, ExpireAt(day)),
            new UpdateOptions { IsUpsert = true }, ct);
    }

    public Task RecordHealthCheckAsync(
        string serverId, DateOnly day, bool ok, CancellationToken ct = default)
        => _serverHealth.UpdateOneAsync(
            Builders<ServerHealthDaily>.Filter.Eq(x => x.Id, UsageDailyKey.For(serverId, day)),
            Builders<ServerHealthDaily>.Update
                .Inc(x => x.ChecksTotal, 1)
                .Inc(x => x.ChecksOk, ok ? 1 : 0)
                .SetOnInsert(x => x.ServerId, serverId)
                .SetOnInsert(x => x.Date, UsageDailyKey.Format(day))
                .SetOnInsert(x => x.ExpireAt, ExpireAt(day)),
            new UpdateOptions { IsUpsert = true }, ct);

    public async Task<long> SumServerTrafficAsync(
        string serverId, DateOnly from, DateOnly to, CancellationToken ct = default)
    {
        var result = await _serverUsage
            .Aggregate()
            .Match(InRange(serverId, from, to))
            .Group(x => 1, g => new { Rx = g.Sum(x => x.RxBytes), Tx = g.Sum(x => x.TxBytes) })
            .FirstOrDefaultAsync(ct);

        return result is null ? 0 : result.Rx + result.Tx;
    }

    public async Task<Dictionary<string, long>> SumTrafficByServerAsync(
        DateOnly from, DateOnly to, CancellationToken ct = default)
    {
        var grouped = await _serverUsage
            .Aggregate()
            .Match(InRange(null, from, to))
            .Group(x => x.ServerId,
                g => new { ServerId = g.Key, Rx = g.Sum(x => x.RxBytes), Tx = g.Sum(x => x.TxBytes) })
            .ToListAsync(ct);

        return grouped.ToDictionary(x => x.ServerId, x => x.Rx + x.Tx);
    }

    public async Task<long> SumTotalTrafficAsync(
        DateOnly from, DateOnly to, CancellationToken ct = default)
    {
        var result = await _serverUsage
            .Aggregate()
            .Match(InRange(null, from, to))
            .Group(x => 1, g => new { Rx = g.Sum(x => x.RxBytes), Tx = g.Sum(x => x.TxBytes) })
            .FirstOrDefaultAsync(ct);

        return result is null ? 0 : result.Rx + result.Tx;
    }

    public async Task<double?> GetUptimePercentAsync(
        string serverId, DateOnly from, DateOnly to, CancellationToken ct = default)
    {
        var b = Builders<ServerHealthDaily>.Filter;

        var result = await _serverHealth
            .Aggregate()
            .Match(b.And(
                b.Eq(x => x.ServerId, serverId),
                b.Gte(x => x.Date, UsageDailyKey.Format(from)),
                b.Lte(x => x.Date, UsageDailyKey.Format(to))))
            .Group(x => 1,
                g => new { Total = g.Sum(x => x.ChecksTotal), Ok = g.Sum(x => x.ChecksOk) })
            .FirstOrDefaultAsync(ct);

        if (result is null || result.Total == 0) return null;

        return Math.Round((double)result.Ok / result.Total * 100, 1);
    }

    /// <summary>Диапазон дат по строковому полю: ISO-формат сортируется как хронология.</summary>
    private static FilterDefinition<ServerUsageDaily> InRange(
        string? serverId, DateOnly from, DateOnly to)
    {
        var b = Builders<ServerUsageDaily>.Filter;

        var filter = b.And(
            b.Gte(x => x.Date, UsageDailyKey.Format(from)),
            b.Lte(x => x.Date, UsageDailyKey.Format(to)));

        return serverId is null ? filter : b.And(b.Eq(x => x.ServerId, serverId), filter);
    }

    private static DateTime ExpireAt(DateOnly day)
        => day.ToDateTime(TimeOnly.MinValue, DateTimeKind.Utc).Add(Retention);
}
