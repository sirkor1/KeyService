using AmneziaKeyService.Core.Models;
using Microsoft.Extensions.Options;
using MongoDB.Driver;

namespace AmneziaKeyService.Infrastructure.Migrations;

/// <summary>
/// Индексы суточных срезов трафика и доступности.
///
/// TTL держит объём в узде: срез на ключ на сутки — это до нескольких тысяч
/// документов в день, и без потолка коллекция растёт бесконечно. 400 дней
/// выбраны так, чтобы годовое сравнение видело полный месяц прошлого года.
/// </summary>
public class M009_UsageIndexes : IMongoMigration
{
    private readonly MongoDbOptions _opts;

    public M009_UsageIndexes(IOptions<MongoDbOptions> opts) => _opts = opts.Value;

    public string Id => "009_usage_indexes";

    public async Task ApplyAsync(IMongoDatabase db, CancellationToken ct)
    {
        var keyUsage = db.GetCollection<KeyUsageDaily>(_opts.KeyUsageDailyCollection);
        var keyKeys  = Builders<KeyUsageDaily>.IndexKeys;

        await keyUsage.Indexes.CreateManyAsync(
        [
            new CreateIndexModel<KeyUsageDaily>(
                keyKeys.Ascending(x => x.KeyId).Ascending(x => x.Date)),

            new CreateIndexModel<KeyUsageDaily>(
                keyKeys.Ascending(x => x.ServerId).Ascending(x => x.Date)),

            // ExpireAfter нулевой: момент удаления записан в самом документе,
            // поэтому срок хранения меняется правкой ExpireAt, а не индекса.
            new CreateIndexModel<KeyUsageDaily>(keyKeys.Ascending(x => x.ExpireAt),
                new CreateIndexOptions { ExpireAfter = TimeSpan.Zero }),
        ], ct);

        var serverUsage = db.GetCollection<ServerUsageDaily>(_opts.ServerUsageDailyCollection);
        var serverKeys  = Builders<ServerUsageDaily>.IndexKeys;

        await serverUsage.Indexes.CreateManyAsync(
        [
            new CreateIndexModel<ServerUsageDaily>(
                serverKeys.Ascending(x => x.ServerId).Ascending(x => x.Date)),

            // Плитка «Трафик за месяц» суммирует все узлы разом — фильтр
            // идёт только по дате, и составной индекс тут не помогает.
            new CreateIndexModel<ServerUsageDaily>(serverKeys.Ascending(x => x.Date)),

            new CreateIndexModel<ServerUsageDaily>(serverKeys.Ascending(x => x.ExpireAt),
                new CreateIndexOptions { ExpireAfter = TimeSpan.Zero }),
        ], ct);

        var health     = db.GetCollection<ServerHealthDaily>(_opts.ServerHealthDailyCollection);
        var healthKeys = Builders<ServerHealthDaily>.IndexKeys;

        await health.Indexes.CreateManyAsync(
        [
            new CreateIndexModel<ServerHealthDaily>(
                healthKeys.Ascending(x => x.ServerId).Ascending(x => x.Date)),

            new CreateIndexModel<ServerHealthDaily>(healthKeys.Ascending(x => x.ExpireAt),
                new CreateIndexOptions { ExpireAfter = TimeSpan.Zero }),
        ], ct);
    }
}
