using AmneziaKeyService.Core.Models;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using MongoDB.Bson;
using MongoDB.Driver;

namespace AmneziaKeyService.Infrastructure.Migrations;

/// <summary>
/// Задерживает старт процесса, пока worker не применит все миграции.
///
/// Миграции применяет ровно один процесс — worker: три раннера на одной базе
/// дали бы гонку на коллекции <c>_migrations</c>, где проверка «уже применена»
/// и запись факта применения не атомарны между собой. Остальным процессам
/// остаётся дождаться.
///
/// Плата за это — порядок запуска: не поднялся worker, не поднимется и панель.
/// Обмен осознанный, поэтому ожидание должно быть громким: раз в несколько
/// секунд в лог уходит, чего именно ждём.
/// </summary>
public class MongoSchemaGate : IHostedService
{
    private const string CollectionName = "_migrations";

    private static readonly TimeSpan PollInterval = TimeSpan.FromSeconds(3);

    /// <summary>
    /// Сколько ждать, прежде чем сдаться. Вечное ожидание хуже падения:
    /// контейнер в состоянии «стартует» не перезапускается оркестратором
    /// и не попадает в healthcheck, то есть проблема остаётся невидимой.
    /// </summary>
    private static readonly TimeSpan Timeout = TimeSpan.FromMinutes(5);

    private readonly IMongoClient _mongo;
    private readonly MongoDbOptions _opts;
    private readonly IEnumerable<IMongoMigration> _migrations;
    private readonly ILogger<MongoSchemaGate> _logger;

    public MongoSchemaGate(
        IMongoClient mongo,
        IOptions<MongoDbOptions> opts,
        IEnumerable<IMongoMigration> migrations,
        ILogger<MongoSchemaGate> logger)
    {
        _mongo      = mongo;
        _opts       = opts.Value;
        _migrations = migrations;
        _logger     = logger;
    }

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        var expected = _migrations.Select(m => m.Id).ToHashSet(StringComparer.Ordinal);
        if (expected.Count == 0) return;

        var collection = _mongo.GetDatabase(_opts.DatabaseName)
            .GetCollection<BsonDocument>(CollectionName);

        var deadline = DateTime.UtcNow + Timeout;
        var announced = false;

        while (!cancellationToken.IsCancellationRequested)
        {
            var missing = await MissingAsync(collection, expected, cancellationToken);

            if (missing.Count == 0)
            {
                if (announced) _logger.LogInformation("Схема готова, продолжаю запуск.");
                return;
            }

            if (DateTime.UtcNow > deadline)
            {
                throw new InvalidOperationException(
                    $"Миграции не применены за {Timeout.TotalMinutes:0} мин: " +
                    $"{string.Join(", ", missing)}. Проверьте, запущен ли worker.");
            }

            _logger.LogWarning(
                "Жду миграций от worker: не применено {Count} ({Missing}).",
                missing.Count, string.Join(", ", missing));

            announced = true;
            await Task.Delay(PollInterval, cancellationToken);
        }
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    private static async Task<List<string>> MissingAsync(
        IMongoCollection<BsonDocument> collection,
        HashSet<string> expected,
        CancellationToken ct)
    {
        // Фильтр по ожидаемым идентификаторам, а не выборка всей коллекции:
        // документ миграции крошечный, но читать чужие записи незачем.
        // Проекция намеренно не задаётся: типизированная Project(d => d["_id"])
        // не переводится LINQ-транслятором драйвера для BsonDocument.
        var applied = await collection
            .Find(Builders<BsonDocument>.Filter.In("_id", expected))
            .ToListAsync(ct);

        var appliedIds = applied
            .Select(d => d.GetValue("_id", BsonNull.Value))
            .OfType<BsonString>()
            .Select(v => v.AsString);

        return [.. expected.Except(appliedIds, StringComparer.Ordinal).Order(StringComparer.Ordinal)];
    }
}
