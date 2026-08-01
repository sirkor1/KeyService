using AmneziaKeyService.Core.Models;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using MongoDB.Bson;
using MongoDB.Driver;

namespace AmneziaKeyService.Infrastructure.Migrations;

/// <summary>
/// Прогоняет миграции при старте, до того как заработают контроллеры и Telegram-бот.
/// Регистрируется первым среди IHostedService.
///
/// Если миграция падает — приложение не стартует: работать на полумигрированной
/// схеме опаснее, чем не подняться вовсе.
/// </summary>
public class MongoMigrationRunner : IHostedService
{
    private const string CollectionName = "_migrations";

    private readonly IMongoClient _mongo;
    private readonly MongoDbOptions _opts;
    private readonly IEnumerable<IMongoMigration> _migrations;
    private readonly ILogger<MongoMigrationRunner> _logger;

    public MongoMigrationRunner(
        IMongoClient mongo,
        IOptions<MongoDbOptions> opts,
        IEnumerable<IMongoMigration> migrations,
        ILogger<MongoMigrationRunner> logger)
    {
        _mongo      = mongo;
        _opts       = opts.Value;
        _migrations = migrations;
        _logger     = logger;
    }

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        var db      = _mongo.GetDatabase(_opts.DatabaseName);
        var applied = db.GetCollection<BsonDocument>(CollectionName);

        foreach (var migration in _migrations.OrderBy(m => m.Id, StringComparer.Ordinal))
        {
            var already = await applied
                .Find(Builders<BsonDocument>.Filter.Eq("_id", migration.Id))
                .AnyAsync(cancellationToken);

            if (already)
            {
                _logger.LogDebug("Миграция {Id} уже применена.", migration.Id);
                continue;
            }

            _logger.LogInformation("Применяю миграцию {Id}…", migration.Id);
            await migration.ApplyAsync(db, cancellationToken);

            await applied.InsertOneAsync(new BsonDocument
            {
                ["_id"]       = migration.Id,
                ["appliedAt"] = DateTime.UtcNow
            }, cancellationToken: cancellationToken);

            _logger.LogInformation("Миграция {Id} применена.", migration.Id);
        }
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
