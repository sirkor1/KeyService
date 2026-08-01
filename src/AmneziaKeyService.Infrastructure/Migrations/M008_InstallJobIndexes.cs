using AmneziaKeyService.Core.Models;
using Microsoft.Extensions.Options;
using MongoDB.Driver;

namespace AmneziaKeyService.Infrastructure.Migrations;

/// <summary>Индексы коллекций задач установки.</summary>
public class M008_InstallJobIndexes : IMongoMigration
{
    private readonly MongoDbOptions _opts;

    public M008_InstallJobIndexes(IOptions<MongoDbOptions> opts) => _opts = opts.Value;

    public string Id => "008_install_job_indexes";

    public async Task ApplyAsync(IMongoDatabase db, CancellationToken ct)
    {
        var jobs = db.GetCollection<InstallJob>(_opts.InstallJobsCollection);
        var jobKeys = Builders<InstallJob>.IndexKeys;

        await jobs.Indexes.CreateManyAsync(
        [
            new CreateIndexModel<InstallJob>(
                jobKeys.Ascending(x => x.ServerId).Ascending(x => x.Status)),

            new CreateIndexModel<InstallJob>(jobKeys.Descending(x => x.CreatedAt)),

            // Задачи хранятся 30 дней: после этого история установки уже
            // не нужна, а логи занимают заметное место.
            new CreateIndexModel<InstallJob>(jobKeys.Ascending(x => x.FinishedAt),
                new CreateIndexOptions
                {
                    Name        = "finishedAt_ttl",
                    ExpireAfter = TimeSpan.FromDays(30),
                    Sparse      = true,
                }),
        ], ct);

        var logs = db.GetCollection<InstallJobLog>(_opts.InstallJobLogsCollection);
        var logKeys = Builders<InstallJobLog>.IndexKeys;

        await logs.Indexes.CreateManyAsync(
        [
            new CreateIndexModel<InstallJobLog>(
                logKeys.Ascending(x => x.JobId).Ascending(x => x.Seq)),

            new CreateIndexModel<InstallJobLog>(logKeys.Ascending(x => x.At),
                new CreateIndexOptions
                {
                    Name        = "at_ttl",
                    ExpireAfter = TimeSpan.FromDays(30),
                }),
        ], ct);
    }
}
