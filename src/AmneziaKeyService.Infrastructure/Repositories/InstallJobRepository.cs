using AmneziaKeyService.Core.DTOs;
using AmneziaKeyService.Core.Interfaces;
using AmneziaKeyService.Core.Models;
using Microsoft.Extensions.Options;
using MongoDB.Bson;
using MongoDB.Driver;

namespace AmneziaKeyService.Infrastructure.Repositories;

public class InstallJobRepository : IInstallJobRepository
{
    private readonly IMongoCollection<InstallJob> _jobs;
    private readonly IMongoCollection<InstallJobLog> _logs;

    public InstallJobRepository(IMongoClient mongo, IOptions<MongoDbOptions> opts)
    {
        var db = mongo.GetDatabase(opts.Value.DatabaseName);
        _jobs = db.GetCollection<InstallJob>(opts.Value.InstallJobsCollection);
        _logs = db.GetCollection<InstallJobLog>(opts.Value.InstallJobLogsCollection);
        // Индексы создаёт миграция 008.
    }

    public async Task<InstallJob> CreateAsync(InstallJob job, CancellationToken ct = default)
    {
        await _jobs.InsertOneAsync(job, cancellationToken: ct);
        return job;
    }

    public async Task<InstallJob?> GetByIdAsync(string id, CancellationToken ct = default)
    {
        if (!ObjectId.TryParse(id, out _)) return null;
        return await _jobs.Find(x => x.Id == id).FirstOrDefaultAsync(ct);
    }

    public Task UpdateAsync(InstallJob job, CancellationToken ct = default)
        => _jobs.ReplaceOneAsync(Builders<InstallJob>.Filter.Eq(x => x.Id, job.Id), job,
            cancellationToken: ct);

    public async Task<Paged<InstallJob>> SearchAsync(JobQuery query, CancellationToken ct = default)
    {
        var b = Builders<InstallJob>.Filter;
        var filters = new List<FilterDefinition<InstallJob>>();

        if (!string.IsNullOrWhiteSpace(query.ServerId)) filters.Add(b.Eq(x => x.ServerId, query.ServerId));
        if (!string.IsNullOrWhiteSpace(query.Status))   filters.Add(b.Eq(x => x.Status, query.Status));

        var filter = filters.Count == 0 ? FilterDefinition<InstallJob>.Empty : b.And(filters);
        var paging = query.Paging;

        var total = await _jobs.CountDocumentsAsync(filter, cancellationToken: ct);
        var items = await _jobs.Find(filter)
            .SortByDescending(x => x.CreatedAt)
            .Skip(paging.Skip)
            .Limit(paging.PageSize)
            .ToListAsync(ct);

        return new Paged<InstallJob>(items, total, paging.Page, paging.PageSize);
    }

    public Task<InstallJob?> FindActiveByServerAsync(string serverId, CancellationToken ct = default)
    {
        var b = Builders<InstallJob>.Filter;

        return _jobs.Find(b.And(
                b.Eq(x => x.ServerId, serverId),
                b.In(x => x.Status, new[] { InstallJobStatuses.Queued, InstallJobStatuses.Running })))
            .FirstOrDefaultAsync(ct)!;
    }

    public async Task<long> FailInterruptedAsync(string reason, CancellationToken ct = default)
    {
        var b = Builders<InstallJob>.Filter;

        var result = await _jobs.UpdateManyAsync(
            b.In(x => x.Status, new[] { InstallJobStatuses.Queued, InstallJobStatuses.Running }),
            Builders<InstallJob>.Update
                .Set(x => x.Status, InstallJobStatuses.Failed)
                .Set(x => x.Error, reason)
                .Set(x => x.FinishedAt, DateTime.UtcNow),
            cancellationToken: ct);

        return result.ModifiedCount;
    }

    public async Task<bool> RequestCancelAsync(string id, CancellationToken ct = default)
    {
        var b = Builders<InstallJob>.Filter;

        var result = await _jobs.UpdateOneAsync(
            b.And(
                b.Eq(x => x.Id, id),
                b.In(x => x.Status, new[] { InstallJobStatuses.Queued, InstallJobStatuses.Running })),
            Builders<InstallJob>.Update.Set(x => x.CancelRequested, true),
            cancellationToken: ct);

        return result.ModifiedCount > 0;
    }

    public Task AppendLogAsync(InstallJobLog entry, CancellationToken ct = default)
        => _logs.InsertOneAsync(entry, cancellationToken: ct);

    public Task<List<InstallJobLog>> GetLogAsync(
        string jobId, long afterSeq, int limit, CancellationToken ct = default)
    {
        var b = Builders<InstallJobLog>.Filter;

        return _logs.Find(b.And(b.Eq(x => x.JobId, jobId), b.Gt(x => x.Seq, afterSeq)))
            .SortBy(x => x.Seq)
            .Limit(Math.Clamp(limit, 1, 1000))
            .ToListAsync(ct);
    }
}
