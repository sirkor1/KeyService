using AmneziaKeyService.Core.DTOs;
using AmneziaKeyService.Core.Interfaces;
using AmneziaKeyService.Core.Models;
using Microsoft.Extensions.Options;
using MongoDB.Driver;

namespace AmneziaKeyService.Infrastructure.Repositories;

public class AuditLogRepository : IAuditLogRepository
{
    private readonly IMongoCollection<AuditEntry> _collection;

    public AuditLogRepository(IMongoClient mongo, IOptions<MongoDbOptions> opts)
    {
        var db = mongo.GetDatabase(opts.Value.DatabaseName);
        _collection = db.GetCollection<AuditEntry>(opts.Value.AuditLogCollection);
    }

    public Task AppendAsync(AuditEntry entry, CancellationToken ct = default)
        => _collection.InsertOneAsync(entry, cancellationToken: ct);

    public async Task<Paged<AuditEntry>> SearchAsync(AuditQuery query, CancellationToken ct = default)
    {
        var b = Builders<AuditEntry>.Filter;
        var filters = new List<FilterDefinition<AuditEntry>>();

        if (!string.IsNullOrWhiteSpace(query.Level))      filters.Add(b.Eq(x => x.Level, query.Level));
        if (!string.IsNullOrWhiteSpace(query.TargetType)) filters.Add(b.Eq(x => x.TargetType, query.TargetType));
        if (!string.IsNullOrWhiteSpace(query.TargetId))   filters.Add(b.Eq(x => x.TargetId, query.TargetId));
        if (query.From is { } from)                       filters.Add(b.Gte(x => x.At, from));
        if (query.To is { } to)                           filters.Add(b.Lte(x => x.At, to));

        var filter = filters.Count == 0 ? FilterDefinition<AuditEntry>.Empty : b.And(filters);
        var paging = query.Paging;

        var total = await _collection.CountDocumentsAsync(filter, cancellationToken: ct);

        var items = await _collection.Find(filter)
            .SortByDescending(x => x.At)
            .Skip(paging.Skip)
            .Limit(paging.PageSize)
            .ToListAsync(ct);

        return new Paged<AuditEntry>(items, total, paging.Page, paging.PageSize);
    }

    public Task<long> CountByLevelAsync(string level, TimeSpan within, CancellationToken ct = default)
    {
        var since = DateTime.UtcNow - within;
        var b = Builders<AuditEntry>.Filter;

        return _collection.CountDocumentsAsync(
            b.And(b.Eq(x => x.Level, level), b.Gte(x => x.At, since)),
            cancellationToken: ct);
    }
}

public class PanelSettingsRepository : IPanelSettingsRepository
{
    private readonly IMongoCollection<PanelSettings> _collection;

    public PanelSettingsRepository(IMongoClient mongo, IOptions<MongoDbOptions> opts)
    {
        var db = mongo.GetDatabase(opts.Value.DatabaseName);
        _collection = db.GetCollection<PanelSettings>(opts.Value.PanelSettingsCollection);
    }

    /// <summary>
    /// Документа может не быть — панель работает на значениях по умолчанию
    /// до первого сохранения, а не падает.
    /// </summary>
    public async Task<PanelSettings> GetAsync(CancellationToken ct = default)
        => await _collection.Find(x => x.Id == PanelSettings.SingletonId).FirstOrDefaultAsync(ct)
           ?? new PanelSettings();

    public async Task<PanelSettings> UpdateAsync(
        int? defaultExpiryDays,
        long? defaultTrafficLimitBytes,
        string updatedByUserId,
        CancellationToken ct = default)
    {
        var update = Builders<PanelSettings>.Update
            .Set(x => x.DefaultExpiryDays, defaultExpiryDays)
            .Set(x => x.DefaultTrafficLimitBytes, defaultTrafficLimitBytes)
            .Set(x => x.UpdatedAt, DateTime.UtcNow)
            .Set(x => x.UpdatedByUserId, updatedByUserId);

        return await _collection.FindOneAndUpdateAsync(
            x => x.Id == PanelSettings.SingletonId,
            update,
            new FindOneAndUpdateOptions<PanelSettings>
            {
                IsUpsert = true,
                ReturnDocument = ReturnDocument.After
            },
            ct);
    }
}
