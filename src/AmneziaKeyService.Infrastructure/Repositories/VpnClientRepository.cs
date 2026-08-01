using System.Net;
using System.Text.RegularExpressions;
using AmneziaKeyService.Core.DTOs;
using AmneziaKeyService.Core.Interfaces;
using AmneziaKeyService.Core.Models;
using Microsoft.Extensions.Options;
using MongoDB.Bson;
using MongoDB.Driver;

namespace AmneziaKeyService.Infrastructure.Repositories;

public class VpnClientRepository : IVpnClientRepository
{
    private readonly IMongoCollection<VpnClient> _collection;

    public VpnClientRepository(IMongoClient mongo, IOptions<MongoDbOptions> opts)
    {
        var db = mongo.GetDatabase(opts.Value.DatabaseName);
        _collection = db.GetCollection<VpnClient>(opts.Value.ClientsCollection);
        // Индексы создаёт миграция 005. Прежняя версия дропала и пересоздавала
        // индекс при каждом старте — DDL на горячем пути запуска.
    }

    // ── Существующие запросы: на них завязаны бот и /api/vpn/* ────────────────

    public Task<VpnClient?> FindByUserIdAndServerAsync(string userId, string serverId, CancellationToken ct = default)
        => _collection.Find(x => x.UserId == userId && x.ServerId == serverId).FirstOrDefaultAsync(ct)!;

    public Task<List<VpnClient>> GetByUserIdAsync(string userId, CancellationToken ct = default)
        => _collection.Find(x => x.UserId == userId && x.IsActive).ToListAsync(ct);

    public Task<List<VpnClient>> GetByUserIdAndServerAsync(string userId, string serverId, CancellationToken ct = default)
        => _collection.Find(x => x.UserId == userId && x.ServerId == serverId && x.IsActive).ToListAsync(ct);

    /// <summary>
    /// Невалидный ObjectId — это «не найдено», а не ошибка: id приходит из URL.
    /// Без проверки драйвер бросил бы FormatException на конвертации фильтра.
    /// </summary>
    public async Task<VpnClient?> FindByIdAsync(string id, CancellationToken ct = default)
    {
        if (!ObjectId.TryParse(id, out _)) return null;
        return await _collection.Find(x => x.Id == id).FirstOrDefaultAsync(ct);
    }

    public Task CreateAsync(VpnClient client, CancellationToken ct = default)
        => _collection.InsertOneAsync(client, cancellationToken: ct);

    public Task UpdateAsync(VpnClient client, CancellationToken ct = default)
        => _collection.ReplaceOneAsync(
            Builders<VpnClient>.Filter.Eq(x => x.Id, client.Id), client, cancellationToken: ct);

    public async Task<string?> GetMaxAssignedIpAsync(string serverId, CancellationToken ct = default)
    {
        var ips = await GetAssignedIpsAsync(serverId, null, ct);
        return ips.Count == 0 ? null : ips.OrderByDescending(IpToUInt32).First();
    }

    public async Task<List<string>> GetAssignedIpsAsync(
        string serverId, string? protocolId, CancellationToken ct = default)
    {
        var b = Builders<VpnClient>.Filter;
        var filters = new List<FilterDefinition<VpnClient>>
        {
            b.Eq(x => x.ServerId, serverId),
            b.Ne(x => x.AssignedIp, null),
            // Отозванные ключи освобождают адрес: их peer удалён с сервера.
            b.Ne(x => x.Status, KeyStatuses.Revoked)
        };

        if (protocolId is not null)
            filters.Add(b.Eq(x => x.ProtocolId, protocolId));

        var ips = await _collection.Find(b.And(filters))
            .Project(x => x.AssignedIp)
            .ToListAsync(ct);

        return [.. ips.OfType<string>().Where(ip => IPAddress.TryParse(ip, out _))];
    }

    // ── Запросы панели ────────────────────────────────────────────────────────

    public async Task<Paged<VpnClient>> SearchAsync(KeyQuery query, CancellationToken ct = default)
    {
        var filter = BuildFilter(query);
        var paging = query.Paging;

        var total = await _collection.CountDocumentsAsync(filter, cancellationToken: ct);

        var items = await _collection.Find(filter)
            .SortByDescending(x => x.CreatedAt)
            .Skip(paging.Skip)
            .Limit(paging.PageSize)
            .ToListAsync(ct);

        return new Paged<VpnClient>(items, total, paging.Page, paging.PageSize);
    }

    private static FilterDefinition<VpnClient> BuildFilter(KeyQuery query)
    {
        var b = Builders<VpnClient>.Filter;
        var filters = new List<FilterDefinition<VpnClient>>();

        if (!string.IsNullOrWhiteSpace(query.Search))
        {
            // Regex.Escape: строка приходит от пользователя, спецсимволы
            // регулярного выражения должны трактоваться буквально.
            var pattern = new BsonRegularExpression(Regex.Escape(query.Search), "i");
            filters.Add(b.Or(
                b.Regex(x => x.OwnerName,  pattern),
                b.Regex(x => x.DeviceName, pattern),
                b.Regex(x => x.ShortId,    pattern),
                b.Regex(x => x.Label,      pattern)));
        }

        if (!string.IsNullOrWhiteSpace(query.Status))
            filters.Add(b.Eq(x => x.Status, query.Status));

        if (!string.IsNullOrWhiteSpace(query.ServerId))
            filters.Add(b.Eq(x => x.ServerId, query.ServerId));

        if (!string.IsNullOrWhiteSpace(query.ProtocolKind))
            filters.Add(b.Eq(x => x.ProtocolKind, query.ProtocolKind));

        if (!string.IsNullOrWhiteSpace(query.UserId))
            filters.Add(b.Eq(x => x.UserId, query.UserId));

        return filters.Count == 0 ? FilterDefinition<VpnClient>.Empty : b.And(filters);
    }

    public Task<VpnClient?> FindByShortIdAsync(string shortId, CancellationToken ct = default)
        => _collection.Find(x => x.ShortId == shortId).FirstOrDefaultAsync(ct)!;

    public async Task<Dictionary<string, long>> CountByStatusAsync(CancellationToken ct = default)
    {
        var grouped = await _collection.Aggregate()
            .Group(x => x.Status, g => new { Status = g.Key, Count = g.LongCount() })
            .ToListAsync(ct);

        return grouped.ToDictionary(x => x.Status ?? KeyStatuses.Active, x => x.Count);
    }

    public async Task<Dictionary<string, long>> CountActiveByServerAsync(CancellationToken ct = default)
    {
        var grouped = await _collection.Aggregate()
            .Match(x => x.Status == KeyStatuses.Active)
            .Group(x => x.ServerId, g => new { ServerId = g.Key, Count = g.LongCount() })
            .ToListAsync(ct);

        return grouped.Where(x => x.ServerId is not null)
                      .ToDictionary(x => x.ServerId!, x => x.Count);
    }

    public async Task<Dictionary<string, long>> CountActiveByUserAsync(CancellationToken ct = default)
    {
        var grouped = await _collection.Aggregate()
            .Match(x => x.Status == KeyStatuses.Active)
            .Group(x => x.UserId, g => new { UserId = g.Key, Count = g.LongCount() })
            .ToListAsync(ct);

        return grouped.Where(x => x.UserId is not null)
                      .ToDictionary(x => x.UserId!, x => x.Count);
    }

    public Task<long> CountExpiringSoonAsync(TimeSpan within, CancellationToken ct = default)
    {
        var deadline = DateTime.UtcNow + within;
        var b = Builders<VpnClient>.Filter;

        return _collection.CountDocumentsAsync(
            b.And(
                b.Eq(x => x.Status, KeyStatuses.Active),
                b.Ne(x => x.ExpiresAt, null),
                b.Lte(x => x.ExpiresAt, deadline)),
            cancellationToken: ct);
    }

    // ── Фоновые воркеры (фаза 5) ──────────────────────────────────────────────

    public Task<List<VpnClient>> GetLiveByServerAsync(string serverId, CancellationToken ct = default)
    {
        var b = Builders<VpnClient>.Filter;

        // Всё, кроме отозванных: у suspended, expired и pendingRevoke peer
        // на узле ещё жив, и трафик по нему считать надо.
        return _collection.Find(b.And(
                b.Eq(x => x.ServerId, serverId),
                b.Ne(x => x.Status, KeyStatuses.Revoked)))
            .ToListAsync(ct);
    }

    public Task ApplyUsageAsync(
        IReadOnlyCollection<KeyUsageUpdate> updates, CancellationToken ct = default)
    {
        if (updates.Count == 0) return Task.CompletedTask;

        var writes = new List<WriteModel<VpnClient>>(updates.Count);

        foreach (var u in updates)
        {
            var update = Builders<VpnClient>.Update
                .Inc(x => x.Usage.RxBytes, u.RxDelta)
                .Inc(x => x.Usage.TxBytes, u.TxDelta)
                .Set(x => x.Usage.RxRaw, u.RxRaw)
                .Set(x => x.Usage.TxRaw, u.TxRaw)
                .Set(x => x.Usage.LastSeenAt, u.LastSeenAt);

            // Хэндшейка могло не быть ни разу — тогда прежнее значение не трогаем:
            // затирать его на null означало бы «клиент отключился», а это не так.
            if (u.LastHandshakeAt is { } handshake)
                update = update.Set(x => x.Usage.LastHandshakeAt, handshake);

            writes.Add(new UpdateOneModel<VpnClient>(
                Builders<VpnClient>.Filter.Eq(x => x.Id, u.KeyId), update));
        }

        return _collection.BulkWriteAsync(writes, new BulkWriteOptions { IsOrdered = false }, ct);
    }

    public Task<List<VpnClient>> FindEnforcementCandidatesAsync(
        DateTime now, CancellationToken ct = default)
    {
        var b = Builders<VpnClient>.Filter;

        var expired = b.And(b.Ne(x => x.ExpiresAt, null), b.Lte(x => x.ExpiresAt, now));

        // Сравнение суммы двух полей с третьим выражается только через $expr.
        // Отсутствующий trafficLimitBytes даёт false на первом же условии,
        // поэтому ключи без квоты сюда не попадают.
        var overQuota = new BsonDocumentFilterDefinition<VpnClient>(new BsonDocument("$expr",
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
                b.Eq(x => x.Status, KeyStatuses.Active),
                b.Or(expired, overQuota)))
            .ToListAsync(ct);
    }

    public Task<List<VpnClient>> FindPendingRevokeAsync(int limit, CancellationToken ct = default)
        => _collection.Find(Builders<VpnClient>.Filter.Eq(x => x.Status, KeyStatuses.PendingRevoke))
            .SortBy(x => x.RevokedAt)
            .Limit(Math.Clamp(limit, 1, 500))
            .ToListAsync(ct);

    public Task<List<VpnClient>> FindExpiringUnwarnedAsync(
        DateTime until, CancellationToken ct = default)
    {
        var b = Builders<VpnClient>.Filter;

        return _collection.Find(b.And(
                b.Eq(x => x.Status, KeyStatuses.Active),
                b.Ne(x => x.ExpiresAt, null),
                b.Gt(x => x.ExpiresAt, DateTime.UtcNow),
                b.Lte(x => x.ExpiresAt, until),
                // Eq(null) ловит и отсутствующее поле, и явный null.
                b.Eq(x => x.ExpiryWarnedAt, null)))
            .ToListAsync(ct);
    }

    public Task MarkExpiryWarnedAsync(
        IReadOnlyCollection<string> keyIds, CancellationToken ct = default)
    {
        if (keyIds.Count == 0) return Task.CompletedTask;

        return _collection.UpdateManyAsync(
            Builders<VpnClient>.Filter.In(x => x.Id, keyIds),
            Builders<VpnClient>.Update.Set(x => x.ExpiryWarnedAt, DateTime.UtcNow),
            cancellationToken: ct);
    }

    private static uint IpToUInt32(string ip)
    {
        var bytes = IPAddress.Parse(ip).GetAddressBytes();
        if (BitConverter.IsLittleEndian) Array.Reverse(bytes);
        return BitConverter.ToUInt32(bytes, 0);
    }
}
