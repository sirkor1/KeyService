using AmneziaKeyService.Core.DTOs;
using AmneziaKeyService.Core.Interfaces;
using AmneziaKeyService.Core.Models;
using Microsoft.Extensions.Options;
using MongoDB.Bson;
using MongoDB.Driver;

namespace AmneziaKeyService.Infrastructure.Repositories;

public class VpnServerRepository : IVpnServerRepository
{
    private readonly IMongoCollection<VpnServer> _collection;

    public VpnServerRepository(IMongoClient mongo, IOptions<MongoDbOptions> opts)
    {
        var db = mongo.GetDatabase(opts.Value.DatabaseName);
        _collection = db.GetCollection<VpnServer>(opts.Value.ServerConfigCollection);
        // Индексы создаёт миграция 005: делать это в конструкторе значит
        // выполнять DDL при каждом старте и на каждом инстансе.
    }

    public Task<List<VpnServer>> GetAllAsync(CancellationToken ct = default)
        => _collection.Find(FilterDefinition<VpnServer>.Empty)
            .SortBy(x => x.Name)
            .ToListAsync(ct);

    /// <summary>
    /// Невалидный ObjectId — это не ошибка, а «не найдено»: id приходит из URL.
    /// Без проверки драйвер бросил бы FormatException на конвертации фильтра.
    /// </summary>
    public async Task<VpnServer?> GetByIdAsync(string id, CancellationToken ct = default)
    {
        if (!ObjectId.TryParse(id, out _)) return null;
        return await _collection.Find(x => x.Id == id).FirstOrDefaultAsync(ct);
    }

    public async Task<Paged<VpnServer>> SearchAsync(ServerQuery query, CancellationToken ct = default)
    {
        var filter = BuildFilter(query);
        var paging = query.Paging;

        var total = await _collection.CountDocumentsAsync(filter, cancellationToken: ct);

        var items = await _collection.Find(filter)
            .SortBy(x => x.Name)
            .Skip(paging.Skip)
            .Limit(paging.PageSize)
            .ToListAsync(ct);

        return new Paged<VpnServer>(items, total, paging.Page, paging.PageSize);
    }

    private static FilterDefinition<VpnServer> BuildFilter(ServerQuery query)
    {
        var b = Builders<VpnServer>.Filter;
        var filters = new List<FilterDefinition<VpnServer>>();

        if (!string.IsNullOrWhiteSpace(query.Search))
        {
            // Regex.Escape: строка поиска приходит от пользователя, спецсимволы
            // регулярного выражения должны трактоваться буквально.
            var pattern = new BsonRegularExpression(System.Text.RegularExpressions.Regex.Escape(query.Search), "i");
            filters.Add(b.Or(b.Regex(x => x.Name, pattern), b.Regex(x => x.Host, pattern)));
        }

        if (!string.IsNullOrWhiteSpace(query.Status))
            filters.Add(b.Eq(x => x.Status, query.Status));

        if (!string.IsNullOrWhiteSpace(query.ProtocolKind))
            filters.Add(b.ElemMatch(x => x.Protocols, p => p.Kind == query.ProtocolKind));

        return filters.Count == 0 ? FilterDefinition<VpnServer>.Empty : b.And(filters);
    }

    public async Task<VpnServer> CreateAsync(VpnServer server, CancellationToken ct = default)
    {
        await _collection.InsertOneAsync(server, cancellationToken: ct);
        return server;
    }

    public async Task<bool> UpdateAsync(VpnServer server, CancellationToken ct = default)
    {
        server.UpdatedAt = DateTime.UtcNow;
        var fields = server.ToBsonDocument();
        fields.Remove("_id");
        fields.Remove("disabledProtocolIds");
        var result = await _collection.UpdateOneAsync(
            x => x.Id == server.Id, new BsonDocument("$set", fields), cancellationToken: ct);
        return result.MatchedCount > 0;
    }

    public async Task<bool> SetProtocolEnabledAsync(string id, string protocolId, bool enabled, CancellationToken ct = default)
    {
        var update = enabled
            ? Builders<VpnServer>.Update.Pull(x => x.DisabledProtocolIds, protocolId)
            : Builders<VpnServer>.Update.AddToSet(x => x.DisabledProtocolIds, protocolId);
        // Also support records whose original Enabled flag was false.
        update = update.Set("protocols.$.enabled", true).Set(x => x.UpdatedAt, DateTime.UtcNow);
        var result = await _collection.UpdateOneAsync(
            Builders<VpnServer>.Filter.Eq(x => x.Id, id) & Builders<VpnServer>.Filter.ElemMatch(x => x.Protocols, p => p.Id == protocolId),
            update, cancellationToken: ct);
        return result.MatchedCount > 0;
    }

    public async Task UpdateHealthAsync(VpnServer server, CancellationToken ct = default)
    {
        await _collection.UpdateOneAsync(x => x.Id == server.Id,
            Builders<VpnServer>.Update.Set(x => x.Health, server.Health), cancellationToken: ct);
        // Never overwrite an installation's setup/error state with a stale probe.
        if (server.Status is ServerStatuses.Ok or ServerStatuses.Offline)
            await _collection.UpdateOneAsync(x => x.Id == server.Id &&
                (x.Status == ServerStatuses.Ok || x.Status == ServerStatuses.Offline),
                Builders<VpnServer>.Update.Set(x => x.Status, server.Status), cancellationToken: ct);
    }

    public Task UpdateInstallationAsync(VpnServer server, CancellationToken ct = default)
        => _collection.UpdateOneAsync(x => x.Id == server.Id,
            Builders<VpnServer>.Update.Set(x => x.Protocols, server.Protocols)
                .Set(x => x.DefaultProtocolId, server.DefaultProtocolId)
                .Set(x => x.Status, server.Status)
                .Set("ssh.hostFingerprint", server.Ssh.HostFingerprint)
                .Set(x => x.UpdatedAt, DateTime.UtcNow), cancellationToken: ct);

    public Task UpdateMetadataAsync(VpnServer server, CancellationToken ct = default)
        => _collection.UpdateOneAsync(x => x.Id == server.Id,
            Builders<VpnServer>.Update.Set(x => x.Host, server.Host).Set(x => x.Name, server.Name)
                .Set(x => x.Geo, server.Geo).Set(x => x.Provider, server.Provider)
                .Set(x => x.Note, server.Note).Set(x => x.KeyLimit, server.KeyLimit)
                .Set(x => x.Dns1, server.Dns1).Set(x => x.Dns2, server.Dns2)
                .Set("ssh.port", server.Ssh.Port).Set("ssh.user", server.Ssh.User)
                .Set("ssh.authType", server.Ssh.AuthType).Set("ssh.password", server.Ssh.Password)
                .Set("ssh.privateKeyPath", server.Ssh.PrivateKeyPath)
                .Set(x => x.UpdatedAt, DateTime.UtcNow), cancellationToken: ct);

    public Task UpdateReconciliationAsync(VpnServer server, CancellationToken ct = default)
        => _collection.UpdateOneAsync(x => x.Id == server.Id,
            Builders<VpnServer>.Update.Set(x => x.OrphanPeerCount, server.OrphanPeerCount)
                .Set(x => x.ReconciledAt, server.ReconciledAt), cancellationToken: ct);

    public Task UpdateProtocolParamsAsync(string id, ProtocolInstance protocol, CancellationToken ct = default)
        => _collection.UpdateOneAsync(
            Builders<VpnServer>.Filter.Eq(x => x.Id, id) & Builders<VpnServer>.Filter.ElemMatch(x => x.Protocols, p => p.Id == protocol.Id),
            Builders<VpnServer>.Update.Set("protocols.$.wg", protocol.Wg)
                .Set("protocols.$.xray", protocol.Xray).Set("protocols.$.lastSyncedAt", protocol.LastSyncedAt), cancellationToken: ct);

    public async Task<bool> DeleteAsync(string id, CancellationToken ct = default)
    {
        var result = await _collection.DeleteOneAsync(x => x.Id == id, ct);
        return result.DeletedCount > 0;
    }

    public async Task<Dictionary<string, long>> CountByStatusAsync(CancellationToken ct = default)
    {
        var grouped = await _collection.Aggregate()
            .Group(x => x.Status, g => new { Status = g.Key, Count = g.LongCount() })
            .ToListAsync(ct);

        return grouped.ToDictionary(x => x.Status ?? ServerStatuses.Ok, x => x.Count);
    }
}
