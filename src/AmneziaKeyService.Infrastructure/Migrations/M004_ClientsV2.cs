using AmneziaKeyService.Core.Models;
using Microsoft.Extensions.Options;
using MongoDB.Bson;
using MongoDB.Driver;

namespace AmneziaKeyService.Infrastructure.Migrations;

/// <summary>
/// Переводит выданные ключи в схему v2: статус, короткий идентификатор,
/// привязка к протоколу, нулевой счётчик трафика.
///
/// Ключи, существовавшие до этой миграции, выданы Telegram-ботом на
/// единственный протокол узла — им проставляется протокол по умолчанию.
/// </summary>
public class M004_ClientsV2 : IMongoMigration
{
    private readonly MongoDbOptions _opts;

    public M004_ClientsV2(IOptions<MongoDbOptions> opts) => _opts = opts.Value;

    public string Id => "004_clients_v2";

    public async Task ApplyAsync(IMongoDatabase db, CancellationToken ct)
    {
        var clients = db.GetCollection<BsonDocument>(_opts.ClientsCollection);
        var servers = db.GetCollection<BsonDocument>(_opts.ServerConfigCollection);

        // Карта serverId → (protocolId, kind) протокола по умолчанию.
        // M003 отрабатывает раньше, поэтому protocols[] уже на месте.
        var protocolByServer = new Dictionary<string, (string Id, string Kind)>();
        foreach (var server in await servers.Find(FilterDefinition<BsonDocument>.Empty).ToListAsync(ct))
        {
            if (server.GetValue("protocols", BsonNull.Value) is not BsonArray { Count: > 0 } protocols)
                continue;

            var defaultId = server.GetValue("defaultProtocolId", BsonNull.Value);
            var chosen = protocols
                .OfType<BsonDocument>()
                .FirstOrDefault(p => !defaultId.IsBsonNull && p.GetValue("id", BsonNull.Value) == defaultId)
                ?? protocols.OfType<BsonDocument>().First();

            protocolByServer[server["_id"].ToString()!] =
                (chosen.GetValue("id", "").ToString()!, chosen.GetValue("kind", "").ToString()!);
        }

        var taken = await LoadExistingShortIdsAsync(clients, ct);

        var pending = await clients
            .Find(Builders<BsonDocument>.Filter.Exists("status", false))
            .ToListAsync(ct);

        foreach (var doc in pending)
        {
            var isActive = doc.GetValue("isActive", true).ToBoolean();
            var serverId = doc.GetValue("serverId", BsonNull.Value).ToString();

            var update = Builders<BsonDocument>.Update
                .Set("schemaVersion", 2)
                .Set("status", isActive ? KeyStatuses.Active : KeyStatuses.Revoked)
                .Set("shortId", NextShortId(doc, taken))
                .Set("source", KeySources.Telegram)
                .Set("usage", new BsonDocument
                {
                    ["rxBytes"] = 0L,
                    ["txBytes"] = 0L,
                    ["rxRaw"]   = 0L,
                    ["txRaw"]   = 0L
                });

            if (serverId is not null && protocolByServer.TryGetValue(serverId, out var protocol))
            {
                update = update
                    .Set("protocolId", protocol.Id)
                    .Set("protocolKind", protocol.Kind);
            }

            await clients.UpdateOneAsync(
                Builders<BsonDocument>.Filter.Eq("_id", doc["_id"]),
                update,
                cancellationToken: ct);
        }
    }

    private static async Task<HashSet<string>> LoadExistingShortIdsAsync(
        IMongoCollection<BsonDocument> clients, CancellationToken ct)
    {
        var existing = await clients
            .Find(Builders<BsonDocument>.Filter.Exists("shortId", true))
            .Project(Builders<BsonDocument>.Projection.Include("shortId"))
            .ToListAsync(ct);

        return [.. existing
            .Select(d => d.GetValue("shortId", BsonNull.Value))
            .Where(v => !v.IsBsonNull)
            .Select(v => v.ToString()!)];
    }

    /// <summary>
    /// Короткий идентификатор выводится из _id — так он стабилен при повторном
    /// запуске миграции. Коллизии разрешаются добавлением случайного суффикса.
    /// </summary>
    private static string NextShortId(BsonDocument doc, HashSet<string> taken)
    {
        var seed = doc["_id"].ToString()!;
        var candidate = Format(seed[^6..]);

        while (!taken.Add(candidate))
            candidate = Format(Guid.NewGuid().ToString("N")[..6]);

        return candidate;
    }

    private static string Format(string raw) => $"KEY-{raw.ToUpperInvariant()}";
}
