using AmneziaKeyService.Core.Models;
using Microsoft.Extensions.Options;
using MongoDB.Bson;
using MongoDB.Driver;

namespace AmneziaKeyService.Infrastructure.Migrations;

/// <summary>Repair only the incorrect defaults persisted by the plain WG installer.</summary>
public sealed class M015_WireGuardKeyPaths(IOptions<MongoDbOptions> options) : IMongoMigration
{
    public string Id => "015_wireguard_key_paths";

    public async Task ApplyAsync(IMongoDatabase db, CancellationToken ct)
    {
        var servers = db.GetCollection<BsonDocument>(options.Value.ServerConfigCollection);
        foreach (var (field, file) in new[]
        {
            ("serverPubKeyPath", "wireguard_server_public_key.key"),
            ("pskKeyPath", "wireguard_psk.key")
        })
        {
            var match = new BsonDocument
            {
                { "kind", ProtocolKinds.WireGuard },
                { "wg.serverConfigPath", "/opt/amnezia/wireguard/wg0.conf" },
                { "wg." + field, "/opt/amnezia/awg/" + file }
            };
            // Set individual nested fields: preserve custom paths, keys, states,
            // protocol identities and concurrent changes to the rest of the node.
            await servers.UpdateManyAsync(
                new BsonDocument("protocols", new BsonDocument("$elemMatch", match)),
                new BsonDocument("$set", new BsonDocument("protocols.$[p].wg." + field, "/opt/amnezia/wireguard/" + file)),
                new UpdateOptions
                {
                    ArrayFilters = new[] { new BsonDocumentArrayFilterDefinition<BsonDocument>(
                        new BsonDocument(match.Elements.Select(e => new BsonElement("p." + e.Name, e.Value)))) }
                }, ct);
        }
    }
}
