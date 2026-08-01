using AmneziaKeyService.Core.Interfaces;
using AmneziaKeyService.Core.Models;
using Microsoft.Extensions.Options;
using MongoDB.Bson;
using MongoDB.Driver;

namespace AmneziaKeyService.Infrastructure.Migrations;

/// <summary>
/// Переводит server_config в схему v2: собирает protocols[0] из плоских AWG-полей,
/// переносит SSH-доступ в ssh{} с шифрованием секретов.
///
/// Два принципиальных решения:
///
/// 1. _id документов сохраняются. На serverId ссылается каждый выданный ключ;
///    пересоздание документов осиротило бы их все.
///
/// 2. Legacy-поля НЕ удаляются. Откат образа на предыдущую версию должен
///    оставаться рабочим; их зачистка — отдельная поздняя миграция.
/// </summary>
public class M003_ServersV2 : IMongoMigration
{
    private readonly MongoDbOptions _opts;
    private readonly ISecretProtector _secrets;

    public M003_ServersV2(IOptions<MongoDbOptions> opts, ISecretProtector secrets)
    {
        _opts    = opts.Value;
        _secrets = secrets;
    }

    public string Id => "003_servers_v2";

    public async Task ApplyAsync(IMongoDatabase db, CancellationToken ct)
    {
        var collection = db.GetCollection<BsonDocument>(_opts.ServerConfigCollection);

        // Только документы, ещё не переведённые на v2: миграция должна
        // переживать повторный запуск после падения на середине.
        var pending = await collection
            .Find(Builders<BsonDocument>.Filter.Exists("protocols", false))
            .ToListAsync(ct);

        foreach (var doc in pending)
        {
            var update = BuildUpdate(doc);
            await collection.UpdateOneAsync(
                Builders<BsonDocument>.Filter.Eq("_id", doc["_id"]),
                update,
                cancellationToken: ct);
        }
    }

    private UpdateDefinition<BsonDocument> BuildUpdate(BsonDocument doc)
    {
        var containerName = Str(doc, "containerName") ?? "amnezia-awg";
        var wgBin         = Str(doc, "wgBin")         ?? "wg";

        // Пути и имя интерфейса копируются ДОСЛОВНО. У живых узлов встречаются
        // сочетания, не совпадающие ни с одним upstream-пресетом (контейнер
        // amnezia-awg с awg0.conf); «нормализация» сломала бы им доступ.
        var wg = new BsonDocument
        {
            ["interfaceName"]    = Str(doc, "awgInterface")        ?? "wg0",
            ["binary"]           = wgBin,
            ["serverConfigPath"] = Str(doc, "awgConfigPath")       ?? "/opt/amnezia/awg/wg0.conf",
            ["serverPubKeyPath"] = Str(doc, "serverPublicKeyPath") ?? "/opt/amnezia/awg/wireguard_server_public_key.key",
            ["pskKeyPath"]       = Str(doc, "pskKeyPath")          ?? "/opt/amnezia/awg/wireguard_psk.key",
            ["subnetAddress"]    = Str(doc, "subnetAddress")       ?? "10.8.1.0",
            ["subnetCidr"]       = Str(doc, "subnetCidr")          ?? "24",
            ["serverPubKey"]     = Nullable(doc, "serverPubKey"),
            ["pskKey"]           = Nullable(doc, "pskKey"),
            ["lastKnownPeerIp"]  = Nullable(doc, "lastKnownPeerIp"),
            ["obfuscation"]      = doc.GetValue("obfuscation", BsonNull.Value)
        };

        var protocol = new BsonDocument
        {
            ["id"]             = Guid.NewGuid().ToString("N"),
            ["kind"]           = InferKind(wgBin, containerName),
            ["containerName"]  = containerName,
            ["enabled"]        = true,
            ["state"]          = ProtocolStates.Installed,
            ["port"]           = Str(doc, "awgPort") ?? "55424",
            ["transportProto"] = "udp",
            ["mtu"]            = ObfuscationMtu(doc),
            ["installedAt"]    = doc.GetValue("updatedAt", BsonNull.Value),
            ["lastSyncedAt"]   = doc.GetValue("updatedAt", BsonNull.Value),
            ["wg"]             = wg
        };

        var ssh = new BsonDocument
        {
            ["port"]     = doc.GetValue("sshPort", 22).ToInt32(),
            ["user"]     = Str(doc, "sshUser") ?? "root",
            ["authType"] = string.IsNullOrEmpty(Str(doc, "sshPrivateKeyPath"))
                ? SshAuthTypes.Password
                : SshAuthTypes.PrivateKey,
            ["privateKeyPath"] = Nullable(doc, "sshPrivateKeyPath")
        };

        // Пароль шифруется здесь же: до этой миграции он лежал в базе открытым текстом.
        var password = Str(doc, "sshPassword");
        if (!string.IsNullOrEmpty(password))
            ssh["password"] = _secrets.Protect(password)!.ToBsonDocument();

        return Builders<BsonDocument>.Update
            .Set("schemaVersion", 2)
            .Set("name", Str(doc, "description") ?? "AmneziaVPN Server")
            .Set("ssh", ssh)
            .Set("status", ServerStatuses.Ok)
            .Set("dns1", "1.1.1.1")
            .Set("dns2", "8.8.8.8")
            .Set("protocols", new BsonArray { protocol })
            .Set("defaultProtocolId", protocol["id"])
            .Set("createdAt", doc.GetValue("createdAt", DateTime.UtcNow))
            .Set("updatedAt", DateTime.UtcNow);
    }

    /// <summary>MTU жил внутри obfuscation, а в новой схеме относится к протоколу.</summary>
    private static BsonValue ObfuscationMtu(BsonDocument doc)
        => doc.GetValue("obfuscation", BsonNull.Value) is BsonDocument obf
            ? obf.GetValue("mtu", BsonNull.Value)
            : BsonNull.Value;

    private static string InferKind(string wgBin, string containerName)
    {
        if (containerName.Contains("awg2", StringComparison.OrdinalIgnoreCase)) return ProtocolKinds.Awg2;
        if (containerName.Contains("wireguard", StringComparison.OrdinalIgnoreCase)) return ProtocolKinds.WireGuard;
        return string.Equals(wgBin, "awg", StringComparison.OrdinalIgnoreCase)
            ? ProtocolKinds.Awg2
            : ProtocolKinds.AwgLegacy;
    }

    private static string? Str(BsonDocument doc, string name)
    {
        var value = doc.GetValue(name, BsonNull.Value);
        return value.IsBsonNull ? null : value.ToString();
    }

    private static BsonValue Nullable(BsonDocument doc, string name)
        => doc.GetValue(name, BsonNull.Value);
}
