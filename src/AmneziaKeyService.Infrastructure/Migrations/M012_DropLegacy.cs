using AmneziaKeyService.Core.Models;
using Microsoft.Extensions.Options;
using MongoDB.Bson;
using MongoDB.Driver;

namespace AmneziaKeyService.Infrastructure.Migrations;

/// <summary>
/// Удаляет плоские поля исходной схемы server_config после перехода на v2.
///
/// Миграция намеренно работает только с точным allowlist полей, перенесённых
/// M003. В частности, она не трогает одноимённые значения внутри ssh{} и
/// protocols[]: там они являются частью актуальной схемы. Перед удалением
/// проверяется, что для каждого документа с legacy-полями уже есть пригодная
/// v2-структура. Это не даёт молча потерять единственный SSH credential.
/// </summary>
public sealed class M012_DropLegacy : IMongoMigration
{
    private static readonly string[] LegacyServerFields =
    [
        "description",
        "sshPort",
        "sshUser",
        "sshPassword",
        "sshPrivateKeyPath",
        "awgPort",
        "containerName",
        "awgConfigPath",
        "serverPublicKeyPath",
        "pskKeyPath",
        "awgInterface",
        "wgBin",
        "subnetAddress",
        "subnetCidr",
        "serverPubKey",
        "pskKey",
        "lastKnownPeerIp",
        "obfuscation"
    ];

    private readonly MongoDbOptions _options;

    public M012_DropLegacy(IOptions<MongoDbOptions> options) => _options = options.Value;

    public string Id => "012_drop_legacy";

    public async Task ApplyAsync(IMongoDatabase db, CancellationToken ct)
    {
        var servers = db.GetCollection<BsonDocument>(_options.ServerConfigCollection);
        var pendingFilter = Builders<BsonDocument>.Filter.Or(
            LegacyServerFields.Select(field => Builders<BsonDocument>.Filter.Exists(field)).ToArray());

        // The runner records completion only after ApplyAsync succeeds. Reading
        // first makes an interrupted migration safe to repeat and avoids a
        // broad $unset on a malformed hand-written document.
        var pending = await servers.Find(pendingFilter).ToListAsync(ct);
        foreach (var server in pending)
            ValidateV2(server);

        if (pending.Count == 0) return;

        var unset = Builders<BsonDocument>.Update.Combine(
            LegacyServerFields.Select(field => Builders<BsonDocument>.Update.Unset(field)));

        await servers.UpdateManyAsync(pendingFilter, unset, cancellationToken: ct);
    }

    private static void ValidateV2(BsonDocument server)
    {
        if (server.GetValue("schemaVersion", BsonNull.Value) is not BsonInt32 { Value: >= 2 })
            ThrowIncomplete(server);

        if (server.GetValue("name", BsonNull.Value) is not BsonString { Value.Length: > 0 })
            ThrowIncomplete(server);

        var ssh = server.GetValue("ssh", BsonNull.Value) as BsonDocument;
        if (ssh is null ||
            ssh.GetValue("port", BsonNull.Value).IsBsonNull ||
            ssh.GetValue("user", BsonNull.Value) is not BsonString { Value.Length: > 0 } ||
            ssh.GetValue("authType", BsonNull.Value) is not BsonString { Value.Length: > 0 })
        {
            ThrowIncomplete(server);
            return;
        }

        var hasLegacyPassword = HasNonEmptyString(server, "sshPassword");
        if (hasLegacyPassword && ssh.GetValue("password", BsonNull.Value) is not BsonDocument)
            ThrowIncomplete(server);

        if (HasNonEmptyString(server, "sshPrivateKeyPath") &&
            ssh.GetValue("privateKeyPath", BsonNull.Value) is not BsonString { Value.Length: > 0 })
            ThrowIncomplete(server);

        var protocols = server.GetValue("protocols", BsonNull.Value) as BsonArray;
        if (protocols is null || protocols.Count == 0 ||
            protocols.Any(protocol => protocol is not BsonDocument p ||
                p.GetValue("id", BsonNull.Value) is not BsonString { Value.Length: > 0 } ||
                p.GetValue("kind", BsonNull.Value) is not BsonString { Value.Length: > 0 } ||
                p.GetValue("containerName", BsonNull.Value) is not BsonString { Value.Length: > 0 }))
        {
            ThrowIncomplete(server);
            return;
        }

        ValidateWireGuardMappings(server, protocols);
    }

    /// <summary>
    /// M003 собирала единственный протокол WireGuard из этих плоских полей.
    /// После появления мультипротокольности он мог быть дополнен другими
    /// протоколами, поэтому equality не требуется: достаточно, что один
    /// текущий WireGuard-протокол уже содержит каждое нужное значение.
    /// Если старый протокол был удалён или документ вручную повреждён, cleanup
    /// останавливается вместо удаления последних operational-параметров.
    /// </summary>
    private static void ValidateWireGuardMappings(BsonDocument server, BsonArray protocols)
    {
        if (!LegacyWgFields.Any(field => HasValue(server, field))) return;

        var hasMappedProtocol = protocols
            .OfType<BsonDocument>()
            .Any(protocol => IsCompleteWireGuardMapping(protocol, server));

        if (!hasMappedProtocol) ThrowIncomplete(server);
    }

    private static bool IsCompleteWireGuardMapping(BsonDocument protocol, BsonDocument server)
    {
        if (protocol.GetValue("kind", BsonNull.Value) is not BsonString kind ||
            !ProtocolKinds.WireGuardFamily.Contains(kind.Value) ||
            protocol.GetValue("wg", BsonNull.Value) is not BsonDocument wg)
            return false;

        return HasMappedString(server, "awgPort", protocol, "port") &&
               HasMappedString(server, "containerName", protocol, "containerName") &&
               HasMappedString(server, "awgConfigPath", wg, "serverConfigPath") &&
               HasMappedString(server, "serverPublicKeyPath", wg, "serverPubKeyPath") &&
               HasMappedString(server, "pskKeyPath", wg, "pskKeyPath") &&
               HasMappedString(server, "awgInterface", wg, "interfaceName") &&
               HasMappedString(server, "wgBin", wg, "binary") &&
               HasMappedString(server, "subnetAddress", wg, "subnetAddress") &&
               HasMappedString(server, "subnetCidr", wg, "subnetCidr") &&
               HasMappedString(server, "serverPubKey", wg, "serverPubKey") &&
               HasMappedString(server, "pskKey", wg, "pskKey") &&
               HasMappedString(server, "lastKnownPeerIp", wg, "lastKnownPeerIp") &&
               (!HasValue(server, "obfuscation") || wg.GetValue("obfuscation", BsonNull.Value) is BsonDocument);
    }

    private static readonly string[] LegacyWgFields =
    [
        "awgPort", "containerName", "awgConfigPath", "serverPublicKeyPath", "pskKeyPath",
        "awgInterface", "wgBin", "subnetAddress", "subnetCidr", "serverPubKey", "pskKey",
        "lastKnownPeerIp", "obfuscation"
    ];

    private static bool HasMappedString(BsonDocument source, string sourceField, BsonDocument target, string targetField) =>
        !HasValue(source, sourceField) || HasNonEmptyString(target, targetField);

    private static bool HasNonEmptyString(BsonDocument document, string field) =>
        document.GetValue(field, BsonNull.Value) is BsonString { Value.Length: > 0 };

    private static bool HasValue(BsonDocument document, string field) =>
        document.GetValue(field, BsonNull.Value) switch
        {
            BsonNull => false,
            BsonString { Value.Length: 0 } => false,
            _ => true
        };

    private static void ThrowIncomplete(BsonDocument server) =>
        throw new InvalidOperationException(
            $"Cannot remove legacy fields from server_config document {server.GetValue("_id", "<unknown>")}: " +
            "the required v2 data is incomplete. Restore or finish migration 003 before starting the worker.");
}
