using AmneziaKeyService.Core.Models;
using AmneziaKeyService.Infrastructure.Migrations;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using MongoDB.Bson;
using MongoDB.Driver;

var mongoUrl = Environment.GetEnvironmentVariable("MONGO_URL") ?? "mongodb://localhost:27017";
var databaseName = "amnezia_verify_legacy_" + Guid.NewGuid().ToString("N");
var client = new MongoClient(mongoUrl);
var database = client.GetDatabase(databaseName);
var options = Options.Create(new MongoDbOptions
{
    DatabaseName = databaseName,
    ServerConfigCollection = "server_config"
});
var migration = new M012_DropLegacy(options);
var runner = new MongoMigrationRunner(client, options, [migration], NullLogger<MongoMigrationRunner>.Instance);
var servers = database.GetCollection<BsonDocument>("server_config");
var migrations = database.GetCollection<BsonDocument>("_migrations");
var legacyFields = new[]
{
    "description", "sshPort", "sshUser", "sshPassword", "sshPrivateKeyPath",
    "awgPort", "containerName", "awgConfigPath", "serverPublicKeyPath", "pskKeyPath",
    "awgInterface", "wgBin", "subnetAddress", "subnetCidr", "serverPubKey", "pskKey",
    "lastKnownPeerIp", "obfuscation"
};

var legacyId = ObjectId.GenerateNewId();
var modernId = ObjectId.GenerateNewId();
var createdAt = new BsonDateTime(DateTime.UtcNow.AddDays(-1));
var updatedAt = new BsonDateTime(DateTime.UtcNow);

var modernProtocol = new BsonDocument
{
    ["id"] = "protocol-1",
    ["kind"] = "awg",
    ["containerName"] = "amnezia-awg",
    ["port"] = "55424",
    ["wg"] = new BsonDocument
    {
        ["interfaceName"] = "wg0",
        ["binary"] = "wg",
        ["serverConfigPath"] = "/opt/amnezia/awg/wg0.conf",
        ["serverPubKeyPath"] = "/opt/amnezia/awg/public.key",
        ["pskKeyPath"] = "/opt/amnezia/awg/psk.key",
        ["subnetAddress"] = "10.8.1.0",
        ["subnetCidr"] = "24",
        ["serverPubKey"] = "modern-public-key",
        ["pskKey"] = "modern-psk",
        ["lastKnownPeerIp"] = "10.8.1.99",
        ["obfuscation"] = new BsonDocument { ["mtu"] = "1376", ["s1"] = "1" }
    }
};

await servers.InsertManyAsync([
    new BsonDocument
    {
        ["_id"] = legacyId,
        ["schemaVersion"] = 2,
        ["name"] = "Migrated node",
        ["host"] = "198.51.100.10",
        ["createdAt"] = createdAt,
        ["updatedAt"] = updatedAt,
        ["ssh"] = new BsonDocument
        {
            ["port"] = 2222,
            ["user"] = "root",
            ["authType"] = "password",
            ["password"] = new BsonDocument
            {
                ["v"] = 1,
                ["alg"] = "AESGCM",
                ["keyId"] = "test",
                ["nonce"] = "nonce",
                ["ct"] = "ciphertext",
                ["tag"] = "tag"
            }
        },
        ["protocols"] = new BsonArray { modernProtocol },
        ["defaultProtocolId"] = "protocol-1",
        ["description"] = "Old name",
        ["sshPort"] = 2222,
        ["sshUser"] = "root",
        ["sshPassword"] = "plaintext-ssh-password",
        ["sshPrivateKeyPath"] = BsonNull.Value,
        ["awgPort"] = "55424",
        ["containerName"] = "amnezia-awg",
        ["awgConfigPath"] = "/opt/amnezia/awg/wg0.conf",
        ["serverPublicKeyPath"] = "/opt/amnezia/awg/public.key",
        ["pskKeyPath"] = "/opt/amnezia/awg/psk.key",
        ["awgInterface"] = "wg0",
        ["wgBin"] = "wg",
        ["subnetAddress"] = "10.8.1.0",
        ["subnetCidr"] = "24",
        ["serverPubKey"] = "legacy-public-key",
        ["pskKey"] = "legacy-psk",
        ["lastKnownPeerIp"] = "10.8.1.50",
        ["obfuscation"] = new BsonDocument { ["mtu"] = "1420" }
    },
    new BsonDocument
    {
        ["_id"] = modernId,
        ["schemaVersion"] = 2,
        ["name"] = "Modern node",
        ["host"] = "198.51.100.11",
        ["createdAt"] = createdAt,
        ["updatedAt"] = updatedAt,
        ["ssh"] = new BsonDocument
        {
            ["port"] = 22,
            ["user"] = "root",
            ["authType"] = "agent"
        },
        ["protocols"] = new BsonArray { modernProtocol.DeepClone().AsBsonDocument },
        ["defaultProtocolId"] = "protocol-1"
    }
]);

var checks = new List<(bool Passed, string Name)>();
try
{
    await runner.StartAsync(CancellationToken.None);
    var migrated = await servers.Find(Builders<BsonDocument>.Filter.Eq("_id", legacyId)).SingleAsync();
    var untouched = await servers.Find(Builders<BsonDocument>.Filter.Eq("_id", modernId)).SingleAsync();

    var removed = legacyFields.All(field => !migrated.Contains(field));
    checks.Add((removed, "all top-level legacy fields, including plaintext sshPassword, are removed"));
    checks.Add((migrated["host"] == "198.51.100.10" &&
                migrated["createdAt"] == createdAt && migrated["updatedAt"] == updatedAt &&
                migrated["ssh"].AsBsonDocument["password"].AsBsonDocument["ct"] == "ciphertext",
        "modern node identity, timestamps and encrypted SSH credential are preserved"));
    checks.Add((migrated["protocols"].AsBsonArray[0].AsBsonDocument["containerName"] == "amnezia-awg" &&
                migrated["protocols"].AsBsonArray[0].AsBsonDocument["wg"].AsBsonDocument["pskKey"] == "modern-psk",
        "nested modern protocol fields with legacy-like names are preserved"));
    checks.Add((untouched.Contains("updatedAt") && untouched["updatedAt"] == updatedAt &&
                untouched["protocols"].AsBsonArray[0].AsBsonDocument.Contains("containerName"),
        "already modern document is not altered"));
    checks.Add((await migrations.CountDocumentsAsync(Builders<BsonDocument>.Filter.Eq("_id", migration.Id)) == 1,
        "worker runner records the successful migration in _migrations"));

    await runner.StartAsync(CancellationToken.None);
    var repeated = await servers.Find(Builders<BsonDocument>.Filter.Eq("_id", legacyId)).SingleAsync();
    checks.Add((legacyFields.All(field => !repeated.Contains(field)) &&
                await migrations.CountDocumentsAsync(Builders<BsonDocument>.Filter.Eq("_id", migration.Id)) == 1,
        "second worker run is idempotent and does not duplicate _migrations"));

    var incompleteId = ObjectId.GenerateNewId();
    await servers.InsertOneAsync(new BsonDocument
    {
        ["_id"] = incompleteId,
        ["schemaVersion"] = 2,
        ["name"] = "Incomplete node",
        ["ssh"] = new BsonDocument
        {
            ["port"] = 22,
            ["user"] = "root",
            ["authType"] = "password"
        },
        ["protocols"] = new BsonArray { modernProtocol.DeepClone().AsBsonDocument },
        ["sshPassword"] = "must-not-be-deleted-without-encryption"
    });

    var rejected = false;
    try
    {
        await migration.ApplyAsync(database, CancellationToken.None);
    }
    catch (InvalidOperationException)
    {
        rejected = true;
    }

    var incomplete = await servers.Find(Builders<BsonDocument>.Filter.Eq("_id", incompleteId)).SingleAsync();
    checks.Add((rejected && incomplete.Contains("sshPassword"),
        "incomplete v2 document blocks cleanup before its only SSH credential is lost"));

    await servers.DeleteOneAsync(Builders<BsonDocument>.Filter.Eq("_id", incompleteId));

    var incompleteOperationalId = ObjectId.GenerateNewId();
    await servers.InsertOneAsync(new BsonDocument
    {
        ["_id"] = incompleteOperationalId,
        ["schemaVersion"] = 2,
        ["name"] = "Operationally incomplete node",
        ["ssh"] = new BsonDocument
        {
            ["port"] = 22,
            ["user"] = "root",
            ["authType"] = "agent"
        },
        ["protocols"] = new BsonArray
        {
            new BsonDocument
            {
                ["id"] = "protocol-without-wg-settings",
                ["kind"] = "awg",
                ["containerName"] = "amnezia-awg"
            }
        },
        ["awgConfigPath"] = "/opt/amnezia/awg/wg0.conf"
    });

    var operationalRejected = false;
    try
    {
        await migration.ApplyAsync(database, CancellationToken.None);
    }
    catch (InvalidOperationException)
    {
        operationalRejected = true;
    }

    var incompleteOperational = await servers
        .Find(Builders<BsonDocument>.Filter.Eq("_id", incompleteOperationalId)).SingleAsync();
    checks.Add((operationalRejected && incompleteOperational.Contains("awgConfigPath"),
        "incomplete WG mapping blocks cleanup before operational paths are lost"));
}
finally
{
    await client.DropDatabaseAsync(databaseName);
}

foreach (var check in checks)
    Console.WriteLine($"{(check.Passed ? "PASS" : "FAIL")}: {check.Name}");

return checks.Count == 8 && checks.All(check => check.Passed) ? 0 : 1;
