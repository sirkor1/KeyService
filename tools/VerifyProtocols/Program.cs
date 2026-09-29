using System.Reflection;
using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using AmneziaKeyService.Core.Exceptions;
using AmneziaKeyService.Core.Interfaces;
using AmneziaKeyService.Core.Models;
using AmneziaKeyService.Infrastructure.Install;
using AmneziaKeyService.Infrastructure.Migrations;
using AmneziaKeyService.Infrastructure.Protocols;
using AmneziaKeyService.Infrastructure.Repositories;
using AmneziaKeyService.Infrastructure.Scripts;
using AmneziaKeyService.Infrastructure.Services;
using Microsoft.Extensions.Options;
using MongoDB.Bson;
using MongoDB.Driver;

var checks = 0;
void Check(bool value, string name) { if (!value) throw new Exception(name); checks++; Console.WriteLine($"PASS: {name}"); }
void Reject(Action action, string name) { try { action(); } catch (BadRequestException) { Check(true, name); return; } throw new Exception(name); }

var old = new ProtocolInstance { Kind = ProtocolKinds.Awg2, ContainerName = "amnezia-awg2", Port = "40000", State = ProtocolStates.Installed,
    Wg = new WgProtocolParams { SubnetAddress = "10.8.1.0", SubnetCidr = "24" } };
var server = new VpnServer { Id = ObjectId.GenerateNewId().ToString(), Host = "192.0.2.1", Protocols = [old], DefaultProtocolId = old.Id };
var spec = new ProtocolSpec { Kind = ProtocolKinds.Awg3 };
ProtocolInstallRules.Prepare(server, [spec]);
Check(spec.Port != old.Port && spec.SubnetAddress != old.Wg.SubnetAddress, "upgrade selects separate port and subnet");
Check(server.Protocols.Count == 1 && server.Protocols[0].Id == old.Id, "preflight preserves old protocol identity");
Reject(() => ProtocolInstallRules.Prepare(server, [new() { Kind = ProtocolKinds.Awg2 }]), "duplicate kind rejected");
Reject(() => ProtocolInstallRules.Prepare(server, [new() { Kind = ProtocolKinds.Awg3, Port = "40000" }]), "occupied port rejected");
Reject(() => ProtocolInstallRules.Prepare(server, [new() { Kind = ProtocolKinds.Awg3, Port = "1;id" }]), "invalid port rejected before SSH");
Reject(() => ProtocolInstallRules.Prepare(server, [new() { Kind = ProtocolKinds.Awg3, SubnetAddress = "10.8.0.0", SubnetCidr = "16" }]), "overlapping CIDR rejected");

var scripts = new ScriptRegistry();
var installer = new WireGuardInstaller(WireGuardInstallProfile.Awg3, scripts);
var operations = new List<string>();
var files = new Dictionary<string, string>();
var ssh = Stub.Create<ISshSession>((method, values) => {
    if (method.Name == nameof(ISshSession.DisposeAsync)) return ValueTask.CompletedTask;
    var strings = values.OfType<string>().ToArray();
    operations.AddRange(strings);
    if (method.Name == nameof(ISshSession.WriteContainerFileAsync)) files[strings[1]] = strings[2];
    if (method.Name == nameof(ISshSession.RunInContainerScriptAsync)) files["configure"] = strings[1];
    if (method.Name == nameof(ISshSession.RunCheckedAsync)) return Task.FromResult("amnezia-awg2\n");
    if (method.ReturnType == typeof(Task<string>)) return Task.FromResult("");
    if (method.ReturnType == typeof(Task<SshResult>)) return Task.FromResult(new SshResult(0, "", ""));
    return Task.CompletedTask;
});
var progress = Stub.Create<IInstallProgress>((_, _) => Task.CompletedTask);
// Check the install/read boundary against the actual upstream scripts, not just
// a permissive SSH stub that returns a key for every requested file path.
var freshSsh = Stub.Create<ISshSession>((method, _) => {
    if (method.Name == nameof(ISshSession.DisposeAsync)) return ValueTask.CompletedTask;
    if (method.ReturnType == typeof(Task<string>)) return Task.FromResult("");
    if (method.ReturnType == typeof(Task<SshResult>)) return Task.FromResult(new SshResult(0, "", ""));
    return Task.CompletedTask;
});
foreach (var profile in new[] { WireGuardInstallProfile.WireGuard, WireGuardInstallProfile.AwgLegacy, WireGuardInstallProfile.Awg2, WireGuardInstallProfile.Awg3 })
{
    var installed = await new WireGuardInstaller(profile, scripts).InstallAsync(freshSsh, server,
        new ProtocolSpec { Kind = profile.Kind, SubnetAddress = "10.77.77.0" }, progress);
    var configuration = scripts.Read($"{profile.ScriptFolder}/configure_container.sh");
    foreach (var path in new[] { installed.Wg!.ServerPubKeyPath, installed.Wg.PskKeyPath, installed.Wg.ServerConfigPath })
        Check(configuration.Contains("> " + path), $"{profile.Kind}: reads file created by upstream script ({path})");
}
var protocol = await installer.InstallAsync(ssh, server, spec, progress);
Check(protocol.ContainerName == "amnezia-awg3" && protocol.Id != old.Id, "new isolated container and stable old ID");
Check(!operations.Any(s => s.Contains("docker rm") || s.Contains("docker stop")), "installation never removes or stops old containers");
Check(!files["configure"].Contains("$HEADER_PROTECTION_KEY") && files["configure"].Contains("HeaderProtectionKey = "), "server receives new AWG parameters");
Check(!operations.Where(s => s.Contains("docker exec") || s.Contains("docker cp")).Any(s => s.Contains("amnezia-awg2")), "writes do not target old container");
Check(operations.Any(s => s.StartsWith("FROM amneziavpn/amneziawg-go@sha256:")), "AWG3 engine pinned to verified image");

var existingSsh = Stub.Create<ISshSession>((_, _) => Task.FromResult("amnezia-awg2\namnezia-awg3\n"));
try { await installer.InstallAsync(existingSsh, server, spec, progress); throw new Exception("existing container overwritten"); }
catch (BadRequestException) { Check(true, "unmanaged existing container is protected"); }

var configurator = new WireGuardConfigurator(WireGuardProfile.Awg3, scripts, new KeyGenerationService(), new IpAllocator(null!));
protocol.Wg!.ServerPubKey = Convert.ToBase64String(new byte[32]);
protocol.Wg.PskKey = Convert.ToBase64String(new byte[32]);
var client = new VpnClient { ServerId = server.Id, ProtocolId = protocol.Id, ProtocolKind = protocol.Kind,
    AssignedIp = "10.8.2.2", ClientPrivKey = Convert.ToBase64String(new byte[32]), ClientPubKey = Convert.ToBase64String(new byte[32]) };
var json = JsonNode.Parse(VpnConfigReader.BuildConfigJson(server, protocol, client, configurator))!;
var entry = json["containers"]![0]!;
Check(json["defaultContainer"]!.GetValue<string>() == "amnezia-awg2" && entry["container"]!.GetValue<string>() == "amnezia-awg2", "export uses recognised upstream container type");
Check(entry["awg"]!["protocol_version"]!.GetValue<string>() == "3.1", "export carries upstream protocol version");
var last = JsonNode.Parse(entry["awg"]!["last_config"]!.GetValue<string>())!;
var conf = last["config"]!.GetValue<string>();
Check(!Regex.IsMatch(conf, @"\$[A-Z_]+"), "client template has no unresolved placeholders");
Check(last["HeaderProtectionKey"]!.GetValue<string>() == protocol.Wg.Obfuscation!.HeaderProtectionKey &&
    conf.Contains($"HeaderProtectionKey = {protocol.Wg.Obfuscation.HeaderProtectionKey}"), "header key preserved in JSON and conf");
Check(conf.Contains("PersistentKeepalive = 25-35"), "AWG3 keepalive range exported");
Check(!SecretRedactor.Redact(conf).Contains(protocol.Wg.Obfuscation.HeaderProtectionKey), "header key redacted from logs");
var obfKey = protocol.Wg.Obfuscation.HeaderProtectionKey;
var obfConfig = files["configure"];
protocol.Wg.ServerPubKey = null;
protocol.Wg.Obfuscation = null;
var readSsh = Stub.Create<ISshSession>((_, values) => Task.FromResult(values.OfType<string>().Last().EndsWith(".conf")
    ? obfConfig : Convert.ToBase64String(new byte[32])));
await configurator.EnsureServerParamsAsync(readSsh, server, protocol);
Check(protocol.Wg.Obfuscation!.HeaderProtectionKey == obfKey && protocol.Wg.Obfuscation.I1.Length > 0,
    "refresh preserves header key and commented I parameters");
Check(protocol.Wg.Obfuscation.ContentPaddingAddition == "" && protocol.Wg.Obfuscation.I2 == "", "empty parameters do not consume the next config line");

server.Protocols.Add(protocol);
server.DisabledProtocolIds.Add(old.Id);
Check(server.IssuanceProtocol(null)?.Id == protocol.Id, "default issuance skips disabled old version");
Check(server.IssuanceProtocol(old.Id) is null && VpnConfigReader.ResolveProtocol(server, old.Id).Id == old.Id,
    "disabled version blocks new issuance but still resolves existing keys");
server.DisabledProtocolIds.Add(protocol.Id);
Check(server.IssuanceProtocol(null) is null, "all protocols may be disabled for new issuance");
server.DisabledProtocolIds.Remove(protocol.Id);
Check(Encoding.UTF8.GetByteCount($"np:{server.Id}:{protocol.Id}") <= 64, "Telegram callback fits byte limit");

var mongoArg = args.FirstOrDefault(a => a.StartsWith("--mongo="));
if (mongoArg is not null)
{
    var mongo = new MongoClient(mongoArg[8..]);
    var dbName = "verify_protocols_" + Guid.NewGuid().ToString("N");
    try
    {
        var repo = new VpnServerRepository(mongo, Options.Create(new MongoDbOptions { DatabaseName = dbName }));
        server.DisabledProtocolIds.Clear();
        await repo.CreateAsync(server);
        var stale = (await repo.GetByIdAsync(server.Id))!;
        await repo.SetProtocolEnabledAsync(server.Id, old.Id, false);
        await repo.UpdateAsync(stale);
        var saved = (await repo.GetByIdAsync(server.Id))!;
        Check(!saved.CanIssue(saved.FindProtocol(old.Id)!), "stale SSH save cannot undo admin disable");
        await repo.SetProtocolEnabledAsync(server.Id, old.Id, true);
        saved = (await repo.GetByIdAsync(server.Id))!;
        Check(saved.CanIssue(saved.FindProtocol(old.Id)!), "admin can re-enable protocol");
        var staleProbe = (await repo.GetByIdAsync(server.Id))!;
        saved.Protocols.Add(new ProtocolInstance { Kind = "xray", ContainerName = "amnezia-xray" });
        await repo.UpdateAsync(saved);
        await repo.UpdateHealthAsync(staleProbe);
        await repo.UpdateReconciliationAsync(staleProbe);
        Check((await repo.GetByIdAsync(server.Id))!.Protocols.Count == 3, "stale monitoring cannot erase newly installed protocol");
        staleProbe.Name = "Updated during install";
        await repo.UpdateMetadataAsync(staleProbe);
        Check((await repo.GetByIdAsync(server.Id))!.Protocols.Count == 3, "metadata updates preserve installed protocols");
        await repo.UpdateInstallationAsync(saved);
        Check((await repo.GetByIdAsync(server.Id))!.Name == "Updated during install", "installation preserves concurrent metadata changes");

        var brokenWg = new ProtocolInstance { Kind = ProtocolKinds.WireGuard, ContainerName = "amnezia-wireguard", State = ProtocolStates.Failed,
            Wg = new WgProtocolParams { ServerConfigPath = "/opt/amnezia/wireguard/wg0.conf", ServerPubKey = "cached-public", PskKey = "cached-psk" } };
        var customWg = new ProtocolInstance { Kind = ProtocolKinds.WireGuard,
            Wg = new WgProtocolParams { ServerConfigPath = "/custom/wg0.conf", ServerPubKeyPath = "/custom/public.key", PskKeyPath = "/custom/psk.key" } };
        saved.Protocols.AddRange([brokenWg, customWg]);
        await repo.UpdateInstallationAsync(saved);
        var migration = new M015_WireGuardKeyPaths(Options.Create(new MongoDbOptions { DatabaseName = dbName }));
        await migration.ApplyAsync(mongo.GetDatabase(dbName), CancellationToken.None);
        await migration.ApplyAsync(mongo.GetDatabase(dbName), CancellationToken.None);
        var repaired = (await repo.GetByIdAsync(server.Id))!;
        var repairedWg = repaired.FindProtocol(brokenWg.Id)!;
        Check(repairedWg.Wg!.ServerPubKeyPath == "/opt/amnezia/wireguard/wireguard_server_public_key.key" &&
            repairedWg.Wg.PskKeyPath == "/opt/amnezia/wireguard/wireguard_psk.key", "path migration repairs saved WG defaults and is repeatable");
        Check(repairedWg.State == ProtocolStates.Failed && repairedWg.Wg.ServerPubKey == "cached-public" && repairedWg.Wg.PskKey == "cached-psk",
            "path migration preserves keys and does not claim failed installation succeeded");
        Check(repaired.FindProtocol(old.Id)!.Wg!.ServerPubKeyPath == old.Wg.ServerPubKeyPath &&
            repaired.FindProtocol(customWg.Id)!.Wg!.PskKeyPath == "/custom/psk.key", "path migration preserves AWG and custom paths");
    }
    finally { await mongo.DropDatabaseAsync(dbName); }
}
Console.WriteLine($"Passed {checks} protocol checks.");

public class Stub : DispatchProxy
{
    public Func<MethodInfo, object?[], object?> Handler { get; set; } = null!;
    protected override object? Invoke(MethodInfo? targetMethod, object?[]? args) => Handler(targetMethod!, args ?? []);
    public static T Create<T>(Func<MethodInfo, object?[], object?> handler) where T : class
    {
        var value = Create<T, Stub>();
        ((Stub)(object)value).Handler = handler;
        return value;
    }
}
