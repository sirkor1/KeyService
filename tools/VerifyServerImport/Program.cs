using System.Reflection;
using System.Text.Json;
using AmneziaKeyService.Api.Controllers;
using AmneziaKeyService.Core.DTOs.Panel;
using AmneziaKeyService.Core.Exceptions;
using AmneziaKeyService.Core.Interfaces;
using AmneziaKeyService.Core.Models;
using AmneziaKeyService.Infrastructure.Protocols;
using AmneziaKeyService.Infrastructure.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Options;
using MongoDB.Bson;
using MongoDB.Bson.Serialization;
using MongoDB.Driver;
using AmneziaKeyService.Infrastructure.Repositories;

var checks = 0;
void Check(bool ok, string description)
{
    if (!ok) throw new Exception(description);
    Console.WriteLine("PASS: " + description);
    checks++;
}
async Task Reject(Func<Task> action, string description)
{
    try { await action(); }
    catch (BadRequestException) { Check(true, description); return; }
    throw new Exception(description);
}
var fixture = new Fixture();
var discovery = await fixture.Service.DiscoverAsync(fixture.Request(), default);
Check(discovery.Protocols.Count == 3 && discovery.Protocols.All(p => p.CanImport), "detect all three existing containers");
Check(discovery.Protocols.Select(p => p.Kind).SequenceEqual(new[] { "awg3", "awg2", "wireguard" }), "protocol versions remain distinct");
Check(discovery.Protocols.Select(p => p.Port).SequenceEqual(new[] { "41050", "37526", "35967" }), "read actual published ports");
Check(discovery.Protocols.All(p => p.PeerCount == 1), "count pre-existing peers");
Check(fixture.Saved.Count == 0, "discovery creates no database record");
var json = JsonSerializer.Serialize(discovery);
Check(!json.Contains(fixture.PrivateKey) && !json.Contains(fixture.Psk) && !json.Contains("ssh-secret"), "preview contains no config or SSH secrets");

var request = fixture.Import(discovery);
var imported = await fixture.Service.ImportAsync(request, "actor", default);
Check(imported.Protocols.Count == 3 && imported.OrphanPeerCount == 3, "one server owns all selected protocols and orphan counts");
Check(imported.DefaultProtocolId == imported.Protocols[0].Id && imported.Protocols.All(p => p.State == ProtocolStates.Installed), "import is ready without installation jobs");
Check(imported.Protocols.Single(p => p.Kind == "wireguard").Wg!.ServerPubKeyPath.Contains("/wireguard/"), "WireGuard keeps its own key directory");
Check(imported.Protocols.Single(p => p.Kind == "awg3").Wg!.Obfuscation!.HeaderProtectionKey == "fixture-header", "AWG3 header protection retained");
Check(imported.Protocols.Single(p => p.Kind == "awg2").Wg!.Obfuscation!.I1 == "<r 2>", "commented I1 retained");
Check(imported.Protocols.Single(p => p.Kind == "awg2").Wg!.Obfuscation!.Jc == "3", "inline comments stripped from imported obfuscation");
Check(!imported.ToJson().Contains("ssh-secret"), "SSH credentials encrypted before persistence");
var restored = BsonSerializer.Deserialize<VpnServer>(imported.ToBson());
Check(restored.Id == imported.Id && restored.Protocols.Select(p => p.Id).SequenceEqual(imported.Protocols.Select(p => p.Id)) &&
    restored.Protocols.All(p => p.Wg!.IsCached), "current BSON model and protocol identities round-trip");
await Reject(() => fixture.Service.ImportAsync(request, "actor", default), "duplicate endpoint is rejected");
Check(fixture.Saved.Count == 1, "duplicate import creates no second record");
Check(fixture.Operations.All(op => op.StartsWith("docker ps ") || op.StartsWith("docker inspect ") ||
    op.StartsWith("read:") || (op.StartsWith("docker exec ") && op.Contains(" show "))), "SSH operations are exclusively read-only");

fixture = new Fixture();
discovery = await fixture.Service.DiscoverAsync(fixture.Request(), default);
fixture.Configs["amnezia-awg2"] = fixture.Configs["amnezia-awg2"].Replace("# I1 = <r 2>", "# I1 = <r 3>");
await Reject(() => fixture.Service.ImportAsync(fixture.Import(discovery), "actor", default), "config changed after preview is rejected");
Check(fixture.Saved.Count == 0, "stale preview cannot persist a server");

fixture = new Fixture();
fixture.LivePeers = "";
discovery = await fixture.Service.DiscoverAsync(fixture.Request(), default);
Check(discovery.Protocols.All(p => !p.CanImport), "config peers missing from live interface block import");
await Reject(() => fixture.Service.ImportAsync(fixture.Import(discovery), "actor", default), "unverified protocols cannot be imported via crafted request");

fixture = new Fixture();
fixture.LivePeers += fixture.OtherPeer + "\t10.8.1.99/32\n";
discovery = await fixture.Service.DiscoverAsync(fixture.Request(), default);
Check(discovery.Protocols.All(p => !p.CanImport), "runtime-only peers block future destructive syncconf");

fixture = new Fixture();
fixture.Stopped.Add("amnezia-awg3");
discovery = await fixture.Service.DiscoverAsync(fixture.Request(), default);
Check(discovery.Protocols.Single(p => p.Kind == "awg3").CanImport == false && discovery.Protocols.Count(p => p.CanImport) == 2, "stopped container does not hide healthy protocols");
request = fixture.Import(discovery);
request.Containers = ["amnezia-wireguard"];
imported = await fixture.Service.ImportAsync(request, null, default);
Check(imported.Protocols.Count == 1 && imported.DefaultProtocol!.Kind == "wireguard", "subset import honors user selection");

fixture = new Fixture();
fixture.BadPublicKey = true;
discovery = await fixture.Service.DiscoverAsync(fixture.Request(), default);
Check(discovery.Protocols.All(p => !p.CanImport), "mismatched runtime/server public keys rejected");

fixture = new Fixture();
fixture.Configs["amnezia-awg2"] = fixture.Configs["amnezia-awg2"].Replace(fixture.PrivateKey, new KeyGenerationService().GenerateX25519KeyPair().PrivateKeyBase64);
discovery = await fixture.Service.DiscoverAsync(fixture.Request(), default);
Check(!discovery.Protocols.Single(p => p.Kind == "awg2").CanImport, "stale private key in saved config rejected");

fixture = new Fixture();
fixture.PortOffset = 10;
discovery = await fixture.Service.DiscoverAsync(fixture.Request(), default);
Check(discovery.Protocols[0].Port == "41060", "external NAT port used instead of internal listen port");
fixture.LoopbackOnly = true;
discovery = await fixture.Service.DiscoverAsync(fixture.Request(), default);
Check(discovery.Protocols.All(p => !p.CanImport), "loopback-only UDP publishing rejected");

fixture = new Fixture();
fixture.Configs["amnezia-awg2"] += "\n[Peer]\nPublicKey = broken\nAllowedIPs = 10.8.1.3/32\n";
discovery = await fixture.Service.DiscoverAsync(fixture.Request(), default);
Check(!discovery.Protocols.Single(p => p.Kind == "awg2").CanImport, "malformed peer detected without leaking config");
Check(!JsonSerializer.Serialize(discovery).Contains(fixture.PrivateKey), "error responses contain no secret config");

fixture = new Fixture();
discovery = await fixture.Service.DiscoverAsync(fixture.Request(), default);
request = fixture.Import(discovery);
request.Containers = ["amnezia-awg2; touch /tmp/unsafe"];
var commandsBefore = fixture.Operations.Count;
await Reject(() => fixture.Service.ImportAsync(request, null, default), "untrusted container rejected before SSH");
Check(fixture.Operations.Count == commandsBefore, "no untrusted container reaches shell");
request.Containers = ["amnezia-awg2", "amnezia-awg2"];
await Reject(() => fixture.Service.ImportAsync(request, null, default), "repeated selection rejected");
var invalidAccess = fixture.Request();
invalidAccess.SshPrivateKey = "also-a-key";
await Reject(() => fixture.Service.DiscoverAsync(invalidAccess, default), "ambiguous SSH authentication rejected");
invalidAccess = fixture.Request();
invalidAccess.Host = "example.com;id";
await Reject(() => fixture.Service.DiscoverAsync(invalidAccess, default), "invalid host rejected");

var config = fixture.Configs["amnezia-wireguard"];
await Reject(() => Task.FromResult(ExistingWireGuardConfig.Parse(config.Replace("10.8.1.1/24", "10.8.1.10/24"), WireGuardInstallProfile.WireGuard)), "nonstandard server address cannot collide with future clients");
var parsed = ExistingWireGuardConfig.Parse(config, WireGuardInstallProfile.WireGuard);
Check(parsed.Network == "10.8.1.0" && parsed.Cidr == "24", "interface host address normalized to network");
await Reject(() => Task.Run(() => parsed.CheckLivePeers(fixture.Peer + "\t10.8.1.99/32")), "changed live AllowedIPs rejected");
var newerInOldContainer = ExistingWireGuardConfig.Parse(fixture.Configs["amnezia-awg3"], WireGuardInstallProfile.Awg2);
Check(newerInOldContainer.Kind == "awg3", "AWG3 config in amnezia-awg2 container identified correctly");
Check(typeof(ServerImportController).GetCustomAttribute<AuthorizeAttribute>()?.Policy == AuthPolicies.PanelAdmin,
    "discovery and import require panel admin policy");

fixture = new Fixture();
fixture.ExtraContainer = "amnezia-xray";
discovery = await fixture.Service.DiscoverAsync(fixture.Request(), default);
Check(discovery.Warnings.Count == 1, "unsupported containers clearly reported and left untouched");

var mongoArg = args.FirstOrDefault(a => a.StartsWith("--mongo="));
if (mongoArg is not null)
{
    var settings = MongoClientSettings.FromConnectionString(mongoArg[8..]);
    settings.ServerSelectionTimeout = TimeSpan.FromSeconds(5);
    var mongo = new MongoClient(settings);
    var database = "verify_server_import_" + Guid.NewGuid().ToString("N");
    var repository = new VpnServerRepository(mongo, Options.Create(new MongoDbOptions { DatabaseName = database }));
    try
    {
        fixture = new Fixture(repository);
        discovery = await fixture.Service.DiscoverAsync(fixture.Request(), default);
        // No new migrations/indexes required: the existing unique _id protects this race.
        async Task<bool> TryImport()
        {
            try { await fixture.Service.ImportAsync(fixture.Import(discovery), null, default); return true; }
            catch (BadRequestException) { return false; }
        }
        var outcomes = await Task.WhenAll(TryImport(), TryImport());
        Check(outcomes.Count(ok => ok) == 1, "concurrent Mongo imports have exactly one winner");
        var saved = await repository.GetAllAsync();
        Check(saved.Count == 1 && saved[0].Protocols.Count == 3 && saved[0].OrphanPeerCount == 3,
            "Mongo persists a single server with all protocols and existing peers");
        Check(saved[0].Protocols.Select(p => p.Kind).SequenceEqual(new[] { "awg3", "awg2", "wireguard" }),
            "Mongo retains distinct protocol versions");
    }
    finally { await mongo.DropDatabaseAsync(database); }
}
Console.WriteLine($"Server import: {checks} checks passed.");

public class Fixture
{
    public string PrivateKey { get; }
    public string PublicKey { get; }
    public string Peer { get; } = new KeyGenerationService().GenerateX25519KeyPair().PublicKeyBase64;
    public string OtherPeer { get; } = new KeyGenerationService().GenerateX25519KeyPair().PublicKeyBase64;
    public string Psk { get; } = Convert.ToBase64String(Enumerable.Repeat((byte)7, 32).ToArray());
    public string LivePeers { get; set; }
    public Dictionary<string, string> Configs { get; } = [];
    public List<string> Operations { get; } = [];
    public List<VpnServer> Saved { get; } = [];
    public HashSet<string> Stopped { get; } = [];
    public bool BadPublicKey { get; set; }
    public bool LoopbackOnly { get; set; }
    public int PortOffset { get; set; }
    public string? ExtraContainer { get; set; }
    public ServerImportService Service { get; }
    private readonly Dictionary<string, string> ports = new() { ["amnezia-awg3"] = "41050", ["amnezia-awg2"] = "37526", ["amnezia-wireguard"] = "35967" };
    public Fixture(IVpnServerRepository? actualRepository = null)
    {
        (PrivateKey, PublicKey) = new KeyGenerationService().GenerateX25519KeyPair();
        LivePeers = Peer + "\t10.8.1.2/32\n";
        foreach (var (name, port) in ports)
        {
            var obf = name == "amnezia-wireguard" ? "" : "Jc = 3 # comment\nJmin = 10\nJmax = 30\nS1 = 15\nS2 = 18\nH1 = 1\nH2 = 2\nH3 = 3\nH4 = 4\n# I1 = <r 2>\n";
            if (name == "amnezia-awg3") obf += "HeaderProtectionKey = fixture-header\n";
            Configs[name] = $"[Interface]\nPrivateKey = {PrivateKey}\nAddress = 10.8.1.1/24\nListenPort = {port}\n{obf}\n[Peer]\nPublicKey = {Peer}\nPresharedKey = {Psk}\nAllowedIPs = 10.8.1.2/32\n";
        }
        var ssh = Stub.Create<ISshSession>((method, args) =>
        {
            if (method.Name == nameof(ISshSession.DisposeAsync)) return ValueTask.CompletedTask;
            if (method.Name == nameof(ISshSession.ReadContainerFileAsync))
            {
                var name = (string)args[0]!; var path = (string)args[1]!;
                Operations.Add("read:" + name + ":" + path);
                if (path.EndsWith(".conf")) return Task.FromResult(Configs[name]);
                if (path.EndsWith("wireguard_server_public_key.key")) return Task.FromResult(PublicKey);
                if (path.EndsWith("wireguard_psk.key")) return Task.FromResult(Psk);
                throw new Exception("Unexpected file " + path);
            }
            if (method.Name == nameof(ISshSession.RunCheckedAsync))
            {
                var command = (string)args[0]!;
                Operations.Add(command);
                if (command == "docker ps -a --format '{{.Names}}'")
                    return Task.FromResult(string.Join('\n', Configs.Keys) + "\n" + ExtraContainer);
                if (command.StartsWith("docker inspect --format "))
                {
                    var name = command.Split(' ')[^1];
                    var bindings = new Dictionary<string, object> { [ports[name] + "/udp"] = new[] {
                        new { HostIp = LoopbackOnly ? "127.0.0.1" : "0.0.0.0", HostPort = (int.Parse(ports[name]) + PortOffset).ToString() } } };
                    return Task.FromResult(JsonSerializer.Serialize(new { running = !Stopped.Contains(name), network = "bridge", ports = bindings }));
                }
                if (command.StartsWith("docker exec ") && command.Contains(" show "))
                {
                    var name = command.Split(' ')[2];
                    if (command.EndsWith(" public-key")) return Task.FromResult(BadPublicKey ? OtherPeer : PublicKey);
                    if (command.EndsWith(" listen-port")) return Task.FromResult(ports[name]);
                    if (command.EndsWith(" allowed-ips")) return Task.FromResult(LivePeers);
                }
            }
            // In particular, any install, restart, script upload or write fails the test.
            throw new Exception("Forbidden SSH operation: " + method.Name);
        });
        var factory = Stub.Create<ISshSessionFactory>((_, _) => Task.FromResult(ssh));
        var repository = Stub.Create<IVpnServerRepository>((method, args) => method.Name switch {
            nameof(IVpnServerRepository.GetAllAsync) => Task.FromResult(Saved.ToList()),
            nameof(IVpnServerRepository.CreateAsync) => Save((VpnServer)args[0]!),
            _ => throw new Exception("Unexpected repository operation")
        });
        var protector = new AesGcmSecretProtector(Options.Create(new SecurityOptions {
            DataProtectionKey = Convert.ToBase64String(Enumerable.Repeat((byte)9, 32).ToArray())
        }));
        Service = new ServerImportService(factory, protector, actualRepository ?? repository);
    }
    private Task<VpnServer> Save(VpnServer server) { Saved.Add(server); return Task.FromResult(server); }
    public DiscoverServerRequest Request() => new() { Host = "192.0.2.1", SshPassword = "ssh-secret" };
    public ImportServerRequest Import(ServerDiscoveryDto discovery) => new()
    {
        Host = "192.0.2.1", Name = "Existing node", SshPassword = "ssh-secret", Revision = discovery.Revision,
        Containers = ["amnezia-awg3", "amnezia-awg2", "amnezia-wireguard"]
    };
}

public class Stub : DispatchProxy
{
    private Func<MethodInfo, object?[], object?> handler = null!;
    public static T Create<T>(Func<MethodInfo, object?[], object?> handler) where T : class
    {
        var value = Create<T, Stub>();
        ((Stub)(object)value).handler = handler;
        return value;
    }
    protected override object? Invoke(MethodInfo? method, object?[]? args) => handler(method!, args ?? []);
}
