using System.Reflection;
using System.Text.Json;
using AmneziaKeyService.Api.Controllers;
using AmneziaKeyService.Core.Exceptions;
using AmneziaKeyService.Core.Interfaces;
using AmneziaKeyService.Core.Models;
using AmneziaKeyService.Infrastructure.Install;
using AmneziaKeyService.Infrastructure.Repositories;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Options;
using MongoDB.Bson;
using MongoDB.Driver;

var checks = 0;
void Check(bool ok, string label) { if (!ok) throw new Exception(label); checks++; Console.WriteLine("OK " + label); }
async Task Reject(Func<Task> action, string label) {
    try { await action(); } catch (BadRequestException) { Check(true, label); return; }
    throw new Exception("Accepted: " + label);
}

var f = new Fixture();
await Reject(() => f.Queue(confirmation: "wrong"), "exact name confirmation required");
Check(f.Jobs.Count == 0 && f.Commands.Count == 0, "bad confirmation creates no work");
var job = await f.Queue();
Check(f.Partition == f.Server!.Id && f.Commands.Count == 0, "queued under node partition, no SSH in request");
await Reject(() => f.Queue(), "active operation blocks a second request");
await f.Service.ExecuteAsync(job, default);
Check(job.Status == InstallJobStatuses.Succeeded, "cleanup succeeds");
Check(f.Server!.Protocols.Count == 0 && f.Server.Status == ServerStatuses.Empty, "empty reusable server retained");
Check(f.Server.Name == "Test node" && f.Server.Ssh.User == "root", "metadata and SSH retained");
Check(f.Containers.Keys.SequenceEqual(["unrelated-app"]), "only registered containers deleted");
Check(f.Keys.All(k => k.Status == KeyStatuses.Revoked && !k.IsActive), "all key states and legacy keys revoked");
Check(f.Commands.Where(c => c.Contains(" rm ")).All(c => c.StartsWith("sudo docker rm -f -v ") && c.Split(' ')[^1].Length == 64), "delete uses immutable IDs");
var commandsBeforeDelete = f.Commands.Count;
job = await f.Queue(InstallJobKinds.DeleteServer);
await f.Service.ExecuteAsync(job, default);
Check(job.Status == InstallJobStatuses.Succeeded && f.Server is null && f.Commands.Count == commandsBeforeDelete, "delete removes record without SSH");

foreach (var status in new[] { KeyStatuses.Active, KeyStatuses.PendingRevoke, KeyStatuses.Suspended, KeyStatuses.Expired }) {
    f = new(); f.Keys = [new() { Status = status }];
    await Reject(() => f.Queue(InstallJobKinds.DeleteServer), "cannot forget live key state " + status);
}
f = new(); f.Keys.Clear(); job = await f.Queue(InstallJobKinds.DeleteServer);
f.Keys.Add(new() { Status = KeyStatuses.Active });
await f.Service.ExecuteAsync(job, default);
Check(job.Status == InstallJobStatuses.Failed && f.Server is not null, "delete rechecks keys under lease");

f = new(); job = await f.Queue(); f.Server!.Host = "192.0.2.99";
await f.Service.ExecuteAsync(job, default);
Check(job.Status == InstallJobStatuses.Failed && f.Commands.Count == 0, "changed endpoint rejected before SSH");
f = new(); job = await f.Queue(); f.Server!.Protocols.Add(new() { Kind = "xray", ContainerName = "amnezia-xray" });
await f.Service.ExecuteAsync(job, default);
Check(job.Status == InstallJobStatuses.Failed && f.Commands.Count == 0, "changed protocol scope rejected");
f = new(); f.Server!.Protocols[0].ContainerName = "amnezia-awg3; echo bad";
await Reject(() => f.Queue(), "container injection rejected");
f = new(); f.Server!.Protocols[1].ContainerName = f.Server.Protocols[0].ContainerName;
await Reject(() => f.Queue(), "duplicate containers rejected");
f = new(); f.WritableMount = true; job = await f.Queue();
await f.Service.ExecuteAsync(job, default);
Check(job.Status == InstallJobStatuses.Failed && !f.Commands.Any(c => c.Contains(" rm ")) && f.Keys.Any(k => k.IsActive), "external storage rejected before deletion");
f = new(); f.FailRemove = "amnezia-wireguard"; job = await f.Queue();
await f.Service.ExecuteAsync(job, default);
Check(job.Status == InstallJobStatuses.Failed && f.Server!.Protocols.Count == 2, "partial failure retains retry scope");
Check(f.Keys.Where(k => k.ProtocolId == "wg").All(k => k.Status != KeyStatuses.Revoked), "failed removal does not falsely revoke keys");
Check(f.Keys.Where(k => k.ProtocolId is "awg" or null).All(k => k.Status == KeyStatuses.Revoked), "completed removal revokes its keys");
Check(f.Server!.IssuanceProtocol(null) is null, "partial cleanup blocks new key issuance");
f.FailRemove = null; job = await f.Queue(); await f.Service.ExecuteAsync(job, default);
Check(job.Status == InstallJobStatuses.Succeeded && f.Keys.All(k => !k.IsActive), "explicit retry handles already absent container");
f = new(); f.Server!.DefaultProtocolId = null; job = await f.Queue(); await f.Service.ExecuteAsync(job, default);
Check(job.Status == InstallJobStatuses.Succeeded && f.Keys.All(k => !k.IsActive), "legacy default fallback survives cleanup");
f = new(); f.Keys.Add(new() { ProtocolId = "missing" }); job = await f.Queue(); await f.Service.ExecuteAsync(job, default);
Check(job.Status == InstallJobStatuses.Failed && f.Commands.Count == 0, "orphan key references rejected before remote changes");
f = new(); f.KeepContainer = true; job = await f.Queue(); await f.Service.ExecuteAsync(job, default);
Check(job.Status == InstallJobStatuses.Failed && f.Keys.All(k => k.Status != KeyStatuses.Revoked), "verify removal even after successful docker result");
f = new(); job = await f.Queue(); job.CancelRequested = true; await f.Service.ExecuteAsync(job, default);
Check(job.Status == InstallJobStatuses.Canceled && f.Commands.Count == 0, "cancel before work has no remote effects");
f = new(); f.FailPublish = true;
try { await f.Queue(); } catch (InvalidOperationException) { }
Check(f.Jobs.Single().Status == InstallJobStatuses.Failed, "failed event publication does not leave pending job");
Check(typeof(ServerMaintenanceController).GetCustomAttribute<AuthorizeAttribute>()?.Policy == AuthPolicies.PanelAdmin,
    "destructive API requires administrator");

var mongoArg = args.FirstOrDefault(a => a.StartsWith("--mongo="));
if (mongoArg is not null) {
    var mongo = new MongoClient(mongoArg[8..]);
    var name = "verify_server_maintenance_" + Guid.NewGuid().ToString("N");
    var options = Options.Create(new MongoDbOptions { DatabaseName = name });
    try {
        var repo = new VpnClientRepository(mongo, options);
        var serverId = ObjectId.GenerateNewId().ToString();
        var userId = ObjectId.GenerateNewId().ToString();
        foreach (var status in new[] { KeyStatuses.Active, KeyStatuses.Expired, KeyStatuses.PendingRevoke, KeyStatuses.Suspended }) {
            var client = new VpnClient { ServerId = serverId, UserId = userId, ProtocolId = "awg", ClientPrivKey = "private", PskKey = "psk", VpnConfigJson = "{}" };
            client.SetStatus(status); await repo.CreateAsync(client);
        }
        await repo.CreateAsync(new() { ServerId = serverId, UserId = userId, ProtocolId = null });
        await repo.CreateAsync(new() { ServerId = serverId, UserId = userId, ProtocolId = "other" });
        var foreign = new VpnClient { ServerId = ObjectId.GenerateNewId().ToString(), UserId = userId, ProtocolId = "awg" };
        await repo.CreateAsync(foreign);
        var previouslyRevoked = new VpnClient { ServerId = serverId, UserId = userId, ProtocolId = "awg",
            PskKey = "old-psk", RevokedAt = new DateTime(2025, 1, 1, 0, 0, 0, DateTimeKind.Utc), RevokeReason = "manual" };
        previouslyRevoked.SetStatus(KeyStatuses.Revoked);
        await repo.CreateAsync(previouslyRevoked);
        await repo.RevokeRemovedProtocolAsync(serverId, "awg", true, userId);
        var old = await repo.FindByIdAsync(previouslyRevoked.Id);
        Check(old!.PskKey is null && old.RevokedAt == previouslyRevoked.RevokedAt && old.RevokeReason == "manual", "Mongo clears old revoked secrets without rewriting history");
        var keys = await repo.SearchAsync(new(ServerId: serverId));
        Check(keys.Total == 7 && keys.Items.Count(k => k.Status == KeyStatuses.Revoked) == 6, "Mongo keeps history and includes legacy keys");
        Check(keys.Items.Where(k => k.RevokeReason == "server_cleanup").All(k => !k.IsActive && k.ClientPrivKey is null && k.PskKey is null && k.VpnConfigJson is null && k.RevokedAt is not null), "Mongo erases obsolete secrets and synchronizes lifecycle fields");
        Check((await repo.FindByIdAsync(foreign.Id))!.IsActive && (await repo.GetLiveByServerAsync(serverId)).Count == 1, "Mongo leaves other server and protocol keys intact");
        var at = keys.Items.First(k => k.RevokeReason == "server_cleanup").RevokedAt;
        await repo.RevokeRemovedProtocolAsync(serverId, "awg", true, userId);
        Check((await repo.SearchAsync(new(ServerId: serverId))).Items.Where(k => k.RevokeReason == "server_cleanup").All(k => k.RevokedAt == at), "repeated reconciliation preserves revocation timestamp");
        var serverRepo = new VpnServerRepository(mongo, options);
        var server = await serverRepo.CreateAsync(new() { Name = "Cleaned", Host = "192.0.2.1", Status = ServerStatuses.Empty });
        Check((await serverRepo.GetByIdAsync(server.Id))!.Status == ServerStatuses.Empty, "empty server state persists");
        await serverRepo.DeleteAsync(server.Id);
        Check(await serverRepo.GetByIdAsync(server.Id) is null, "record deletion persists");
    } finally { await mongo.DropDatabaseAsync(name); }
}
Console.WriteLine($"Server maintenance checks passed: {checks}.");

class Fixture {
    public VpnServer? Server = new() { Id = "0123456789abcdef01234567", Name = "Test node", Host = "192.0.2.1",
        DefaultProtocolId = "awg", Protocols = [new() { Id = "awg", Kind = "awg3", ContainerName = "amnezia-awg3" },
            new() { Id = "wg", Kind = "wireguard", ContainerName = "amnezia-wireguard" }] };
    public List<VpnClient> Keys = [new() { ProtocolId = "awg" }, new() { ProtocolId = null }, new() { ProtocolId = "wg", Status = KeyStatuses.PendingRevoke }];
    public List<InstallJob> Jobs = [];
    public List<string> Commands = [];
    public Dictionary<string, string> Containers = new() { ["amnezia-awg3"] = new('a', 64), ["amnezia-wireguard"] = new('b', 64), ["unrelated-app"] = new('c', 64) };
    public string? Partition;
    public string? FailRemove;
    public bool WritableMount, KeepContainer, FailPublish;
    public ServerMaintenanceService Service;
    public Fixture() {
        var servers = Stub.Create<IVpnServerRepository>((m, a) => {
            if (m.Name == "GetByIdAsync") return Task.FromResult(Server);
            if (m.Name == "DeleteAsync") { Server = null; return Task.FromResult(true); }
            if (m.Name is "UpdateInstallationAsync" or "UpdateReconciliationAsync") return Task.CompletedTask;
            throw new Exception(m.Name);
        });
        var clients = Stub.Create<IVpnClientRepository>((m, a) => {
            if (m.Name == "GetLiveByServerAsync") return Task.FromResult(Keys.Where(k => k.Status != KeyStatuses.Revoked).ToList());
            if (m.Name == "RevokeRemovedProtocolAsync") {
                foreach (var k in Keys.Where(k => k.ProtocolId == (string)a[1]! || ((bool)a[2]! && k.ProtocolId is null))) k.SetStatus(KeyStatuses.Revoked);
                return Task.CompletedTask;
            }
            throw new Exception(m.Name);
        });
        var jobs = Stub.Create<IInstallJobRepository>((m, a) => {
            if (m.Name == "FindActiveByServerAsync") return Task.FromResult(Jobs.FirstOrDefault(j => !j.IsTerminal));
            if (m.Name == "GetByIdAsync") return Task.FromResult(Jobs.SingleOrDefault(j => j.Id == (string)a[0]!));
            if (m.Name == "CreateAsync") { var j = (InstallJob)a[0]!; j.Id = ObjectId.GenerateNewId().ToString(); Jobs.Add(j); return Task.FromResult(j); }
            if (m.Name is "UpdateAsync" or "AppendLogAsync") return Task.CompletedTask;
            throw new Exception(m.Name);
        });
        var events = Stub.Create<IDomainEventPublisher>((m, a) => {
            if (FailPublish) throw new InvalidOperationException();
            Partition = (string?)a[2]; return Task.FromResult(new DomainEvent());
        });
        var ssh = Stub.Create<ISshSession>((m, a) => {
            if (m.Name == "DisposeAsync") return ValueTask.CompletedTask;
            if (m.Name != "RunCheckedAsync") throw new Exception("Unexpected SSH " + m.Name);
            var command = (string)a[0]!; Commands.Add(command);
            if (command == "sudo docker ps -a --format '{{.Names}}'") return Task.FromResult(string.Join('\n', Containers.Keys));
            if (command.StartsWith("sudo docker inspect ")) {
                var name = command.Split(' ')[^1];
                return Task.FromResult(JsonSerializer.Serialize(new[] { new { Id = Containers[name], Name = "/" + name,
                    Mounts = new[] { new { RW = true, Type = "bind", Source = WritableMount ? "/vpn-data" : "/lib/modules",
                        Destination = WritableMount ? "/opt/amnezia" : "/lib/modules" } } } }));
            }
            if (command.StartsWith("sudo docker rm -f -v ")) {
                var name = Containers.Single(x => x.Value == command.Split(' ')[^1]).Key;
                if (name == FailRemove) return Task.FromException<string>(new SshCommandException("cleanup_remove_container", 1, null, null));
                if (!KeepContainer) Containers.Remove(name);
                return Task.FromResult("");
            }
            throw new Exception("Unexpected command " + command);
        });
        var factory = Stub.Create<ISshSessionFactory>((m, a) => Task.FromResult(ssh));
        var audit = Stub.Create<IAuditService>((m, a) => Task.CompletedTask);
        Service = new(servers, clients, jobs, events, factory, audit);
    }
    public Task<InstallJob> Queue(string kind = InstallJobKinds.CleanupServer, string confirmation = "Test node")
        => Service.EnqueueAsync("0123456789abcdef01234567", kind, confirmation, null, default);
}
public class Stub : DispatchProxy {
    private Func<MethodInfo, object?[], object?> handler = null!;
    public static T Create<T>(Func<MethodInfo, object?[], object?> handler) where T : class {
        var value = Create<T, Stub>(); ((Stub)(object)value).handler = handler; return value;
    }
    protected override object? Invoke(MethodInfo? method, object?[]? args) => handler(method!, args ?? []);
}
