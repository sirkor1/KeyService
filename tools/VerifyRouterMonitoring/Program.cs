using AmneziaKeyService.Core.Models;
using AmneziaKeyService.Infrastructure.Events;
using AmneziaKeyService.Infrastructure.Migrations;
using AmneziaKeyService.Infrastructure.Monitoring;
using AmneziaKeyService.Infrastructure.Repositories;
using AmneziaKeyService.Infrastructure.Services;
using Microsoft.Extensions.Options;
using MongoDB.Bson;
using MongoDB.Bson.Serialization;
using MongoDB.Driver;
using AmneziaKeyService.Api.Controllers;
using AmneziaKeyService.Core.Interfaces;
using AmneziaKeyService.Core.Exceptions;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging.Abstractions;
using System.Reflection;
using System.Text.Json;

var passed = 0;
void Check(bool value, string message)
{
    if (!value) throw new Exception(message);
    passed++;
    Console.WriteLine("PASS " + message);
}
var now = DateTime.UtcNow;
RouterMonitor Fresh() => new() { UserId = ObjectId.GenerateNewId().ToString(), Name = "Home", LastCheckedAt = now };
var r = Fresh();
Check(RouterMonitorRules.ConnectionState(r, null, now) == RouterStates.Waiting, "No disconnect before first handshake");
RouterMonitorRules.Observe(r, RouterStates.Waiting, null, null, now);
Check(r.PendingHistory.Count == 0, "Initial waiting is quiet");
RouterMonitorRules.Observe(r, RouterStates.Online, now, null, now);
Check(r.PendingHistory.Count == 1 && r.PendingHistory[0].DeliveryStatus == "pending", "First connection enqueues one durable transition");
RouterMonitorRules.Observe(r, RouterStates.Online, now, null, now.AddSeconds(30));
Check(r.PendingHistory.Count == 1, "Unchanged observations do not duplicate alerts");
Check(RouterMonitorRules.ConnectionState(r, now.AddMinutes(1), now) == RouterStates.Unknown, "Future node clock is unknown");
Check(RouterMonitorRules.ConnectionState(r, now, now.AddSeconds(240)) == RouterStates.Online, "Handshake threshold includes boundary");
Check(RouterMonitorRules.ConnectionState(r, now, now.AddSeconds(241)) == RouterStates.Offline, "Expired handshake means offline on valid sample");
for (var i = 60; i <= 240; i += 30) RouterMonitorRules.Observe(r, RouterStates.Online, now, null, now.AddSeconds(i));
RouterMonitorRules.Observe(r, RouterStates.Offline, now, null, now.AddSeconds(270));
Check(r.OutageStartedAt == now.AddSeconds(270), "Outage starts at detection, not last handshake");
RouterMonitorRules.Observe(r, RouterStates.Online, now.AddSeconds(300), null, now.AddSeconds(300));
Check(r.PendingHistory.Last().OutageSeconds == 30, "Measured outage duration");
var offlineEvent = r.PendingHistory.First(h => h.State == RouterStates.Offline);
Check(!RouterMonitorRules.CanDeliver(r, offlineEvent, now.AddSeconds(300)), "Superseded outage alert is coalesced");
Check(RouterMonitorRules.CanDeliver(r, r.PendingHistory.Last(), now.AddSeconds(300)), "Current restoration can be delivered");
r.DeliveryGeneration++;
Check(!RouterMonitorRules.CanDeliver(r, r.PendingHistory.Last(), now.AddSeconds(300)), "Rebinding/settings invalidate pending delivery");
Check(RouterStates.Effective(r, now.AddSeconds(450)) == RouterStates.Unknown, "Dead worker does not leave stale online status");
RouterMonitorRules.Observe(r, RouterStates.Offline, now.AddSeconds(300), null, now.AddSeconds(700));
Check(r.PendingHistory[^2].State == RouterStates.Unknown && r.OutageStartedAt == now.AddSeconds(700), "Restart gap is not counted as outage");
RouterMonitorRules.Observe(r, RouterStates.Unknown, null, "SSH failed", now.AddSeconds(730));
RouterMonitorRules.Observe(r, RouterStates.Online, now.AddSeconds(760), null, now.AddSeconds(760));
Check(r.PendingHistory.Last().OutageSeconds is null, "Unknown interval breaks duration measurement");
r.Paused = true;
RouterMonitorRules.Observe(r, RouterStates.Offline, null, null, now.AddSeconds(790));
Check(r.State == RouterStates.Paused && r.OutageStartedAt is null, "Pause suppresses outage accounting");
r.Paused = false;
r.NotificationsEnabled = false;
RouterMonitorRules.Observe(r, RouterStates.Online, now.AddSeconds(820), null, now.AddSeconds(820));
Check(r.PendingHistory.Last().DeliveryStatus == "skipped", "Muted monitoring retains history");
Check(!RouterMonitorRules.CanReceive(new User { IsActive = true, TelegramId = 123, Status = UserStatuses.Blocked }), "Blocked recipient rejected");
Check(!RouterMonitorRules.CanReceive(new User { IsActive = true }), "Missing Telegram rejected");
Check(RouterMonitorRules.CanReceive(new User { IsActive = true, TelegramId = 123 }), "Registered active recipient accepted");
var roundtrip = BsonSerializer.Deserialize<RouterMonitor>(r.ToBson());
Check(roundtrip.PendingHistory[0].Id == r.PendingHistory[0].Id, "Embedded outbox BSON keeps transition identity");
var conf = RouterConfigFile.Build("[Interface]\nPrivateKey = fake\nAddress = 10.1.2.3/32\nDNS = 1.1.1.1\n[Peer]\nPublicKey = fake\nAllowedIPs = 0.0.0.0/0, ::/0\nPersistentKeepalive = 0\n", "10.1.2.128");
Check(conf.Contains("AllowedIPs = 10.1.2.129/32") && !conf.Contains("0.0.0.0/0") && !conf.Contains("::/0"), "Only upstream server tunnel address is routed");
Check(!conf.Contains("DNS") && conf.Contains("PersistentKeepalive = 25") && !conf.Contains("PersistentKeepalive = 0"), "Export leaves DNS unchanged and keeps tunnel alive");
foreach (var method in new[] { "Create", "Update", "Archive", "Test", "Config", "Options" })
    Check(typeof(RoutersController).GetMethod(method)!.GetCustomAttributes<AuthorizeAttribute>().Any(a => a.Policy == AuthPolicies.PanelAdmin), "Admin policy protects " + method);
Check(typeof(RoutersController).GetCustomAttributes<AuthorizeAttribute>().Any(a => a.Policy == AuthPolicies.PanelRead), "Router data requires panel authorization");

var mongoArg = args.FirstOrDefault(a => a.StartsWith("--mongo="));
if (mongoArg is not null)
{
    var dbName = "router_verify_" + Guid.NewGuid().ToString("N");
    var mongo = new MongoClient(mongoArg[8..]);
    var db = mongo.GetDatabase(dbName);
    var opts = Options.Create(new MongoDbOptions { DatabaseName = dbName });
    using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(50));
    var ct = deadline.Token;
    try
    {
        var migration = new M014_RouterMonitoring();
        await migration.ApplyAsync(db, ct);
        await migration.ApplyAsync(db, ct);
        Check(true, "Migration is repeatable on MongoDB standalone");
        var repo = new RouterMonitorRepository(mongo, opts);
        var clients = new VpnClientRepository(mongo, opts);
        var events = new DomainEventRepository(mongo, opts);
        var observer = new RouterObservationService(repo, clients, events);
        var router = Fresh();
        router.ServerId = ObjectId.GenerateNewId().ToString();
        router.ProtocolId = "wg-test";
        await repo.CreateAsync(router, ct);
        await Task.WhenAll(repo.EnsureProvisionAsync(router, ct), repo.EnsureProvisionAsync(router, ct));
        Check(await db.GetCollection<DomainEvent>("domain_events").CountDocumentsAsync(FilterDefinition<DomainEvent>.Empty, cancellationToken: ct) == 1, "Provision outbox relays exactly one key event");
        var payload = (await events.GetByIdAsync(router.ProvisionEventId, ct))!.PayloadAs<KeyIssuePayload>();
        Check(payload.KeyId == router.KeyId && payload.Source == "router" && payload.ExpiryDays is null && payload.TrafficLimitBytes is null, "Dedicated key has no expiry or quota");
        router = (await repo.GetAsync(router.Id, ct))!;
        await db.GetCollection<DomainEvent>("domain_events").DeleteOneAsync(x => x.Id == router.ProvisionEventId, ct);
        await repo.EnsureProvisionAsync(router, ct);
        Check(await events.GetByIdAsync(router.ProvisionEventId, ct) is null, "Event TTL cleanup cannot reissue router credentials");
        var stale = (await repo.GetAsync(router.Id, ct))!;
        router.Name = "Updated";
        Check(await repo.SaveAsync(router, ct), "Atomic configuration save");
        Check(!await repo.SaveAsync(stale, ct), "Stale write rejected");
        await clients.CreateAsync(new VpnClient { Id = router.KeyId, UserId = router.UserId, ServerId = router.ServerId,
            ProtocolId = router.ProtocolId, ClientPubKey = "peer-public", Source = "router" }, ct);
        Check((await clients.GetByUserIdAsync(router.UserId, ct)).Count == 0 && await clients.FindByUserIdAndServerAsync(router.UserId, router.ServerId, ct) is null, "Router credentials not reused by regular VPN clients");
        Check((await clients.SearchAsync(new KeyQuery(Search: router.KeyId), ct)).Items.Single().Id == router.KeyId, "Router key link survives display-name changes");
        await observer.ObserveAsync(router.ServerId, router.ProtocolId, [new("peer-public", null, null, DateTime.UtcNow, 0, 0)], null, ct);
        var online = (await repo.GetAsync(router.Id, ct))!;
        Check(online.State == RouterStates.Online && online.PendingHistory.Count == 0, "Observation persisted and outbox drained");
        await observer.ObserveAsync(router.ServerId, router.ProtocolId, null, "Old failed sample", ct, online.LastCheckedAt!.Value.AddSeconds(-1));
        Check((await repo.GetAsync(router.Id, ct))!.State == RouterStates.Online, "Late failure cannot overwrite a newer successful sample");
        var history = await repo.HistoryAsync(router.Id, ct);
        Check(history.Count == 1 && history[0].State == RouterStates.Online, "History created once");
        // Simulate crash after insert but before acknowledgement with the original outbox content.
        online.PendingHistory.Add(history[0]);
        await repo.SaveAsync(online, ct);
        await repo.FlushAsync(online, ct);
        Check((await repo.HistoryAsync(router.Id, ct)).Count == 1, "Outbox replay does not duplicate history/delivery");
        await observer.ObserveAsync(router.ServerId, router.ProtocolId, null, "SSH failed", ct);
        Check((await repo.GetAsync(router.Id, ct))!.State == RouterStates.Unknown, "SSH failure never means home disconnected");
        await observer.ObserveAsync(router.ServerId, router.ProtocolId, [], null, ct);
        Check((await repo.GetAsync(router.Id, ct))!.State == RouterStates.Setup, "Missing peer means setup required");
        var key = (await clients.FindByIdAsync(router.KeyId, ct))!;
        key.SetStatus(KeyStatuses.Revoked);
        await clients.UpdateAsync(key, ct);
        await observer.ObserveAsync(router.ServerId, router.ProtocolId, null, "SSH failed", ct);
        Check((await repo.GetAsync(router.Id, ct))!.State == RouterStates.Setup, "Revoked key identified even during SSH failure");
        Check((await repo.ForUserAsync(ObjectId.GenerateNewId().ToString(), ct)).Count == 0, "User-scoped list excludes other recipients");
        var current = (await repo.GetAsync(router.Id, ct))!;
        current.PendingHistory.Add(new RouterTransition { RouterId = router.Id, UserId = router.UserId, At = now.AddMinutes(-2), AvailableAt = now.AddMinutes(-1), State = "test", DeliveryStatus = "pending" });
        await repo.SaveAsync(current, ct);
        await repo.FlushAsync(current, ct);
        var claims = await Task.WhenAll(repo.ClaimDeliveryAsync("bot-a", ct), repo.ClaimDeliveryAsync("bot-b", ct));
        Check(claims.Count(x => x is not null) == 1, "Only one bot can claim a delivery");
        var item = claims.First(x => x is not null)!;
        await repo.CompleteDeliveryAsync(item, "wrong-owner", "sent", null, 0, ct);
        Check((await repo.HistoryAsync(router.Id, ct)).First(h => h.Id == item.Id).DeliveryStatus == "sending", "Delivery completion is fenced by lease owner");
        await repo.CompleteDeliveryAsync(item, item.LeaseOwner!, "pending", "Temporary Telegram failure", 0, ct);
        var retry = await repo.ClaimDeliveryAsync("bot-c", ct);
        Check(retry?.Id == item.Id && retry.Attempts == 2, "Temporary failure survives and retries");
        // Simulated lease expiry models bot death after taking a delivery.
        await db.GetCollection<RouterTransition>("router_history").UpdateOneAsync(h => h.Id == retry!.Id,
            Builders<RouterTransition>.Update.Set(h => h.LeaseUntil, DateTime.UtcNow.AddMinutes(-1)), cancellationToken: ct);
        var reclaimed = await repo.ClaimDeliveryAsync("bot-d", ct);
        Check(reclaimed?.Id == item.Id && reclaimed.Attempts == 3, "Crashed bot delivery is reclaimable");

        var userRepo = new UserRepository(mongo, opts);
        var serverRepo = new VpnServerRepository(mongo, opts);
        var user = new User { Id = ObjectId.GenerateNewId().ToString(), Username = "test-recipient", TelegramId = 12345 };
        await userRepo.CreateAsync(user, ct);
        var node = new VpnServer { Id = ObjectId.GenerateNewId().ToString(), Name = "Test node", Host = "127.0.0.1",
            Protocols = [new ProtocolInstance { Id = "plain-wg", Kind = ProtocolKinds.WireGuard, Port = "51820", ContainerName = "amnezia-wireguard", Wg = new() }] };
        await db.GetCollection<VpnServer>(opts.Value.ServerConfigCollection).InsertOneAsync(node, cancellationToken: ct);
        var audit = new AuditService(new AuditLogRepository(mongo, opts), NullLogger<AuditService>.Instance);
        var controller = new RoutersController(repo, userRepo, serverRepo, clients, new TestConfigReader(), audit)
            { ControllerContext = new ControllerContext { HttpContext = new DefaultHttpContext() } };
        node.DisabledProtocolIds.Add("plain-wg");
        await db.GetCollection<VpnServer>(opts.Value.ServerConfigCollection).ReplaceOneAsync(s => s.Id == node.Id, node, cancellationToken: ct);
        var unavailable = (OkObjectResult)await controller.Options(ct);
        Check(JsonSerializer.SerializeToElement(unavailable.Value).GetProperty("servers").GetArrayLength() == 0, "Disabled protocol absent from router options");
        node.DisabledProtocolIds.Clear();
        await db.GetCollection<VpnServer>(opts.Value.ServerConfigCollection).ReplaceOneAsync(s => s.Id == node.Id, node, cancellationToken: ct);
        var created = (AcceptedResult)await controller.Create(new(" Home API ", user.Id, node.Id, "plain-wg"), ct);
        var createdId = JsonSerializer.SerializeToElement(created.Value).GetProperty("Id").GetString()!;
        var added = (await repo.GetAsync(createdId, ct))!;
        Check(added.Name == "Home API" && added.UserId == user.Id, "API creates named router with registered recipient");
        try { await controller.Create(new("Invalid", "not-an-id", node.Id, "plain-wg"), ct); Check(false, "Invalid recipient rejected"); }
        catch (BadRequestException) { Check(true, "Invalid recipient rejected"); }
        node.Protocols[0].Kind = ProtocolKinds.Awg2;
        await db.GetCollection<VpnServer>(opts.Value.ServerConfigCollection).ReplaceOneAsync(s => s.Id == node.Id, node, cancellationToken: ct);
        try { await controller.Create(new("AWG", user.Id, node.Id, "plain-wg"), ct); Check(false, "AWG cannot be used for stock router profile"); }
        catch (BadRequestException) { Check(true, "AWG cannot be used for stock router profile"); }
        node.Protocols[0].Kind = ProtocolKinds.WireGuard;
        await db.GetCollection<VpnServer>(opts.Value.ServerConfigCollection).ReplaceOneAsync(s => s.Id == node.Id, node, cancellationToken: ct);
        var second = new User { Id = ObjectId.GenerateNewId().ToString(), Username = "second-recipient", TelegramId = 54321 };
        await userRepo.CreateAsync(second, ct);
        var settings = new UpdateRouterRequest(added.Name, second.Id, false, true, 240, added.DeliveryGeneration);
        Check(await controller.Update(added.Id, settings, ct) is NoContentResult, "Admin can rebind recipient");
        Check(await controller.Update(added.Id, settings, ct) is ConflictObjectResult, "Stale settings cannot overwrite another edit");
        Check((await repo.ForUserAsync(user.Id, ct)).Count == 0 && (await repo.ForUserAsync(second.Id, ct)).Count == 1, "Rebinding removes access from previous Telegram user");
        Check(await controller.Test(added.Id, ct) is AcceptedResult, "Test notification is durably queued");
        Check(await controller.Test(added.Id, ct) is ObjectResult { StatusCode: 429 }, "Test notification rate limited");
        await clients.CreateAsync(new VpnClient { Id = added.KeyId, UserId = user.Id, ServerId = node.Id, ProtocolId = "plain-wg", Source = "router" }, ct);
        var configResult = (OkObjectResult)await controller.Config(added.Id, ct);
        var configBody = JsonSerializer.SerializeToElement(configResult.Value).GetProperty("content").GetString()!;
        Check(configBody.Contains("PersistentKeepalive = 25") && controller.Response.Headers.CacheControl == "no-store", "API exports constrained config without browser caching");
        Check(await controller.Archive(added.Id, ct) is NoContentResult, "Monitoring can be archived");
        Check((await clients.FindByIdAsync(added.KeyId, ct))!.IsActive, "Archiving observation never revokes VPN key");
        try { await controller.Get(added.Id, ct); Check(false, "Archived router hidden"); }
        catch (NotFoundException) { Check(true, "Archived router hidden"); }
    }
    finally { await mongo.DropDatabaseAsync(dbName); }
}
Console.WriteLine($"Router monitoring checks passed: {passed}");

sealed class TestConfigReader : IVpnConfigReader
{
    public Task<string> BuildVpnUriAsync(VpnClient client, CancellationToken ct = default) => throw new NotSupportedException();
    public Task<ClientFile> BuildClientFileAsync(VpnClient client, CancellationToken ct = default)
        => Task.FromResult(new ClientFile("test.conf", "text/plain", "[Interface]\nPrivateKey = test\n[Peer]\nPublicKey = test\nAllowedIPs = 0.0.0.0/0\n"));
}
