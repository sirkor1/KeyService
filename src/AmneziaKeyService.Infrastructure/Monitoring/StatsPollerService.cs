using AmneziaKeyService.Core.Interfaces;
using AmneziaKeyService.Core.Models;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using AmneziaKeyService.Infrastructure.Repositories;

namespace AmneziaKeyService.Infrastructure.Monitoring;

/// <summary>
/// Снимает счётчики трафика с узлов и раскладывает их по ключам.
///
/// Одна SSH-сессия на узел за тик: подключение стоит дороже самих команд,
/// а протоколов на узле обычно два-три.
///
/// Xray не опрашивается: в генерируемом upstream server.json нет блока
/// stats/api, и пер-юзерных счётчиков там просто нет. Ключи VLESS остаются
/// с нулевым трафиком — это отсутствие данных, а не отсутствие трафика,
/// и панель рисует их прочерком.
/// </summary>
public class StatsPollerService : PeriodicWorker
{
    private readonly TimeSpan _statsInterval;
    private DateTime _nextStatsAt;
    private bool _collectUsage;
    public StatsPollerService(
        IServiceScopeFactory scopeFactory,
        IOptions<PollingOptions> options,
        ILogger<StatsPollerService> logger)
        : base(scopeFactory,
               options.Value.For(TimeSpan.FromSeconds(Math.Min(30, options.Value.StatsIntervalSeconds))),
               logger)
    {
        _statsInterval = TimeSpan.FromSeconds(Math.Max(1, options.Value.StatsIntervalSeconds));
    }

    protected override string Name => "stats";

    protected override async Task TickAsync(IServiceProvider services, CancellationToken ct)
    {
        await services.GetRequiredService<RouterObservationService>().PrepareAsync(ct);
        var servers = await services.GetRequiredService<IVpnServerRepository>().GetAllAsync(ct);
        var routers = await services.GetRequiredService<RouterMonitorRepository>().ListAsync(ct);
        _collectUsage = DateTime.UtcNow >= _nextStatsAt;
        if (_collectUsage) _nextStatsAt = DateTime.UtcNow + _statsInterval;

        var pollable = servers
            .Where(s => (_collectUsage && s.Status == ServerStatuses.Ok && s.Protocols.Any(IsPollable)) || routers.Any(r => r.ServerId == s.Id && !r.Paused))
            .ToList();

        foreach (var missing in routers.Where(r => servers.All(s => s.Id != r.ServerId)).Select(r => r.ServerId).Distinct())
            await services.GetRequiredService<RouterObservationService>().ObserveAsync(missing, null, null, "VPN-узел удалён", ct);

        if (pollable.Count == 0) return;

        await ForEachServerAsync(pollable, async (scope, server, token) =>
        {
            var sampledAt = DateTime.UtcNow;
            try { await PollAsync(scope, server, token); }
            catch (Exception) when (!token.IsCancellationRequested)
            {
                await scope.GetRequiredService<RouterObservationService>().ObserveAsync(server.Id, null, null, "VPN-узел недоступен для опроса", token, sampledAt);
                throw;
            }
        }, ct);
    }

    /// <summary>Протокол, с которого вообще можно снять счётчики.</summary>
    private static bool IsPollable(ProtocolInstance p)
        => p.State == ProtocolStates.Installed
           && ProtocolKinds.IsWireGuardFamily(p.Kind)
           && p.Wg is not null;

    private async Task PollAsync(
        IServiceProvider services, VpnServer server, CancellationToken ct)
    {
        var clients = services.GetRequiredService<IVpnClientRepository>();
        var usage   = services.GetRequiredService<IUsageRepository>();

        var live = await clients.GetLiveByServerAsync(server.Id, ct);

        // Ключ без публичного ключа — это xray или недовыданный WireGuard;
        // сопоставить его с peer-ом нечем.
        var byPubKey = live
            .Where(c => !string.IsNullOrEmpty(c.ClientPubKey))
            .GroupBy(c => c.ClientPubKey!)
            .ToDictionary(g => g.Key, g => g.First());

        var monitored = (await services.GetRequiredService<RouterMonitorRepository>().ListAsync(ct)).Where(r => r.ServerId == server.Id).ToList();
        if (byPubKey.Count == 0 && monitored.Count == 0) return;
        var observer = services.GetRequiredService<RouterObservationService>();
        foreach (var protocolId in monitored.Where(r => !server.Protocols.Any(p => p.Id == r.ProtocolId && IsPollable(p))).Select(r => r.ProtocolId).Distinct())
            await observer.ObserveAsync(server.Id, protocolId, [], "Протокол отсутствует или не установлен", ct);

        var updates = new List<KeyUsageUpdate>();
        var deltas  = new List<UsageDelta>();
        var now     = DateTime.UtcNow;

        long serverRx = 0, serverTx = 0;

        await using var ssh = await services
            .GetRequiredService<ISshSessionFactory>()
            .ConnectAsync(server, ct);

        foreach (var protocol in server.Protocols.Where(IsPollable).Where(p => _collectUsage || monitored.Any(r => r.ProtocolId == p.Id && !r.Paused)))
        {
            var sampledAt = DateTime.UtcNow;
            var peers = await ReadPeersAsync(ssh, server, protocol, ct);
            await observer.ObserveAsync(server.Id, protocol.Id, peers, peers is null ? "Не удалось прочитать WireGuard" : null, ct, sampledAt);
            if (peers is null || !_collectUsage) continue;

            foreach (var peer in peers)
            {
                if (!byPubKey.TryGetValue(peer.PublicKey, out var client)) continue;

                var rxDelta = UsageMath.Delta(peer.RxBytes, client.Usage.RxRaw);
                var txDelta = UsageMath.Delta(peer.TxBytes, client.Usage.TxRaw);

                updates.Add(new KeyUsageUpdate(
                    KeyId:           client.Id,
                    RxDelta:         rxDelta,
                    TxDelta:         txDelta,
                    RxRaw:           peer.RxBytes,
                    TxRaw:           peer.TxBytes,
                    LastHandshakeAt: peer.LatestHandshake,
                    LastSeenAt:      now));

                if (rxDelta == 0 && txDelta == 0) continue;

                deltas.Add(new UsageDelta(client.Id, server.Id, rxDelta, txDelta));
                serverRx += rxDelta;
                serverTx += txDelta;
            }
        }

        if (updates.Count == 0) return;

        var day = DateOnly.FromDateTime(now);

        await clients.ApplyUsageAsync(updates, ct);
        await usage.IncrementKeysAsync(deltas, day, ct);
        await usage.IncrementServerAsync(server.Id, day, serverRx, serverTx, ct);

        Logger.LogDebug(
            "Узел {ServerName}: снято {PeerCount} peer-ов, приращение {RxBytes}/{TxBytes} байт.",
            server.Name, updates.Count, serverRx, serverTx);
    }

    private async Task<List<WgPeer>?> ReadPeersAsync(
        ISshSession ssh, VpnServer server, ProtocolInstance protocol, CancellationToken ct)
    {
        var wg = protocol.Wg!;

        // RunAsync, а не RunCheckedAsync: недоступный контейнер — рядовое
        // событие фонового опроса, а не повод бросать исключение наверх.
        var result = await ssh.RunAsync(
            $"docker exec -i {protocol.ContainerName} {wg.Binary} show {wg.InterfaceName} dump", ct);

        if (!result.Ok)
        {
            Logger.LogWarning(
                "Узел {ServerName}: не удалось прочитать счётчики протокола {ProtocolKind} " +
                "(контейнер {ContainerName}, код {ExitStatus}).",
                server.Name, protocol.Kind, protocol.ContainerName, result.ExitStatus);

            return null;
        }

        // Empty/malformed output is a failed observation, not an empty peer list.
        var firstLine = result.StdOut.Split('\n')[0].TrimEnd('\r').Split('\t');
        return firstLine.Length == 4 ? WgDumpParser.Parse(result.StdOut) : null;
    }
}
