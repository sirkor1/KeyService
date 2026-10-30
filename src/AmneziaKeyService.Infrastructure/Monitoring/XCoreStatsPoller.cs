using AmneziaKeyService.Core.Interfaces;
using AmneziaKeyService.Core.Models;
using AmneziaKeyService.Infrastructure.Protocols.XCore;
using AmneziaKeyService.Infrastructure.Subscriptions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace AmneziaKeyService.Infrastructure.Monitoring;

/// <summary>
/// Снимает счётчики трафика подписчиков с узлов xcore и накапливает их приращениями.
///
/// Счётчики читаются без <c>-reset</c>. Сброс при каждом чтении хранил бы приращение на узле,
/// и сбой записи в базу потерял бы его; чтение без сброса теряет самое большее то, что нельзя
/// узнать вовсе. Обнуление при перезапуске контейнера переживает <see cref="UsageMath.Delta"/>
/// — тем же путём, что и счётчики WireGuard.
/// </summary>
public class XCoreStatsPoller : PeriodicWorker
{
    public XCoreStatsPoller(
        IServiceScopeFactory scopeFactory,
        IOptions<PollingOptions> options,
        ILogger<XCoreStatsPoller> logger)
        : base(scopeFactory,
               options.Value.For(TimeSpan.FromSeconds(Math.Max(1, options.Value.StatsIntervalSeconds))),
               logger)
    {
    }

    protected override string Name => "xcore-stats";

    protected override async Task TickAsync(IServiceProvider services, CancellationToken ct)
    {
        var servers = await services.GetRequiredService<IVpnServerRepository>().GetAllAsync(ct);

        // Как и опрос WireGuard, ходим только на узлы в статусе ok: на недоступный
        // узел SSH-подключение ждало бы таймаута на каждом тике. Узлы берём шире подписочных:
        // через исключённый из подписки узел ещё ходят по сохранённым ссылкам — см. SyncTargets.
        var pollable = XCoreSyncPublisher.SyncTargets(servers)
            .Where(n => n.Server.Status == ServerStatuses.Ok)
            .Select(n => n.Server)
            .DistinctBy(s => s.Id)
            .ToList();

        if (pollable.Count == 0) return;

        await ForEachServerAsync(pollable, PollAsync, ct);
    }

    /// <summary>
    /// Один узел за тик. Публичный, чтобы tools/VerifyXCore прогонял его на заглушке узла, а не
    /// через расписание воркера.
    /// </summary>
    public async Task PollAsync(IServiceProvider services, VpnServer server, CancellationToken ct)
    {
        var subscriptions = services.GetRequiredService<ISubscriptionRepository>();
        var usage = services.GetRequiredService<IUsageRepository>();

        var node = server.Protocols.First(server.IsSubscriptionNode).XCore!;

        await using var ssh = await services.GetRequiredService<ISshSessionFactory>().ConnectAsync(server, ct);

        // Недоступный узел — рядовое событие опроса: пропускаем тик и не трогаем сырые
        // значения. Иначе следующее чтение приняли бы за рестарт и посчитали весь счётчик заново.
        var result = await ssh.RunAsync(XCoreNode.UserStatsCommand(node.ApiPort), ct);
        if (!result.Ok)
        {
            Logger.LogWarning("Узел xcore {ServerName}: счётчики не прочитаны, код {ExitStatus}.",
                server.Name, result.ExitStatus);
            return;
        }

        IReadOnlyDictionary<string, XrayUserTraffic> traffic;
        try
        {
            traffic = XrayApiOutput.ParseUserTraffic(result.StdOut);
        }
        catch (XrayOutputException ex)
        {
            Logger.LogWarning("Узел xcore {ServerName}: ответ statsquery не разобран: {Reason}.",
                server.Name, ex.Message);
            return;
        }

        var byId = traffic.ToDictionary(t => t.Key, t => Subscription.IdFromXrayEmail(t.Key));
        var known = (await subscriptions.FindByIdsAsync(byId.Values.OfType<string>(), ct)).ToDictionary(s => s.Id);

        var now = DateTime.UtcNow;
        var updates = new List<SubscriptionUsageUpdate>();
        long serverRx = 0, serverTx = 0;

        // Подписки без счётчика на узле (ещё не добавлены или пропали) здесь не видны, и это
        // правильно: нечего ни прибавлять, ни обнулять.
        foreach (var (email, counters) in traffic)
        {
            if (byId[email] is not { } id || !known.TryGetValue(id, out var subscription)) continue;

            // Xray считает с точки зрения клиента: uplink — отправленное им, downlink — полученное.
            // В подписке rx — полученное клиентом.
            long rxRaw = counters.Downlink, txRaw = counters.Uplink;
            subscription.RawByNode.TryGetValue(server.Id, out var previous);

            var rxDelta = UsageMath.Delta(rxRaw, previous?.Rx ?? 0);
            var txDelta = UsageMath.Delta(txRaw, previous?.Tx ?? 0);

            if (previous is not null && previous.Rx == rxRaw && previous.Tx == txRaw) continue;

            updates.Add(new SubscriptionUsageUpdate(id, server.Id, rxDelta, txDelta, rxRaw, txRaw, now));
            serverRx += rxDelta;
            serverTx += txDelta;
        }

        if (updates.Count == 0) return;

        var day = DateOnly.FromDateTime(now);

        await subscriptions.ApplyUsageAsync(updates, ct);
        foreach (var update in updates)
            await usage.IncrementSubscriptionAsync(update.SubscriptionId, day, update.RxDelta, update.TxDelta, ct);
        await usage.IncrementServerAsync(server.Id, day, serverRx, serverTx, ct);

        Logger.LogDebug(
            "Узел xcore {ServerName}: снято {Count} подписчиков, приращение {RxBytes}/{TxBytes} байт.",
            server.Name, updates.Count, serverRx, serverTx);
    }
}
