using AmneziaKeyService.Core.Interfaces;
using AmneziaKeyService.Core.Models;
using AmneziaKeyService.Infrastructure.Services;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace AmneziaKeyService.Infrastructure.Monitoring;

/// <summary>
/// Сверяет peer-ов на узлах с выданными ключами.
///
/// Ничего не удаляет — только считает и сообщает. На боевых узлах дрейф почти
/// наверняка есть: до появления отзыва в фазе 3 peer-ы заводились руками,
/// и автоматическое удаление «лишнего» отключило бы живых пользователей.
/// Решение по каждому сироте принимает оператор.
/// </summary>
public class ReconcileService : PeriodicWorker
{
    public ReconcileService(
        IServiceScopeFactory scopeFactory,
        IOptions<PollingOptions> options,
        ILogger<ReconcileService> logger)
        : base(scopeFactory,
               options.Value.For(TimeSpan.FromHours(options.Value.ReconcileIntervalHours)),
               logger)
    {
    }

    protected override string Name => "reconcile";

    protected override async Task TickAsync(IServiceProvider services, CancellationToken ct)
    {
        var servers = await services.GetRequiredService<IVpnServerRepository>().GetAllAsync(ct);

        var checkable = servers
            .Where(s => s.Status == ServerStatuses.Ok)
            .Where(s => s.Protocols.Any(IsReconcilable))
            .ToList();

        if (checkable.Count == 0) return;

        await ForEachServerAsync(checkable, ReconcileAsync, ct);
    }

    /// <summary>Протокол, у которого список peer-ов вообще можно получить.</summary>
    private static bool IsReconcilable(ProtocolInstance p)
        => p.Enabled
           && p.State == ProtocolStates.Installed
           && ProtocolKinds.IsWireGuardFamily(p.Kind)
           && p.Wg is not null;

    private async Task ReconcileAsync(
        IServiceProvider services, VpnServer server, CancellationToken ct)
    {
        var clients = services.GetRequiredService<IVpnClientRepository>();

        var live = await clients.GetLiveByServerAsync(server.Id, ct);

        var known = live
            .Select(c => c.ClientPubKey)
            .OfType<string>()
            .ToHashSet(StringComparer.Ordinal);

        var orphans = new List<string>();

        await using var ssh = await services
            .GetRequiredService<ISshSessionFactory>()
            .ConnectAsync(server, ct);

        foreach (var protocol in server.Protocols.Where(IsReconcilable))
        {
            var wg = protocol.Wg!;

            var result = await ssh.RunAsync(
                $"docker exec -i {protocol.ContainerName} {wg.Binary} show {wg.InterfaceName} dump", ct);

            if (!result.Ok)
            {
                // Недочитанный протокол пропускаем: посчитать по нему ноль
                // сирот означало бы соврать в меньшую сторону.
                Logger.LogWarning(
                    "Узел {ServerName}: сверка протокола {ProtocolKind} не удалась (код {ExitStatus}).",
                    server.Name, protocol.Kind, result.ExitStatus);

                continue;
            }

            orphans.AddRange(WgDumpParser.Parse(result.StdOut)
                .Where(peer => !known.Contains(peer.PublicKey))
                .Select(peer => peer.PublicKey));
        }

        await SaveAsync(services, server, orphans, ct);
    }

    private async Task SaveAsync(
        IServiceProvider services, VpnServer server, List<string> orphans, CancellationToken ct)
    {
        var previous = server.OrphanPeerCount;

        server.OrphanPeerCount = orphans.Count;
        server.ReconciledAt    = DateTime.UtcNow;

        await services.GetRequiredService<IVpnServerRepository>().UpdateAsync(server, ct);

        if (orphans.Count == 0)
        {
            if (previous > 0)
                Logger.LogInformation(
                    "Узел {ServerName}: расхождений больше нет, было {PreviousCount}.",
                    server.Name, previous);

            return;
        }

        Logger.LogWarning(
            "Узел {ServerName} ({ServerId}): peer-ов без ключа — {OrphanCount}.",
            server.Name, server.Id, orphans.Count);

        // В журнал идёт только счёт. Публичные ключи peer-ов — это данные
        // конкретных клиентов, а журнал выгружается из панели целиком.
        await services.GetRequiredService<IAuditService>().WriteAsync(
            AuditEvents.PeersReconciled,
            $"На узле «{server.Name}» найдено peer-ов без выданного ключа: {orphans.Count}",
            targetType: AuditTargets.Server, targetId: server.Id, targetName: server.Name,
            level: AuditLevels.Warn, ct: ct);
    }
}
