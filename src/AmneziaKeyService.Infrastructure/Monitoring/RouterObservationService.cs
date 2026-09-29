using AmneziaKeyService.Core.Interfaces;
using AmneziaKeyService.Core.Models;
using AmneziaKeyService.Infrastructure.Repositories;

namespace AmneziaKeyService.Infrastructure.Monitoring;

public sealed class RouterObservationService(
    RouterMonitorRepository routers, IVpnClientRepository clients, IDomainEventRepository events)
{
    public async Task PrepareAsync(CancellationToken ct)
    {
        foreach (var router in await routers.ListAsync(ct, includeArchived: true))
        {
            await routers.FlushAsync(router, ct);
            await routers.EnsureProvisionAsync(router, ct);
        }
    }

    public async Task ObserveAsync(string serverId, string? protocolId, List<WgPeer>? peers,
        string? error, CancellationToken ct, DateTime? sampledAt = null)
    {
        foreach (var snapshot in (await routers.ListAsync(ct)).Where(r => r.ServerId == serverId
                     && (protocolId is null || r.ProtocolId == protocolId)))
        {
            // Reload after an outbox flush or another process's settings update.
            var router = await routers.GetAsync(snapshot.Id, ct);
            if (router is null || router.Archived) continue;
            var key = await clients.FindByIdAsync(router.KeyId, ct);
            var now = sampledAt ?? DateTime.UtcNow;
            if (router.LastCheckedAt > now) continue;
            string state;
            string? detail = error;
            DateTime? handshake = null;
            if (key is null)
            {
                var evt = await events.GetByIdAsync(router.ProvisionEventId, ct);
                state = (evt?.Status is DomainEventStatuses.Failed or DomainEventStatuses.Canceled or DomainEventStatuses.Succeeded)
                    || (router.ProvisionDispatched && evt is null)
                    ? RouterStates.Setup : RouterStates.Waiting;
                detail = state == RouterStates.Setup ? "Не удалось создать ключ. Проверьте журнал выдачи." : "Готовится ключ подключения";
            }
            else if (!key.IsActive || key.Status != KeyStatuses.Active)
            {
                state = RouterStates.Setup;
                detail = "Ключ отозван или ожидает отзыва";
            }
            else if (peers is null)
            {
                state = RouterStates.Unknown;
            }
            else
            {
                var peer = peers.Find(p => p.PublicKey == key.ClientPubKey);
                if (peer is null)
                {
                    state = RouterStates.Setup;
                    detail = "Peer отсутствует в конфигурации VPN";
                }
                else
                {
                    handshake = peer.LatestHandshake;
                    state = RouterMonitorRules.ConnectionState(router, handshake, now);
                    detail = state == RouterStates.Unknown ? "Проверьте часы на VPN-узле" : null;
                }
            }
            RouterMonitorRules.Observe(router, state, handshake, detail, now);
            if (await routers.SaveAsync(router, ct)) await routers.FlushAsync(router, ct);
        }
    }
}
