using AmneziaKeyService.Core.Interfaces;
using AmneziaKeyService.Core.Models;
using AmneziaKeyService.Infrastructure.Events;
using AmneziaKeyService.Infrastructure.Services;
using Microsoft.Extensions.Logging;
using MongoDB.Bson;

namespace AmneziaKeyService.Infrastructure.Keys;

/// <summary>
/// Исполняет отзыв ключа по событию.
///
/// Сам ничего не решает — вызывает тот же <see cref="IVpnConfigService"/>,
/// которым сегодня пользуется <c>KeysController</c>.
/// </summary>
public class KeyRevokeHandler : IDomainEventHandler
{
    private readonly IVpnConfigService _vpnConfig;
    private readonly IVpnClientRepository _clients;
    private readonly IVpnServerRepository _servers;
    private readonly IUserRepository _users;
    private readonly IAuditService _audit;
    private readonly ILogger<KeyRevokeHandler> _logger;

    public KeyRevokeHandler(
        IVpnConfigService vpnConfig,
        IVpnClientRepository clients,
        IVpnServerRepository servers,
        IUserRepository users,
        IAuditService audit,
        ILogger<KeyRevokeHandler> logger)
    {
        _vpnConfig = vpnConfig;
        _clients   = clients;
        _servers   = servers;
        _users     = users;
        _audit     = audit;
        _logger    = logger;
    }

    public string EventType => DomainEventTypes.KeyRevoke;

    /// <summary>
    /// Отзыв идемпотентен по построению: <see cref="IVpnConfigService.RevokeAsync"/>
    /// выходит рано, если ключ уже в статусе revoked, поэтому повтор безопасен —
    /// в отличие от выдачи, второй заход не заведёт второй peer.
    /// </summary>
    public DomainEventPolicy Policy => DomainEventPolicy.Retrying(5, TimeSpan.FromSeconds(30));

    public async Task<BsonDocument?> HandleAsync(DomainEvent evt, CancellationToken ct)
    {
        var payload = evt.PayloadAs<KeyRevokePayload>();

        var client = await _vpnConfig.RevokeAsync(
            payload.KeyId, payload.Reason, payload.RevokedByUserId, ct);

        var server = await _servers.GetByIdAsync(client.ServerId, ct);
        var actor  = await ResolveActorAsync(evt.ActorUserId, ct);

        // pendingRevoke — узел был недоступен, RevokeAsync это не бросает,
        // а помечает ключ; добивает его EnforcementService.RetryPendingAsync
        // раз в минуту. Это успех события, а не провал: заводить здесь второй
        // механизм повтора поверх уже существующего незачем.
        var stuck = client.Status == KeyStatuses.PendingRevoke;

        await _audit.WriteAsync(AuditEvents.KeyRevoked,
            stuck
                ? $"Ключ {client.ShortId} помечен к отзыву, но узел «{server?.Name}» недоступен — peer ещё активен"
                : $"Отозван ключ {client.ShortId} на узле «{server?.Name}»",
            actor, AuditTargets.Key, client.Id, client.ShortId,
            stuck ? AuditLevels.Warn : AuditLevels.Info,
            payload.Comment is { } comment ? new Dictionary<string, string> { ["comment"] = comment } : null,
            ct);

        return new BsonDocument
        {
            ["keyId"]   = client.Id,
            ["shortId"] = client.ShortId ?? string.Empty,
            ["status"]  = client.Status,
        };
    }

    /// <summary>
    /// Провал означает, что ключ остался активным — оператор должен увидеть
    /// это в панели, а не искать причину в логах контейнера воркера.
    /// </summary>
    public async Task OnFailedAsync(DomainEvent evt, string error, CancellationToken ct)
    {
        var payload = evt.PayloadAs<KeyRevokePayload>();

        _logger.LogError("Отзыв ключа {KeyId} провален: {Error}", payload.KeyId, error);

        var client = await _clients.FindByIdAsync(payload.KeyId, ct);
        var server = client is null ? null : await _servers.GetByIdAsync(client.ServerId, ct);
        var actor  = await ResolveActorAsync(evt.ActorUserId, ct);

        await _audit.WriteAsync(AuditEvents.KeyRevokeFailed,
            $"Не удалось отозвать ключ {client?.ShortId ?? payload.KeyId} на узле «{server?.Name}»: " +
            "ключ остался активным.",
            actor, AuditTargets.Key, payload.KeyId, client?.ShortId, AuditLevels.Error, ct: ct);
    }

    /// <summary>
    /// Имя автора для журнала. В JWT-claim попадает логин (unique_name),
    /// а не DisplayName — тем же полем, что и в остальном журнале, иначе
    /// в истории появилась бы неоднородная колонка «Кто». При неудаче
    /// поиска (пользователь удалён, id пуст) имя остаётся null.
    /// </summary>
    private async Task<AuditActor> ResolveActorAsync(string? actorUserId, CancellationToken ct)
    {
        if (actorUserId is null) return new AuditActor(null, null);

        var user = await _users.FindByIdAsync(actorUserId, ct);
        return new AuditActor(actorUserId, user?.Username);
    }
}
