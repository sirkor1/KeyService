using AmneziaKeyService.Core.Interfaces;
using AmneziaKeyService.Core.Models;
using AmneziaKeyService.Infrastructure.Events;
using AmneziaKeyService.Infrastructure.Services;
using Microsoft.Extensions.Logging;
using MongoDB.Bson;

namespace AmneziaKeyService.Infrastructure.Keys;

/// <summary>
/// Исполняет выдачу ключа по событию.
///
/// Сам ничего не решает — вызывает тот же <see cref="IVpnConfigService"/>,
/// которым сегодня пользуется <c>KeysController</c>. Изменилась только
/// доставка запроса: панель публикует событие вместо синхронного вызова.
/// </summary>
public class KeyIssueHandler : IDomainEventHandler
{
    private readonly IVpnConfigService _vpnConfig;
    private readonly IVpnClientRepository _clients;
    private readonly IVpnServerRepository _servers;
    private readonly IUserRepository _users;
    private readonly IAuditService _audit;
    private readonly IDomainEventPublisher _events;
    private readonly ILogger<KeyIssueHandler> _logger;

    public KeyIssueHandler(
        IVpnConfigService vpnConfig,
        IVpnClientRepository clients,
        IVpnServerRepository servers,
        IUserRepository users,
        IAuditService audit,
        IDomainEventPublisher events,
        ILogger<KeyIssueHandler> logger)
    {
        _vpnConfig = vpnConfig;
        _clients   = clients;
        _servers   = servers;
        _users     = users;
        _audit     = audit;
        _events    = events;
        _logger    = logger;
    }

    public string EventType => DomainEventTypes.KeyIssue;

    /// <summary>
    /// Повторов нет. К моменту сбоя peer мог уже быть заведён на узле —
    /// повтор завёл бы второй; откат уже заведённого peer-а при неудачной
    /// записи документа делает сам <see cref="IVpnConfigService.IssueAsync"/>.
    /// </summary>
    public DomainEventPolicy Policy => DomainEventPolicy.Once;

    public async Task<BsonDocument?> HandleAsync(DomainEvent evt, CancellationToken ct)
    {
        var payload = evt.PayloadAs<KeyIssuePayload>();

        var client = await _vpnConfig.IssueAsync(payload.OwnerUserId, payload.ServerId, new IssueKeyOptions
        {
            KeyId             = payload.KeyId,
            ProtocolId        = payload.ProtocolId,
            OwnerName         = payload.OwnerName,
            DeviceName        = payload.DeviceName,
            Label             = payload.Label,
            ExpiryDays        = payload.ExpiryDays,
            TrafficLimitBytes = payload.TrafficLimitBytes,
            CreatedByUserId   = payload.CreatedByUserId,
            Source            = payload.Source,
        }, ct);

        var server = await _servers.GetByIdAsync(payload.ServerId, ct);
        var actor  = await ResolveActorAsync(evt.ActorUserId, ct);

        await _audit.WriteAsync(AuditEvents.KeyIssued,
            $"Выдан ключ {client.ShortId} на узле «{server?.Name}» для {client.OwnerName}",
            actor, AuditTargets.Key, client.Id, client.ShortId, ct: ct);

        if (payload.Notify is { } notify)
        {
            // partitionKey — null: уведомление не трогает узел, и аренду
            // партиции брать не за что. С ключом узла доставка встала бы
            // в очередь за операциями над этим узлом без всякой причины.
            await _events.PublishAsync(
                DomainEventTypes.NotifyKeyIssued,
                new NotifyKeyIssuedPayload(client.Id, server?.Name, null, notify),
                partitionKey: null,
                correlationId: client.Id,
                actorUserId: evt.ActorUserId,
                ct);
        }

        return new BsonDocument
        {
            ["keyId"]      = client.Id,
            ["shortId"]    = client.ShortId ?? string.Empty,
            ["assignedIp"] = client.AssignedIp ?? string.Empty,
        };
    }

    /// <summary>
    /// Прибирает за неудавшейся выдачей. Может быть вызван дважды (диспетчер
    /// и жнец) — уборка идемпотентна.
    /// </summary>
    public async Task OnFailedAsync(DomainEvent evt, string error, CancellationToken ct)
    {
        var payload = evt.PayloadAs<KeyIssuePayload>();

        _logger.LogWarning("Выдача ключа {KeyId} провалена: {Error}", payload.KeyId, error);

        // Идентификатор назначен заранее заявкой ровно ради этой проверки:
        // документ с этим _id уже существует — значит выдача состоялась,
        // а провалилось только закрытие события (например, процесс умер
        // между записью ключа и завершением события). Убирать владельца
        // живого ключа было бы ошибкой.
        if (await _clients.FindByIdAsync(payload.KeyId, ct) is not null) return;

        if (payload.OwnerCreated) await _users.DeleteAsync(payload.OwnerUserId, ct);

        var server = await _servers.GetByIdAsync(payload.ServerId, ct);
        var actor  = await ResolveActorAsync(evt.ActorUserId, ct);

        await _audit.WriteAsync(AuditEvents.KeyIssueFailed,
            $"Не удалось выдать ключ на узле «{server?.Name}»: операция прервана, повторите выдачу.",
            actor, AuditTargets.Server, server?.Id, server?.Name, AuditLevels.Error, ct: ct);

        if (payload.Notify is { } notify)
        {
            await _events.PublishAsync(
                DomainEventTypes.NotifyKeyIssued,
                new NotifyKeyIssuedPayload(null, server?.Name, "Не удалось выдать ключ.", notify),
                partitionKey: null,
                correlationId: payload.KeyId,
                actorUserId: evt.ActorUserId,
                ct);
        }
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
