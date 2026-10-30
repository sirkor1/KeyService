using System.Text.RegularExpressions;
using AmneziaKeyService.Core.Exceptions;
using AmneziaKeyService.Core.Interfaces;
using AmneziaKeyService.Core.Models;
using AmneziaKeyService.Infrastructure.Events;
using AmneziaKeyService.Infrastructure.Protocols.XCore;
using AmneziaKeyService.Infrastructure.Services;
using Microsoft.Extensions.Logging;
using MongoDB.Bson;

namespace AmneziaKeyService.Infrastructure.Subscriptions;

/// <summary>
/// Приводит узел xcore к списку подписчиков из базы. Само событие списка не несёт: список
/// читается в момент работы, поэтому одно событие закрывает все правки, сделанные до него —
/// на этом держится <see cref="IDomainEventPublisher.PublishIfNoPendingAsync"/>.
/// </summary>
public partial class XCoreSyncHandler : IDomainEventHandler
{
    private const int MaxErrorLength = 300;

    private readonly IVpnServerRepository _servers;
    private readonly ISubscriptionRepository _subscriptions;
    private readonly ISshSessionFactory _sshFactory;
    private readonly XCoreSyncService _sync;
    private readonly ISecretProtector _secrets;
    private readonly XCoreSyncPublisher _publisher;
    private readonly ILogger<XCoreSyncHandler> _logger;

    public XCoreSyncHandler(
        IVpnServerRepository servers,
        ISubscriptionRepository subscriptions,
        ISshSessionFactory sshFactory,
        XCoreSyncService sync,
        ISecretProtector secrets,
        XCoreSyncPublisher publisher,
        ILogger<XCoreSyncHandler> logger)
    {
        _servers       = servers;
        _subscriptions = subscriptions;
        _sshFactory    = sshFactory;
        _sync          = sync;
        _secrets       = secrets;
        _publisher     = publisher;
        _logger        = logger;
    }

    public string EventType => DomainEventTypes.XCoreSync;

    /// <summary>
    /// Идемпотентна по построению: синхронизация сводит узел к желаемому состоянию, а не
    /// применяет разницу, поэтому повтор безопасен. Не вернуть оборванную в очередь значило бы
    /// оставить отозванную подписку работающей на узле до следующей сверки.
    /// </summary>
    public DomainEventPolicy Policy => DomainEventPolicy.Retrying(5, TimeSpan.FromSeconds(30));

    [GeneratedRegex(@"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")]
    private static partial Regex Uuid();

    public async Task<BsonDocument?> HandleAsync(DomainEvent evt, CancellationToken ct)
    {
        var payload = evt.PayloadAs<XCoreSyncPayload>();

        var server = await _servers.GetByIdAsync(payload.ServerId, ct);
        var protocol = server?.FindProtocol(payload.ProtocolId);

        // Узел удалили, протокол убрали или он ещё не установлен (установка завершится событием
        // сама): делать нечего, и повтор ничего бы не изменил — это успех, а не провал.
        if (server is null || protocol is not { Kind: ProtocolKinds.XCore, XCore.Role: XCoreRoles.Exit or XCoreRoles.Entry }
            || protocol.State != ProtocolStates.Installed)
            return new BsonDocument { ["serverId"] = payload.ServerId, ["skipped"] = "not_applicable" };

        await EnsureRouteIdAsync(server, protocol, ct);

        var desired = await ReadDesiredAsync(protocol, ct);
        await using var ssh = await _sshFactory.ConnectAsync(server, ct);

        XCoreSyncResult result;
        try
        {
            result = await _sync.SyncAsync(ssh, server, protocol, desired.Users, ct, exits: desired.Exits);
        }
        catch (XCoreSyncException ex) when (ex.ApiUnavailable)
        {
            // API не ответил — контейнер завис или упал. Файл конфига к этому моменту уже
            // верный, поэтому перезапуск поднимает процесс ровно с ним. Одна попытка в этой
            // же обработке: дальше повторяет политика события. Список читаем заново — первая
            // попытка могла занять минуту.
            _logger.LogWarning(
                "Узел xcore {ServerName}: API Xray не ответил ({Reason}), повторяю с перезапуском.",
                server.Name, ex.Message);
            desired = await ReadDesiredAsync(protocol, ct);
            result = await _sync.SyncAsync(
                ssh, server, protocol, desired.Users, ct, forceRestart: true, exits: desired.Exits);
        }

        await _servers.MarkXCoreAppliedAsync(
            server.Id, protocol.Id, result.Revision, result.StructureRevision, DateTime.UtcNow, ct);

        _logger.LogInformation(
            "Узел xcore {ServerName}: {Action}, добавлено {Added}, удалено {Removed}.",
            server.Name, result.Action, result.Added, result.Removed);

        // Caddy — после Xray и отдельной записью: отозванный подписчик не должен ждать, пока выпустится
        // сертификат домена подписки, а сбой Caddy не должен отменять уже применённых пользователей.
        // Исключение уходит вызывающему: политика события повторит, а после последней неудачи
        // OnFailedAsync покажет причину в SyncError.
        XCoreCaddyResult caddy;
        try
        {
            caddy = await _sync.SyncCaddyAsync(ssh, protocol, ct);
        }
        catch (XCoreSyncException ex) when (ex.CaddyFailedRevision is { } failedRevision)
        {
            // Запоминаем неудачу до повторного броска: повтор события придёт уже на паузу, а не на
            // очередной перезапуск Caddy и очередной запрос сертификата.
            await _servers.SetXCoreCaddyFailedAsync(server.Id, protocol.Id, failedRevision, DateTime.UtcNow, ct);
            throw;
        }

        if (caddy.Action == XCoreCaddyAction.Restart)
        {
            await _servers.MarkXCoreCaddyAppliedAsync(server.Id, protocol.Id, caddy.Revision, ct);
            _logger.LogInformation("Узел xcore {ServerName}: Caddyfile обновлён, Caddy перезапущен.", server.Name);
        }
        else if (caddy.Action == XCoreCaddyAction.Paused)
        {
            // Событие на этом завершается успешно: повторять его до конца паузы бессмысленно. Причину оператор
            // видит в SyncError — Xray-часть уже применена и очистила прежнюю ошибку выше.
            await _servers.SetXCoreSyncErrorAsync(
                server.Id, protocol.Id, XCoreSyncService.CaddyPausedMessage(caddy.RetryAt!.Value), ct);
            _logger.LogWarning(
                "Узел xcore {ServerName}: выпуск сертификата домена подписки на паузе до {RetryAt:HH:mm} UTC.",
                server.Name, caddy.RetryAt);
        }

        return new BsonDocument
        {
            ["serverId"] = server.Id,
            ["action"]   = result.Action.ToString(),
            ["added"]    = result.Added,
            ["removed"]  = result.Removed,
            ["caddy"]    = caddy.Action.ToString(),
        };
    }

    /// <summary>
    /// Оператор должен увидеть, что отзыв или выдача не дошли до узла, а не искать причину в
    /// логах worker. Текст проходит через фильтр секретов и дополнительно лишается любых UUID.
    /// </summary>
    public async Task OnFailedAsync(DomainEvent evt, string error, CancellationToken ct)
    {
        var payload = evt.PayloadAs<XCoreSyncPayload>();
        await _servers.SetXCoreSyncErrorAsync(payload.ServerId, payload.ProtocolId, SafeError(error), ct);
    }

    public static string SafeError(string? error, string fallback = "Синхронизация подписчиков не удалась.")
    {
        var clean = Uuid().Replace(SecretRedactor.Tail(error, MaxErrorLength), "***").Trim();
        return clean.Length == 0 ? fallback : clean;
    }

    /// <summary>
    /// Желаемое состояние узла по базе. Выход получает подписчиков и служебных пользователей всех
    /// работающих входов; вход — только подписчиков, а его выходы задают конфиг (<c>Exits</c>).
    /// Служебные пользователи в подписки не попадают: у них другой email, а поллер трафика читает
    /// только <c>sub-</c>.
    /// </summary>
    private async Task<(List<XCoreUser> Users, IReadOnlyList<XCoreExitTarget>? Exits)> ReadDesiredAsync(
        ProtocolInstance protocol, CancellationToken ct)
    {
        List<XCoreUser> users =
        [
            .. (await _subscriptions.FindDesiredAsync(DateTime.UtcNow, ct))
                .Select(s => new XCoreUser(s.XrayEmail, s.XrayUuid)),
        ];

        var servers = await _servers.GetAllAsync(ct);
        if (protocol.XCore!.Role == XCoreRoles.Entry)
            return (users, XCoreTopology.ExitTargets(servers));

        users.AddRange(XCoreTopology.RelayUsers(servers, _secrets));
        return (users, null);
    }

    /// <summary>
    /// Выход без номера маршрута (поставлен до появления входов) получает его здесь: без номера
    /// ни один вход его не увидит. Запись точечная и условная — параллельное назначение другим
    /// процессом не затирается. После записи конфиги входов устарели, и узлы синхронизируются заново.
    /// </summary>
    private async Task EnsureRouteIdAsync(VpnServer server, ProtocolInstance protocol, CancellationToken ct)
    {
        var node = protocol.XCore!;
        if (node.Role != XCoreRoles.Exit || node.RouteId is not null) return;

        // Номер выбирается по снимку базы, а два выхода без номера могут дойти сюда одновременно:
        // проигравшего отсекает уникальный индекс (M017), и он берёт следующий свободный уже по новому снимку.
        for (var attempt = 1; ; attempt++)
        {
            var routeId = XCoreRoute.NextFree(XCoreTopology.UsedRouteIds(await _servers.GetAllAsync(ct)));
            try
            {
                if (!await _servers.SetXCoreRouteIdAsync(server.Id, protocol.Id, routeId, ct)) return;
            }
            catch (RouteIdTakenException) when (attempt < XCoreRoute.AssignAttempts)
            {
                continue;
            }

            node.RouteId = routeId;
            _logger.LogInformation("Выходу xcore {ServerName} назначен маршрут {RouteId}.", server.Name, routeId);
            await _publisher.PublishForAllAsync(null, ct);
            return;
        }
    }
}
