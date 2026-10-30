using AmneziaKeyService.Core.Interfaces;
using AmneziaKeyService.Core.Models;
using Microsoft.Extensions.Logging;

namespace AmneziaKeyService.Infrastructure.Subscriptions;

/// <summary>
/// Просит worker привести узлы xcore к актуальному списку подписчиков. Общий для всех, кто
/// меняет состав подписчиков (сервис подписок, принуждение, сверка, установка узла).
///
/// Сбой публикации не бросается: изменение к этому моменту уже записано в базу, и откатывать
/// выдачу или отзыв из-за недоступной очереди нельзя. Потерянное событие подберёт сверка
/// <see cref="Monitoring.XCoreReconcileService"/> — отсюда и допустимость глотать ошибку.
/// </summary>
public class XCoreSyncPublisher
{
    private readonly IVpnServerRepository _servers;
    private readonly IDomainEventPublisher _events;
    private readonly ILogger<XCoreSyncPublisher> _logger;

    public XCoreSyncPublisher(
        IVpnServerRepository servers, IDomainEventPublisher events, ILogger<XCoreSyncPublisher> logger)
    {
        _servers = servers;
        _events  = events;
        _logger  = logger;
    }

    /// <summary>
    /// Узлы xcore любой роли, которые отдаются в подписках (<see cref="VpnServer.IsSubscriptionNode"/>).
    /// Для синхронизации и учёта трафика не подходит — там <see cref="SyncTargets"/>.
    /// </summary>
    public static IEnumerable<(VpnServer Server, ProtocolInstance Protocol)> SubscriptionNodes(
        IEnumerable<VpnServer> servers)
        => servers.SelectMany(s => s.Protocols.Where(s.IsSubscriptionNode).Select(p => (s, p)));

    /// <summary>
    /// Все установленные узлы xcore, включая выключенные и исключённые из подписок. Это адресаты
    /// синхронизации и учёта трафика, и они шире <see cref="SubscriptionNodes"/> намеренно:
    /// узел, убранный из подписки, остаётся живым Xray с прежним списком пользователей. Перестань
    /// он синхронизироваться, отозванный подписчик сохранил бы на нём доступ по уже сохранённой
    /// ссылке, а без учёта трафика — ещё и обошёл бы квоту.
    /// </summary>
    public static IEnumerable<(VpnServer Server, ProtocolInstance Protocol)> SyncTargets(
        IEnumerable<VpnServer> servers)
        => servers.SelectMany(s => s.Protocols
            .Where(p => p.Kind == ProtocolKinds.XCore
                && p.State == ProtocolStates.Installed
                && p.XCore is { Role: XCoreRoles.Exit or XCoreRoles.Entry })
            .Select(p => (s, p)));

    /// <summary>
    /// Входы, которым нужны российские списки: все установленные, включая выключенные и исключённые из
    /// подписок — по той же причине, что и <see cref="SyncTargets"/>: узел остаётся живым Xray, и вернувшись в
    /// работу, он не должен оказаться на списках месячной давности.
    /// </summary>
    public static IEnumerable<(VpnServer Server, ProtocolInstance Protocol)> GeoTargets(
        IEnumerable<VpnServer> servers)
        => SyncTargets(servers).Where(n => n.Protocol.XCore!.Role == XCoreRoles.Entry);

    /// <summary>
    /// Только выходы (<see cref="VpnServer.IsSubscriptionExit"/>): к ним ведут прямые ссылки, и
    /// только их наличие означает, что подписке есть что показать — вход без выходов ссылок не даёт.
    /// </summary>
    public static IEnumerable<(VpnServer Server, ProtocolInstance Protocol)> SubscriptionExits(
        IEnumerable<VpnServer> servers)
        => servers.SelectMany(s => s.Protocols.Where(s.IsSubscriptionExit).Select(p => (s, p)));

    /// <summary>
    /// Публикует синхронизацию на все подходящие узлы. Возвращает, на сколько создано событие.
    /// Любое изменение топологии (установка, удаление, выключение узла) идёт именно сюда, а не на
    /// один узел: входы зависят от выходов, а выходы — от входов. Чтение списка узлов тоже не
    /// бросает: вызывающий к этому моменту уже записал изменение, как и при сбое публикации.
    /// </summary>
    public async Task<int> PublishForAllAsync(string? actorUserId, CancellationToken ct = default)
    {
        List<VpnServer> servers;
        try
        {
            servers = await _servers.GetAllAsync(ct);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogWarning(ex, "Не удалось прочитать узлы для xcore.sync: узлы догонит сверка.");
            return 0;
        }

        var published = 0;
        foreach (var (server, protocol) in SyncTargets(servers))
            if (await PublishForNodeAsync(server.Id, protocol.Id, actorUserId, ct))
                published++;
        return published;
    }

    /// <summary>
    /// Публикует синхронизацию одного узла. False — событие не создано: либо уже ждёт такое же,
    /// либо публикация не удалась (тогда в логе предупреждение).
    /// </summary>
    public async Task<bool> PublishForNodeAsync(
        string serverId, string protocolId, string? actorUserId = null, CancellationToken ct = default)
    {
        try
        {
            var evt = await _events.PublishIfNoPendingAsync(
                DomainEventTypes.XCoreSync,
                new XCoreSyncPayload(serverId, protocolId),
                partitionKey: serverId,
                correlationId: serverId,
                actorUserId: actorUserId,
                ct);
            return evt is not null;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogWarning(ex,
                "Не удалось опубликовать xcore.sync для узла {ServerId}: узел догонит сверка.", serverId);
            return false;
        }
    }

    /// <summary>
    /// Просит обновить российские списки одного входа. Партиция — узел, как у синхронизации, поэтому оба
    /// события идут по очереди. <paramref name="tag"/> null — «последний релиз», его определит обработчик.
    /// False — событие не создано: уже ждёт такое же либо публикация не удалась (тогда в логе предупреждение;
    /// следующий проход <c>XCoreGeoUpdateService</c> повторит).
    /// </summary>
    public async Task<bool> PublishGeoUpdateAsync(
        string serverId, string protocolId, string? tag, string? actorUserId = null, CancellationToken ct = default)
    {
        try
        {
            var evt = await _events.PublishIfNoPendingAsync(
                DomainEventTypes.XCoreGeoUpdate,
                new XCoreGeoUpdatePayload(serverId, protocolId, tag),
                partitionKey: serverId,
                correlationId: serverId,
                actorUserId: actorUserId,
                ct);
            return evt is not null;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogWarning(ex,
                "Не удалось опубликовать xcore.geo_update для узла {ServerId}: обновление повторит worker.", serverId);
            return false;
        }
    }
}
