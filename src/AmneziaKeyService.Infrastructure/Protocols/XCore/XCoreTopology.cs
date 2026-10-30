using AmneziaKeyService.Core.Interfaces;
using AmneziaKeyService.Core.Models;

namespace AmneziaKeyService.Infrastructure.Protocols.XCore;

/// <summary>
/// Что один узел xcore должен знать о других: выходы для входа и служебные учётные записи входов
/// для выхода. Чистые функции над списком узлов — вход и выход синхронизируются независимыми
/// событиями, и каждый обязан получить из базы одно и то же представление топологии.
/// </summary>
public static class XCoreTopology
{
    /// <summary>
    /// Email служебного пользователя входа на выходах. Префикс отличается от <c>sub-</c>:
    /// поллер трафика читает только <c>user>>>sub-</c>, поэтому служебный трафик в подписки
    /// не попадает — он остаётся только в статистике самого узла.
    /// </summary>
    public const string RelayEmailPrefix = "relay-";

    public static string RelayEmail(string entryServerId) => RelayEmailPrefix + entryServerId;

    /// <summary>Номера маршрутов, уже занятые выходами, — на любом узле и в любом состоянии.</summary>
    public static IReadOnlyList<int> UsedRouteIds(IEnumerable<VpnServer> servers) =>
    [
        .. servers.SelectMany(s => s.Protocols)
            .Where(p => p.Kind == ProtocolKinds.XCore && p.XCore is { Role: XCoreRoles.Exit, RouteId: not null })
            .Select(p => p.XCore!.RouteId!.Value),
    ];

    /// <summary>
    /// Выходы, на которые вход может направить трафик: работающие, не скрытые из подписок, с
    /// номером маршрута и полными параметрами подключения. Выход без номера или без ключа Reality
    /// в маршрутизацию не попадает — ссылка на него не подключилась бы, а правило сломало бы вход.
    /// Порядок — по номеру маршрута.
    /// </summary>
    public static IReadOnlyList<(VpnServer Server, ProtocolInstance Protocol)> RoutableExits(
        IEnumerable<VpnServer> servers) =>
    [
        .. servers.SelectMany(s => s.Protocols.Where(s.IsSubscriptionExit).Select(p => (Server: s, Protocol: p)))
            .Where(n => IsRoutable(n.Protocol.XCore!))
            .OrderBy(n => n.Protocol.XCore!.RouteId)
            .ThenBy(n => n.Server.Id, StringComparer.Ordinal),
    ];

    public static IReadOnlyList<XCoreExitTarget> ExitTargets(IEnumerable<VpnServer> servers) =>
    [
        .. RoutableExits(servers).Select(n =>
        {
            var x = n.Protocol.XCore!;
            return new XCoreExitTarget(
                x.RouteId!.Value, x.Domain, x.XhttpPort, x.RealityPublicKey!, x.ShortIds[0], x.XhttpPath!, x.Fingerprint,
                x.VlessEncryption ? x.VlessEncryptionClient : null);
        }),
    ];

    /// <summary>
    /// Служебные пользователи для выхода: по одному на каждый работающий вход. Вход без служебного
    /// UUID (не задан) пропускается — подключиться к выходу он всё равно не смог бы.
    /// </summary>
    public static IReadOnlyList<XCoreUser> RelayUsers(IEnumerable<VpnServer> servers, ISecretProtector secrets) =>
    [
        .. servers.SelectMany(s => s.Protocols
                .Where(p => p.Kind == ProtocolKinds.XCore && p.XCore is { Role: XCoreRoles.Entry } && s.IsServing(p))
                .Select(p => (Server: s, Uuid: secrets.Unprotect(p.XCore!.RelayUuid))))
            .Where(e => !string.IsNullOrWhiteSpace(e.Uuid))
            .Select(e => new XCoreUser(RelayEmail(e.Server.Id), e.Uuid!)),
    ];

    // Выход с включённым шифрованием, но без клиентской строки, в маршрутизацию не попадает: вход подключился бы
    // к нему как к открытому и получал бы отказ на каждом соединении. Его собственный конфиг при этом не соберётся,
    // и синхронизация покажет причину в SyncError.
    private static bool IsRoutable(XCoreProtocolParams x) =>
        x.RouteId is { } id && XCoreRoute.IsValid(id)
        && !string.IsNullOrWhiteSpace(x.Domain) && !string.IsNullOrWhiteSpace(x.RealityPublicKey)
        && !string.IsNullOrWhiteSpace(x.XhttpPath) && x.ShortIds.Count > 0
        && (!x.VlessEncryption || !string.IsNullOrWhiteSpace(x.VlessEncryptionClient));
}
