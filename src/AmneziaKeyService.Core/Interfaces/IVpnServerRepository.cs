using AmneziaKeyService.Core.DTOs;
using AmneziaKeyService.Core.Models;

namespace AmneziaKeyService.Core.Interfaces;

/// <summary>Доступ к узлам VPN (коллекция server_config).</summary>
public interface IVpnServerRepository
{
    Task<List<VpnServer>> GetAllAsync(CancellationToken ct = default);

    Task<VpnServer?> GetByIdAsync(string id, CancellationToken ct = default);

    /// <summary>Поиск с фильтрами для списка серверов в панели.</summary>
    Task<Paged<VpnServer>> SearchAsync(ServerQuery query, CancellationToken ct = default);

    Task<VpnServer> CreateAsync(VpnServer server, CancellationToken ct = default);

    Task<bool> UpdateAsync(VpnServer server, CancellationToken ct = default);

    Task<bool> SetProtocolEnabledAsync(string id, string protocolId, bool enabled, CancellationToken ct = default);
    /// <exception cref="Exceptions.RouteIdTakenException">
    /// Номер маршрута нового выхода занят другим узлом: выберите следующий свободный и повторите.
    /// </exception>
    Task UpdateInstallationAsync(VpnServer server, CancellationToken ct = default);
    Task UpdateMetadataAsync(VpnServer server, CancellationToken ct = default);
    Task UpdateHealthAsync(VpnServer server, CancellationToken ct = default);
    Task UpdateReconciliationAsync(VpnServer server, CancellationToken ct = default);
    Task UpdateProtocolParamsAsync(string id, ProtocolInstance protocol, CancellationToken ct = default);

    /// <summary>
    /// Фиксирует успешное применение конфига xcore и сбрасывает ошибку. Правится только
    /// элемент массива protocols: запись всего документа узла затёрла бы изменения,
    /// сделанные параллельно (health-проверка, правка метаданных).
    /// </summary>
    Task MarkXCoreAppliedAsync(
        string id, string protocolId, string revision, string structureRevision, DateTime appliedAt,
        CancellationToken ct = default);

    /// <summary>Записывает причину неудачного применения конфига xcore.</summary>
    Task SetXCoreSyncErrorAsync(string id, string protocolId, string error, CancellationToken ct = default);

    /// <summary>
    /// Назначает выходу xcore номер маршрута, только если у него ещё нет номера. Правится
    /// один элемент массива protocols по тем же причинам, что и в <see cref="MarkXCoreAppliedAsync"/>.
    /// False — протокол не найден или номер уже есть.
    /// </summary>
    /// <exception cref="Exceptions.RouteIdTakenException">Номер занят выходом другого узла (индекс M017).</exception>
    Task<bool> SetXCoreRouteIdAsync(string id, string protocolId, int routeId, CancellationToken ct = default);

    /// <summary>
    /// Записывает хеш Caddyfile, применённого к узлу. Отдельно от <see cref="MarkXCoreAppliedAsync"/>: Caddy
    /// синхронизируется после Xray, и сбой первого не должен отменять уже применённый второй.
    /// </summary>
    Task MarkXCoreCaddyAppliedAsync(string id, string protocolId, string revision, CancellationToken ct = default);

    /// <summary>
    /// Запоминает неудачный выпуск сертификата домена подписки для данной ревизии Caddyfile: до
    /// <c>XCore:CaddyRetryMinutes</c> с этого момента Caddy с той же ревизией не перезапускается.
    /// </summary>
    Task SetXCoreCaddyFailedAsync(
        string id, string protocolId, string revision, DateTime failedAt, CancellationToken ct = default);

    /// <summary>
    /// Фиксирует, что файлы российских списков релиза <paramref name="tag"/> лежат на узле: тег, время
    /// подмены и проверки, и снимает ошибку обновления. Вызывается только после подмены файлов — по тегу
    /// рендерер решает, ссылаться ли конфигу на <c>ext:rf-…</c>.
    /// </summary>
    Task MarkXCoreRfListsAppliedAsync(
        string id, string protocolId, string tag, DateTime at, CancellationToken ct = default);

    /// <summary>Отмечает, что списки сверены с GitHub и новее применённых релиза нет (или он уже применён).</summary>
    Task SetXCoreRfListsCheckedAsync(string id, string protocolId, DateTime at, CancellationToken ct = default);

    /// <summary>Записывает причину неудачного обновления российских списков (null снимает ошибку).</summary>
    Task SetXCoreGeoErrorAsync(string id, string protocolId, string? error, CancellationToken ct = default);

    /// <summary>
    /// Точечно обновляет настройки xcore из панели. Поля роли, домена узла и ключей не затрагиваются, а
    /// поля маршрутизации входа пишутся, только если у протокола роль «вход». False — протокол не найден.
    /// </summary>
    Task<bool> UpdateXCoreSettingsAsync(
        string id, string protocolId, DTOs.Panel.XCoreSettingsUpdate update, CancellationToken ct = default);

    /// <summary>Записывает состояние плеч входа. Точечно: проверка не должна затирать правку настроек.</summary>
    Task SetXCoreExitHealthAsync(
        string id, string protocolId, IReadOnlyList<XCoreExitHealth> health, CancellationToken ct = default);

    Task<bool> DeleteAsync(string id, CancellationToken ct = default);

    /// <summary>Количество узлов в разрезе статусов — для плитки «Узлы онлайн».</summary>
    Task<Dictionary<string, long>> CountByStatusAsync(CancellationToken ct = default);
}

/// <summary>
/// Фильтры списка серверов. Search сопоставляется с именем и хостом —
/// как в макете: «Поиск по имени или IP».
/// </summary>
public record ServerQuery(
    string? Search = null,
    string? ProtocolKind = null,
    string? Status = null,
    int? Page = null,
    int? PageSize = null)
{
    public PageRequest Paging => new(Page, PageSize);
}
