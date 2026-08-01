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
