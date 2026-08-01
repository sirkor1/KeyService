using AmneziaKeyService.Core.DTOs;
using AmneziaKeyService.Core.Models;

namespace AmneziaKeyService.Core.Interfaces;

public interface IVpnClientRepository
{
    // ── Существующие методы: на них завязаны Telegram-бот и /api/vpn/* ────────

    Task<VpnClient?> FindByUserIdAndServerAsync(string userId, string serverId, CancellationToken ct = default);
    Task<List<VpnClient>> GetByUserIdAsync(string userId, CancellationToken ct = default);
    Task<List<VpnClient>> GetByUserIdAndServerAsync(string userId, string serverId, CancellationToken ct = default);
    Task<VpnClient?> FindByIdAsync(string id, CancellationToken ct = default);
    Task CreateAsync(VpnClient client, CancellationToken ct = default);
    Task UpdateAsync(VpnClient client, CancellationToken ct = default);

    /// <summary>Максимальный из уже назначенных tunnel-IP для конкретного сервера.</summary>
    Task<string?> GetMaxAssignedIpAsync(string serverId, CancellationToken ct = default);

    // ── Для панели ────────────────────────────────────────────────────────────

    Task<Paged<VpnClient>> SearchAsync(KeyQuery query, CancellationToken ct = default);

    Task<VpnClient?> FindByShortIdAsync(string shortId, CancellationToken ct = default);

    /// <summary>Количество ключей в разрезе статусов — плитка «Выданных ключей».</summary>
    Task<Dictionary<string, long>> CountByStatusAsync(CancellationToken ct = default);

    /// <summary>Число активных ключей по каждому серверу — колонка «Ключи» в списке узлов.</summary>
    Task<Dictionary<string, long>> CountActiveByServerAsync(CancellationToken ct = default);

    /// <summary>Число активных ключей по каждому пользователю — колонка «Ключей».</summary>
    Task<Dictionary<string, long>> CountActiveByUserAsync(CancellationToken ct = default);

    /// <summary>Активные ключи, срок которых истекает в ближайшее время — «Требуют внимания».</summary>
    Task<long> CountExpiringSoonAsync(TimeSpan within, CancellationToken ct = default);

    /// <summary>
    /// Занятые туннельные IP в подсети протокола. Нужен аллокатору, чтобы выдавать
    /// наименьший свободный адрес: «максимум + 1» навсегда исчерпывает /24,
    /// потому что отозванные ключи не освобождают адрес.
    /// </summary>
    Task<List<string>> GetAssignedIpsAsync(string serverId, string? protocolId, CancellationToken ct = default);

    // ── Фоновые воркеры (фаза 5) ──────────────────────────────────────────────

    /// <summary>
    /// Ключи узла, которым на сервере должен соответствовать живой peer:
    /// всё, кроме отозванных. Опрос трафика сопоставляет по ним peer-ов,
    /// сверка по ним же ищет сирот.
    /// </summary>
    Task<List<VpnClient>> GetLiveByServerAsync(string serverId, CancellationToken ct = default);

    /// <summary>
    /// Пишет показания счётчиков одним bulk-запросом. Накопленный итог идёт
    /// через $inc, а не через запись всего документа: одновременная выдача
    /// или отзов ключа не должны потерять приращение.
    /// </summary>
    Task ApplyUsageAsync(IReadOnlyCollection<KeyUsageUpdate> updates, CancellationToken ct = default);

    /// <summary>Активные ключи, у которых истёк срок или исчерпана квота.</summary>
    Task<List<VpnClient>> FindEnforcementCandidatesAsync(DateTime now, CancellationToken ct = default);

    /// <summary>Ключи, застрявшие в pendingRevoke: отзыв запрошен, peer ещё жив.</summary>
    Task<List<VpnClient>> FindPendingRevokeAsync(int limit, CancellationToken ct = default);

    /// <summary>Активные ключи, истекающие до указанного момента, по которым ещё не предупреждали.</summary>
    Task<List<VpnClient>> FindExpiringUnwarnedAsync(DateTime until, CancellationToken ct = default);

    /// <summary>Отмечает, что о скором истечении ключа уже предупредили.</summary>
    Task MarkExpiryWarnedAsync(IReadOnlyCollection<string> keyIds, CancellationToken ct = default);
}

/// <summary>
/// Показания счётчиков по одному ключу за тик опроса.
/// Приращения — то, что нужно добавить к накопленному итогу; сырые значения
/// перезаписываются как есть и служат базой для следующего сравнения.
/// </summary>
public record KeyUsageUpdate(
    string KeyId,
    long RxDelta,
    long TxDelta,
    long RxRaw,
    long TxRaw,
    DateTime? LastHandshakeAt,
    DateTime LastSeenAt);

/// <summary>
/// Фильтры списка ключей. Search сопоставляется с владельцем, устройством
/// и коротким идентификатором — как в макете.
/// </summary>
public record KeyQuery(
    string? Search = null,
    string? Status = null,
    string? ServerId = null,
    string? ProtocolKind = null,
    string? UserId = null,
    int? Page = null,
    int? PageSize = null)
{
    public PageRequest Paging => new(Page, PageSize);
}
