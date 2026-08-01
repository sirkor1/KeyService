using AmneziaKeyService.Core.DTOs;
using AmneziaKeyService.Core.Models;

namespace AmneziaKeyService.Core.Interfaces;

/// <summary>Параметры выдачи ключа из панели.</summary>
public record IssueKeyOptions
{
    /// <summary>
    /// Предназначенный идентификатор документа ключа. Назначает продюсер
    /// события — до того, как он существует, — чтобы обработчик события мог
    /// в OnFailedAsync отличить «выдача не состоялась» от «состоялась, но
    /// событие не закрылось» (например, процесс умер между записью ключа
    /// и завершением события). Null — идентификатор сгенерирует драйвер,
    /// как раньше делали синхронные вызовы бота и /api/vpn/*.
    /// </summary>
    public string? KeyId { get; init; }

    /// <summary>Протокол узла. Null — протокол по умолчанию.</summary>
    public string? ProtocolId { get; init; }

    public string? OwnerName { get; init; }
    public string? DeviceName { get; init; }
    public string? Label { get; init; }

    /// <summary>Срок действия в днях. Null — бессрочно.</summary>
    public int? ExpiryDays { get; init; }

    /// <summary>Квота трафика в байтах. Null — без ограничения.</summary>
    public long? TrafficLimitBytes { get; init; }

    /// <summary>Кто выдал. Для журнала.</summary>
    public string? CreatedByUserId { get; init; }

    public string Source { get; init; } = KeySources.Panel;
}

/// <summary>Причина отзыва — попадает в журнал и в документ ключа.</summary>
public static class RevokeReasons
{
    public const string Manual  = "manual";
    public const string Expired = "expired";
    public const string Quota   = "quota";
}

public interface IVpnConfigService : IVpnConfigReader
{
    // ── Совместимость: этим пользуются Telegram-бот и /api/vpn/* ─────────────

    /// <summary>
    /// Выдаёт (или создаёт) VPN-конфиг для клиента на указанном сервере.
    /// Если конфиг уже существует — возвращает закэшированный.
    /// </summary>
    Task<VpnConfigResponse> GetOrCreateConfigAsync(
        string userId, string serverId, CancellationToken ct = default);

    /// <summary>
    /// Всегда создаёт новый ключ (новый peer на сервере, новый IP).
    /// Используется для добавления ключа на дополнительное устройство.
    /// </summary>
    Task<VpnConfigResponse> CreateNewConfigAsync(
        string userId, string serverId, CancellationToken ct = default);

    // ── Панель ────────────────────────────────────────────────────────────────

    /// <summary>Выдаёт ключ с параметрами панели и возвращает созданную запись.</summary>
    Task<VpnClient> IssueAsync(
        string userId, string serverId, IssueKeyOptions options, CancellationToken ct = default);

    /// <summary>
    /// Отзывает ключ: удаляет peer с узла и помечает запись.
    ///
    /// Если узел недоступен, запись переводится в pendingRevoke, а не в revoked:
    /// пока peer жив на сервере, доступ у клиента сохраняется, и помечать ключ
    /// отозванным было бы неправдой.
    /// </summary>
    Task<VpnClient> RevokeAsync(
        string clientId, string reason, string? revokedByUserId, CancellationToken ct = default);

    // BuildVpnUriAsync и BuildClientFileAsync унаследованы от IVpnConfigReader:
    // сборка конфига узла не требует.
}
