using AmneziaKeyService.Core.Models;

namespace AmneziaKeyService.Core.DTOs.Panel;

/// <summary>Строка таблицы «Выданные ключи».</summary>
public record KeyListItemDto(
    string Id,
    string ShortId,
    string? OwnerName,
    string? DeviceName,
    string? Label,
    string ServerId,
    string? ServerName,
    string? ProtocolId,
    string? ProtocolKind,
    string? ProtocolDisplayName,
    string? AssignedIp,
    DateTime IssuedAt,
    DateTime? ExpiresAt,
    long TrafficBytes,
    long? TrafficLimitBytes,
    DateTime? LastHandshakeAt,
    bool Online,
    string Status,
    string Source,
    string? RouterId = null)
{
    public static KeyListItemDto From(VpnClient c, string? serverName, string? ownerFallback) => new(
        c.Id,
        // ShortId отсутствует у ключей, не прошедших миграцию 004 — показываем
        // хвост _id, чтобы колонка не пустовала.
        c.ShortId ?? $"KEY-{c.Id[^6..].ToUpperInvariant()}",
        c.OwnerName ?? ownerFallback,
        c.DeviceName,
        c.Label,
        c.ServerId,
        serverName,
        c.ProtocolId,
        c.ProtocolKind,
        c.ProtocolKind is null ? null : ProtocolKinds.DisplayName(c.ProtocolKind),
        c.AssignedIp,
        c.CreatedAt,
        c.ExpiresAt,
        c.Usage.TotalBytes,
        c.TrafficLimitBytes,
        c.Usage.LastHandshakeAt,
        c.Usage.IsOnline,
        c.Status,
        c.Source);
}

/// <summary>
/// Детали ключа. Приватный ключ и PSK не отдаются: панель показывает их
/// ровно один раз в момент выдачи и больше восстановить не может.
/// </summary>
public record KeyDetailDto(
    KeyListItemDto Summary,
    string? ClientPubKey,
    string? XrayClientId,
    string? UserId,
    DateTime? RevokedAt,
    string? RevokeReason,
    long RxBytes,
    long TxBytes,
    DateTime? LastSeenAt)
{
    public static KeyDetailDto From(VpnClient c, string? serverName, string? ownerFallback) => new(
        KeyListItemDto.From(c, serverName, ownerFallback),
        c.ClientPubKey,
        c.XrayClientId,
        c.UserId,
        c.RevokedAt,
        c.RevokeReason,
        c.Usage.RxBytes,
        c.Usage.TxBytes,
        c.Usage.LastSeenAt);
}

/// <summary>Строка таблицы «Пользователи».</summary>
public record UserListItemDto(
    string Id,
    string Username,
    string? DisplayName,
    string? Contact,
    long? TelegramId,
    string Role,
    string Status,
    long KeysCount,
    DateTime CreatedAt)
{
    public static UserListItemDto From(User u, long keysCount) => new(
        u.Id, u.Username, u.DisplayName, u.Contact, u.TelegramId, u.Role, u.Status, keysCount, u.CreatedAt);
}

/// <summary>Строка журнала событий.</summary>
public record AuditEntryDto(
    string Id,
    DateTime At,
    string Level,
    string Event,
    string Message,
    string? ActorName,
    string? TargetType,
    string? TargetId,
    string? TargetName)
{
    public static AuditEntryDto From(AuditEntry e) => new(
        e.Id, e.At, e.Level, e.Event, e.Message, e.ActorName, e.TargetType, e.TargetId, e.TargetName);
}

/// <summary>Настройки панели.</summary>
public record PanelSettingsDto(
    int? DefaultExpiryDays,
    int? DeviceLimitPerClient,
    string DefaultProtocolKind,
    long? DefaultTrafficLimitBytes,
    bool MaskSecrets,
    bool TwoFactorEnabled,
    string? AlertTelegramChat,
    DateTime? UpdatedAt)
{
    public static PanelSettingsDto From(PanelSettings s) => new(
        s.DefaultExpiryDays, s.DeviceLimitPerClient, s.DefaultProtocolKind, s.DefaultTrafficLimitBytes,
        s.MaskSecrets, s.TwoFactorEnabled, s.AlertTelegramChat, s.UpdatedAt);
}

/// <summary>
/// Редактируемая часть настроек. В неё намеренно не входят поля, которые
/// пока не используются runtime: протокол, лимит устройств, 2FA, Telegram-
/// уведомления и маскирование секретов.
/// </summary>
public record UpdatePanelSettingsRequest(
    int? DefaultExpiryDays,
    long? DefaultTrafficLimitBytes);
