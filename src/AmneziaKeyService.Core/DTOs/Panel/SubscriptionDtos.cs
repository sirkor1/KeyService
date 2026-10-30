using AmneziaKeyService.Core.Models;

namespace AmneziaKeyService.Core.DTOs.Panel;

/// <summary>
/// Строка таблицы «Подписки». Ни токена, ни UUID здесь нет: это учётные данные, и ссылку
/// панель получает отдельным запросом <see cref="SubscriptionLinkDto"/>.
/// </summary>
public record SubscriptionListItemDto(
    string Id,
    string UserId,
    string? UserName,
    string Status,
    string? RevokeReason,
    DateTime CreatedAt,
    DateTime? ExpiresAt,
    long TrafficBytes,
    long? TrafficLimitBytes,
    DateTime? LastSeenAt,
    string Source)
{
    public static SubscriptionListItemDto From(Subscription s, string? userName) => new(
        s.Id, s.UserId, userName, s.Status, s.RevokeReason, s.CreatedAt, s.ExpiresAt,
        s.Usage.TotalBytes, s.TrafficLimitBytes, s.Usage.LastSeenAt, s.Source);
}

/// <summary>Карточка подписки. Использование — с точки зрения клиента: получено и отправлено им.</summary>
public record SubscriptionDetailDto(
    SubscriptionListItemDto Summary,
    long RxBytes,
    long TxBytes,
    DateTime? RevokedAt,
    DateTime? TokenRotatedAt,
    string? CreatedByUserId)
{
    public static SubscriptionDetailDto From(Subscription s, string? userName) => new(
        SubscriptionListItemDto.From(s, userName),
        s.Usage.RxBytes, s.Usage.TxBytes, s.RevokedAt, s.TokenRotatedAt, s.CreatedByUserId);
}

/// <summary>Публичная ссылка подписки. Это секрет: любой, кто её знает, пользуется подпиской.</summary>
public record SubscriptionLinkDto(string Url);

/// <summary>
/// Выдача подписки. <c>ExpiryDays</c> и <c>TrafficLimitBytes</c>: null — взять из настроек
/// панели, 0 — без ограничения (так же, как при выдаче ключа).
/// </summary>
public record CreateSubscriptionRequest(string? UserId, int? ExpiryDays, long? TrafficLimitBytes);

/// <summary>Новые границы подписки целиком: null (или 0 для квоты) снимает ограничение.</summary>
public record UpdateSubscriptionLimitsRequest(DateTime? ExpiresAt, long? TrafficLimitBytes);
