using AmneziaKeyService.Core.DTOs;
using AmneziaKeyService.Core.Models;

namespace AmneziaKeyService.Core.Interfaces;

/// <summary>Доступ к подпискам (коллекция subscriptions).</summary>
public interface ISubscriptionRepository
{
    Task<Subscription?> FindByIdAsync(string id, CancellationToken ct = default);

    /// <summary>Поиск по хешу токена (<see cref="SubscriptionTokenCrypto.Hash"/>).</summary>
    Task<Subscription?> FindByTokenHashAsync(string tokenHash, CancellationToken ct = default);

    Task<Subscription?> FindActiveByUserAsync(string userId, CancellationToken ct = default);

    /// <summary>
    /// Последняя по времени создания подписка пользователя в любом статусе. Нужна правилу
    /// повторной выдачи: после отзыва решает причина именно последней подписки.
    /// </summary>
    Task<Subscription?> FindLatestByUserAsync(string userId, CancellationToken ct = default);

    Task<List<Subscription>> FindByIdsAsync(IEnumerable<string> ids, CancellationToken ct = default);

    /// <summary>
    /// Создаёт подписку. False — уникальный индекс не пустил: у пользователя уже есть
    /// активная подписка (вторая из-за гонки между проверкой и вставкой).
    /// </summary>
    Task<bool> TryCreateAsync(Subscription subscription, CancellationToken ct = default);

    Task<Paged<Subscription>> SearchAsync(SubscriptionQuery query, CancellationToken ct = default);

    /// <summary>
    /// Подписки, которые должны быть на узлах: активные и с неистёкшим сроком. Именно это
    /// множество — желаемый список пользователей узла.
    /// </summary>
    Task<List<Subscription>> FindDesiredAsync(DateTime now, CancellationToken ct = default);

    /// <summary>Активные подписки с истёкшим сроком или исчерпанной квотой — кандидаты на отзыв.</summary>
    Task<List<Subscription>> FindEnforcementCandidatesAsync(DateTime now, CancellationToken ct = default);

    /// <summary>
    /// Переводит активную подписку в отозванную. False — она уже не активна (или не существует),
    /// и переход сделал кто-то другой.
    /// </summary>
    Task<bool> TryRevokeAsync(string id, string reason, DateTime now, CancellationToken ct = default);

    /// <summary>Подставляет новые токен и UUID. False — подписка не активна.</summary>
    Task<bool> TryReplaceCredentialsAsync(
        string id, string tokenHash, EncryptedValue tokenEncrypted, string xrayUuid, DateTime now,
        CancellationToken ct = default);

    /// <summary>Заменяет срок и квоту (null — без ограничения). False — подписка не активна.</summary>
    Task<bool> TryUpdateLimitsAsync(
        string id, DateTime? expiresAt, long? trafficLimitBytes, CancellationToken ct = default);

    Task ApplyUsageAsync(IReadOnlyCollection<SubscriptionUsageUpdate> updates, CancellationToken ct = default);
}

/// <summary>
/// Приращение трафика подписки на одном узле и новые сырые показания счётчиков.
/// Приращения прибавляются к накопленному, сырые значения перезаписываются и служат базой
/// для следующего сравнения.
/// </summary>
public record SubscriptionUsageUpdate(
    string SubscriptionId,
    string ServerId,
    long RxDelta,
    long TxDelta,
    long RxRaw,
    long TxRaw,
    DateTime SeenAt);

/// <summary>
/// Фильтры списка подписок. Владелец ищется по имени в контроллере, поэтому здесь —
/// готовые идентификаторы пользователей, а не строка поиска. <see cref="Id"/> и
/// <see cref="UserIds"/> — две ветки одного поиска и соединяются по «или».
/// </summary>
public record SubscriptionQuery(
    string? Id = null,
    IReadOnlyCollection<string>? UserIds = null,
    string? Status = null,
    int? Page = null,
    int? PageSize = null)
{
    public PageRequest Paging => new(Page, PageSize);
}
