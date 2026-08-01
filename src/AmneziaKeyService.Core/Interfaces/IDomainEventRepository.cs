using AmneziaKeyService.Core.Models;
using MongoDB.Bson;

namespace AmneziaKeyService.Core.Interfaces;

/// <summary>
/// Публикация работы для другого процесса.
///
/// Отдельно от репозитория: продюсеру (api, бот) нужен только этот метод,
/// и давать ему захват с завершением означало бы разрешить исполнять
/// собственные просьбы.
/// </summary>
public interface IDomainEventPublisher
{
    /// <param name="partitionKey">
    /// Ключ сериализации. Для операций над узлом — его идентификатор:
    /// события одной партиции никогда не исполняются одновременно.
    /// </param>
    /// <param name="correlationId">Ключ, узел или задача — для сшивки с журналом.</param>
    Task<DomainEvent> PublishAsync(
        string type,
        object payload,
        string? partitionKey = null,
        string? correlationId = null,
        string? actorUserId = null,
        CancellationToken ct = default);
}

/// <summary>Очередь работ поверх коллекции domain_events.</summary>
public interface IDomainEventRepository : IDomainEventPublisher
{
    Task<DomainEvent?> GetByIdAsync(string id, CancellationToken ct = default);

    /// <summary>
    /// Берёт одно свободное событие поддерживаемого типа и помечает своим.
    ///
    /// Атомарен: захват — это один findOneAndUpdate, а он атомарен на уровне
    /// документа даже без транзакций. Два процесса не получат одно событие.
    /// Null — брать нечего.
    /// </summary>
    Task<DomainEvent?> ClaimAsync(
        IReadOnlyCollection<string> types, string owner, TimeSpan leaseTtl, CancellationToken ct = default);

    /// <summary>
    /// Продлевает аренду на время работы. False — аренду уже отобрали,
    /// и продолжать нельзя: событие мог подхватить другой процесс.
    /// </summary>
    Task<bool> RenewLeaseAsync(
        string id, string owner, TimeSpan leaseTtl, CancellationToken ct = default);

    /// <summary>
    /// Возвращает событие в очередь.
    /// </summary>
    /// <param name="countsAsAttempt">
    /// False, если работа так и не начиналась — например, партиция была занята.
    /// Иначе занятый узел сжигал бы попытки события, которое ещё не пробовали.
    /// </param>
    Task RequeueAsync(
        string id, DateTime availableAt, bool countsAsAttempt, CancellationToken ct = default);

    Task CompleteAsync(string id, BsonDocument? result, CancellationToken ct = default);

    Task FailAsync(string id, string error, CancellationToken ct = default);

    /// <summary>
    /// События, чью аренду не продлили: процесс умер в середине работы.
    /// Что с ними делать, решает политика их обработчика.
    /// </summary>
    Task<List<DomainEvent>> FindExpiredAsync(
        IReadOnlyCollection<string> types, int limit, CancellationToken ct = default);
}

/// <summary>
/// Именованные аренды: сериализация операций по узлу и, позже, выбор
/// единственного активного экземпляра таймерного воркера.
/// </summary>
public interface ILeaseRepository
{
    /// <summary>
    /// Берёт аренду, если она свободна или уже принадлежит этому владельцу.
    /// False — держит кто-то другой.
    /// </summary>
    Task<bool> TryAcquireAsync(
        string key, string owner, TimeSpan ttl, CancellationToken ct = default);

    /// <summary>Продлевает свою аренду. False — потеряна.</summary>
    Task<bool> RenewAsync(
        string key, string owner, TimeSpan ttl, CancellationToken ct = default);

    /// <summary>Отпускает аренду. Чужую не трогает.</summary>
    Task ReleaseAsync(string key, string owner, CancellationToken ct = default);
}
