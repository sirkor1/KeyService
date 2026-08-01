using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;

namespace AmneziaKeyService.Core.Models;

/// <summary>
/// Просьба выполнить работу, адресованная другому процессу.
///
/// Api и бот пишут событие, worker его забирает и исполняет. Очередь живёт
/// в MongoDB, а не в памяти: канал не переживает границу процессов, а работа
/// вроде установки узла идёт минутами и обязана пережить перезапуск того,
/// кто её попросил.
///
/// Захват атомарен на одном документе (findOneAndUpdate) — этого достаточно
/// и на standalone-развёртывании, где нет ни транзакций, ни change streams.
/// </summary>
[BsonIgnoreExtraElements]
public class DomainEvent
{
    [BsonId]
    [BsonRepresentation(BsonType.ObjectId)]
    public string Id { get; set; } = default!;

    /// <summary>См. <see cref="DomainEventTypes"/>. По нему событие находит обработчика.</summary>
    [BsonElement("type")]
    public string Type { get; set; } = default!;

    /// <summary>См. <see cref="DomainEventStatuses"/>.</summary>
    [BsonElement("status")]
    public string Status { get; set; } = DomainEventStatuses.Pending;

    /// <summary>Аргументы работы. Схема своя у каждого типа.</summary>
    [BsonElement("payload")]
    public BsonDocument Payload { get; set; } = [];

    /// <summary>
    /// Что получилось. Секретам здесь не место: ссылку vpn:// и клиентский
    /// файл api собирает сам по идентификатору ключа — для этого не нужен узел.
    /// </summary>
    [BsonElement("result")]
    public BsonDocument? Result { get; set; }

    /// <summary>Уже безопасный текст: без команд SSH и без секретов.</summary>
    [BsonElement("error")]
    public string? Error { get; set; }

    /// <summary>
    /// Ключ сериализации. Для операций над узлом — его идентификатор:
    /// две правки конфига WireGuard одновременно теряют peer-ов, поэтому
    /// события одной партиции исполняются строго по одному.
    /// </summary>
    [BsonElement("partitionKey")]
    public string? PartitionKey { get; set; }

    [BsonElement("attempt")]
    public int Attempt { get; set; }

    /// <summary>
    /// Сколько раз пробовать. Единица означает «повторять нельзя»: установка
    /// не идемпотентна на середине, а повтор выдачи ключа завёл бы второй peer.
    /// </summary>
    [BsonElement("maxAttempts")]
    public int MaxAttempts { get; set; } = 1;

    /// <summary>Кто взял событие в работу и до какого момента. Null — свободно.</summary>
    [BsonElement("lease")]
    public EventLease? Lease { get; set; }

    /// <summary>Момент, начиная с которого событие можно взять. Так же делается backoff.</summary>
    [BsonElement("availableAt")]
    public DateTime AvailableAt { get; set; } = DateTime.UtcNow;

    /// <summary>Идентификатор ключа, узла или задачи — сшивка с журналом и с Seq.</summary>
    [BsonElement("correlationId")]
    public string? CorrelationId { get; set; }

    /// <summary>Кто попросил. Null — сам сервис.</summary>
    [BsonElement("actorUserId")]
    public string? ActorUserId { get; set; }

    [BsonElement("createdAt")]
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    [BsonElement("startedAt")]
    public DateTime? StartedAt { get; set; }

    [BsonElement("finishedAt")]
    public DateTime? FinishedAt { get; set; }

    public bool IsTerminal => DomainEventStatuses.Terminal.Contains(Status);

    /// <summary>Разбирает аргументы в типизированную запись.</summary>
    public T PayloadAs<T>() => MongoDB.Bson.Serialization.BsonSerializer.Deserialize<T>(Payload);
}

/// <summary>
/// Кто держит событие или партицию и до какого момента.
/// Аренда, а не флаг «в работе»: процесс может умереть, не сняв флаг,
/// и тогда событие зависло бы навсегда.
/// </summary>
[BsonIgnoreExtraElements]
public class EventLease
{
    [BsonElement("owner")]
    public string Owner { get; set; } = default!;

    [BsonElement("until")]
    public DateTime Until { get; set; }
}

public static class DomainEventStatuses
{
    public const string Pending   = "pending";
    public const string Claimed   = "claimed";
    public const string Succeeded = "succeeded";
    public const string Failed    = "failed";
    public const string Canceled  = "canceled";

    public static readonly string[] Terminal = [Succeeded, Failed, Canceled];
}

/// <summary>Типы событий. Строкой в одном месте, чтобы продюсер и обработчик не разошлись.</summary>
public static class DomainEventTypes
{
    public const string ServerInstall   = "server.install";
    public const string ProtocolAdd     = "protocol.add";
    public const string ProtocolRemove  = "protocol.remove";
    public const string ServerRefresh   = "server.refresh";

    public const string KeyIssue  = "key.issue";
    public const string KeyRevoke = "key.revoke";

    /// <summary>Уведомления потребляет бот, а не worker.</summary>
    public const string NotifyKeyIssued = "notify.key_issued";
}

/// <summary>
/// Как обращаться с событием, если оно не удалось или процесс исчез посреди
/// работы. Задаётся обработчиком: только он знает, идемпотентна ли операция.
/// </summary>
/// <param name="MaxAttempts">
/// Сколько раз пробовать всего. Единица — повтор запрещён.
/// </param>
/// <param name="RetryOnLeaseExpiry">
/// Что делать с событием, чью аренду не продлили (процесс умер в середине).
/// True — вернуть в очередь, false — пометить провалившимся. Ложное «вернуть»
/// у неидемпотентной операции хуже потерянной работы: установка запустится
/// поверх наполовину настроенного узла.
/// </param>
/// <param name="RetryBackoff">Пауза перед следующей попыткой.</param>
public record DomainEventPolicy(
    int MaxAttempts,
    bool RetryOnLeaseExpiry,
    TimeSpan RetryBackoff)
{
    /// <summary>Операция не идемпотентна: одна попытка, повторов нет.</summary>
    public static readonly DomainEventPolicy Once =
        new(MaxAttempts: 1, RetryOnLeaseExpiry: false, RetryBackoff: TimeSpan.Zero);

    /// <summary>Операция идемпотентна: повторяем до успеха.</summary>
    public static DomainEventPolicy Retrying(int maxAttempts, TimeSpan backoff)
        => new(maxAttempts, RetryOnLeaseExpiry: true, backoff);
}
