using MongoDB.Bson.Serialization.Attributes;

namespace AmneziaKeyService.Core.Models;

/// <summary>
/// Суточные срезы трафика и доступности.
///
/// Не time-series коллекции: у всех трёх срезов детерминированный строковый
/// _id вида "{owner}:{yyyy-MM-dd}", поэтому тик воркера обновляет их через
/// upsert с $inc. Повторный тик после сбоя не задваивает данные и не требует
/// транзакции — свойство, ради которого схема и выбрана.
///
/// Дата хранится строкой в ISO-формате, а не DateTime и не DateOnly:
/// лексикографический порядок совпадает с хронологическим, диапазонные
/// запросы работают как есть, а в mongosh документ читается глазами.
/// </summary>
public static class UsageDailyKey
{
    public const string DateFormat = "yyyy-MM-dd";

    public static string Format(DateOnly day) => day.ToString(DateFormat);

    public static string For(string ownerId, DateOnly day) => $"{ownerId}:{Format(day)}";

    public static string For(string keyId, string serverId, DateOnly day)
        => $"{keyId}:{serverId}:{Format(day)}";
}

/// <summary>Трафик одного ключа за сутки. Коллекция key_usage_daily.</summary>
[BsonIgnoreExtraElements]
public class KeyUsageDaily
{
    [BsonId]
    public string Id { get; set; } = default!;

    [BsonElement("keyId")]
    public string KeyId { get; set; } = default!;

    [BsonElement("serverId")]
    public string ServerId { get; set; } = default!;

    /// <summary>Дата в формате yyyy-MM-dd, UTC.</summary>
    [BsonElement("date")]
    public string Date { get; set; } = default!;

    [BsonElement("rxBytes")]
    public long RxBytes { get; set; }

    [BsonElement("txBytes")]
    public long TxBytes { get; set; }

    /// <summary>Момент удаления документа TTL-индексом.</summary>
    [BsonElement("expireAt")]
    public DateTime ExpireAt { get; set; }
}

/// <summary>Трафик узла за сутки — сумма по всем его ключам. Коллекция server_usage_daily.</summary>
[BsonIgnoreExtraElements]
public class ServerUsageDaily
{
    [BsonId]
    public string Id { get; set; } = default!;

    [BsonElement("serverId")]
    public string ServerId { get; set; } = default!;

    [BsonElement("date")]
    public string Date { get; set; } = default!;

    [BsonElement("rxBytes")]
    public long RxBytes { get; set; }

    [BsonElement("txBytes")]
    public long TxBytes { get; set; }

    [BsonElement("expireAt")]
    public DateTime ExpireAt { get; set; }
}

/// <summary>
/// Доступность узла за сутки: сколько проверок прошло и сколько из них удачных.
/// Аптайм за 30 дней — отношение сумм, а не среднее по дням: сутки с одной
/// проверкой не должны весить столько же, сколько полные.
/// Коллекция server_health_daily.
/// </summary>
[BsonIgnoreExtraElements]
public class ServerHealthDaily
{
    [BsonId]
    public string Id { get; set; } = default!;

    [BsonElement("serverId")]
    public string ServerId { get; set; } = default!;

    [BsonElement("date")]
    public string Date { get; set; } = default!;

    [BsonElement("checksTotal")]
    public long ChecksTotal { get; set; }

    [BsonElement("checksOk")]
    public long ChecksOk { get; set; }

    [BsonElement("expireAt")]
    public DateTime ExpireAt { get; set; }
}
