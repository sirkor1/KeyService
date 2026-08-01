using MongoDB.Bson.Serialization.Attributes;

namespace AmneziaKeyService.Core.Models;

/// <summary>
/// Именованная аренда с истечением. Коллекция leases.
///
/// Не «флаг занятости»: процесс может исчезнуть, не сняв флаг, и ресурс
/// остался бы заблокированным навсегда. Аренда истекает сама, поэтому худшее,
/// что даёт падение держателя, — задержка до конца срока.
/// </summary>
[BsonIgnoreExtraElements]
public class Lease
{
    /// <summary>См. <see cref="LeaseKeys"/>.</summary>
    [BsonId]
    public string Id { get; set; } = default!;

    [BsonElement("owner")]
    public string Owner { get; set; } = default!;

    [BsonElement("until")]
    public DateTime Until { get; set; }
}

public static class LeaseKeys
{
    /// <summary>Сериализация операций над одним узлом.</summary>
    public static string Partition(string partitionKey) => $"partition:{partitionKey}";

    /// <summary>Единственный активный экземпляр таймерного воркера.</summary>
    public static string Worker(string name) => $"worker:{name}";
}
