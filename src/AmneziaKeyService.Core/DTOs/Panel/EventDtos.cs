using AmneziaKeyService.Core.Models;
using MongoDB.Bson;

namespace AmneziaKeyService.Core.DTOs.Panel;

/// <summary>
/// Ответ на заявку, поставленную в очередь доменных событий: узел синхронно
/// не трогаем, поэтому вместо готового результата отдаём идентификаторы
/// для последующего опроса — GET /api/events/{eventId}.
/// </summary>
public record EventAcceptedDto(string EventId, string KeyId);

/// <summary>
/// Статус доменного события для опроса панелью и клиентским /api/vpn/*.
/// </summary>
public record DomainEventDto(
    string Id,
    string Type,
    string Status,
    string? Error,
    Dictionary<string, string?>? Result,
    DateTime CreatedAt,
    DateTime? StartedAt,
    DateTime? FinishedAt)
{
    public static DomainEventDto From(DomainEvent evt) => new(
        evt.Id,
        evt.Type,
        evt.Status,
        evt.Error,
        ToFlatResult(evt.Result),
        evt.CreatedAt,
        evt.StartedAt,
        evt.FinishedAt);

    /// <summary>
    /// Result события — сырой BsonDocument, и наружу в JSON его отдавать нельзя:
    /// это внутреннее представление MongoDB, а не публичный контракт. Все
    /// обработчики кладут туда только плоские скалярные поля (keyId, shortId,
    /// status, assignedIp), поэтому Dictionary&lt;string, string?&gt; ничего
    /// не теряет — вложенных документов и массивов в Result не бывает.
    /// </summary>
    private static Dictionary<string, string?>? ToFlatResult(BsonDocument? result)
    {
        if (result is null) return null;

        var flat = new Dictionary<string, string?>();
        foreach (var element in result)
        {
            flat[element.Name] = element.Value.IsBsonNull
                ? null
                : element.Value.IsString ? element.Value.AsString : element.Value.ToString();
        }

        return flat;
    }
}

/// <summary>
/// Готовый секрет уже выданного ключа: ссылка vpn:// и клиентский файл.
/// В отличие от прежнего ответа на выдачу, эту ручку можно вызывать повторно,
/// пока ключ активен — конфиг собирается по сохранённому документу ключа,
/// узел для этого не нужен.
/// </summary>
public record KeySecretDto(string VpnUri, string FileName, string FileContent);
