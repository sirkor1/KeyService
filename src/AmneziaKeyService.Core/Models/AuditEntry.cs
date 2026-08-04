using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;

namespace AmneziaKeyService.Core.Models;

/// <summary>
/// Запись журнала событий — экран «Журнал событий» в панели.
/// Коллекция audit_log, TTL 180 дней (индекс создаётся миграцией 005).
/// </summary>
[BsonIgnoreExtraElements]
public class AuditEntry
{
    [BsonId]
    [BsonRepresentation(BsonType.ObjectId)]
    public string Id { get; set; } = default!;

    [BsonElement("at")]
    public DateTime At { get; set; } = DateTime.UtcNow;

    /// <summary>См. <see cref="AuditLevels"/>.</summary>
    [BsonElement("level")]
    public string Level { get; set; } = AuditLevels.Info;

    /// <summary>Машинный код события: "server.created", "key.revoked".</summary>
    [BsonElement("event")]
    public string Event { get; set; } = default!;

    /// <summary>Человекочитаемое описание на русском — колонка «Событие».</summary>
    [BsonElement("message")]
    public string Message { get; set; } = default!;

    [BsonElement("actorUserId")]
    public string? ActorUserId { get; set; }

    /// <summary>Имя актора на момент события: пользователь мог быть удалён или переименован.</summary>
    [BsonElement("actorName")]
    public string? ActorName { get; set; }

    /// <summary>Тип цели: "server", "key", "user", "passcode", "system".</summary>
    [BsonElement("targetType")]
    public string? TargetType { get; set; }

    [BsonElement("targetId")]
    public string? TargetId { get; set; }

    /// <summary>Имя цели — колонка справа в журнале.</summary>
    [BsonElement("targetName")]
    public string? TargetName { get; set; }

    /// <summary>
    /// Произвольные детали. Секреты сюда класть нельзя: журнал выгружается
    /// из панели целиком.
    /// </summary>
    [BsonElement("meta")]
    public Dictionary<string, string>? Meta { get; set; }
}

/// <summary>Уровни журнала. Соответствуют тегам info / внимание / ошибка в макете.</summary>
public static class AuditLevels
{
    public const string Info  = "info";
    public const string Warn  = "warn";
    public const string Error = "error";

    public static readonly string[] All = [Info, Warn, Error];
}

/// <summary>Типы целей журнала.</summary>
public static class AuditTargets
{
    public const string Server   = "server";
    public const string Key      = "key";
    public const string User     = "user";
    public const string PassCode = "passcode";
    public const string Notification = "notification";
    public const string System   = "system";
}

/// <summary>
/// Автор события журнала вне HTTP-запроса. Обработчики доменных событий
/// в worker не видят ClaimsPrincipal — его негде взять без запроса, — но имя
/// автора всё равно нужно в колонке «Кто»: панель не должна показывать
/// выдачу ключа без выдавшего.
/// </summary>
public readonly record struct AuditActor(string? UserId, string? Name);
