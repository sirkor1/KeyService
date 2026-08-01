using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;

namespace AmneziaKeyService.Core.Models;

public class User
{
    [BsonId]
    [BsonRepresentation(BsonType.ObjectId)]
    public string Id { get; set; } = default!;

    [BsonElement("username")]
    public string Username { get; set; } = default!;

    [BsonElement("passwordHash")]
    public string PasswordHash { get; set; } = default!;

    [BsonElement("createdAt")]
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    [BsonElement("isActive")]
    public bool IsActive { get; set; } = true;

    /// <summary>
    /// Telegram user ID. Отсутствует у пользователей, зарегистрированных через HTTP API.
    ///
    /// BsonIgnoreIfNull обязателен: индекс по telegramId уникальный и sparse, но sparse
    /// пропускает только отсутствующее поле — явный null индексируется. Без этого атрибута
    /// второй же пользователь без Telegram падал с E11000 duplicate key.
    /// </summary>
    [BsonElement("telegramId")]
    [BsonIgnoreIfNull]
    public long? TelegramId { get; set; }

    /// <summary>
    /// Роль — см. <see cref="UserRoles"/>. По умолчанию client:
    /// новые записи создаются регистрацией и Telegram-ботом, а это всегда конечные VPN-пользователи.
    /// Роли панели назначаются только администратором.
    /// </summary>
    [BsonElement("role")]
    public string Role { get; set; } = UserRoles.Client;

    /// <summary>Статус учётной записи — см. <see cref="UserStatuses"/>.</summary>
    [BsonElement("status")]
    public string Status { get; set; } = UserStatuses.Active;

    /// <summary>Отображаемое имя в панели. Null — показываем Username.</summary>
    [BsonElement("displayName")]
    public string? DisplayName { get; set; }

    /// <summary>Контакт клиента (e-mail или @telegram) — колонка «Контакт» в списке пользователей.</summary>
    [BsonElement("contact")]
    public string? Contact { get; set; }

    /// <summary>Может ли пользователь входить в админ-панель.</summary>
    public bool IsPanelUser => UserRoles.PanelRead.Contains(Role);
}
