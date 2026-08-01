using MongoDB.Bson.Serialization.Attributes;

namespace AmneziaKeyService.Core.Models;

/// <summary>
/// Настройки панели — экран «Настройки панели». Единственный документ
/// в коллекции panel_settings с фиксированным _id.
/// </summary>
[BsonIgnoreExtraElements]
public class PanelSettings
{
    public const string SingletonId = "panel";

    [BsonId]
    public string Id { get; set; } = SingletonId;

    // ── Выдача ключей по умолчанию ────────────────────────────────────────────

    /// <summary>Срок действия нового ключа в днях. Null — бессрочно.</summary>
    [BsonElement("defaultExpiryDays")]
    public int? DefaultExpiryDays { get; set; } = 90;

    /// <summary>Сколько устройств разрешено одному клиенту. Null — без ограничения.</summary>
    [BsonElement("deviceLimitPerClient")]
    public int? DeviceLimitPerClient { get; set; } = 3;

    /// <summary>См. <see cref="ProtocolKinds"/>.</summary>
    [BsonElement("defaultProtocolKind")]
    public string DefaultProtocolKind { get; set; } = ProtocolKinds.Awg2;

    /// <summary>Квота трафика на ключ по умолчанию, байты. Null — без лимита.</summary>
    [BsonElement("defaultTrafficLimitBytes")]
    public long? DefaultTrafficLimitBytes { get; set; }

    // ── Безопасность ──────────────────────────────────────────────────────────

    /// <summary>
    /// Скрывать секреты в интерфейсе. Значение справочное: панель в любом случае
    /// не может показать приватный ключ повторно — он не хранится в открытом виде
    /// после выдачи.
    /// </summary>
    [BsonElement("maskSecrets")]
    public bool MaskSecrets { get; set; } = true;

    /// <summary>Двухфакторный вход. Пока не реализован — в панели тумблер задизейблен.</summary>
    [BsonElement("twoFactorEnabled")]
    public bool TwoFactorEnabled { get; set; }

    /// <summary>Куда слать уведомления о падении узла: "@vpn_ops_bot" или пусто.</summary>
    [BsonElement("alertTelegramChat")]
    public string? AlertTelegramChat { get; set; }

    [BsonElement("updatedAt")]
    public DateTime? UpdatedAt { get; set; }

    [BsonElement("updatedByUserId")]
    public string? UpdatedByUserId { get; set; }
}

/// <summary>
/// Правила для действительно применяемых настроек выдачи ключей. Они вынесены
/// из контроллера, чтобы их можно было проверить автономной консольной
/// проверкой без HTTP- и MongoDB-окружения.
/// </summary>
public static class PanelSettingsRules
{
    public const int MinDefaultExpiryDays = 1;
    public const int MaxDefaultExpiryDays = 3650;
    public const long MinDefaultTrafficLimitBytes = 1024L * 1024L;
    public const long MaxDefaultTrafficLimitBytes = 10L * 1024 * 1024 * 1024 * 1024;

    /// <summary>Null означает «без ограничения».</summary>
    public static bool TryValidate(
        int? defaultExpiryDays,
        long? defaultTrafficLimitBytes,
        out string? error)
    {
        if (defaultExpiryDays is < MinDefaultExpiryDays or > MaxDefaultExpiryDays)
        {
            error = $"Срок по умолчанию должен быть от {MinDefaultExpiryDays} до {MaxDefaultExpiryDays} дней либо пустым для бессрочного ключа.";
            return false;
        }

        if (defaultTrafficLimitBytes is < MinDefaultTrafficLimitBytes or > MaxDefaultTrafficLimitBytes)
        {
            error = "Лимит трафика по умолчанию должен быть от 1 МиБ до 10 ТиБ либо пустым для отсутствия лимита.";
            return false;
        }

        error = null;
        return true;
    }
}
