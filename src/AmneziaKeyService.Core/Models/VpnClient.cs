using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;

namespace AmneziaKeyService.Core.Models;

/// <summary>
/// Выданный ключ: привязан к пользователю, серверу и конкретному протоколу.
/// Коллекция clients.
/// </summary>
[BsonIgnoreExtraElements]
public class VpnClient
{
    [BsonId]
    [BsonRepresentation(BsonType.ObjectId)]
    public string Id { get; set; } = default!;

    [BsonElement("schemaVersion")]
    public int SchemaVersion { get; set; } = 2;

    /// <summary>Ссылка на User.Id.</summary>
    [BsonElement("userId")]
    [BsonRepresentation(BsonType.ObjectId)]
    public string UserId { get; set; } = default!;

    /// <summary>
    /// ID сервера (VpnServer.Id). Хранится строкой, а не ObjectId: так было
    /// в исходной схеме, и на этом поле завязаны все выданные ботом ключи.
    /// </summary>
    [BsonElement("serverId")]
    public string ServerId { get; set; } = default!;

    /// <summary>
    /// ID протокола внутри сервера. Null у ключей, выданных до перехода
    /// на мультипротокол — они относятся к протоколу по умолчанию.
    /// </summary>
    [BsonElement("protocolId")]
    public string? ProtocolId { get; set; }

    /// <summary>Дублирует вид протокола, чтобы не поднимать сервер ради отображения списка.</summary>
    [BsonElement("protocolKind")]
    public string? ProtocolKind { get; set; }

    /// <summary>Короткий человекочитаемый идентификатор: KEY-7F3A. Уникален.</summary>
    [BsonElement("shortId")]
    public string? ShortId { get; set; }

    // ── Описание для панели ───────────────────────────────────────────────────

    /// <summary>Владелец ключа, как его ввели при выдаче. Null — берём имя пользователя.</summary>
    [BsonElement("ownerName")]
    public string? OwnerName { get; set; }

    /// <summary>Устройство: «iPhone 15», «Ноутбук Lenovo».</summary>
    [BsonElement("deviceName")]
    public string? DeviceName { get; set; }

    [BsonElement("label")]
    public string? Label { get; set; }

    // ── Криптография ──────────────────────────────────────────────────────────

    /// <summary>Назначенный туннельный IP, напр. "10.8.1.2". Только для WireGuard-семейства.</summary>
    [BsonElement("assignedIp")]
    public string? AssignedIp { get; set; }

    [BsonElement("clientPrivKey")]
    public string? ClientPrivKey { get; set; }

    [BsonElement("clientPubKey")]
    public string? ClientPubKey { get; set; }

    [BsonElement("pskKey")]
    public string? PskKey { get; set; }

    /// <summary>UUID клиента в Xray. Только для протокола xray.</summary>
    [BsonElement("xrayClientId")]
    public string? XrayClientId { get; set; }

    /// <summary>Готовый JSON конфига AmneziaVPN — до кодирования в vpn://.</summary>
    [BsonElement("vpnConfigJson")]
    public string? VpnConfigJson { get; set; }

    // ── Жизненный цикл ────────────────────────────────────────────────────────

    /// <summary>См. <see cref="KeyStatuses"/>.</summary>
    [BsonElement("status")]
    public string Status { get; set; } = KeyStatuses.Active;

    /// <summary>
    /// Legacy-флаг. Держится синхронно со Status через <see cref="SetStatus"/>:
    /// на нём завязаны запросы репозитория, от которых зависит Telegram-бот.
    /// </summary>
    [BsonElement("isActive")]
    public bool IsActive { get; set; } = true;

    [BsonElement("expiresAt")]
    public DateTime? ExpiresAt { get; set; }

    /// <summary>Квота трафика в байтах. Null — без ограничения.</summary>
    [BsonElement("trafficLimitBytes")]
    public long? TrafficLimitBytes { get; set; }

    [BsonElement("usage")]
    public KeyUsage Usage { get; set; } = new();

    /// <summary>
    /// Когда о скором истечении ключа предупредили в журнале. Без этой отметки
    /// воркер писал бы предупреждение на каждом тике все семь дней подряд.
    ///
    /// BsonIgnoreIfNull, а не явный null: на sparse-индексах явный null ведёт
    /// себя не как отсутствие поля — на этом уже наступали с TelegramId.
    /// </summary>
    [BsonElement("expiryWarnedAt")]
    [BsonIgnoreIfNull]
    public DateTime? ExpiryWarnedAt { get; set; }

    [BsonElement("revokedAt")]
    public DateTime? RevokedAt { get; set; }

    [BsonElement("revokedByUserId")]
    public string? RevokedByUserId { get; set; }

    /// <summary>"manual" | "expired" | "quota".</summary>
    [BsonElement("revokeReason")]
    public string? RevokeReason { get; set; }

    [BsonElement("createdAt")]
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    [BsonElement("createdByUserId")]
    public string? CreatedByUserId { get; set; }

    /// <summary>См. <see cref="KeySources"/>.</summary>
    [BsonElement("source")]
    public string Source { get; set; } = KeySources.Panel;

    /// <summary>Меняет статус, не давая IsActive и Status разойтись.</summary>
    public void SetStatus(string status)
    {
        Status   = status;
        IsActive = status == KeyStatuses.Active;
    }

    public bool IsExpired => ExpiresAt is { } e && e <= DateTime.UtcNow;

    public bool IsOverQuota => TrafficLimitBytes is { } limit && Usage.TotalBytes >= limit;
}

/// <summary>
/// Учёт трафика по ключу.
///
/// RxRaw/TxRaw — последние сырые показания счётчиков контейнера. Они монотонны
/// с момента старта контейнера и обнуляются при рестарте, поэтому накопленные
/// RxBytes/TxBytes считаются приращениями с учётом обнуления.
/// </summary>
[BsonIgnoreExtraElements]
public class KeyUsage
{
    [BsonElement("rxBytes")]
    public long RxBytes { get; set; }

    [BsonElement("txBytes")]
    public long TxBytes { get; set; }

    [BsonElement("rxRaw")]
    public long RxRaw { get; set; }

    [BsonElement("txRaw")]
    public long TxRaw { get; set; }

    [BsonElement("lastHandshakeAt")]
    public DateTime? LastHandshakeAt { get; set; }

    [BsonElement("lastSeenAt")]
    public DateTime? LastSeenAt { get; set; }

    public long TotalBytes => RxBytes + TxBytes;

    /// <summary>Считаем клиента подключённым, если хендшейк был не более трёх минут назад.</summary>
    public bool IsOnline =>
        LastHandshakeAt is { } h && DateTime.UtcNow - h < TimeSpan.FromMinutes(3);
}
