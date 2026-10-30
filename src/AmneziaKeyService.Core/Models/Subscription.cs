using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;

namespace AmneziaKeyService.Core.Models;

/// <summary>
/// Подписка на VPN через клиент с поддержкой ссылок-подписок (Happ, v2ray-клиенты):
/// одна постоянная ссылка, за которой стоят все узлы xcore. Живёт отдельно от ключей
/// <see cref="VpnClient"/> и не зависит от них. Коллекция subscriptions.
/// </summary>
[BsonIgnoreExtraElements]
public class Subscription
{
    /// <summary>Email пользователя в Xray — ключ в счётчиках трафика и в API узла.</summary>
    public const string XrayEmailPrefix = "sub-";

    [BsonId]
    [BsonRepresentation(BsonType.ObjectId)]
    public string Id { get; set; } = default!;

    /// <summary>Ссылка на User.Id. Активная подписка у пользователя одна — это держит индекс.</summary>
    [BsonElement("userId")]
    [BsonRepresentation(BsonType.ObjectId)]
    public string UserId { get; set; } = default!;

    /// <summary>См. <see cref="SubscriptionStatuses"/>.</summary>
    [BsonElement("status")]
    public string Status { get; set; } = SubscriptionStatuses.Active;

    /// <summary>См. <see cref="Interfaces.RevokeReasons"/>; задано только у отозванной подписки.</summary>
    [BsonElement("revokeReason")]
    [BsonIgnoreIfNull]
    public string? RevokeReason { get; set; }

    [BsonElement("expiresAt")]
    public DateTime? ExpiresAt { get; set; }

    /// <summary>Квота трафика в байтах. Null — без ограничения.</summary>
    [BsonElement("trafficLimitBytes")]
    public long? TrafficLimitBytes { get; set; }

    /// <summary>
    /// UUID пользователя VLESS — один на все узлы. Он есть в каждой ссылке на узел, поэтому
    /// при перевыпуске меняется вместе с токеном: иначе старая ссылка продолжала бы работать
    /// на уже импортированных устройствах. Это учётные данные: наружу не отдаётся.
    /// </summary>
    [BsonElement("xrayUuid")]
    public string XrayUuid { get; set; } = default!;

    /// <summary>SHA-256 токена (hex): по нему ищется подписка в <c>/sub/{token}</c>.</summary>
    [BsonElement("tokenHash")]
    public string TokenHash { get; set; } = default!;

    /// <summary>
    /// Токен в зашифрованном виде — тем же способом, что SSH-пароли. Хеша для показа ссылки
    /// недостаточно: пользователь запрашивает её повторно, а перевыпуск ради этого отключал бы
    /// уже настроенные устройства.
    /// </summary>
    [BsonElement("tokenEncrypted")]
    public EncryptedValue? TokenEncrypted { get; set; }

    /// <summary>
    /// Накопленный трафик с точки зрения клиента: <c>RxBytes</c> — полученное им (downlink Xray),
    /// <c>TxBytes</c> — отправленное (uplink). Так же их читает заголовок <c>subscription-userinfo</c>.
    /// Сырые показания здесь не используются (<c>RxRaw</c>/<c>TxRaw</c> остаются нулями):
    /// у подписки счётчики на каждом узле свои — см. <see cref="RawByNode"/>.
    /// </summary>
    [BsonElement("usage")]
    public KeyUsage Usage { get; set; } = new();

    /// <summary>
    /// Сырые показания счётчиков Xray последнего опроса по узлам: serverId → (rx, tx).
    /// Счётчики обнуляются при перезапуске контейнера, поэтому накопление идёт приращениями
    /// от этих значений (<c>UsageMath.Delta</c>), а не присваиванием.
    /// </summary>
    [BsonElement("rawByNode")]
    public Dictionary<string, SubscriptionNodeRaw> RawByNode { get; set; } = [];

    [BsonElement("createdAt")]
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    [BsonElement("createdByUserId")]
    [BsonIgnoreIfNull]
    public string? CreatedByUserId { get; set; }

    [BsonElement("revokedAt")]
    [BsonIgnoreIfNull]
    public DateTime? RevokedAt { get; set; }

    /// <summary>Когда токен и UUID перевыпускались в последний раз.</summary>
    [BsonElement("tokenRotatedAt")]
    [BsonIgnoreIfNull]
    public DateTime? TokenRotatedAt { get; set; }

    /// <summary>Откуда создана: <see cref="KeySources.Telegram"/> или <see cref="KeySources.Panel"/>.</summary>
    [BsonElement("source")]
    public string Source { get; set; } = KeySources.Panel;

    public string XrayEmail => XrayEmailPrefix + Id;

    public bool IsActive => Status == SubscriptionStatuses.Active;

    public bool IsExpired(DateTime now) => ExpiresAt is { } e && e <= now;

    public bool IsOverQuota => TrafficLimitBytes is { } limit && Usage.TotalBytes >= limit;

    /// <summary>Подписка отдаёт ссылки: активна и срок не истёк (отзыв по сроку идёт с задержкой воркера).</summary>
    public bool IsServing(DateTime now) => IsActive && !IsExpired(now);

    /// <summary>Id подписки из email Xray; null, если email не в формате <c>sub-{id}</c>.</summary>
    public static string? IdFromXrayEmail(string email) =>
        email.StartsWith(XrayEmailPrefix, StringComparison.Ordinal)
        && ObjectId.TryParse(email[XrayEmailPrefix.Length..], out _)
            ? email[XrayEmailPrefix.Length..]
            : null;
}

/// <summary>Сырые показания счётчиков подписки на одном узле (с точки зрения клиента).</summary>
[BsonIgnoreExtraElements]
public class SubscriptionNodeRaw
{
    [BsonElement("rx")]
    public long Rx { get; set; }

    [BsonElement("tx")]
    public long Tx { get; set; }
}

public static class SubscriptionStatuses
{
    public const string Active  = "active";
    public const string Revoked = "revoked";

    public static readonly string[] All = [Active, Revoked];
}
