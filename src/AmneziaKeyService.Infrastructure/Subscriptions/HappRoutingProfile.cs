using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using AmneziaKeyService.Core.Models;

namespace AmneziaKeyService.Infrastructure.Subscriptions;

/// <summary>
/// Профиль маршрутизации Happ для заголовка <c>routing</c> ответа <c>/sub/</c>: российские сайты и адреса идут
/// напрямую с устройства пользователя (сайты видят его домашний IP), а заблокированные в РФ — через туннель.
/// Входу российский трафик при этом не достаётся вовсе. Формат — https://www.happ.su/main/dev-docs/routing.md.
///
/// Профиль статичен, кроме названия. <see cref="LastUpdated"/> поэтому константа, а не «сейчас»: Happ
/// перекачивает geo-файлы, когда <c>LastUpdated</c> выросло (и не чаще раза в неделю), и значение «сейчас»
/// заставляло бы его делать это на каждом обновлении подписки. Менять содержимое профиля можно, только подняв
/// <see cref="LastUpdated"/>: иначе приложения не заметят правку (tools/VerifySubscriptions сверяет отпечаток
/// содержимого и падает, если константа не тронута).
/// </summary>
public static class HappRoutingProfile
{
    public const string HeaderName = "routing";
    public const string DefaultName = "RU direct";
    public const int NameMaxLength = 30;

    /// <summary>
    /// Время последней правки содержимого профиля (unix, секунды). Поднимается вручную вместе с правкой
    /// <see cref="Build"/>; текущее значение — 2026-10-29 00:00:00 UTC.
    /// </summary>
    public const long LastUpdated = 1793232000;

    // Файлы runetfreedom: теги ru-blocked и ru-available-only-inside есть только в них, встроенные списки Happ
    // их не содержат. Тот же репозиторий, из которого вход получает свои списки (XCore:RfListsRepo по умолчанию).
    private const string GeoBase = "https://github.com/runetfreedom/russia-v2ray-rules-dat/releases/latest/download/";
    public const string GeoipUrl = GeoBase + "geoip.dat";
    public const string GeositeUrl = GeoBase + "geosite.dat";

    /// <summary>
    /// Значение заголовка или null, если профиль выключен. Название — часть профиля: Happ обновляет профиль с
    /// тем же именем и добавляет новый при другом.
    /// </summary>
    public static string? HeaderValue(SubscriptionOptions options)
    {
        if (!options.HappRoutingEnabled) return null;
        return "happ://routing/add/" + Convert.ToBase64String(Encoding.UTF8.GetBytes(Build(options.HappRoutingName)));
    }

    /// <summary>
    /// JSON профиля. Логические значения Happ — строки («true»/«false», как в его документации), порядок полей
    /// фиксирован, чтобы тело ответа не менялось от запроса к запросу.
    /// </summary>
    public static string Build(string? name) => new JsonObject
    {
        ["Name"] = NormalizeName(name),
        ["GlobalProxy"] = "true",
        ["DomainStrategy"] = "IPIfNonMatch",
        ["FakeDNS"] = "false",
        ["LastUpdated"] = LastUpdated.ToString(),
        // Запросы туннеля — DoH Cloudflare, как в профиле Happ по умолчанию: уходят через VPN, и российский
        // резолвер их не видит.
        ["RemoteDNSType"] = "DoH",
        ["RemoteDNSDomain"] = "https://cloudflare-dns.com/dns-query",
        ["RemoteDNSIP"] = "1.1.1.1",
        // Прямые запросы — российский резолвер (Яндекс) по IP: ответы для российских CDN подходят российскому
        // адресу, а запрос по IP не требует ни имени, ни TLS, то есть не зависит от самого DNS. Домен пуст, тип
        // DoU — как в примере из документации Happ; DoH-адрес Яндекса проверить стабильно не удалось.
        ["DomesticDNSType"] = "DoU",
        ["DomesticDNSDomain"] = "",
        ["DomesticDNSIP"] = "77.88.8.8",
        ["DnsHosts"] = new JsonObject { ["cloudflare-dns.com"] = "1.1.1.1" },
        ["Geoipurl"] = GeoipUrl,
        ["Geositeurl"] = GeositeUrl,
        ["DirectSites"] = Strings("geosite:category-ru", "geosite:category-gov-ru", "geosite:ru-available-only-inside"),
        ["DirectIp"] = Strings("geoip:ru", "geoip:private"),
        ["ProxySites"] = Strings("geosite:ru-blocked"),
        ["ProxyIp"] = Strings(),
        ["BlockSites"] = Strings(),
        ["BlockIp"] = Strings(),
    }.ToJsonString();

    /// <summary>SHA-256 содержимого без названия и <see cref="LastUpdated"/> — для проверки «правка без подъёма константы».</summary>
    public static string ContentFingerprint()
    {
        var node = JsonNode.Parse(Build(DefaultName))!.AsObject();
        node.Remove("Name");
        node.Remove("LastUpdated");
        return Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(node.ToJsonString())));
    }

    public static string NormalizeName(string? name)
    {
        var trimmed = string.IsNullOrWhiteSpace(name) ? DefaultName : name.Trim();
        if (trimmed.Length <= NameMaxLength) return trimmed;
        var cut = NameMaxLength;
        // Без разрыва суррогатной пары (эмодзи в названии).
        if (char.IsHighSurrogate(trimmed[cut - 1])) cut--;
        return trimmed[..cut];
    }

    private static JsonArray Strings(params string[] values) =>
        new([.. values.Select(v => (JsonNode)JsonValue.Create(v)!)]);
}
