using MongoDB.Bson.Serialization.Attributes;

namespace AmneziaKeyService.Core.Models;

/// <summary>
/// Параметры обфускации AmneziaWG — Jc, S1-S4, H1-H4, I1-I5.
/// Соответствуют полям секции [Interface] в конфиге сервера.
///
/// Клиент ОБЯЗАН передавать ровно те же значения, что стоят на сервере:
/// расхождение не даёт ошибки, хэндшейк просто не проходит.
/// </summary>
[BsonIgnoreExtraElements]
public class AwgObfuscationParams
{
    // Количество и размер мусорных пакетов
    [BsonElement("jc")]   public string Jc   { get; set; } = "3";
    [BsonElement("jmin")] public string Jmin { get; set; } = "10";
    [BsonElement("jmax")] public string Jmax { get; set; } = "30";

    // Размер мусора: init / response / cookie-reply / transport
    [BsonElement("s1")] public string S1 { get; set; } = "15";
    [BsonElement("s2")] public string S2 { get; set; } = "18";
    [BsonElement("s3")] public string S3 { get; set; } = "20";
    [BsonElement("s4")] public string S4 { get; set; } = "23";

    // Магические заголовки
    [BsonElement("h1")] public string H1 { get; set; } = "1020325451";
    [BsonElement("h2")] public string H2 { get; set; } = "3288052141";
    [BsonElement("h3")] public string H3 { get; set; } = "1766607858";
    [BsonElement("h4")] public string H4 { get; set; } = "2528465083";

    // Специальные мусорные пакеты. I1 обычно содержит DNS-запрос-заглушку,
    // I2-I5 чаще пусты.
    [BsonElement("i1")] public string I1 { get; set; } =
        "<r 2><b 0x858000010001000000000669636c6f756403636f6d0000010001c00c000100010000105a00044d583737>";
    [BsonElement("i2")] public string I2 { get; set; } = "";
    [BsonElement("i3")] public string I3 { get; set; } = "";
    [BsonElement("i4")] public string I4 { get; set; } = "";
    [BsonElement("i5")] public string I5 { get; set; } = "";

    [BsonElement("headerProtectionKey")] public string HeaderProtectionKey { get; set; } = "";
    [BsonElement("contentPaddingAddition")] public string ContentPaddingAddition { get; set; } = "";
    [BsonElement("rekeyAfterTime")] public string RekeyAfterTime { get; set; } = "";
    [BsonElement("rekeyTimeout")] public string RekeyTimeout { get; set; } = "";
    [BsonElement("rejectAfterTime")] public string RejectAfterTime { get; set; } = "";
    [BsonElement("keepaliveTimeout")] public string KeepaliveTimeout { get; set; } = "";
    [BsonElement("maxHandshakeAttempts")] public string MaxHandshakeAttempts { get; set; } = "";
    [BsonElement("randomTrailers")] public string RandomTrailers { get; set; } = "";
    [BsonElement("disableCookies")] public string DisableCookies { get; set; } = "";

    /// <summary>MTU: 1280 на мобильных, 1376 на десктопах.</summary>
    [BsonElement("mtu")] public string Mtu { get; set; } = "1376";
}
