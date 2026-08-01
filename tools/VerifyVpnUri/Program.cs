using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using AmneziaKeyService.Core.Models;
using AmneziaKeyService.Infrastructure.Protocols;
using AmneziaKeyService.Infrastructure.Scripts;
using AmneziaKeyService.Infrastructure.Services;

// Проверяет формат конфига vpn:// без обращения к серверам.
//
// Зачем: коллекция clients пуста — значит ни один ключ, собранный этим
// сервисом, ни разу не импортировался в живой AmneziaVPN. Ошибка формата
// проявляется не сообщением, а несостоявшимся хэндшейком, поэтому структура
// сверяется здесь, поле за полем, с ожиданиями exportController.cpp
// и конфигураторов из amnezia-client.

var failures = new List<string>();
var checks = 0;

void Check(string name, bool ok, string? detail = null)
{
    checks++;
    Console.WriteLine($"  [{(ok ? "OK  " : "ПРОВАЛ")}] {name}{(detail is null ? "" : $" — {detail}")}");
    if (!ok) failures.Add(name);
}

Console.OutputEncoding = Encoding.UTF8;

// ── Тестовые данные ──────────────────────────────────────────────────────────
// Значения обфускации взяты с боевого узла: у него нестандартные S1/S2
// и нулевые S3/S4, а такие комбинации ломаются чаще «красивых» дефолтов.

var server = new VpnServer
{
    Id   = "69ca5beaba00e3c10adc451d",
    Name = "FirstByte Germany",
    Host = "89.44.85.223",
    Dns1 = "1.1.1.1",
    Dns2 = "8.8.8.8",
};

var wgProtocol = new ProtocolInstance
{
    Id             = "1ff8453f9dca41f89531b10d5156057d",
    Kind           = ProtocolKinds.AwgLegacy,
    ContainerName  = "amnezia-awg",
    Port           = "42174",
    TransportProto = "udp",
    Mtu            = "1376",
    Wg = new WgProtocolParams
    {
        InterfaceName    = "wg0",
        Binary           = "wg",
        ServerConfigPath = "/opt/amnezia/awg/wg0.conf",
        SubnetAddress    = "10.8.1.0",
        SubnetCidr       = "24",
        ServerPubKey     = "kJ8zQwErTyUiOpAsDfGhJkLzXcVbNmQwErTyUiOpAs0=",
        PskKey           = "pSk1234567890AbCdEfGhIjKlMnOpQrStUvWxYz9876=",
        Obfuscation = new AwgObfuscationParams
        {
            Jc = "6", Jmin = "10", Jmax = "50",
            S1 = "132", S2 = "88", S3 = "0", S4 = "0",
            H1 = "1461826852", H2 = "788998698", H3 = "656934058", H4 = "2125120218",
            I1 = "", I2 = "", I3 = "", I4 = "", I5 = "",
            Mtu = "1376",
        },
    },
};

var wgClient = new VpnClient
{
    Id            = "6a6be0178a32c6160e84c07d",
    ShortId       = "KEY-7F3A2B",
    AssignedIp    = "10.8.1.15",
    ClientPrivKey = "cLiEnTpRiVaTeKeY1234567890AbCdEfGhIjKlMnOp0=",
    ClientPubKey  = "cLiEnTpUbLiCkEy1234567890AbCdEfGhIjKlMnOpQ0=",
    PskKey        = "pSk1234567890AbCdEfGhIjKlMnOpQrStUvWxYz9876=",
};

var scripts = new ScriptRegistry();

// ── Шаблоны на месте ─────────────────────────────────────────────────────────

Console.WriteLine("\n== Встроенные шаблоны ==");
foreach (var path in new[] { "awg/template.conf", "awg_legacy/template.conf",
                             "wireguard/template.conf", "xray/template.json" })
{
    string? content = null;
    try { content = scripts.Read(path); } catch { /* сообщим ниже */ }
    Check($"шаблон {path} читается", content is { Length: > 0 });
    Check($"шаблон {path} без CR", content?.Contains('\r') == false);
}

// ── Подстановка переменных ───────────────────────────────────────────────────

Console.WriteLine("\n== Подстановка $VAR ==");
{
    var rendered = ScriptTemplateRenderer.Render(
        "a=$FOO b=$FOOBAR c=$CUR_USER",
        new Dictionary<string, string> { ["FOO"] = "1", ["FOOBAR"] = "2" });

    Check("длинный ключ не съеден коротким префиксом", rendered.Contains("b=2"), rendered);
    Check("короткий ключ подставлен", rendered.Contains("a=1"));
    Check("чужая shell-переменная не тронута", rendered.Contains("$CUR_USER"));
}

// ── Конфиг WireGuard ─────────────────────────────────────────────────────────

Console.WriteLine("\n== Клиентский .conf (AmneziaWG) ==");

var wgConfigurator = new WireGuardConfigurator(
    WireGuardProfile.AwgLegacy, scripts, new KeyGenerationService(), null!);

var entry = wgConfigurator.BuildContainerEntry(server, wgProtocol, wgClient);
var lastConfigRaw = entry["awg"]!["last_config"]!.GetValue<string>();
var lastConfig = JsonNode.Parse(lastConfigRaw)!.AsObject();
var confText = lastConfig["config"]!.GetValue<string>();

Check("Address совпадает с выданным IP", confText.Contains("Address = 10.8.1.15/32"));
Check("PrivateKey клиента на месте", confText.Contains($"PrivateKey = {wgClient.ClientPrivKey}"));
Check("PublicKey сервера на месте", confText.Contains($"PublicKey = {wgProtocol.Wg!.ServerPubKey}"));
Check("PresharedKey на месте", confText.Contains($"PresharedKey = {wgClient.PskKey}"));
Check("Endpoint с реальным портом", confText.Contains("Endpoint = 89.44.85.223:42174"));
Check("AllowedIPs полный туннель", confText.Contains("AllowedIPs = 0.0.0.0/0, ::/0"));
Check("PersistentKeepalive = 25", confText.Contains("PersistentKeepalive = 25"));
Check("DNS из настроек узла", confText.Contains("DNS = 1.1.1.1, 8.8.8.8"));
Check("параметры обфускации подставлены", confText.Contains("Jc = 6") && confText.Contains("S1 = 132"));

// В шаблоне awg_legacy строк S3/S4 нет вовсе: legacy-версия AmneziaWG их
// не поддерживает. Клиент обязан передавать ровно тот набор, что есть
// на сервере, поэтому лишние строки здесь были бы ошибкой.
Check("legacy не передаёт S3/S4 в .conf",
    !confText.Contains("S3 =") && !confText.Contains("S4 ="));
Check("пустые I1-I5 не попали в конфиг", !confText.Contains("I1 ="));
Check("нет незамещённых плейсхолдеров", !confText.Contains('$'), FirstDollar(confText));
Check("переводы строк только LF", !confText.Contains('\r'));

Console.WriteLine("\n== last_config (AmneziaWG) ==");
Check("last_config — строка, а не объект", entry["awg"]!["last_config"] is JsonValue);
foreach (var key in new[] { "config", "client_priv_key", "client_pub_key", "server_pub_key",
                            "psk_key", "client_ip", "hostName", "port", "mtu",
                            "persistent_keep_alive", "allowed_ips", "clientId" })
{
    Check($"есть поле {key}", lastConfig.ContainsKey(key));
}
Check("port — число, а не строка", lastConfig["port"] is JsonValue v && v.GetValue<int>() == 42174);
Check("clientId равен публичному ключу клиента",
    lastConfig["clientId"]!.GetValue<string>() == wgClient.ClientPubKey);
Check("обфускация заглавными ключами", lastConfig.ContainsKey("Jc") && lastConfig.ContainsKey("H1"));
Check("legacy без S3/S4 в last_config",
    !lastConfig.ContainsKey("S3") && !lastConfig.ContainsKey("S4"));

Console.WriteLine("\n== containers[] (AmneziaWG) ==");
Check("container совпадает с именем контейнера",
    entry["container"]!.GetValue<string>() == "amnezia-awg");
Check("ключ протокола awg", entry["awg"] is not null);
Check("обфускация строчными ключами на верхнем уровне",
    entry["awg"]!["jc"] is not null && entry["awg"]!["h1"] is not null);
Check("legacy без protocol_version", entry["awg"]!["protocol_version"] is null);

{
    var awg2Entry = new WireGuardConfigurator(
        WireGuardProfile.Awg2, scripts, new KeyGenerationService(), null!)
        .BuildContainerEntry(server, wgProtocol, wgClient);

    Check("awg2 добавляет protocol_version=2",
        awg2Entry["awg"]!["protocol_version"]?.GetValue<string>() == "2");

    var awg2Last = JsonNode.Parse(awg2Entry["awg"]!["last_config"]!.GetValue<string>())!.AsObject();
    Check("awg2 передаёт S3/S4", awg2Last.ContainsKey("S3") && awg2Last.ContainsKey("S4"));
}

// ── Кодирование vpn:// ───────────────────────────────────────────────────────

Console.WriteLine("\n== Кодирование vpn:// ==");

var root = new JsonObject
{
    ["hostName"]         = server.Host,
    ["description"]      = server.Name,
    ["dns1"]             = server.Dns1,
    ["dns2"]             = server.Dns2,
    ["defaultContainer"] = wgProtocol.ContainerName,
    ["containers"]       = new JsonArray(entry.DeepClone()),
};

var json = root.ToJsonString(new JsonSerializerOptions
{
    Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
});

var uri = AmneziaUriEncoder.Encode(json);

Check("префикс vpn://", uri.StartsWith("vpn://", StringComparison.Ordinal));

// Проверяем полезную нагрузку, а не всю строку: сам префикс содержит «/».
var encoded = uri["vpn://".Length..];
Check("base64url без padding",
    !encoded.Contains('=') && !encoded.Contains('+') && !encoded.Contains('/'));

var payload = Convert.FromBase64String(
    encoded.Replace('-', '+').Replace('_', '/')
           .PadRight((encoded.Length + 3) / 4 * 4, '='));

var declaredSize = (payload[0] << 24) | (payload[1] << 16) | (payload[2] << 8) | payload[3];
Check("заголовок qCompress = длине исходного JSON",
    declaredSize == Encoding.UTF8.GetByteCount(json), $"{declaredSize} против {Encoding.UTF8.GetByteCount(json)}");
Check("следом идёт поток zlib (RFC 1950)", payload[4] == 0x78, $"0x{payload[4]:x2}");

var decoded = AmneziaUriEncoder.Decode(uri);
Check("декодирование возвращает исходный JSON", decoded == json);

Console.WriteLine("\n== Экранирование ==");
{
    // I1 содержит «<r 2><b 0x…>». Со стандартным энкодером < превращается
    // в <, и клиент такой конфиг не принимает.
    var withJunk = new AwgObfuscationParams { I1 = "<r 2><b 0x8580>" };
    var protoWithJunk = new ProtocolInstance
    {
        Kind = ProtocolKinds.AwgLegacy, ContainerName = "amnezia-awg", Port = "42174",
        Wg = new WgProtocolParams { ServerPubKey = "x", PskKey = "y", Obfuscation = withJunk },
    };

    var junkEntry = wgConfigurator.BuildContainerEntry(server, protoWithJunk, wgClient);
    var junkJson = new JsonObject { ["containers"] = new JsonArray(junkEntry.DeepClone()) }
        .ToJsonString(new JsonSerializerOptions
        {
            Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
        });

    Check("угловые скобки в I1 на верхнем уровне не экранированы", junkJson.Contains("<r 2>"));

    // Внутри last_config тоже: это отдельная сериализация со своим энкодером.
    var junkLast = junkEntry["awg"]!["last_config"]!.GetValue<string>();
    Check("угловые скобки в last_config не экранированы",
        junkLast.Contains("<r 2>"), FirstJunk(junkLast));

    // И главное — что клиент получит после разбора, каким бы ни было экранирование.
    var junkParsed = JsonNode.Parse(junkLast)!.AsObject();
    Check("после разбора last_config I1 восстанавливается",
        junkParsed["I1"]!.GetValue<string>() == "<r 2><b 0x8580>");
}

// ── Конфиг Xray ──────────────────────────────────────────────────────────────

Console.WriteLine("\n== Клиентский конфиг (VLESS Reality) ==");
{
    var xrayProtocol = new ProtocolInstance
    {
        Id = "p2", Kind = ProtocolKinds.Xray, ContainerName = "amnezia-xray",
        Port = "443", TransportProto = "tcp",
        Xray = new XrayProtocolParams
        {
            SiteName  = "www.googletagmanager.com",
            PublicKey = "xRaYpUbLiCkEy1234567890AbCdEfGhIjKlMnOpQrSt",
            ShortId   = "a1b2c3d4e5f60718",
        },
    };

    var xrayClient = new VpnClient
    {
        Id = "x1", ShortId = "KEY-XR001",
        XrayClientId = "7b1f2e3d-4c5b-6a79-8899-aabbccddeeff",
    };

    var xray = new XrayConfigurator(
        scripts, Microsoft.Extensions.Logging.Abstractions.NullLogger<XrayConfigurator>.Instance);

    var xrayEntry = xray.BuildContainerEntry(server, xrayProtocol, xrayClient);
    var xrayLast = JsonNode.Parse(xrayEntry["xray"]!["last_config"]!.GetValue<string>())!.AsObject();

    Check("container = amnezia-xray", xrayEntry["container"]!.GetValue<string>() == "amnezia-xray");

    var outbound = xrayLast["outbounds"]!.AsArray()[0]!.AsObject();
    var vnext = outbound["settings"]!["vnext"]!.AsArray()[0]!.AsObject();
    var user = vnext["users"]!.AsArray()[0]!.AsObject();
    var reality = outbound["streamSettings"]!["realitySettings"]!.AsObject();

    Check("protocol = vless", outbound["protocol"]!.GetValue<string>() == "vless");
    Check("адрес узла подставлен", vnext["address"]!.GetValue<string>() == server.Host);
    Check("порт числом", vnext["port"]!.GetValue<int>() == 443);
    Check("uuid клиента подставлен", user["id"]!.GetValue<string>() == xrayClient.XrayClientId);
    Check("flow = xtls-rprx-vision", user["flow"]!.GetValue<string>() == "xtls-rprx-vision");
    Check("security = reality",
        outbound["streamSettings"]!["security"]!.GetValue<string>() == "reality");
    Check("SNI подставлен", reality["serverName"]!.GetValue<string>() == "www.googletagmanager.com");
    Check("публичный ключ Reality подставлен",
        reality["publicKey"]!.GetValue<string>() == xrayProtocol.Xray!.PublicKey);
    Check("shortId подставлен", reality["shortId"]!.GetValue<string>() == xrayProtocol.Xray.ShortId);
    Check("fingerprint = chrome", reality["fingerprint"]!.GetValue<string>() == "chrome");
    Check("локальный socks на 10808",
        xrayLast["inbounds"]!.AsArray()[0]!["port"]!.GetValue<int>() == 10808);
}

// ── Итог ─────────────────────────────────────────────────────────────────────

Console.WriteLine($"\nПроверок: {checks}, провалов: {failures.Count}");
if (failures.Count > 0)
{
    Console.WriteLine("Провалились:");
    foreach (var f in failures) Console.WriteLine($"  - {f}");
    return 1;
}

Console.WriteLine("Формат соответствует ожиданиям amnezia-client.");
return 0;

static string? FirstDollar(string text)
{
    var index = text.IndexOf('$');
    return index < 0 ? null : text.Substring(index, Math.Min(40, text.Length - index));
}

static string? FirstJunk(string text)
{
    var index = text.IndexOf("003C", StringComparison.Ordinal);
    return index < 0 ? null : text.Substring(Math.Max(0, index - 20), 40);
}
