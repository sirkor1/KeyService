using System.Diagnostics;
using System.Security.Cryptography;
using System.Reflection;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using AmneziaKeyService.Core.DTOs.Panel;
using AmneziaKeyService.Core.Exceptions;
using AmneziaKeyService.Core.Interfaces;
using AmneziaKeyService.Core.Models;
using AmneziaKeyService.Infrastructure.Install;
using AmneziaKeyService.Infrastructure.Monitoring;
using AmneziaKeyService.Infrastructure.Protocols;
using AmneziaKeyService.Infrastructure.Protocols.XCore;
using AmneziaKeyService.Infrastructure.Scripts;
using AmneziaKeyService.Infrastructure.Services;
using AmneziaKeyService.Infrastructure.Subscriptions;
using AmneziaKeyService.Infrastructure.DependencyInjection;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using MongoDB.Bson;
using MongoDB.Bson.Serialization;

// Проверяет xcore без живого узла: рендер конфига Xray, разбор вывода xray,
// фильтр секретов и то, что xcore не попадает в выдачу vpn://.
//
// Зачем: всё это ошибается молча. Все `xray api` завершаются с кодом 0 даже при
// ошибке, поэтому парсеры — единственный способ узнать, что пользователь не
// добавился. Рендерер с нестабильным порядком полей даёт разные ревизии для одного
// состояния и заставляет синхронизацию гонять узел вхолостую. А пропущенный
// фильтром приватный ключ Reality уезжает в Seq вместе со строкой лога.
//
// Образцы вывода сняты с ghcr.io/xtls/xray-core:26.10.21
// (sha256:d5c3729dfeed7c412af17a63b941c48c76ba68afee5b6184fe4078f8fa8bedcc).
// --docker дополнительно прогоняет конфиг через `xray run -test` в этом образе.

const string XrayImage = "ghcr.io/xtls/xray-core:26.10.21";

var failures = new List<string>();
var checks = 0;

void Check(string name, bool ok, string? detail = null)
{
    checks++;
    Console.WriteLine($"  [{(ok ? "OK  " : "ПРОВАЛ")}] {name}{(detail is null ? "" : $" — {detail}")}");
    if (!ok) failures.Add(name);
}

bool Throws<T>(Action action) where T : Exception
{
    try { action(); return false; }
    catch (T) { return true; }
}

Console.OutputEncoding = Encoding.UTF8;

// ── Тестовые данные ──────────────────────────────────────────────────────────

const string PrivateKey = "CCjvIm9FrG2plFwEag9_EIjqZ5YegsIIzTRa7ysTNF8";
const string PublicKey = "vN5-VmKdoRXOgLJeJ1n3uX2nGxzPDE48X9qHZUT32is";
const string UuidAbc = "11111111-2222-3333-4444-555555555555";
const string UuidDef = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
const string UuidGhi = "01234567-89ab-cdef-0123-456789abcdef";

XCoreProtocolParams NewNode() => new()
{
    Role = XCoreRoles.Exit,
    Domain = "node1.example.com",
    ImageRef = XrayImage,
    RealityPublicKey = PublicKey,
    ShortIds = ["a1b2c3d4e5f60718"],
    XhttpPath = "/x7Kq2mPz",
    Title = "Нидерланды",
};

var node = NewNode();
List<XCoreUser> users = [new("sub-def", UuidDef), new("sub-abc", UuidAbc)];

// ── Рендерер ─────────────────────────────────────────────────────────────────

Console.WriteLine("Рендерер конфига");

var rendered = XCoreConfigRenderer.Render(node, PrivateKey, users);
var cfg = JsonNode.Parse(rendered.Json)!.AsObject();
var inbounds = cfg["inbounds"]!.AsArray();
var inbound = inbounds[0]!.AsObject();
var stream = inbound["streamSettings"]!.AsObject();
var reality = stream["realitySettings"]!.AsObject();
var clients = inbound["settings"]!["clients"]!.AsArray();

Check("log: warning, access none", cfg["log"]!["loglevel"]!.GetValue<string>() == "warning"
    && cfg["log"]!["access"]!.GetValue<string>() == "none");
Check("api слушает только 127.0.0.1:10085", cfg["api"]!["listen"]!.GetValue<string>() == "127.0.0.1:10085"
    && cfg["api"]!["tag"]!.GetValue<string>() == "api");
Check("api: HandlerService и StatsService",
    string.Join(",", cfg["api"]!["services"]!.AsArray().Select(s => s!.GetValue<string>())) == "HandlerService,StatsService");
Check("порт API берётся из параметров узла",
    JsonNode.Parse(XCoreConfigRenderer.Render(new XCoreProtocolParams
    {
        Domain = "d.example.com", XhttpPath = "/p", ShortIds = ["ab"], ApiPort = 10999,
    }, PrivateKey, []).Json)!["api"]!["listen"]!.GetValue<string>() == "127.0.0.1:10999");
Check("stats: {} присутствует", cfg["stats"] is JsonObject { Count: 0 });
Check("policy.levels.0 считает трафик пользователей",
    cfg["policy"]!["levels"]!["0"]!["statsUserUplink"]!.GetValue<bool>()
    && cfg["policy"]!["levels"]!["0"]!["statsUserDownlink"]!.GetValue<bool>());
Check("ровно один inbound (нет лишних)", inbounds.Count == 1);
Check("inbound: vless-xhttp, 0.0.0.0:443, vless",
    inbound["tag"]!.GetValue<string>() == "vless-xhttp" && inbound["listen"]!.GetValue<string>() == "0.0.0.0"
    && inbound["port"]!.GetValue<int>() == 443 && inbound["protocol"]!.GetValue<string>() == "vless");
Check("decryption none", inbound["settings"]!["decryption"]!.GetValue<string>() == "none");
Check("транспорт xhttp + reality",
    stream["network"]!.GetValue<string>() == "xhttp" && stream["security"]!.GetValue<string>() == "reality");
Check("reality: target 127.0.0.1:8443", reality["target"]!.GetValue<string>() == "127.0.0.1:8443");
Check("reality: dest не используется (только target)", !reality.ContainsKey("dest"));
Check("reality: serverNames = [Domain]",
    reality["serverNames"]!.AsArray().Count == 1 && reality["serverNames"]![0]!.GetValue<string>() == "node1.example.com");
Check("reality: privateKey и shortIds", reality["privateKey"]!.GetValue<string>() == PrivateKey
    && reality["shortIds"]!.AsArray().Select(s => s!.GetValue<string>()).SequenceEqual(["a1b2c3d4e5f60718"]));
Check("xhttp: path и mode auto", stream["xhttpSettings"]!["path"]!.GetValue<string>() == "/x7Kq2mPz"
    && stream["xhttpSettings"]!["mode"]!.GetValue<string>() == "auto");
Check("клиенты: 2, отсортированы по email, level 0",
    clients.Count == 2 && clients[0]!["email"]!.GetValue<string>() == "sub-abc"
    && clients[1]!["email"]!.GetValue<string>() == "sub-def"
    && clients.All(c => c!["level"]!.GetValue<int>() == 0));
Check("клиенты без flow", clients.All(c => !c!.AsObject().ContainsKey("flow")));
Check("клиенты: id совпадает с UUID", clients[0]!["id"]!.GetValue<string>() == UuidAbc
    && clients[1]!["id"]!.GetValue<string>() == UuidDef);
Check("outbounds: direct/freedom и block/blackhole",
    cfg["outbounds"]!.AsArray().Count == 2
    && cfg["outbounds"]![0]!["tag"]!.GetValue<string>() == "direct" && cfg["outbounds"]![0]!["protocol"]!.GetValue<string>() == "freedom"
    && cfg["outbounds"]![1]!["tag"]!.GetValue<string>() == "block" && cfg["outbounds"]![1]!["protocol"]!.GetValue<string>() == "blackhole");

string[] expectedCidrs =
[
    "127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16",
    "100.64.0.0/10", "0.0.0.0/8", "::1/128", "fc00::/7", "fe80::/10",
];
var rules = cfg["routing"]!["rules"]!.AsArray();
Check("routing: первое правило блокирует приватные CIDR",
    rules.Count >= 1 && rules[0]!["outboundTag"]!.GetValue<string>() == "block"
    && rules[0]!["ip"]!.AsArray().Select(s => s!.GetValue<string>()).SequenceEqual(expectedCidrs));
Check("routing: правило без geo-файлов", !rendered.Json.Contains("geoip", StringComparison.Ordinal)
    && !rendered.Json.Contains("geosite", StringComparison.Ordinal));
Check("routing: domainStrategy IPIfNonMatch", cfg["routing"]!["domainStrategy"]!.GetValue<string>() == "IPIfNonMatch");

Check("пустой список пользователей даёт пустой clients",
    JsonNode.Parse(XCoreConfigRenderer.Render(node, PrivateKey, []).Json)!["inbounds"]![0]!["settings"]!["clients"]!.AsArray().Count == 0);

Check("entry: понятное NotSupportedException",
    Throws<NotSupportedException>(() => XCoreConfigRenderer.Render(
        new XCoreProtocolParams { Role = XCoreRoles.Entry, Domain = "d", XhttpPath = "/p", ShortIds = ["a"] }, PrivateKey, [])));
Check("пустой приватный ключ отвергается", Throws<InvalidOperationException>(() => XCoreConfigRenderer.Render(node, " ", users)));
Check("повторный email отвергается",
    Throws<InvalidOperationException>(() => XCoreConfigRenderer.Render(node, PrivateKey, [new("sub-abc", UuidAbc), new("sub-abc", UuidDef)])));
Check("не-GUID UUID отвергается",
    Throws<InvalidOperationException>(() => XCoreConfigRenderer.Render(node, PrivateKey, [new("sub-abc", "not-a-uuid")])));

// ── Ревизия ──────────────────────────────────────────────────────────────────

Console.WriteLine("Ревизия");

var again = XCoreConfigRenderer.Render(NewNode(), PrivateKey, users);
var shuffled = XCoreConfigRenderer.Render(NewNode(), PrivateKey, [users[1], users[0]]);
var extra = XCoreConfigRenderer.Render(NewNode(), PrivateKey, [.. users, new("sub-ghi", UuidGhi)]);
var otherKey = XCoreConfigRenderer.Render(NewNode(), "Zz" + PrivateKey[2..], users);
var otherPath = XCoreConfigRenderer.Render(new XCoreProtocolParams
{
    Domain = node.Domain, XhttpPath = "/other", ShortIds = node.ShortIds,
}, PrivateKey, users);

Check("ревизия — 64 hex-символа нижнего регистра",
    rendered.Revision.Length == 64 && rendered.Revision.All(c => c is >= '0' and <= '9' or >= 'a' and <= 'f'));
Check("ревизия = SHA-256 от Json",
    rendered.Revision == Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(rendered.Json))).ToLowerInvariant());
Check("тот же вход — тот же Json и ревизия", again.Json == rendered.Json && again.Revision == rendered.Revision);
Check("перестановка пользователей не меняет ревизию", shuffled.Revision == rendered.Revision);
Check("добавление пользователя меняет ревизию", extra.Revision != rendered.Revision);
Check("смена ключа меняет ревизию", otherKey.Revision != rendered.Revision);
Check("смена пути меняет ревизию", otherPath.Revision != rendered.Revision);
Check("Json компактный, без переводов строк", !rendered.Json.Contains('\n'));

var structure = XCoreConfigRenderer.RenderStructureRevision(node, PrivateKey);
Check("структурная ревизия = ревизия рендера без пользователей",
    structure == XCoreConfigRenderer.Render(node, PrivateKey, []).Revision && structure != rendered.Revision);
Check("состав пользователей не меняет структурную ревизию",
    XCoreConfigRenderer.RenderStructureRevision(NewNode(), PrivateKey) == structure);
Check("смена пути меняет структурную ревизию",
    XCoreConfigRenderer.RenderStructureRevision(new XCoreProtocolParams
    {
        Domain = node.Domain, XhttpPath = "/other", ShortIds = node.ShortIds,
    }, PrivateKey) != structure);
Check("смена ключа меняет структурную ревизию",
    XCoreConfigRenderer.RenderStructureRevision(NewNode(), "Zz" + PrivateKey[2..]) != structure);

// ── Файл для adu ─────────────────────────────────────────────────────────────

Console.WriteLine("Файл для xray api adu");

var adu = XCoreConfigRenderer.RenderUsersFile(node, [new("sub-abc", UuidAbc)]);
Check("adu: формат совпадает с образцом дословно",
    adu == $$$"""{"inbounds":[{"tag":"vless-xhttp","listen":"0.0.0.0","port":443,"protocol":"vless","settings":{"clients":[{"id":"{{{UuidAbc}}}","email":"sub-abc","level":0}],"decryption":"none"}}]}""");
var aduInbound = JsonNode.Parse(adu)!["inbounds"]![0]!;
Check("adu: есть listen и port", aduInbound["listen"] is not null && aduInbound["port"]!.GetValue<int>() == 443);
Check("adu: порядок пользователей не важен",
    XCoreConfigRenderer.RenderUsersFile(node, users) == XCoreConfigRenderer.RenderUsersFile(node, [users[1], users[0]]));
Check("adu: у входа тот же файл, что у выхода (пользователи добавляются в тот же inbound)",
    XCoreConfigRenderer.RenderUsersFile(new XCoreProtocolParams { Role = XCoreRoles.Entry }, [new("sub-abc", UuidAbc)]) == adu);
Check("adu: неизвестная роль отвергается", Throws<NotSupportedException>(() => XCoreConfigRenderer.RenderUsersFile(
    new XCoreProtocolParams { Role = "relay" }, [])));

// ── Разбор вывода xray ───────────────────────────────────────────────────────

Console.WriteLine("Разбор adu");

const string AduOk = """
    processing inbound: vless-xhttp
    add user: sub-abc
    result: ok
    add user: sub-def
    result: ok
    Added 2 user(s) in total.
    """;
const string AduRepeat = """
    processing inbound: vless-xhttp
    add user: sub-abc
    rpc error: code = Unknown desc = proxy/vless: User sub-abc already exists.
    add user: sub-def
    rpc error: code = Unknown desc = proxy/vless: User sub-def already exists.
    Added 0 user(s) in total.
    """;
const string AduBadFile = """
    processing inbound: vless-xhttp
    failed to build config: infra/conf: Listen on AnyIP but no Port(s) set in InboundDetour.
    Added 0 user(s) in total.
    """;

var r = XrayApiOutput.ParseAddUsers(AduOk);
Check("adu успех: добавлено 2, ошибок нет", r.Added == 2 && r.AlreadyExisted.Count == 0 && r.IsSuccess);
r = XrayApiOutput.ParseAddUsers(AduRepeat);
Check("adu повтор: 0 добавлено, оба в AlreadyExisted, не ошибка",
    r.Added == 0 && r.AlreadyExisted.SequenceEqual(["sub-abc", "sub-def"]) && r.IsSuccess);
r = XrayApiOutput.ParseAddUsers(AduBadFile);
Check("adu плохой файл: 0 добавлено и ошибка про Port",
    r.Added == 0 && !r.IsSuccess && r.Errors.Count == 1 && r.Errors[0].Contains("no Port(s) set"));
r = XrayApiOutput.ParseAddUsers(AduOk.Replace("\n", "\r\n"));
Check("adu: CRLF разбирается так же", r.Added == 2 && r.IsSuccess);
r = XrayApiOutput.ParseAddUsers("""
    processing inbound: vless-xhttp
    add user: sub-abc
    result: ok
    add user: sub-def
    rpc error: code = Unknown desc = proxy/vless: something else broke
    Added 1 user(s) in total.
    """);
Check("adu смешанный: добавлен 1, прочий rpc error — ошибка с email",
    r.Added == 1 && !r.IsSuccess && r.Errors.Count == 1 && r.Errors[0].StartsWith("sub-def:"));
Check("adu: пустой вывод — исключение", Throws<XrayOutputException>(() => XrayApiOutput.ParseAddUsers("")));
Check("adu: без итоговой строки — исключение",
    Throws<XrayOutputException>(() => XrayApiOutput.ParseAddUsers("add user: sub-abc\nresult: ok\n")));
Check("adu: итог расходится с подтверждёнными — исключение",
    Throws<XrayOutputException>(() => XrayApiOutput.ParseAddUsers("add user: sub-abc\nresult: ok\nAdded 5 user(s) in total.")));

Console.WriteLine("Разбор rmu");

var rm = XrayApiOutput.ParseRemoveUsers("remove user: sub-abc\nRemoved 1 user(s) in total.\n");
Check("rmu успех: удалён 1", rm.Removed == 1 && rm.NotFound.Count == 0 && rm.IsSuccess);
rm = XrayApiOutput.ParseRemoveUsers("""
    remove user: sub-abc
    rpc error: code = Unknown desc = proxy/vless: User sub-abc not found.
    Removed 0 user(s) in total.
    """);
Check("rmu нет такого: not found — не ошибка", rm.Removed == 0 && rm.NotFound.SequenceEqual(["sub-abc"]) && rm.IsSuccess);
rm = XrayApiOutput.ParseRemoveUsers("remove user: sub-abc\nremove user: sub-def\nrpc error: code = Unknown desc = proxy/vless: User sub-def not found.\nRemoved 1 user(s) in total.");
Check("rmu смешанный: один удалён, один не найден", rm.Removed == 1 && rm.NotFound.SequenceEqual(["sub-def"]) && rm.IsSuccess);
rm = XrayApiOutput.ParseRemoveUsers("remove user: sub-abc\nrpc error: code = Unavailable desc = connection refused\nRemoved 0 user(s) in total.");
Check("rmu: иная rpc-ошибка — ошибка", rm.Removed == 0 && !rm.IsSuccess);
Check("rmu: без итоговой строки — исключение", Throws<XrayOutputException>(() => XrayApiOutput.ParseRemoveUsers("remove user: sub-abc\n")));

Console.WriteLine("Разбор inbounduser");

const string InboundUserOne = """
    {
        "users": [
            {
                "account": {
                    "_TypedMessage_": "xray.proxy.vless.Account",
                    "id": "11111111-2222-3333-4444-555555555555"
                },
                "email": "sub-abc"
            }
        ]
    }
    """;
var iu = XrayApiOutput.ParseInboundUsers(InboundUserOne);
Check("inbounduser: один пользователь (email, id)", iu.Count == 1 && iu[0] == new XCoreUser("sub-abc", UuidAbc));
Check("inbounduser: {} — пустой список", XrayApiOutput.ParseInboundUsers("{}\n").Count == 0);
Check("inbounduser: не JSON — исключение без текста вывода", ThrowsWithoutText(
    () => XrayApiOutput.ParseInboundUsers("failed: " + UuidAbc), UuidAbc));
Check("inbounduser: пользователь без account.id — исключение",
    Throws<XrayOutputException>(() => XrayApiOutput.ParseInboundUsers("""{"users":[{"email":"sub-abc"}]}""")));
Check("inbounduser: пустой вывод — исключение", Throws<XrayOutputException>(() => XrayApiOutput.ParseInboundUsers("")));

Console.WriteLine("Разбор inboundusercount");

Check("inboundusercount: {} — ноль пользователей", XrayApiOutput.ParseInboundUserCount("{}\n\n") == 0);
Check("inboundusercount: образец с count", XrayApiOutput.ParseInboundUserCount("{\n    \"count\": 3\n}\n\n") == 3);
Check("inboundusercount: count строкой (protobuf)", XrayApiOutput.ParseInboundUserCount("""{"count":"7"}""") == 7);
Check("inboundusercount: ошибка вместо JSON — исключение",
    Throws<XrayOutputException>(() => XrayApiOutput.ParseInboundUserCount("failed to dial 127.0.0.1:10085")));
Check("inboundusercount: пустой вывод — исключение", Throws<XrayOutputException>(() => XrayApiOutput.ParseInboundUserCount("")));
Check("inboundusercount: count не число — исключение",
    Throws<XrayOutputException>(() => XrayApiOutput.ParseInboundUserCount("""{"count":"many"}""")));
Check("inboundusercount: отрицательный count — исключение",
    Throws<XrayOutputException>(() => XrayApiOutput.ParseInboundUserCount("""{"count":-1}""")));

Console.WriteLine("Разбор statsquery");

const string StatsTwo = """
    {
        "stat": [
            {
                "name": "user>>>sub-def>>>traffic>>>uplink",
                "value": 823
            },
            {
                "name": "user>>>sub-def>>>traffic>>>downlink",
                "value": 5397
            }
        ]
    }
    """;
var traffic = XrayApiOutput.ParseUserTraffic(StatsTwo);
Check("statsquery: sub-def uplink 823, downlink 5397",
    traffic.Count == 1 && traffic["sub-def"] == new XrayUserTraffic(823, 5397));
Check("statsquery: {} — пусто", XrayApiOutput.ParseUserTraffic("{}").Count == 0);
traffic = XrayApiOutput.ParseUserTraffic("""
    {"stat":[
      {"name":"user>>>sub-abc>>>traffic>>>uplink"},
      {"name":"user>>>sub-abc>>>traffic>>>downlink","value":7},
      {"name":"inbound>>>vless-xhttp>>>traffic>>>uplink","value":99},
      {"name":"user>>>sub-big>>>traffic>>>uplink","value":9007199254740993}
    ]}
    """);
Check("statsquery: отсутствующий value = 0", traffic["sub-abc"] == new XrayUserTraffic(0, 7));
Check("statsquery: счётчики inbound пропускаются", traffic.Count == 2 && !traffic.ContainsKey("vless-xhttp"));
Check("statsquery: значение за пределами double сохраняется точно", traffic["sub-big"].Uplink == 9007199254740993);
Check("statsquery: value строкой (protobuf int64)",
    XrayApiOutput.ParseUserTraffic("""{"stat":[{"name":"user>>>a>>>traffic>>>uplink","value":"42"}]}""")["a"].Uplink == 42);
Check("statsquery: не JSON — исключение", Throws<XrayOutputException>(() => XrayApiOutput.ParseUserTraffic("rpc error: no")));
Check("statsquery: счётчик без имени — исключение",
    Throws<XrayOutputException>(() => XrayApiOutput.ParseUserTraffic("""{"stat":[{"value":1}]}""")));

Console.WriteLine("Разбор x25519");

const string X25519New = """
    PrivateKey: CCjvIm9FrG2plFwEag9_EIjqZ5YegsIIzTRa7ysTNF8
    Password (PublicKey): vN5-VmKdoRXOgLJeJ1n3uX2nGxzPDE48X9qHZUT32is
    Hash32: y_iNQ3haw4Fzn6WETRTggcYN6eUvB4nLPii1HJe2u0c
    """;
var kp = XrayApiOutput.ParseX25519(X25519New);
Check("x25519: новая форма (Password (PublicKey))", kp.PrivateKey == PrivateKey && kp.PublicKey == PublicKey);
kp = XrayApiOutput.ParseX25519($"PrivateKey: {PrivateKey}\nPublicKey: {PublicKey}\n");
Check("x25519: прежняя форма (PublicKey)", kp.PrivateKey == PrivateKey && kp.PublicKey == PublicKey);
Check("x25519: без публичного ключа — исключение без ключей в тексте",
    ThrowsWithoutText(() => XrayApiOutput.ParseX25519($"PrivateKey: {PrivateKey}\n"), PrivateKey));
Check("x25519: ключ неверной длины — исключение без ключей в тексте",
    ThrowsWithoutText(() => XrayApiOutput.ParseX25519("PrivateKey: abcdef\nPublicKey: ghijkl\n"), "abcdef"));

Console.WriteLine("Разбор run -test");

Check("run -test: Configuration OK. — успех",
    XrayApiOutput.ParseConfigTest("Xray 26.10.21 (Xray, Penetrates Everything.) 0a1b2c3 (go1.25 linux/amd64)\nConfiguration OK.\n") is { Ok: true, Error: null });
var bad = XrayApiOutput.ParseConfigTest("Failed to start: main/commands: failed to load config files: [/c/config.json] > infra/conf: bad\n");
Check("run -test: Failed to start — провал с текстом", !bad.Ok && bad.Error!.StartsWith("Failed to start"));
Check("run -test: пустой вывод — не успех", !XrayApiOutput.ParseConfigTest("").Ok);
Check("run -test: OK и Failed вместе — не успех", !XrayApiOutput.ParseConfigTest("Configuration OK.\nFailed to start: x").Ok);
Check("run -test: подстрока «Configuration OK.» в чужой строке — не успех",
    !XrayApiOutput.ParseConfigTest("note: Configuration OK. is expected").Ok);

// ── Фильтр секретов ──────────────────────────────────────────────────────────

Console.WriteLine("Фильтр секретов");

string Redact(string s) => SecretRedactor.Redact(s);

Check("ключ Reality из 43 символов вырезается", !Redact($"key is {PrivateKey} here").Contains(PrivateKey)
    && Redact($"key is {PrivateKey} here") == "key is *** here");
Check("ключ в JSON-кавычках вырезается", Redact($"\"privateKey\":\"{PrivateKey}\"") == "\"privateKey\":\"***\"");
var edgeKey = "-" + new string('a', 20) + "_B" + new string('c', 19) + "-"; // 43 символа, '-' по краям
Check("ключ с '-' и '_' по краям вырезается", edgeKey.Length == 43 && Redact($"x {edgeKey} y") == "x *** y");
var x25519Redacted = Redact(X25519New);
Check("весь вывод x25519 не содержит ни одного ключа",
    !x25519Redacted.Contains(PrivateKey) && !x25519Redacted.Contains(PublicKey)
    && !x25519Redacted.Contains("y_iNQ3haw4Fzn6WETRTggcYN6eUvB4nLPii1HJe2u0c"), x25519Redacted);
Check("прежнее правило для 44 символов с '=' живо",
    Redact("k cE5vAqRtYuIoPaSdFgHjKlZxCvBnMqWeRtYuIoPaSd0= k") == "k *** k");

Check("UUID в \"id\": \"…\" вырезается", Redact($"{{\"id\": \"{UuidAbc}\", \"email\": \"sub-abc\"}}") == "{\"id\": \"***\", \"email\": \"sub-abc\"}");
Check("UUID в экранированной JSON-строке вырезается",
    !Redact($"echo '{{\\\"id\\\":\\\"{UuidAbc}\\\"}}'").Contains(UuidAbc));
Check("UUID в выводе inbounduser вырезается", !Redact(InboundUserOne).Contains(UuidAbc) && Redact(InboundUserOne).Contains("sub-abc"));
Check("UUID в vless://…@ вырезается", Redact($"vless://{UuidAbc}@node1.example.com:443?type=xhttp") == "vless://***@node1.example.com:443?type=xhttp");
Check("голый UUID не трогается", Redact($"jti {UuidAbc} issued") == $"jti {UuidAbc} issued");
Check("UUID в другом поле не трогается", Redact($"{{\"uuid\":\"{UuidAbc}\"}}") == $"{{\"uuid\":\"{UuidAbc}\"}}");
Check("/sub/<token> вырезается", Redact("GET /sub/" + PrivateKey + " 200") == "GET /sub/*** 200");
Check("токен в полном URL вырезается", Redact("https://sub.example.com/sub/abcDEF123_-abcDEF123_-abcDEF123_-abcDEF1234?x=1")
    == "https://sub.example.com/sub/***?x=1");
Check("короткий сегмент /sub/ не трогается", Redact("GET /sub/list 200") == "GET /sub/list 200");

Check("обычный текст не портится", Redact("Контейнер amnezia-xcore запущен, порт 443 свободен.") == "Контейнер amnezia-xcore запущен, порт 443 свободен.");
Check("ObjectId не портится", Redact("server 69ca5beaba00e3c10adc451d key 6a6be0178a32c6160e84c07d") == "server 69ca5beaba00e3c10adc451d key 6a6be0178a32c6160e84c07d");
Check("protocol id (Guid N) не портится", Redact("protocol 1ff8453f9dca41f89531b10d5156057d") == "protocol 1ff8453f9dca41f89531b10d5156057d");
Check("sha256 hex (ревизия) не портится", Redact($"revision {rendered.Revision}") == $"revision {rendered.Revision}");
const string LongKebab = "amnezia-xcore-sync-node-eu-central-1-prim"; // 41 -> добавим до 43 ниже
var kebab43 = (LongKebab + "ab")[..43];
Check("43-символьное kebab-case имя без заглавных не портится", Redact($"unit {kebab43} ok") == $"unit {kebab43} ok");
var longMixed = string.Concat(Enumerable.Repeat("AbCdEfGhIj", 6));
Check("длинная base64-строка не режется на куски", Redact($"blob {longMixed} end") == $"blob {longMixed} end");
Check("ссылка docker-образа не портится", Redact($"image {XrayImage}@sha256:d5c3729dfeed7c412af17a63b941c48c76ba68afee5b6184fe4078f8fa8bedcc")
    .StartsWith($"image {XrayImage}@sha256:"));
Check("Tail тоже применяет новые правила", !SecretRedactor.Tail($"x {PrivateKey}", 100).Contains(PrivateKey));

// ── Гейтинг выдачи vpn:// ────────────────────────────────────────────────────

Console.WriteLine("Гейтинг выдачи vpn://");

ProtocolInstance NewXCore() => new()
{
    Id = "xcore-1", Kind = ProtocolKinds.XCore, ContainerName = "amnezia-xcore", Port = "443",
    TransportProto = "tcp", State = ProtocolStates.Installed, XCore = NewNode(),
};
ProtocolInstance NewAwg2() => new()
{
    Id = "awg2-1", Kind = ProtocolKinds.Awg2, ContainerName = "amnezia-awg2", Port = "40000",
    State = ProtocolStates.Installed, Wg = new WgProtocolParams(),
};

var xcoreOnly = new VpnServer { Id = "69ca5beaba00e3c10adc451d", Host = "203.0.113.5", Protocols = [NewXCore()] };
var xcoreProto = xcoreOnly.Protocols[0];
Check("xcore не проходит CanIssue", !xcoreOnly.CanIssue(xcoreProto));
Check("xcore проходит IsServing", xcoreOnly.IsServing(xcoreProto));
Check("IssuanceProtocol(null) на узле только с xcore — null", xcoreOnly.IssuanceProtocol(null) is null);
Check("IssuanceProtocol(id xcore) — null", xcoreOnly.IssuanceProtocol(xcoreProto.Id) is null);
xcoreOnly.DefaultProtocolId = xcoreProto.Id;
Check("DefaultProtocolId на xcore не делает его выдаваемым", xcoreOnly.IssuanceProtocol(null) is null);

var mixed = new VpnServer
{
    Id = "69ca5beaba00e3c10adc451e", Host = "203.0.113.6", Protocols = [NewXCore(), NewAwg2()], DefaultProtocolId = "xcore-1",
};
Check("xcore первым и по умолчанию: IssuanceProtocol(null) = awg2", mixed.IssuanceProtocol(null)?.Id == "awg2-1");
Check("явный xcore на смешанном узле — null, явный awg2 — awg2",
    mixed.IssuanceProtocol("xcore-1") is null && mixed.IssuanceProtocol("awg2-1")?.Id == "awg2-1");

var disabled = new VpnServer { Id = "x", Host = "h", Protocols = [NewXCore()], DisabledProtocolIds = ["xcore-1"] };
Check("отключённый администратором xcore: IsServing = false", !disabled.IsServing(disabled.Protocols[0]));
Check("IsServing сохраняет прежнюю семантику для awg2",
    mixed.IsServing(mixed.Protocols[1]) && !new VpnServer { Protocols = [new ProtocolInstance { Id = "a", Kind = ProtocolKinds.Awg2, State = ProtocolStates.Failed }] }
        .IsServing(new ProtocolInstance { Id = "a", Kind = ProtocolKinds.Awg2, State = ProtocolStates.Failed }));

Check("все виды Amnezia выдаваемы, xcore — нет",
    ProtocolKinds.All.All(ProtocolKinds.IsAmneziaIssuable) && !ProtocolKinds.IsAmneziaIssuable(ProtocolKinds.XCore));
Check("xcore не входит в ProtocolKinds.All", !ProtocolKinds.All.Contains(ProtocolKinds.XCore));
Check("контейнер по умолчанию amnezia-xcore", ProtocolKinds.DefaultContainerName(ProtocolKinds.XCore) == "amnezia-xcore");

// ── Приватный ключ и DTO панели ──────────────────────────────────────────────

Console.WriteLine("Приватный ключ: DTO и BSON");

var protector = new AesGcmSecretProtector(Options.Create(new SecurityOptions
{
    DataProtectionKey = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)),
}));
var secured = NewXCore();
secured.XCore!.RealityPrivateKey = protector.Protect(PrivateKey);
var securedServer = new VpnServer { Id = "69ca5beaba00e3c10adc451f", Host = "203.0.113.7", Protocols = [secured, NewAwg2()] };
var enc = secured.XCore.RealityPrivateKey!;

var detailJson = JsonSerializer.Serialize(ServerDetailDto.From(securedServer, new ServerKpiDto(null, 0, 0)));
var listJson = JsonSerializer.Serialize(ServerListItemDto.From(securedServer, 0, 0));
foreach (var (label, json) in new[] { ("карточка узла", detailJson), ("строка списка", listJson) })
{
    Check($"{label}: нет открытого ключа", !json.Contains(PrivateKey, StringComparison.Ordinal));
    Check($"{label}: нет шифротекста, nonce и тега",
        !json.Contains(enc.CipherText, StringComparison.Ordinal) && !json.Contains(enc.Nonce, StringComparison.Ordinal)
        && !json.Contains(enc.Tag, StringComparison.Ordinal));
    Check($"{label}: нет поля realityPrivateKey", !json.Contains("realityPrivateKey", StringComparison.OrdinalIgnoreCase));
}
var summary = ServerListItemDto.From(securedServer, 0, 0).Protocols.First(p => p.Kind == ProtocolKinds.XCore);
Check("DTO показывает xcore как включённый (IsServing)", summary.Enabled);

var bson = securedServer.ToBsonDocument();
var bsonXcore = bson["protocols"].AsBsonArray[0].AsBsonDocument["xcore"].AsBsonDocument;
Check("BSON: ключ хранится EncryptedValue, открытого текста нет",
    bsonXcore["realityPrivateKey"].IsBsonDocument && !bson.ToJson().Contains(PrivateKey, StringComparison.Ordinal));
Check("BSON: у протокола без xcore поля xcore нет (миграция не нужна)",
    !bson["protocols"].AsBsonArray[1].AsBsonDocument.Contains("xcore"));
var restored = BsonSerializer.Deserialize<VpnServer>(bson);
var back = restored.Protocols[0];
Check("BSON: id протокола переживает круг", back.Id == "xcore-1");
Check("BSON: ключ расшифровывается после круга", protector.Unprotect(back.XCore!.RealityPrivateKey) == PrivateKey);
Check("BSON: поля xcore переживают круг",
    back.XCore.Role == "exit" && back.XCore.Domain == "node1.example.com" && back.XCore.ImageRef == XrayImage
    && back.XCore.RealityPublicKey == PublicKey && back.XCore.ShortIds.SequenceEqual(["a1b2c3d4e5f60718"])
    && back.XCore.XhttpPath == "/x7Kq2mPz" && back.XCore.XhttpPort == 443 && back.XCore.ApiPort == 10085
    && back.XCore.Fingerprint == "firefox" && back.XCore.Title == "Нидерланды" && back.XCore.SubscriptionEnabled
    && back.XCore.AppliedRevision is null && back.XCore.SyncError is null);
Check("BSON: старый документ без xcore читается", BsonSerializer.Deserialize<VpnServer>(
    new BsonDocument { { "_id", ObjectId.GenerateNewId() }, { "host", "h" } }).Protocols.Count == 0);

// ── Протокол для vpn:// по умолчанию ─────────────────────────────────────────

Console.WriteLine("Протокол по умолчанию для vpn://");

var legacyMixed = new VpnServer
{
    Id = "69ca5beaba00e3c10adc4530", Host = "203.0.113.8", Protocols = [NewXCore(), NewAwg2()], DefaultProtocolId = "xcore-1",
};
Check("узел awg2 + xcore, DefaultProtocolId на xcore: DefaultProtocol = awg2", legacyMixed.DefaultProtocol?.Id == "awg2-1");
Check("ключ без protocolId разрешается в awg2, а не в xcore",
    VpnConfigReader.ResolveProtocol(legacyMixed, null).Id == "awg2-1");
Check("ключ с явным protocolId xcore по-прежнему находит протокол",
    VpnConfigReader.ResolveProtocol(legacyMixed, "xcore-1").Id == "xcore-1");
Check("только xcore: DefaultProtocol = null", xcoreOnly.DefaultProtocol is null);
Check("только xcore: ключ без protocolId — понятная ошибка, а не xcore",
    Throws<NotFoundException>(() => VpnConfigReader.ResolveProtocol(xcoreOnly, null)));
var awgFailed = new VpnServer
{
    Id = "x", Host = "h", DefaultProtocolId = "xcore-1",
    Protocols = [NewXCore(), new ProtocolInstance { Id = "awg2-1", Kind = ProtocolKinds.Awg2, State = ProtocolStates.Failed }],
};
Check("awg2 в состоянии failed всё равно владелец legacy-ключей (последний вариант)", awgFailed.DefaultProtocol?.Id == "awg2-1");
var xcoreDefaultAwgLater = new VpnServer
{
    Id = "x", Host = "h", DefaultProtocolId = "awg2-1",
    Protocols = [NewXCore(), NewAwg2()],
};
Check("явный DefaultProtocolId на awg2 уважается при xcore первым", xcoreDefaultAwgLater.DefaultProtocol?.Id == "awg2-1");
Check("Quote: одинарная кавычка внутри значения экранируется как '\\''", XCoreNode.Quote("a'b c") == "'a'\\''b c'");
Check("ProtocolKinds.Installable = All + xcore",
    ProtocolKinds.Installable.OrderBy(k => k).SequenceEqual(ProtocolKinds.All.Append(ProtocolKinds.XCore).OrderBy(k => k)));

// ── Правила установки ────────────────────────────────────────────────────────

Console.WriteLine("Правила установки xcore");

const string NodeIp = "203.0.113.5";
const string XDomain = "node1.example.com";

string? RejectionOf(Action action)
{
    try { action(); return null; }
    catch (BadRequestException ex) { return ex.Message; }
}

VpnServer BareServer(params ProtocolInstance[] protocols) =>
    new() { Id = "69ca5beaba00e3c10adc4520", Host = NodeIp, Protocols = [.. protocols] };

ProtocolSpec XSpec(string? domain = XDomain) => new() { Kind = ProtocolKinds.XCore, Domain = domain };

ProtocolInstance Occupying(string kind, string port) => new()
{
    Id = "p-" + kind, Kind = kind, ContainerName = ProtocolKinds.DefaultContainerName(kind), Port = port,
    State = ProtocolStates.Installed,
};

{
    var spec = XSpec("  Node1.Example.COM. ");
    ProtocolInstallRules.Prepare(BareServer(), [spec]);
    Check("правила: xcore принят, порт 443, роль exit, домен нормализован",
        spec.Port == "443" && spec.Role == "exit" && spec.Domain == "node1.example.com");
    spec = new ProtocolSpec { Kind = ProtocolKinds.XCore, Domain = XDomain, Port = "443", Role = "exit" };
    ProtocolInstallRules.Prepare(BareServer(), [spec]);
    Check("правила: явные 443 и exit приняты", spec.Port == "443" && spec.Role == "exit");
}

Check("правила: порт не 443 — отказ",
    RejectionOf(() => ProtocolInstallRules.Prepare(BareServer(), [new() { Kind = "xcore", Domain = XDomain, Port = "8443" }])) is not null);
{
    var entrySpec = new ProtocolSpec { Kind = "xcore", Domain = XDomain, Role = "entry" };
    ProtocolInstallRules.Prepare(BareServer(), [entrySpec]);
    Check("правила: роль entry принята, порт 443, роль сохранена", entrySpec.Port == "443" && entrySpec.Role == "entry");
    Check("правила: у входа те же ограничения на порты и домен",
        RejectionOf(() => ProtocolInstallRules.Prepare(BareServer(Occupying("xray", "443")), [entrySpec])) is not null
        && RejectionOf(() => ProtocolInstallRules.Prepare(BareServer(), [new() { Kind = "xcore", Domain = "1.2.3.4", Role = "entry" }])) is not null);
}
var unknownRoleMessage = RejectionOf(() => ProtocolInstallRules.Prepare(BareServer(), [new() { Kind = "xcore", Domain = XDomain, Role = "relay" }]));
Check("правила: неизвестная роль — отказ с перечнем допустимых",
    unknownRoleMessage is not null && unknownRoleMessage.Contains("exit") && unknownRoleMessage.Contains("entry"));

string?[] badDomains =
[
    null, "", "  ", "1.2.3.4", "999.1.1.1", "localhost", "node", "a b.example.com", "a;rm.example.com", "-a.example.com",
    "a-.example.com", "node1.example.com'", "node1.example.com\nfoo", "a..example.com", "node1.example.c",
    "http://node1.example.com", "node1.example.com:8443", "*.example.com", "xn--", new string('a', 64) + ".example.com",
    "node1.example.com {", "узел.пример.рф",
];
var acceptedBad = badDomains.Where(d => RejectionOf(() => ProtocolInstallRules.Prepare(BareServer(), [XSpec(d)])) is null).ToList();
Check("правила: некорректные домены отвергаются", acceptedBad.Count == 0, string.Join(" | ", acceptedBad.Select(d => d ?? "null")));
foreach (var good in new[] { "xn--80ak6aa92e.xn--p1ai", "sub.node-1.example.com", "a.io" })
    Check($"правила: домен {good} принят",
        RejectionOf(() => ProtocolInstallRules.Prepare(BareServer(), [XSpec(good)])) is null);

Check("правила: xcore уже есть на узле — отказ",
    RejectionOf(() => ProtocolInstallRules.Prepare(BareServer(Occupying("xcore", "443")), [XSpec()])) is not null);
var xrayMessage = RejectionOf(() => ProtocolInstallRules.Prepare(BareServer(Occupying("xray", "443")), [XSpec()]));
Check("правила: amnezia-xray на 443 — отказ с упоминанием портов", xrayMessage is not null && xrayMessage.Contains("443"));
Check("правила: протокол на 80 — отказ",
    RejectionOf(() => ProtocolInstallRules.Prepare(BareServer(Occupying("xray", "80")), [XSpec()])) is not null);
Check("правила: awg2 на 443 тоже отказ (транспорт не различается)",
    RejectionOf(() => ProtocolInstallRules.Prepare(BareServer(Occupying("awg2", "443")), [XSpec()])) is not null);
Check("правила: протокол на высоком порту не мешает",
    RejectionOf(() => ProtocolInstallRules.Prepare(BareServer(Occupying("awg2", "40000")), [XSpec()])) is null);

var withXCore = BareServer(Occupying("xcore", "443"));
Check("правила: на узле с xcore новый протокол на 80 — отказ",
    RejectionOf(() => ProtocolInstallRules.Prepare(withXCore, [new() { Kind = "awg3", Port = "80" }])) is not null);
Check("правила: на узле с xcore новый протокол на 443 — отказ",
    RejectionOf(() => ProtocolInstallRules.Prepare(withXCore, [new() { Kind = "awg3", Port = "443" }])) is not null);
var awgOnXCoreNode = new ProtocolSpec { Kind = "awg3" };
ProtocolInstallRules.Prepare(withXCore, [awgOnXCoreNode]);
Check("правила: на узле с xcore новый протокол получает случайный порт",
    awgOnXCoreNode.Port is not null && awgOnXCoreNode.Port is not ("80" or "443"));
Check("правила: в одной задаче xray на 443 и xcore — отказ",
    RejectionOf(() => ProtocolInstallRules.Prepare(BareServer(), [new() { Kind = "xray", Port = "443" }, XSpec()])) is not null);
Check("правила: в одной задаче xcore и xray на 443 — отказ",
    RejectionOf(() => ProtocolInstallRules.Prepare(BareServer(), [XSpec(), new() { Kind = "xray", Port = "443" }])) is not null);
Check("правила: в одной задаче xcore и awg3 на случайном порту — принято",
    RejectionOf(() => ProtocolInstallRules.Prepare(BareServer(), [XSpec(), new() { Kind = "awg3" }])) is null);
Check("правила: неизвестный вид по-прежнему отвергается",
    RejectionOf(() => ProtocolInstallRules.Prepare(BareServer(), [new() { Kind = "xcore2" }])) is not null);

// ── Установщик ───────────────────────────────────────────────────────────────

Console.WriteLine("Установщик xcore");

FakeDns GoodDns() => new(new() { [XDomain] = [NodeIp] });
XCoreInstaller NewInstaller(FakeDns dns, string? email = "ops@example.com") =>
    new(new ScriptRegistry(), protector, dns, Options.Create(new XCoreOptions { AcmeEmail = email }))
    { CertificateAttempts = 3, CertificatePollInterval = TimeSpan.Zero };
VpnServer NodeServer(string host = NodeIp) => new() { Id = "69ca5beaba00e3c10adc4521", Name = "xc", Host = host };
ProtocolSpec PreparedSpec()
{
    var s = XSpec();
    ProtocolInstallRules.Prepare(NodeServer(), [s]);
    return s;
}
async Task<string?> InstallErrorAsync(XCoreInstaller installer, FakeNode fake, ProtocolSpec spec, VpnServer? server = null)
{
    try
    {
        await installer.InstallAsync(fake.Session, server ?? NodeServer(), spec, new RecordingProgress());
        return null;
    }
    catch (BadRequestException ex) { return ex.Message; }
}
int At(FakeNode fake, int from, string fragment) =>
    fake.Commands.FindIndex(from, c => c.Contains(fragment, StringComparison.Ordinal));

{
    var fake = new FakeNode();
    var progress = new RecordingProgress();
    var installed = await NewInstaller(GoodDns()).InstallAsync(fake.Session, NodeServer(), PreparedSpec(), progress);
    var x = installed.XCore!;

    string[] order =
    [
        "docker ps -a", "mkdir -p", "chmod 700", "WRITE /opt/amnezia-xcore/caddy/Caddyfile",
        "WRITE /opt/amnezia-xcore/caddy/site/index.html", "ufw status", "--name amnezia-xcore-web", "curl ",
        " x25519", "WRITE /opt/amnezia-xcore/conf/config.json", "chmod 600 /opt/amnezia-xcore/conf/config.json",
        "run -test -c /etc/xcore/config.json", "--name amnezia-xcore --network host",
    ];
    var positions = order.Select(fake.IndexOf).ToArray();
    Check("установщик: шаги идут в заданном порядке",
        positions.All(i => i >= 0) && positions.SequenceEqual(positions.OrderBy(i => i)) && positions.Distinct().Count() == positions.Length,
        string.Join(",", positions));
    Check("установщик: ufw выключен — правил нет", !fake.Ran("ufw allow") && !fake.Ran("ufw enable"));
    Check("установщик: каталоги и конфиг закрыты (700/600)",
        fake.Modes[XCoreNode.ConfDir] == "700" && fake.Modes[XCoreNode.OpsDir] == "700" && fake.Modes[XCoreNode.ConfigPath] == "600");
    Check("установщик: Xray запущен по digest, от root, host-сеть, с ops только для чтения",
        fake.Commands.Any(c => c.Contains($"--name amnezia-xcore --network host --user 0:0 --restart always")
            && c.Contains("-v /opt/amnezia-xcore/conf:/etc/xcore:ro -v /opt/amnezia-xcore/ops:/etc/xcore-ops:ro")
            && c.EndsWith($"{XCoreNode.XrayImage} run -c /etc/xcore/config.json")));
    Check("установщик: Caddy запущен по digest с сертификатами в /data",
        fake.Commands.Any(c => c.Contains("--name amnezia-xcore-web --network host --restart always")
            && c.Contains("-v /opt/amnezia-xcore/caddy/data:/data -v /opt/amnezia-xcore/caddy/config:/config")
            && c.EndsWith(XCoreNode.CaddyImage)));
    Check("установщик: ключи генерируются в образе по digest", fake.Ran($"--rm {XCoreNode.XrayImage} x25519"));
    Check("установщик: сертификат проверяется без -k, с --resolve на 127.0.0.1:8443",
        fake.Commands.Any(c => c.StartsWith("curl ") && !c.Contains(" -k") && !c.Contains("--insecure")
            && c.Contains($"--resolve {XDomain}:8443:127.0.0.1 https://{XDomain}:8443/")));

    var caddyfile = fake.Writes.Single(w => w.Path.EndsWith("/Caddyfile")).Content;
    Check("установщик: Caddyfile с подставленными доменом и email",
        caddyfile.Contains($"https://{XDomain}:8443 {{") && caddyfile.Contains($"http://{XDomain} {{")
        && caddyfile.Contains("email ops@example.com") && !caddyfile.Contains("$DOMAIN") && !caddyfile.Contains("$ACME_EMAIL"));
    var index = fake.Writes.Single(w => w.Path.EndsWith("/index.html")).Content;
    Check("установщик: заглушка без упоминаний VPN", index.Contains("<html") && !Regex.IsMatch(index, "vpn|proxy|xray|reality", RegexOptions.IgnoreCase));

    Check("результат: вид, контейнер, порт, транспорт",
        installed.Kind == "xcore" && installed.ContainerName == "amnezia-xcore" && installed.Port == "443"
        && installed.TransportProto == "tcp" && installed.State == ProtocolStates.Installed);
    Check("результат: роль, домен, образ по digest, firefox, подписки включены",
        x.Role == "exit" && x.Domain == XDomain && x.ImageRef == XCoreNode.XrayImage && x.Fingerprint == "firefox"
        && x.SubscriptionEnabled && x.RealityPublicKey == FakeNode.PublicKey && x.XhttpPort == 443);
    Check("результат: shortId — 16 hex, путь — / и 16 символов [a-z0-9]",
        x.ShortIds.Count == 1 && Regex.IsMatch(x.ShortIds[0], "^[0-9a-f]{16}$") && Regex.IsMatch(x.XhttpPath!, "^/[a-z0-9]{16}$"));
    Check("результат: приватный ключ зашифрован и расшифровывается",
        x.RealityPrivateKey is not null && x.RealityPrivateKey.CipherText != FakeNode.PrivateKey
        && protector.Unprotect(x.RealityPrivateKey) == FakeNode.PrivateKey);
    var written = fake.Writes.Single(w => w.Path == XCoreNode.ConfigPath).Content;
    var expected = XCoreConfigRenderer.Render(x, FakeNode.PrivateKey, []);
    Check("результат: записан рендер без пользователей, ревизии совпадают с ним",
        written == expected.Json && x.AppliedRevision == expected.Revision && x.AppliedStructureRevision == expected.Revision
        && x.AppliedAt is not null);

    Check("секреты: приватный ключ только в записи config.json",
        fake.Writes.Where(w => w.Path != XCoreNode.ConfigPath).All(w => !w.Content.Contains(FakeNode.PrivateKey))
        && written.Contains(FakeNode.PrivateKey));
    Check("секреты: ключа нет ни в одной команде и метке операции",
        !fake.Commands.Any(c => c.Contains(FakeNode.PrivateKey)) && !fake.Labels.Any(l => l.Contains(FakeNode.PrivateKey)));
    Check("секреты: ключей нет в ходе установки",
        !progress.Texts.Any(t => t.Contains(FakeNode.PrivateKey) || t.Contains(FakeNode.PublicKey)));

    var second = await NewInstaller(GoodDns()).InstallAsync(new FakeNode().Session, NodeServer(), PreparedSpec(), new RecordingProgress());
    Check("shortId и путь случайны между установками",
        second.XCore!.ShortIds[0] != x.ShortIds[0] && second.XCore.XhttpPath != x.XhttpPath);

    var rm2 = new FakeNode();
    rm2.Containers.UnionWith([XCoreNode.XrayContainer, XCoreNode.WebContainer]);
    rm2.Files[XCoreNode.ConfigPath] = "{}";
    var rmInstaller = NewInstaller(GoodDns());
    await rmInstaller.RemoveAsync(rm2.Session, NodeServer(), installed, new RecordingProgress());
    Check("RemoveAsync: оба контейнера и каталог удалены, каталог — после контейнеров",
        rm2.Containers.Count == 0 && rm2.Files.Count == 0 && rm2.IndexOf("docker rm -f") < rm2.IndexOf("rm -rf /opt/amnezia-xcore"));
    var rm3 = new FakeNode();
    rm3.Containers.Add(XCoreNode.WebContainer);
    await rmInstaller.RemoveAsync(rm3.Session, NodeServer(), installed, new RecordingProgress());
    Check("RemoveAsync идемпотентна: одного из контейнеров нет — не ошибка", rm3.Containers.Count == 0 && rm3.Ran("rm -rf /opt/amnezia-xcore"));
    await rmInstaller.RestartAsync(fake.Session, NodeServer(), installed);
    Check("RestartAsync: docker restart amnezia-xcore", fake.Commands[^1] == "sudo docker restart amnezia-xcore");
}

{
    var fake = new FakeNode { UfwActive = true };
    await NewInstaller(GoodDns()).InstallAsync(fake.Session, NodeServer(), PreparedSpec(), new RecordingProgress());
    Check("установщик: ufw активен — открыты 80/tcp и 443/tcp до запуска Caddy",
        fake.Ran("ufw allow 80/tcp") && fake.Ran("ufw allow 443/tcp")
        && fake.IndexOf("ufw allow 443/tcp") < fake.IndexOf("--name amnezia-xcore-web"));
    Check("установщик: ufw не включается", !fake.Ran("ufw enable"));
}

{
    var dns = new FakeDns(new() { [XDomain] = ["198.51.100.9"] });
    var fake = new FakeNode();
    var message = await InstallErrorAsync(NewInstaller(dns), fake, PreparedSpec());
    Check("DNS: A-запись на чужой адрес — отказ с обоими адресами",
        message is not null && message.Contains("198.51.100.9") && message.Contains(NodeIp) && message.Contains(XDomain), message);
    Check("DNS: при расхождении на узле не выполнено ни одной команды", fake.Commands.Count == 0);

    fake = new FakeNode();
    message = await InstallErrorAsync(NewInstaller(new FakeDns(new())), fake, PreparedSpec());
    Check("DNS: у домена нет A-записи — отказ, узел не тронут", message is not null && message.Contains("нет A-записи") && fake.Commands.Count == 0);

    fake = new FakeNode();
    var multi = new FakeDns(new() { [XDomain] = ["198.51.100.9", NodeIp] });
    Check("DNS: среди нескольких A-записей есть адрес узла — принято", await InstallErrorAsync(NewInstaller(multi), fake, PreparedSpec()) is null);

    fake = new FakeNode();
    var named = new FakeDns(new() { [XDomain] = ["203.0.113.77"], ["node-host.example.net"] = ["203.0.113.77"] });
    var okNamed = await InstallErrorAsync(NewInstaller(named), fake, PreparedSpec(), NodeServer("node-host.example.net"));
    Check("DNS: Host — имя, оно резолвится и сравнивается с A-записью домена",
        okNamed is null && named.Queries.Contains("node-host.example.net"));

    fake = new FakeNode();
    message = await InstallErrorAsync(NewInstaller(new FakeDns(new() { [XDomain] = [NodeIp] })), fake, PreparedSpec(), NodeServer("unresolvable.example.net"));
    Check("DNS: Host не резолвится — отказ без команд на узле", message is not null && fake.Commands.Count == 0);

    fake = new FakeNode();
    var noEmail = NewInstaller(GoodDns(), email: null);
    message = await InstallErrorAsync(noEmail, fake, PreparedSpec());
    Check("без XCore:AcmeEmail установка отклоняется до обращения к узлу", message is not null && message.Contains("AcmeEmail") && fake.Commands.Count == 0);
    message = await InstallErrorAsync(NewInstaller(GoodDns(), email: "x\n}\nhttp://evil {"), new FakeNode(), PreparedSpec());
    Check("email с переводом строки и скобками отвергается (подстановка в Caddyfile)", message is not null);

    fake = new FakeNode();
    var unknownRole = PreparedSpec();
    unknownRole.Role = "relay";
    message = await InstallErrorAsync(NewInstaller(GoodDns()), fake, unknownRole);
    Check("установщик: неизвестная роль отклонена до команд на узле", message is not null && fake.Commands.Count == 0);

    fake = new FakeNode();
    fake.Containers.Add(XCoreNode.WebContainer);
    message = await InstallErrorAsync(NewInstaller(GoodDns()), fake, PreparedSpec());
    Check("установщик: контейнер уже есть — отказ, кроме списка контейнеров ничего не выполнено",
        message is not null && fake.Commands.Count == 1 && fake.Commands[0].StartsWith("sudo docker ps -a"));
    Check("установщик: чужой существующий контейнер не удалён", fake.Containers.Contains(XCoreNode.WebContainer));
}

{
    var fake = new FakeNode { TestFails = true };
    var message = await InstallErrorAsync(NewInstaller(GoodDns()), fake, PreparedSpec());
    Check("run -test не прошёл: отказ с текстом Xray", message is not null && message.Contains("Failed to start"), message);
    Check("run -test не прошёл: контейнер amnezia-xcore не запускался", !fake.Ran("--name amnezia-xcore --network host"));
    Check("run -test не прошёл: Caddy убран, повторная установка не упрётся в «контейнер уже есть»",
        fake.Containers.Count == 0 && fake.Ran("docker rm -f amnezia-xcore amnezia-xcore-web"));
    Check("run -test не прошёл: каталог с сертификатом не тронут", !fake.Ran("rm -rf"));
    Check("run -test не прошёл: сообщение без приватного ключа", message is not null && !message.Contains(FakeNode.PrivateKey));

    fake = new FakeNode { CertificateNever = true };
    message = await InstallErrorAsync(NewInstaller(GoodDns()), fake, PreparedSpec());
    Check("нет сертификата: отказ с подсказкой про A-запись и порт 80",
        message is not null && message.Contains("Не удалось получить сертификат") && message.Contains("порт 80"), message);
    Check("нет сертификата: опрошен ровно CertificateAttempts раз", fake.CurlCalls == 3);
    Check("нет сертификата: ключи не генерировались, Xray не запускался",
        !fake.Ran(" x25519") && !fake.Ran("--name amnezia-xcore --network host") && fake.Containers.Count == 0);
}

// ── Синхронизация ────────────────────────────────────────────────────────────

Console.WriteLine("Синхронизация xcore");

const string UuidRotated = "99999999-8888-7777-6666-555555555555";
XCoreSyncService NewSync() => new(protector, new ScriptRegistry(), Options.Create(new XCoreOptions { AcmeEmail = "ops@example.com" })) { RestartPollAttempts = 3, RestartPollInterval = TimeSpan.Zero };
void Applied(ProtocolInstance protocol, XCoreSyncResult result)
{
    protocol.XCore!.AppliedRevision = result.Revision;
    protocol.XCore.AppliedStructureRevision = result.StructureRevision;
}
async Task<(FakeNode Node, VpnServer Server, ProtocolInstance Protocol)> ProvisionAsync()
{
    var fake = new FakeNode();
    var server = NodeServer();
    var protocol = await NewInstaller(GoodDns()).InstallAsync(fake.Session, server, PreparedSpec(), new RecordingProgress());
    server.Protocols.Add(protocol);
    return (fake, server, protocol);
}
async Task<T?> CatchAsync<T>(Func<Task> action) where T : Exception
{
    try { await action(); return null; }
    catch (T ex) { return ex; }
}
bool LiveIs(FakeNode fake, params (string Email, string Uuid)[] expected) =>
    fake.Live.Count == expected.Length && expected.All(e => fake.Live.Any(u => u.Email == e.Email && u.Uuid == e.Uuid));

var syncNodes = new List<FakeNode>();
var syncMessages = new List<string>();

{
    var (fake, server, protocol) = await ProvisionAsync();
    syncNodes.Add(fake);
    var sync = NewSync();
    XCoreUser Abc() => new("sub-abc", UuidAbc);
    XCoreUser Def() => new("sub-def", UuidDef);
    XCoreUser Ghi() => new("sub-ghi", UuidGhi);

    var start = fake.Commands.Count;
    var result = await sync.SyncAsync(fake.Session, server, protocol, [], default);
    Check("sync: ревизия совпала и живой список пуст — NoOp", result.Action == XCoreSyncAction.NoOp);
    Check("sync: NoOp не пишет и не меняет ничего, только читает список",
        fake.Commands.Count == start + 1 && fake.Commands[^1].Contains("xray api inbounduser"));

    start = fake.Commands.Count;
    result = await sync.SyncAsync(fake.Session, server, protocol, [Def(), Abc()], default);
    Check("sync: новые пользователи — Diff без перезапуска, добавлено 2",
        result is { Action: XCoreSyncAction.Diff, Added: 2, Removed: 0 } && !fake.Ran("docker restart"));
    Check("sync: на узле ровно желаемые пользователи с верными UUID", LiveIs(fake, ("sub-abc", UuidAbc), ("sub-def", UuidDef)));
    var expectedFull = XCoreConfigRenderer.Render(protocol.XCore!, FakeNode.PrivateKey, [Abc(), Def()]);
    Check("sync: config.json на хосте = рендер с полным списком", fake.Files[XCoreNode.ConfigPath] == expectedFull.Json
        && result.Revision == expectedFull.Revision && result.StructureRevision == protocol.XCore!.AppliedStructureRevision);
    var iWrite = At(fake, start, "WRITE /opt/amnezia-xcore/conf/config.new.json");
    var iTest = At(fake, start, "run -test -c /etc/xcore/config.new.json");
    var iMove = At(fake, start, "sudo mv -f /opt/amnezia-xcore/conf/config.new.json /opt/amnezia-xcore/conf/config.json");
    var iAdu = At(fake, start, "xray api adu");
    Check("sync: новый конфиг записан → проверен Xray → переименован → только потом пользователи через API",
        iWrite >= 0 && iWrite < iTest && iTest < iMove && iMove < iAdu, $"{iWrite},{iTest},{iMove},{iAdu}");
    Check("sync: config.new.json не остаётся", !fake.Files.ContainsKey(XCoreNode.NewConfigPath));
    Check("sync: файл ops удалён, а до этого закрыт chmod 600",
        !fake.Files.Keys.Any(k => k.StartsWith(XCoreNode.OpsDir)) && fake.Modes.Any(m => m.Key.StartsWith(XCoreNode.OpsDir + "/adu-") && m.Value == "600"));
    Applied(protocol, result);

    start = fake.Commands.Count;
    result = await sync.SyncAsync(fake.Session, server, protocol, [Abc(), Def()], default);
    Check("sync: повтор с теми же пользователями — NoOp, одна команда чтения",
        result.Action == XCoreSyncAction.NoOp && fake.Commands.Count == start + 1);

    start = fake.Commands.Count;
    result = await sync.SyncAsync(fake.Session, server, protocol, [Abc(), Ghi()], default);
    Check("sync: def → ghi: удалён 1, добавлен 1, без перезапуска",
        result is { Action: XCoreSyncAction.Diff, Added: 1, Removed: 1 } && !fake.Ran("docker restart"));
    Check("sync: на узле abc и ghi, def нет", LiveIs(fake, ("sub-abc", UuidAbc), ("sub-ghi", UuidGhi)));
    var rmu = fake.Commands.Skip(start).Single(c => c.Contains("xray api rmu"));
    Check("sync: rmu вызван только для sub-def", rmu.Contains("'sub-def'") && !rmu.Contains("sub-abc") && !rmu.Contains("sub-ghi"));
    var aduFile = fake.Writes.Last(w => w.Path.StartsWith(XCoreNode.OpsDir + "/adu-"));
    Check("sync: в файл adu попал только недостающий пользователь",
        aduFile.Content.Contains(UuidGhi) && !aduFile.Content.Contains(UuidAbc) && !aduFile.Content.Contains(UuidDef));
    Applied(protocol, result);

    start = fake.Commands.Count;
    result = await sync.SyncAsync(fake.Session, server, protocol, [new("sub-abc", UuidRotated), Ghi()], default);
    Check("sync: перевыпуск UUID — удаление и повторное добавление, а не «already exists»",
        result is { Action: XCoreSyncAction.Diff, Added: 1, Removed: 1 } && LiveIs(fake, ("sub-abc", UuidRotated), ("sub-ghi", UuidGhi)));
    var iRmu = At(fake, start, "xray api rmu");
    Check("sync: удаление стоит перед добавлением", iRmu >= 0 && iRmu < At(fake, start, "xray api adu"));
    Applied(protocol, result);

    fake.Live.Clear();
    start = fake.Commands.Count;
    result = await sync.SyncAsync(fake.Session, server, protocol, [new("sub-abc", UuidRotated), Ghi()], default);
    Check("sync: ревизия сходится, но узел потерял пользователей — Diff их возвращает",
        result is { Action: XCoreSyncAction.Diff, Added: 2, Removed: 0 } && LiveIs(fake, ("sub-abc", UuidRotated), ("sub-ghi", UuidGhi)));
    Check("sync: расхождение с живым списком заново записывает и проверяет файл", At(fake, start, "run -test -c /etc/xcore/config.new.json") >= 0);
    Applied(protocol, result);

    var oldStructure = protocol.XCore!.AppliedStructureRevision;
    protocol.XCore.XhttpPath = "/rotated0123456789";
    start = fake.Commands.Count;
    result = await sync.SyncAsync(fake.Session, server, protocol, [new("sub-abc", UuidRotated), Ghi()], default);
    Check("sync: смена пути XHTTP — структурное изменение, перезапуск", result.Action == XCoreSyncAction.Restart && result.StructureRevision != oldStructure);
    Check("sync: после перезапуска пользователи берутся из файла, API-добавлений нет",
        fake.Ran("sudo docker restart amnezia-xcore") && At(fake, start, "xray api adu") < 0 && At(fake, start, "xray api rmu") < 0
        && LiveIs(fake, ("sub-abc", UuidRotated), ("sub-ghi", UuidGhi)));
    Check("sync: файл с новым путём уже на месте до перезапуска",
        fake.Files[XCoreNode.ConfigPath].Contains("/rotated0123456789")
        && At(fake, start, "sudo mv -f") < At(fake, start, "sudo docker restart"));
    Applied(protocol, result);

    protocol.XCore.AppliedStructureRevision = null;
    protocol.XCore.AppliedRevision = "stale";
    result = await sync.SyncAsync(fake.Session, server, protocol, [new("sub-abc", UuidRotated), Ghi()], default);
    Check("sync: неизвестная прежняя структура — безопасный перезапуск", result.Action == XCoreSyncAction.Restart);

    Check("sync: узел не из этого сервера отвергается",
        await CatchAsync<InvalidOperationException>(() => sync.SyncAsync(fake.Session, NodeServer(), protocol, [], default)) is not null);
}

{
    var (fake, server, protocol) = await ProvisionAsync();
    syncNodes.Add(fake);
    var sync = NewSync();
    var before = fake.Files[XCoreNode.ConfigPath];

    fake.TestFails = true;
    var start = fake.Commands.Count;
    var ex = await CatchAsync<XCoreSyncException>(() => sync.SyncAsync(fake.Session, server, protocol, [new("sub-abc", UuidAbc)], default));
    Check("sync: Xray отклонил конфиг — XCoreSyncException", ex is not null && ex.Message.Contains("отклонил"));
    Check("sync: отклонённый конфиг не подменил рабочий и не остался на хосте",
        fake.Files[XCoreNode.ConfigPath] == before && !fake.Files.ContainsKey(XCoreNode.NewConfigPath)
        && At(fake, start, "sudo mv") < 0 && At(fake, start, "docker restart") < 0 && At(fake, start, "xray api adu") < 0);
    if (ex is not null) syncMessages.Add(ex.Message);
    fake.TestFails = false;

    fake.AduReportsError = true;
    ex = await CatchAsync<XCoreSyncException>(() => sync.SyncAsync(fake.Session, server, protocol, [new("sub-abc", UuidAbc)], default));
    Check("sync: adu сообщил об ошибке — исключение с причиной", ex is not null && ex.Message.Contains("boom"), ex?.Message);
    Check("sync: файл ops удалён даже при ошибке adu", !fake.Files.Keys.Any(k => k.StartsWith(XCoreNode.OpsDir)));
    if (ex is not null) syncMessages.Add(ex.Message);
    fake.AduReportsError = false;

    fake.AduThrows = true;
    var thrown = await CatchAsync<InvalidOperationException>(() => sync.SyncAsync(fake.Session, server, protocol, [new("sub-abc", UuidAbc)], default));
    Check("sync: обрыв на adu пробрасывается, файл ops всё равно удалён",
        thrown is not null && !fake.Files.Keys.Any(k => k.StartsWith(XCoreNode.OpsDir)));
    fake.AduThrows = false;

    fake.ApiDown = true;
    ex = await CatchAsync<XCoreSyncException>(() => sync.SyncAsync(fake.Session, server, protocol, [], default));
    Check("sync: API недоступен — XCoreSyncException с кодом, без текста команды",
        ex is not null && ex.Message.Contains("кодом 1") && !ex.Message.Contains("docker exec"), ex?.Message);
    if (ex is not null) syncMessages.Add(ex.Message);
    fake.ApiDown = false;

    protocol.XCore!.XhttpPath = "/another0123456789";
    fake.RestartLosesUsers = true;
    ex = await CatchAsync<XCoreSyncException>(() => sync.SyncAsync(fake.Session, server, protocol,
        [new("sub-abc", UuidAbc), new("sub-def", UuidDef)], default));
    Check("sync: после перезапуска узел поднялся не со всеми пользователями — ошибка, а не успех",
        ex is not null && ex.Message.Contains("вместо 2"), ex?.Message);
    if (ex is not null) syncMessages.Add(ex.Message);

    protocol.XCore.RealityPrivateKey = null;
    ex = await CatchAsync<XCoreSyncException>(() => sync.SyncAsync(fake.Session, server, protocol, [], default));
    Check("sync: без приватного ключа — понятное исключение", ex is not null && ex.Message.Contains("приватного ключа"));
    protocol.XCore.RealityPrivateKey = protector.Protect(FakeNode.PrivateKey);
    protocol.XCore.ImageRef = "x; rm -rf /";
    Check("sync: ссылка на образ с shell-символами отвергается до команд",
        await CatchAsync<XCoreSyncException>(() => sync.SyncAsync(fake.Session, server, protocol, [], default)) is not null);
}

{
    string[] secrets = [UuidAbc, UuidDef, UuidGhi, UuidRotated, FakeNode.PrivateKey];
    var leakedCommand = syncNodes.SelectMany(n => n.Commands).FirstOrDefault(c => secrets.Any(s => c.Contains(s)));
    Check("секреты: ни UUID, ни приватного ключа в командах синхронизации", leakedCommand is null);
    Check("секреты: ни UUID, ни приватного ключа в метках операций SSH",
        !syncNodes.SelectMany(n => n.Labels).Any(l => secrets.Any(s => l.Contains(s))));
    Check("секреты: ни UUID, ни приватного ключа в текстах исключений",
        syncMessages.Count == 4 && !syncMessages.Any(m => secrets.Any(s => m.Contains(s))));
    Check("секреты: UUID есть только в записях файлов (config и adu)",
        syncNodes.SelectMany(n => n.Writes).Any(w => w.Content.Contains(UuidAbc)));
}

// ── Обработчик xcore.sync ────────────────────────────────────────────────────

Console.WriteLine("Обработчик xcore.sync");

const string SubIdAbc = "69ca5beaba00e3c10adc4591";
const string SubIdDef = "69ca5beaba00e3c10adc4592";
const string SubIdGhi = "69ca5beaba00e3c10adc4593";
Subscription Sub(string id, string uuid) => new() { Id = id, UserId = "69ca5beaba00e3c10adc4599", XrayUuid = uuid };
DomainEvent SyncEvent(VpnServer s, ProtocolInstance p) => new()
{
    Type = DomainEventTypes.XCoreSync,
    Payload = new XCoreSyncPayload(s.Id, p.Id).ToBsonDocument(),
};
int Restarts(FakeNode f) => f.Commands.Count(c => c == "sudo docker restart amnezia-xcore");

{
    var handlerPolicy = new SyncHarness(new FakeNode(), null, NewSync(), protector).Handler;
    Check("handler: тип события — xcore.sync", handlerPolicy.EventType == "xcore.sync");
    Check("handler: политика Retrying(5, 30 с), возвращает оборванное в очередь",
        handlerPolicy.Policy == DomainEventPolicy.Retrying(5, TimeSpan.FromSeconds(30)) && handlerPolicy.Policy.RetryOnLeaseExpiry);
}

{
    var (fake, server, protocol) = await ProvisionAsync();
    protocol.State = ProtocolStates.Installed;
    protocol.XCore!.SyncError = "прежняя ошибка";
    var h = new SyncHarness(fake, server, NewSync(), protector);
    h.Desired.Add(Sub(SubIdAbc, UuidAbc));
    var evt = SyncEvent(server, protocol);

    var result = await h.Handler.HandleAsync(evt, default);
    Check("handler: подписчик из базы добавлен на узел под email sub-{id} со своим UUID, без перезапуска",
        LiveIs(fake, ($"sub-{SubIdAbc}", UuidAbc)) && Restarts(fake) == 0 && result!["action"] == "Diff");
    Check("handler: успех → ревизии, время применения записаны, SyncError сброшен",
        h.Applied is [var applied] && applied.ServerId == server.Id && applied.ProtocolId == protocol.Id
        && protocol.XCore.AppliedRevision == applied.Revision && protocol.XCore.AppliedStructureRevision == applied.Structure
        && protocol.XCore.AppliedAt is not null && protocol.XCore.SyncError is null);
    var expected = XCoreConfigRenderer.Render(protocol.XCore, FakeNode.PrivateKey, [new($"sub-{SubIdAbc}", UuidAbc)]);
    Check("handler: записанная ревизия — ревизия конфига с желаемым списком", protocol.XCore.AppliedRevision == expected.Revision);

    result = await h.Handler.HandleAsync(evt, default);
    Check("handler: повторное событие при том же списке — NoOp, но подтверждение применения обновляется",
        result!["action"] == "NoOp" && h.Applied.Count == 2 && Restarts(fake) == 0);

    h.Desired.Clear();
    h.Desired.Add(Sub(SubIdDef, UuidDef));
    result = await h.Handler.HandleAsync(evt, default);
    Check("handler: отозванная подписка снята с узла, новая добавлена — через API",
        LiveIs(fake, ($"sub-{SubIdDef}", UuidDef)) && result!["added"] == 1 && result["removed"] == 1 && Restarts(fake) == 0);
    Check("handler: узел открывался по SSH по разу на событие", h.Connections == 3);
}

{
    // API завис: первая попытка падает, вторая — с перезапуском — должна его поднять.
    var (fake, server, protocol) = await ProvisionAsync();
    protocol.State = ProtocolStates.Installed;
    var h = new SyncHarness(fake, server, NewSync(), protector);
    h.Desired.Add(Sub(SubIdAbc, UuidAbc));
    var evt = SyncEvent(server, protocol);
    await h.Handler.HandleAsync(evt, default);

    h.Desired.Add(Sub(SubIdDef, UuidDef));
    fake.ApiDown = true;
    fake.RestartRevivesApi = true;
    var start = fake.Commands.Count;
    var result = await h.Handler.HandleAsync(evt, default);
    Check("handler: API не ответил — повтор в той же обработке с принудительным перезапуском (один)",
        result!["action"] == "Restart" && Restarts(fake) == 1);
    Check("handler: после повтора на узле оба подписчика, файл конфига уже содержит их до перезапуска",
        LiveIs(fake, ($"sub-{SubIdAbc}", UuidAbc), ($"sub-{SubIdDef}", UuidDef))
        && At(fake, start, "sudo mv -f") >= 0 && At(fake, start, "sudo mv -f") < At(fake, start, "sudo docker restart"));
    Check("handler: после повтора ревизии записаны, ошибки нет", h.Applied.Count == 2 && protocol.XCore!.SyncError is null && h.Errors.Count == 0);
}

{
    // API не поднимается и после перезапуска: событие падает (дальше — повторы по политике), ошибку видит оператор.
    var (fake, server, protocol) = await ProvisionAsync();
    protocol.State = ProtocolStates.Installed;
    var h = new SyncHarness(fake, server, NewSync(), protector);
    h.Desired.Add(Sub(SubIdGhi, UuidGhi));
    var evt = SyncEvent(server, protocol);
    fake.ApiDown = true;

    var ex = await CatchAsync<XCoreSyncException>(() => h.Handler.HandleAsync(evt, default));
    Check("handler: окончательный провал — XCoreSyncException, ревизии не записаны",
        ex is not null && ex.ApiUnavailable && h.Applied.Count == 0 && Restarts(fake) == 1, ex?.Message);

    await h.Handler.OnFailedAsync(evt, ex!.Message, default);
    Check("handler: OnFailed записывает SyncError в протокол узла",
        h.Errors is [var written] && written.ServerId == server.Id && written.ProtocolId == protocol.Id
        && protocol.XCore!.SyncError == written.Error && written.Error.Contains("API Xray"), protocol.XCore!.SyncError);

    var dirty = $"Failed: user {UuidAbc} key {FakeNode.PrivateKey} \"id\": \"{UuidDef}\"";
    var safe = XCoreSyncHandler.SafeError(dirty);
    Check("handler: безопасный текст ошибки без UUID и ключей",
        !new[] { UuidAbc, UuidDef, FakeNode.PrivateKey }.Any(s => safe.Contains(s)) && safe.StartsWith("Failed: user"), safe);
    Check("handler: длинная ошибка обрезается", XCoreSyncHandler.SafeError(new string('x', 5000)).Length <= 301);
    Check("handler: пустая ошибка получает текст по умолчанию", XCoreSyncHandler.SafeError("  ").Length > 0);

    // Ошибка, не связанная с API (конфиг отклонён), перезапуском не лечится — повтора с рестартом нет.
    var (fake2, server2, protocol2) = await ProvisionAsync();
    protocol2.State = ProtocolStates.Installed;
    var h2 = new SyncHarness(fake2, server2, NewSync(), protector);
    h2.Desired.Add(Sub(SubIdAbc, UuidAbc));
    fake2.TestFails = true;
    var ex2 = await CatchAsync<XCoreSyncException>(() => h2.Handler.HandleAsync(SyncEvent(server2, protocol2), default));
    Check("handler: конфиг отклонён Xray — исключение без принудительного перезапуска",
        ex2 is not null && !ex2.ApiUnavailable && Restarts(fake2) == 0, ex2?.Message);
}

{
    var (fake, server, protocol) = await ProvisionAsync();
    protocol.State = ProtocolStates.Installed;
    var evt = SyncEvent(server, protocol);

    var gone = new SyncHarness(fake, null, NewSync(), protector);
    var result = await gone.Handler.HandleAsync(evt, default);
    Check("handler: узла нет — успех без SSH", result!["skipped"] == "not_applicable" && gone.Connections == 0);

    var other = NodeServer();
    other.Protocols.Add(new ProtocolInstance { Id = protocol.Id, Kind = ProtocolKinds.Awg2, ContainerName = "amnezia-awg2", Port = "40000" });
    var notXCore = new SyncHarness(fake, other, NewSync(), protector);
    result = await notXCore.Handler.HandleAsync(evt, default);
    Check("handler: протокол уже не xcore — успех без SSH", result!["skipped"] == "not_applicable" && notXCore.Connections == 0);

    protocol.State = ProtocolStates.Installing;
    var installing = new SyncHarness(fake, server, NewSync(), protector);
    result = await installing.Handler.HandleAsync(evt, default);
    Check("handler: протокол ещё не установлен — успех без SSH", result!["skipped"] == "not_applicable" && installing.Connections == 0);

    protocol.State = ProtocolStates.Installed;
    protocol.XCore!.Role = "relay";
    var entry = new SyncHarness(fake, server, NewSync(), protector);
    result = await entry.Handler.HandleAsync(evt, default);
    Check("handler: неизвестная роль подписчиков не получает — успех без SSH", result!["skipped"] == "not_applicable" && entry.Connections == 0);

    Check("handler: пропуск ничего не пишет в базу", gone.Applied.Count + notXCore.Applied.Count + installing.Applied.Count + entry.Applied.Count == 0);
}

// ── Учёт трафика xcore ───────────────────────────────────────────────────────

Console.WriteLine("Учёт трафика xcore");

{
    var (fake, server, protocol) = await ProvisionAsync();
    protocol.State = ProtocolStates.Installed;
    var poll = new PollHarness(fake);
    var a = Sub(SubIdAbc, UuidAbc);
    poll.Subscriptions[a.Id] = a;
    var emailA = a.XrayEmail;

    fake.Stats[emailA] = (Uplink: 100, Downlink: 1000);
    await poll.PollAsync(server);
    var statsCommand = fake.Commands.Single(c => c.Contains("xray api statsquery"));
    Check("поллер: statsquery с шаблоном в кавычках и без -reset",
        statsCommand.Contains("-pattern 'user>>>sub-'") && !statsCommand.Contains("-reset"), statsCommand);
    Check("поллер: первый опрос — приращение равно счётчику; rx — downlink, tx — uplink",
        a.Usage.RxBytes == 1000 && a.Usage.TxBytes == 100 && a.RawByNode[server.Id] is { Rx: 1000, Tx: 100 });
    Check("поллер: суточный срез подписки и трафик узла получили то же приращение",
        poll.Daily is [(SubIdAbc, 1000, 100)] && poll.ServerDaily is [var s1] && s1 == (server.Id, 1000, 100));

    fake.Stats[emailA] = (150, 1600);
    await poll.PollAsync(server);
    Check("поллер: второй опрос добавляет разницу, а не значение целиком",
        a.Usage.RxBytes == 1600 && a.Usage.TxBytes == 150 && a.RawByNode[server.Id] is { Rx: 1600, Tx: 150 });

    var applyCalls = poll.ApplyCalls;
    await poll.PollAsync(server);
    Check("поллер: счётчики не изменились — в базу ничего не пишется", poll.ApplyCalls == applyCalls && poll.Daily.Count == 2);

    // Контейнер перезапущен: счётчики Xray обнулились и выросли заново.
    fake.Stats[emailA] = (20, 70);
    await poll.PollAsync(server);
    Check("поллер: сырое значение меньше прежнего — рестарт контейнера, всё показание — новое приращение",
        a.Usage.RxBytes == 1670 && a.Usage.TxBytes == 170 && a.RawByNode[server.Id] is { Rx: 70, Tx: 20 });
    Check("поллер: накопленное не уменьшилось", a.Usage.TotalBytes == 1840);

    // Узел недоступен: сырые значения и накопленное не трогаем.
    var before = (a.Usage.RxBytes, a.Usage.TxBytes, a.RawByNode[server.Id].Rx, a.RawByNode[server.Id].Tx);
    var writes = poll.Updates.Count;
    fake.ApiDown = true;
    fake.Stats[emailA] = (999, 9999);
    await poll.PollAsync(server);
    Check("поллер: API узла не ответил — тик пропущен, сырые значения не тронуты",
        poll.Updates.Count == writes && before == (a.Usage.RxBytes, a.Usage.TxBytes, a.RawByNode[server.Id].Rx, a.RawByNode[server.Id].Tx));
    fake.ApiDown = false;

    poll.Connect = () => throw new SshConnectionException("203.0.113.5", new IOException("timeout"));
    var unreachable = await CatchAsync<SshConnectionException>(() => poll.PollAsync(server));
    Check("поллер: узел недоступен по SSH — исключение уходит в обход узлов, сырые значения не тронуты",
        unreachable is not null && poll.Updates.Count == writes && a.RawByNode[server.Id] is { Rx: 70, Tx: 20 });
    poll.Connect = () => fake.Session;

    // Первое показание после недоступности — обычное приращение от сохранённой базы.
    fake.Stats[emailA] = (30, 200);
    await poll.PollAsync(server);
    Check("поллер: узел вернулся — приращение считается от последних сохранённых значений",
        a.Usage.RxBytes == 1670 + 130 && a.Usage.TxBytes == 170 + 10);

    // Подписка пропала с узла (нет счётчика) и чужие записи.
    writes = poll.Updates.Count;
    var totals = a.Usage.TotalBytes;
    fake.Stats.Clear();
    fake.Stats["sub-ffffffffffffffffffffffff"] = (5, 5);
    fake.Stats["sub-not-an-object-id"] = (7, 7);
    await poll.PollAsync(server);
    Check("поллер: у подписки нет счётчика, а чужие email неизвестны — ничего не меняется",
        poll.Updates.Count == writes && a.Usage.TotalBytes == totals);

    // Вторая подписка и второй узел: сырые значения хранятся по узлам.
    var d = Sub(SubIdDef, UuidDef);
    poll.Subscriptions[d.Id] = d;
    var (fake2, server2, protocol2) = await ProvisionAsync();
    server2.Id = "69ca5beaba00e3c10adc4530";
    protocol2.State = ProtocolStates.Installed;
    poll.Connect = () => fake2.Session;
    fake2.Stats[emailA] = (40, 400);
    fake2.Stats[d.XrayEmail] = (1, 2);
    await poll.PollAsync(server2);
    Check("поллер: тот же подписчик на втором узле считается от нуля, первый узел не затронут",
        a.RawByNode.Count == 2 && a.RawByNode[server2.Id] is { Rx: 400, Tx: 40 } && a.RawByNode[server.Id] is { Rx: 200, Tx: 30 }
        && a.Usage.RxBytes == 1670 + 130 + 400 && d.Usage is { RxBytes: 2, TxBytes: 1 });
}

// ── Регистрация в DI ─────────────────────────────────────────────────────────

Console.WriteLine("Регистрация в DI");

{
    var config = new ConfigurationBuilder()
        .AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Security:DataProtectionKey"] = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)),
            ["XCore:AcmeEmail"] = "ops@example.com",
        }).Build();
    var services = new ServiceCollection();
    services.AddAmneziaData(config);
    services.AddAmneziaProtocols();
    services.AddAmneziaNodeAccess();
    using var provider = services.BuildServiceProvider(new ServiceProviderOptions { ValidateScopes = true });
    using var scope = provider.CreateScope();
    var installers = scope.ServiceProvider.GetRequiredService<IProtocolInstallerRegistry>();
    Check("DI: установщик xcore разрешается из реестра", installers.IsSupported("xcore") && installers.Get("xcore") is XCoreInstaller);
    Check("DI: XCoreSyncService разрешается (AddAmneziaNodeAccess)", scope.ServiceProvider.GetRequiredService<XCoreSyncService>() is not null);
    Check("DI: XCore:AcmeEmail читается из конфигурации",
        scope.ServiceProvider.GetRequiredService<IOptions<XCoreOptions>>().Value.AcmeEmail == "ops@example.com");
}

// ── Оркестратор ──────────────────────────────────────────────────────────────

Console.WriteLine("Оркестратор: установка xcore");

// Подмены для проверки гонки за номер маршрута: обработчик вызывается при записи узла, а выходы, «успевшие»
// записаться раньше, добавляются в то, что отдаёт GetAllAsync.
Func<VpnServer, Task>? orchestratorUpdateHook = null;
List<VpnServer> orchestratorRaced = [];

(InstallOrchestrator Orchestrator, InstallJob Job, VpnServer Server, RecordingEvents Events) NewOrchestrator(
    FakeNode fake, string? role = null, params VpnServer[] others)
{
    var server = new VpnServer { Id = "69ca5beaba00e3c10adc4540", Name = "xc", Host = NodeIp };
    var spec = XSpec();
    spec.Role = role;
    var job = new InstallJob
    {
        Id = "69ca5beaba00e3c10adc4541", ServerId = server.Id, Kind = InstallJobKinds.AddProtocol, Spec = [spec],
        Steps = [.. InstallStepCodes.All.Select(s => new InstallStep { Code = s.Code, Title = s.Title })],
    };
    var servers = Stub.Create<IVpnServerRepository>((m, _) => m.Name switch
    {
        "GetByIdAsync" => Task.FromResult<VpnServer?>(server),
        "GetAllAsync" => Task.FromResult<List<VpnServer>>([server, .. others, .. orchestratorRaced]),
        "UpdateInstallationAsync" => orchestratorUpdateHook?.Invoke(server) ?? Task.CompletedTask,
        _ => throw new NotSupportedException(m.Name),
    });
    var jobs = Stub.Create<IInstallJobRepository>((m, _) => m.Name switch
    {
        "GetByIdAsync" => Task.FromResult<InstallJob?>(job),
        "UpdateAsync" or "AppendLogAsync" => Task.CompletedTask,
        _ => throw new NotSupportedException(m.Name),
    });
    var factory = Stub.Create<ISshSessionFactory>((_, _) => Task.FromResult(fake.Session));
    var events = new RecordingEvents();
    var publisher = new XCoreSyncPublisher(servers, events.Publisher, NullLogger<XCoreSyncPublisher>.Instance);
    var orchestrator = new InstallOrchestrator(servers, jobs, factory,
        new ProtocolInstallerRegistry([NewInstaller(GoodDns())]), new ProtocolRegistry([]), new ScriptRegistry(),
        NullLogger<InstallOrchestrator>.Instance, publisher);
    return (orchestrator, job, server, events);
}

{
    var fake = new FakeNode();
    var (orchestrator, job, server, events) = NewOrchestrator(fake);
    await orchestrator.ExecuteAsync(job, default);
    var installed = server.Protocols.SingleOrDefault();
    Check("оркестратор: установка xcore без конфигуратора завершается успехом", job.Status == InstallJobStatuses.Succeeded, job.Error);
    Check("оркестратор: протокол сохранён как установленный, версия — первая строка xray version",
        installed is { Kind: "xcore", State: ProtocolStates.Installed }
        && installed.ContainerVersion!.StartsWith("Xray 26.10.21") && !installed.ContainerVersion.Contains('\n'));
    Check("оркестратор: проверены оба порта по TCP до запуска контейнеров",
        fake.Commands.Any(c => c == "sudo ss -H -lnt 'sport = :443'") && fake.Commands.Any(c => c == "sudo ss -H -lnt 'sport = :80'")
        && fake.IndexOf("sport = :80'") < fake.IndexOf("docker run -d"));
    Check("оркестратор: API статистики опрошен", fake.Ran("xray api inboundusercount --server=127.0.0.1:10085 -tag=vless-xhttp"));
    Check("оркестратор: версия читается docker exec amnezia-xcore xray version", fake.Commands.Contains(XCoreNode.VersionCommand));
    Check("оркестратор: после установки опубликован xcore.sync ровно на этот узел и протокол, партиция — узел",
        events.Published is [{ Type: DomainEventTypes.XCoreSync } sync]
        && Equals(sync.Payload, new XCoreSyncPayload(server.Id, installed!.Id)) && sync.Partition == server.Id);

    fake = new FakeNode();
    (orchestrator, job, server, events) = NewOrchestrator(fake);
    events.Fail = true;
    await orchestrator.ExecuteAsync(job, default);
    Check("оркестратор: недоступная публикация xcore.sync не проваливает успешную установку (подхватит сверка)",
        job.Status == InstallJobStatuses.Succeeded && events.Published.Count == 0, job.Error);

    fake = new FakeNode();
    fake.BusyPorts.Add("80");
    (orchestrator, job, server, events) = NewOrchestrator(fake);
    await orchestrator.ExecuteAsync(job, default);
    Check("оркестратор: порт 80 занят — задача провалена с понятным текстом, контейнеры не создавались",
        job.Status == InstallJobStatuses.Failed && job.Error!.Contains("443 и 80") && !fake.Ran("docker run"), job.Error);
    Check("оркестратор: проваленная установка xcore.sync не публикует", events.Published.Count == 0);
}

// ── Маршрут выхода в UUID ────────────────────────────────────────────────────

Console.WriteLine("Маршрут выхода в UUID");

Check("маршрут 1: третья группа 0001, остальное нетронуто",
    XCoreRoute.WithRoute(UuidAbc, 1) == "11111111-2222-0001-4444-555555555555");
Check("маршрут 65535: третья группа ffff", XCoreRoute.WithRoute(UuidAbc, 65535) == "11111111-2222-ffff-4444-555555555555");
Check("маршрут 258: big-endian, 0102", XCoreRoute.WithRoute(UuidAbc, 258) == "11111111-2222-0102-4444-555555555555");
Check("маршрут 255 и 256 — не путаются местами байты", XCoreRoute.WithRoute(UuidAbc, 255) == "11111111-2222-00ff-4444-555555555555"
    && XCoreRoute.WithRoute(UuidAbc, 256) == "11111111-2222-0100-4444-555555555555");
Check("маршрут: UUID в верхнем регистре приводится к нижнему",
    XCoreRoute.WithRoute("AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE", 7) == "aaaaaaaa-bbbb-0007-dddd-eeeeeeeeeeee");
Check("маршрут: UUID без дефисов тоже разбирается и выдаётся в формате D",
    XCoreRoute.WithRoute("11111111222233334444555555555555", 3) == "11111111-2222-0003-4444-555555555555");
Check("маршрут: результат — тот же GUID с другой третьей группой, остальные группы равны",
    Guid.Parse(XCoreRoute.WithRoute(UuidDef, 9)).ToString("D")[..13] == UuidDef[..13]
    && Guid.Parse(XCoreRoute.WithRoute(UuidDef, 9)).ToString("D")[18..] == UuidDef[18..]);
Check("маршрут: 0, 65536 и отрицательный отвергаются",
    Throws<ArgumentOutOfRangeException>(() => XCoreRoute.WithRoute(UuidAbc, 0))
    && Throws<ArgumentOutOfRangeException>(() => XCoreRoute.WithRoute(UuidAbc, 65536))
    && Throws<ArgumentOutOfRangeException>(() => XCoreRoute.WithRoute(UuidAbc, -1)));
Check("маршрут: не-GUID отвергается", Throws<ArgumentException>(() => XCoreRoute.WithRoute("not-a-uuid", 1)));
Check("NextFree: пусто — 1; 1,2,4 — 3; 2 — 1 (освободившийся номер используется)",
    XCoreRoute.NextFree([]) == 1 && XCoreRoute.NextFree([1, 2, 4]) == 3 && XCoreRoute.NextFree([2]) == 1);
Check("NextFree: порядок и повторы не важны", XCoreRoute.NextFree([3, 1, 1, 2, 2]) == 4);
Check("NextFree: заняты все 65535 — исключение", Throws<InvalidOperationException>(() => XCoreRoute.NextFree(Enumerable.Range(1, 65535))));
Check("NextFree: заняты все, кроме 65535 — последний номер выдаётся", XCoreRoute.NextFree(Enumerable.Range(1, 65534)) == 65535);

// ── Списки доменов входа ─────────────────────────────────────────────────────

Console.WriteLine("Списки доменов входа");

string Normalized(string raw) => XCoreRoutingDomains.TryNormalize(raw, out var n, out _) ? n : "<отказ>";

Check("домены: голое имя становится domain: (иначе в Xray это подстрока)", Normalized("Example.COM") == "domain:example.com");
Check("домены: domain:, full:, keyword: сохраняются",
    Normalized("domain:a.example.com") == "domain:a.example.com" && Normalized("full:www.example.com") == "full:www.example.com"
    && Normalized(" keyword:Chat_gpt ") == "keyword:chat_gpt");
Check("домены: однобуквенный TLD и punycode допустимы", Normalized("domain:ru") == "domain:ru" && Normalized("xn--80ak6aa92e.xn--p1ai") == "domain:xn--80ak6aa92e.xn--p1ai");

string[] badRoutingDomains =
[
    "", "  ", "regexp:.*", "regexp:^a", "geosite:cn", "geosite:category-ru", "geoip:ru", "ext:file:tag", "dotless:x", "http://example.com",
    "example.com/path", "a b.example.com", "1.2.3.4", "domain:", "keyword:", "keyword:a b", "domain:-bad.com", "full:bad-.com", "domain:a..b.com",
    "*.example.com", "domain:exa\nmple.com", "пример.рф", new string('a', 64) + ".com", new string('a', 250) + ".com", "unknown:x.com",
];
var acceptedBadDomains = badRoutingDomains.Where(d => XCoreRoutingDomains.TryNormalize(d, out _, out _)).ToList();
Check("домены: regexp:/geosite:/ext:, URL, IP, пробелы и пустое отвергаются", acceptedBadDomains.Count == 0, string.Join(" | ", acceptedBadDomains));
Check("домены: Normalize убирает повторы, порядок сохраняется",
    XCoreRoutingDomains.Normalize(["b.example.com", "A.example.com", "domain:b.example.com"], "x").SequenceEqual(["domain:b.example.com", "domain:a.example.com"]));
string? domainErrorText = null;
try { XCoreRoutingDomains.Normalize(["ok.example.com", "regexp:secret-pattern"], "Всегда напрямую"); } catch (InvalidOperationException ex) { domainErrorText = ex.Message; }
Check("домены: ошибка называет список и номер записи, без самого значения",
    domainErrorText is not null && domainErrorText.Contains("Всегда напрямую") && domainErrorText.Contains("запись 2") && !domainErrorText.Contains("secret-pattern"), domainErrorText);
Check("домены: больше 1000 записей отвергается",
    Throws<InvalidOperationException>(() => XCoreRoutingDomains.Normalize(Enumerable.Range(0, 1001).Select(i => $"h{i}.example.com"), "x")));

// ── Рендер входа ─────────────────────────────────────────────────────────────

Console.WriteLine("Рендер входа");

const string RelayUuid = "c0ffee00-1111-4222-8333-444444444444";
const string EntryPrivate = PrivateKey;

string KeyOf(int seed) => Convert.ToBase64String(Enumerable.Range(seed, 32).Select(i => (byte)i).ToArray())
    .TrimEnd('=').Replace('+', '-').Replace('/', '_');

XCoreExitTarget ExitT(int route) =>
    new(route, $"exit{route}.example.com", 443, KeyOf(route * 10), (route % 256).ToString("x2") + "aa11bb22cc33dd", $"/exit{route}path", "firefox");

XCoreProtocolParams NewEntryNode(Action<XCoreProtocolParams>? tweak = null)
{
    var n = new XCoreProtocolParams
    {
        Role = XCoreRoles.Entry,
        Domain = "entry.example.com",
        ImageRef = XrayImage,
        RealityPublicKey = PublicKey,
        ShortIds = ["0a1b2c3d4e5f6071"],
        XhttpPath = "/entrypath01234567",
        ProxyDomains = ["Youtube.com", "keyword:chat"],
        DirectDomains = ["bank.example.ru", "full:pay.example.ru"],
    };
    tweak?.Invoke(n);
    return n;
}

string Describe(JsonNode? rule)
{
    var o = rule!.AsObject();
    var parts = new List<string>();
    foreach (var key in new[] { "vlessRoute", "domain", "ip", "network" })
        if (o.ContainsKey(key))
            parts.Add(key + "=" + (o[key] is JsonArray a ? string.Join("|", a.Select(x => x!.GetValue<string>())) : o[key]!.GetValue<string>()));
    return string.Join(";", parts) + ">" + o["outboundTag"]!.GetValue<string>();
}

string[] RulesOf(string json) => [.. JsonNode.Parse(json)!["routing"]!["rules"]!.AsArray().Select(Describe)];
string PrivateRule = "ip=" + string.Join("|", expectedCidrs) + ">block";

XCoreExitTarget[] twoExits = [ExitT(2), ExitT(1)];
var entryNode = NewEntryNode();
var entryRendered = XCoreConfigRenderer.RenderEntry(entryNode, EntryPrivate, users, RelayUuid, twoExits);
var ecfg = JsonNode.Parse(entryRendered.Json)!.AsObject();
var einbound = ecfg["inbounds"]![0]!.AsObject();

var exitLike = NewNode();
exitLike.Domain = entryNode.Domain;
exitLike.XhttpPath = entryNode.XhttpPath;
exitLike.ShortIds = entryNode.ShortIds;
var inboundWithoutSniffing = JsonNode.Parse(einbound.ToJsonString())!.AsObject();
inboundWithoutSniffing.Remove("sniffing");
Check("вход: ровно один inbound того же вида, что у выхода (кроме sniffing)",
    ecfg["inbounds"]!.AsArray().Count == 1
    && inboundWithoutSniffing.ToJsonString() == JsonNode.Parse(XCoreConfigRenderer.Render(exitLike, EntryPrivate, users).Json)!["inbounds"]![0]!.ToJsonString());
Check("вход: sniffing http/tls/quic с routeOnly",
    einbound["sniffing"]!["enabled"]!.GetValue<bool>() && einbound["sniffing"]!["routeOnly"]!.GetValue<bool>()
    && string.Join(",", einbound["sniffing"]!["destOverride"]!.AsArray().Select(s => s!.GetValue<string>())) == "http,tls,quic");
Check("вход: клиенты отсортированы по email, служебного пользователя среди них нет",
    string.Join(",", einbound["settings"]!["clients"]!.AsArray().Select(c => c!["email"]!.GetValue<string>())) == "sub-abc,sub-def");
Check("вход: dns — два DoH с https+local и queryStrategy UseIPv4, других серверов нет",
    string.Join(",", ecfg["dns"]!["servers"]!.AsArray().Select(s => s!.GetValue<string>()))
        == "https+local://1.1.1.1/dns-query,https+local://8.8.8.8/dns-query"
    && ecfg["dns"]!["queryStrategy"]!.GetValue<string>() == "UseIPv4");
Check("вход: у выхода dns нет", !JsonNode.Parse(rendered.Json)!.AsObject().ContainsKey("dns"));
Check("вход: api, stats и policy те же, что у выхода",
    ecfg["api"]!.ToJsonString() == cfg["api"]!.ToJsonString() && ecfg["policy"]!.ToJsonString() == cfg["policy"]!.ToJsonString()
    && ecfg["stats"] is JsonObject { Count: 0 });
Check("вход: domainStrategy IPIfNonMatch", ecfg["routing"]!["domainStrategy"]!.GetValue<string>() == "IPIfNonMatch");

var eOutbounds = ecfg["outbounds"]!.AsArray();
Check("outbounds: direct, block, затем exit-1 и exit-2 по номеру маршрута (вход упорядочен вопреки порядку аргумента)",
    string.Join(",", eOutbounds.Select(o => o!["tag"]!.GetValue<string>())) == "direct,block,exit-1,exit-2"
    && eOutbounds[0]!["protocol"]!.GetValue<string>() == "freedom" && eOutbounds[1]!["protocol"]!.GetValue<string>() == "blackhole");
var exit1Out = eOutbounds[2]!.AsObject();
var exit1Vnext = exit1Out["settings"]!["vnext"]![0]!;
var exit1Reality = exit1Out["streamSettings"]!["realitySettings"]!;
Check("exit-1: vless, vnext на домен и порт выхода, пользователь — служебный UUID входа, encryption none",
    exit1Out["protocol"]!.GetValue<string>() == "vless" && exit1Vnext["address"]!.GetValue<string>() == "exit1.example.com"
    && exit1Vnext["port"]!.GetValue<int>() == 443 && exit1Vnext["users"]!.AsArray().Count == 1
    && exit1Vnext["users"]![0]!["id"]!.GetValue<string>() == RelayUuid && exit1Vnext["users"]![0]!["encryption"]!.GetValue<string>() == "none"
    && !exit1Vnext["users"]![0]!.AsObject().ContainsKey("flow"));
Check("exit-1: xhttp + reality, serverName = домен выхода, publicKey, shortId, fingerprint, spiderX пуст",
    exit1Out["streamSettings"]!["network"]!.GetValue<string>() == "xhttp" && exit1Out["streamSettings"]!["security"]!.GetValue<string>() == "reality"
    && exit1Reality["serverName"]!.GetValue<string>() == "exit1.example.com" && exit1Reality["publicKey"]!.GetValue<string>() == KeyOf(10)
    && exit1Reality["shortId"]!.GetValue<string>() == "01aa11bb22cc33dd" && exit1Reality["fingerprint"]!.GetValue<string>() == "firefox"
    && exit1Reality["spiderX"]!.GetValue<string>() == "");
Check("exit-1: путь выхода и mode auto",
    exit1Out["streamSettings"]!["xhttpSettings"]!["path"]!.GetValue<string>() == "/exit1path"
    && exit1Out["streamSettings"]!["xhttpSettings"]!["mode"]!.GetValue<string>() == "auto");
var exit2Reality = eOutbounds[3]!["streamSettings"]!["realitySettings"]!;
Check("exit-2: свои домен, ключ и shortId (параметры выходов не смешиваются)",
    eOutbounds[3]!["settings"]!["vnext"]![0]!["address"]!.GetValue<string>() == "exit2.example.com"
    && exit2Reality["serverName"]!.GetValue<string>() == "exit2.example.com" && exit2Reality["publicKey"]!.GetValue<string>() == KeyOf(20)
    && exit2Reality["shortId"]!.GetValue<string>() == "02aa11bb22cc33dd"
    && eOutbounds[3]!["streamSettings"]!["xhttpSettings"]!["path"]!.GetValue<string>() == "/exit2path");

string[] expectedEntryRules =
[
    PrivateRule,
    "vlessRoute=1;domain=domain:youtube.com|keyword:chat>exit-1",
    "vlessRoute=2;domain=domain:youtube.com|keyword:chat>exit-2",
    // Маршрут 0 и неизвестные: «через VPN» сильнее российских списков и для них.
    "domain=domain:youtube.com|keyword:chat>exit-1",
    "domain=domain:bank.example.ru|full:pay.example.ru>direct",
    "domain=geosite:category-ru|geosite:category-gov-ru>direct",
    "ip=geoip:ru>direct",
    "vlessRoute=1>exit-1",
    "vlessRoute=2>exit-2",
    "network=tcp,udp>exit-1",
];
Check("правила входа: порядок строго такой (приватные → через VPN → напрямую → РФ → маршруты → остальное)",
    RulesOf(entryRendered.Json).SequenceEqual(expectedEntryRules), string.Join(" / ", RulesOf(entryRendered.Json)));
Check("правила входа: у каждого type=field",
    ecfg["routing"]!["rules"]!.AsArray().All(r => r!["type"]!.GetValue<string>() == "field"));
Check("правила входа: vlessRoute — десятичная строка, как в правиле Xray",
    ecfg["routing"]!["rules"]![7]!["vlessRoute"]!.GetValue<string>() == "1");
Check("правила входа: приватные CIDR — тот же список, что у выхода",
    ecfg["routing"]!["rules"]![0]!["ip"]!.ToJsonString() == cfg["routing"]!["rules"]![0]!["ip"]!.ToJsonString());

var noRu = XCoreConfigRenderer.RenderEntry(NewEntryNode(n => n.RuDirect = false), EntryPrivate, users, RelayUuid, twoExits);
Check("RuDirect=false: в конфиге нет ни geosite, ни geoip",
    !noRu.Json.Contains("geosite") && !noRu.Json.Contains("geoip"));
Check("RuDirect=false: остальные правила на месте и в том же порядке",
    RulesOf(noRu.Json).SequenceEqual(expectedEntryRules.Where(r => !r.Contains("geo"))));
Check("RuDirect=false даёт другую ревизию", noRu.Revision != entryRendered.Revision);
Check("RuDirect по умолчанию включён", new XCoreProtocolParams().RuDirect);

var plain = XCoreConfigRenderer.RenderEntry(NewEntryNode(n => { n.ProxyDomains = []; n.DirectDomains = []; }), EntryPrivate, users, RelayUuid, twoExits);
Check("без списков доменов правил по доменам оператора нет",
    RulesOf(plain.Json).SequenceEqual([PrivateRule, "domain=geosite:category-ru|geosite:category-gov-ru>direct", "ip=geoip:ru>direct",
        "vlessRoute=1>exit-1", "vlessRoute=2>exit-2", "network=tcp,udp>exit-1"]));
var oneExit = XCoreConfigRenderer.RenderEntry(NewEntryNode(n => n.RuDirect = false), EntryPrivate, users, RelayUuid, [ExitT(7)]);
Check("один выход: все правила на exit-7, final — тоже",
    RulesOf(oneExit.Json).All(r => !r.Contains("exit-1") && !r.Contains("exit-2"))
    && RulesOf(oneExit.Json)[^1] == "network=tcp,udp>exit-7");
var highest = XCoreConfigRenderer.RenderEntry(NewEntryNode(), EntryPrivate, users, RelayUuid, [ExitT(5), ExitT(3), ExitT(65535)]);
Check("final-правило ведёт на наименьший номер маршрута", RulesOf(highest.Json)[^1] == "network=tcp,udp>exit-3");

var closed = XCoreConfigRenderer.RenderEntry(NewEntryNode(), EntryPrivate, users, RelayUuid, []);
Check("без выходов: правила — приватные в блок и «всё» в block, больше ничего",
    RulesOf(closed.Json).SequenceEqual([PrivateRule, "network=tcp,udp>block"]), string.Join(" / ", RulesOf(closed.Json)));
Check("без выходов: ни одно правило не ведёт на direct или exit-*",
    !RulesOf(closed.Json).Any(r => r.EndsWith(">direct") || r.Contains(">exit-")));
Check("без выходов: нет outbound-ов выходов и списки доменов оператора в конфиг не попадают",
    JsonNode.Parse(closed.Json)!["outbounds"]!.AsArray().Count == 2
    && !closed.Json.Contains("youtube") && !closed.Json.Contains("bank.example.ru") && !closed.Json.Contains(RelayUuid));
Check("без выходов: sniffing и dns на месте (вход остаётся входом)",
    JsonNode.Parse(closed.Json)!["inbounds"]![0]!["sniffing"] is not null && JsonNode.Parse(closed.Json)!["dns"] is not null);

// Детерминизм и ревизии.
var entryAgain = XCoreConfigRenderer.RenderEntry(NewEntryNode(), EntryPrivate, [users[1], users[0]], RelayUuid, [twoExits[1], twoExits[0]]);
Check("вход: перестановка пользователей и выходов не меняет Json и ревизию", entryAgain.Json == entryRendered.Json && entryAgain.Revision == entryRendered.Revision);
Check("вход: Json компактный", !entryRendered.Json.Contains('\n'));
var entryStructure = XCoreConfigRenderer.RenderEntryStructureRevision(entryNode, EntryPrivate, RelayUuid, twoExits);
Check("вход: структурная ревизия = рендер без пользователей, не зависит от пользователей",
    entryStructure == XCoreConfigRenderer.RenderEntry(entryNode, EntryPrivate, [], RelayUuid, twoExits).Revision
    && entryStructure != entryRendered.Revision
    && XCoreConfigRenderer.RenderEntry(entryNode, EntryPrivate, [.. users, new("sub-zzz", UuidGhi)], RelayUuid, twoExits).Revision != entryRendered.Revision
    && XCoreConfigRenderer.RenderEntryStructureRevision(entryNode, EntryPrivate, RelayUuid, twoExits) == entryStructure);
Check("вход: добавление, удаление и правка выхода меняют структурную ревизию (топология перезапускает вход)",
    XCoreConfigRenderer.RenderEntryStructureRevision(entryNode, EntryPrivate, RelayUuid, [ExitT(1)]) != entryStructure
    && XCoreConfigRenderer.RenderEntryStructureRevision(entryNode, EntryPrivate, RelayUuid, [.. twoExits, ExitT(3)]) != entryStructure
    && XCoreConfigRenderer.RenderEntryStructureRevision(entryNode, EntryPrivate, RelayUuid, [twoExits[0] with { Domain = "moved.example.com" }, twoExits[1]]) != entryStructure
    && XCoreConfigRenderer.RenderEntryStructureRevision(entryNode, EntryPrivate, RelayUuid, [twoExits[0] with { PublicKey = KeyOf(99) }, twoExits[1]]) != entryStructure);
Check("вход: смена списка доменов или служебного UUID меняет структурную ревизию",
    XCoreConfigRenderer.RenderEntryStructureRevision(NewEntryNode(n => n.ProxyDomains = ["other.example.com"]), EntryPrivate, RelayUuid, twoExits) != entryStructure
    && XCoreConfigRenderer.RenderEntryStructureRevision(entryNode, EntryPrivate, "c0ffee00-1111-4222-8333-444444444445", twoExits) != entryStructure);

// Золотой образец выхода: рендер выхода не должен измениться от появления входа.
var goldenNode = new XCoreProtocolParams
{
    Role = XCoreRoles.Exit, Domain = "node1.example.com", ImageRef = XrayImage, ShortIds = ["a1b2c3d4e5f60718"], XhttpPath = "/x7Kq2mPz",
};
var goldenExit = $$$$"""{"log":{"loglevel":"warning","access":"none"},"api":{"tag":"api","listen":"127.0.0.1:10085","services":["HandlerService","StatsService"]},"stats":{},"policy":{"levels":{"0":{"statsUserUplink":true,"statsUserDownlink":true}}},"inbounds":[{"tag":"vless-xhttp","listen":"0.0.0.0","port":443,"protocol":"vless","settings":{"clients":[{"id":"{{{{UuidAbc}}}}","email":"sub-abc","level":0}],"decryption":"none"},"streamSettings":{"network":"xhttp","security":"reality","realitySettings":{"target":"127.0.0.1:8443","serverNames":["node1.example.com"],"privateKey":"{{{{PrivateKey}}}}","shortIds":["a1b2c3d4e5f60718"]},"xhttpSettings":{"path":"/x7Kq2mPz","mode":"auto"}}}],"outbounds":[{"tag":"direct","protocol":"freedom"},{"tag":"block","protocol":"blackhole"}],"routing":{"domainStrategy":"IPIfNonMatch","rules":[{"type":"field","ip":["127.0.0.0/8","10.0.0.0/8","172.16.0.0/12","192.168.0.0/16","169.254.0.0/16","100.64.0.0/10","0.0.0.0/8","::1/128","fc00::/7","fe80::/10"],"outboundTag":"block"}]}}""";
Check("выход: конфиг совпадает с зафиксированным образцом дословно",
    XCoreConfigRenderer.Render(goldenNode, PrivateKey, [new("sub-abc", UuidAbc)]).Json == goldenExit);


Console.WriteLine("Российские списки на входе: рендер, разбор, раскладка");

// Золотые образцы входа без российских списков, снятые со сборки ДО появления списков (D1): рендер входа без
// RfListsTag обязан остаться побайтово прежним. A — два выхода, списки оператора, «РФ напрямую»; C — вход без выходов.
// Для B (без «РФ напрямую») и D (без списков оператора) хранится SHA-256 тех же образцов.
const string GoldenEntryA = """{"log":{"loglevel":"warning","access":"none"},"api":{"tag":"api","listen":"127.0.0.1:10085","services":["HandlerService","StatsService"]},"stats":{},"policy":{"levels":{"0":{"statsUserUplink":true,"statsUserDownlink":true}}},"dns":{"servers":["https\u002Blocal://1.1.1.1/dns-query","https\u002Blocal://8.8.8.8/dns-query"],"queryStrategy":"UseIPv4"},"inbounds":[{"tag":"vless-xhttp","listen":"0.0.0.0","port":443,"protocol":"vless","settings":{"clients":[{"id":"11111111-2222-3333-4444-555555555555","email":"sub-abc","level":0},{"id":"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee","email":"sub-def","level":0}],"decryption":"none"},"streamSettings":{"network":"xhttp","security":"reality","realitySettings":{"target":"127.0.0.1:8443","serverNames":["entry.example.com"],"privateKey":"CCjvIm9FrG2plFwEag9_EIjqZ5YegsIIzTRa7ysTNF8","shortIds":["0a1b2c3d4e5f6071"]},"xhttpSettings":{"path":"/entrypath01234567","mode":"auto"}},"sniffing":{"enabled":true,"destOverride":["http","tls","quic"],"routeOnly":true}}],"outbounds":[{"tag":"direct","protocol":"freedom"},{"tag":"block","protocol":"blackhole"},{"tag":"exit-1","protocol":"vless","settings":{"vnext":[{"address":"exit1.example.com","port":443,"users":[{"id":"c0ffee00-1111-4222-8333-444444444444","encryption":"none"}]}]},"streamSettings":{"network":"xhttp","security":"reality","realitySettings":{"serverName":"exit1.example.com","publicKey":"CgsMDQ4PEBESExQVFhcYGRobHB0eHyAhIiMkJSYnKCk","shortId":"01aa11bb22cc33dd","fingerprint":"firefox","spiderX":""},"xhttpSettings":{"path":"/exit1path","mode":"auto"}}},{"tag":"exit-2","protocol":"vless","settings":{"vnext":[{"address":"exit2.example.com","port":443,"users":[{"id":"c0ffee00-1111-4222-8333-444444444444","encryption":"none"}]}]},"streamSettings":{"network":"xhttp","security":"reality","realitySettings":{"serverName":"exit2.example.com","publicKey":"FBUWFxgZGhscHR4fICEiIyQlJicoKSorLC0uLzAxMjM","shortId":"02aa11bb22cc33dd","fingerprint":"firefox","spiderX":""},"xhttpSettings":{"path":"/exit2path","mode":"auto"}}}],"routing":{"domainStrategy":"IPIfNonMatch","rules":[{"type":"field","ip":["127.0.0.0/8","10.0.0.0/8","172.16.0.0/12","192.168.0.0/16","169.254.0.0/16","100.64.0.0/10","0.0.0.0/8","::1/128","fc00::/7","fe80::/10"],"outboundTag":"block"},{"type":"field","vlessRoute":"1","domain":["domain:youtube.com","keyword:chat"],"outboundTag":"exit-1"},{"type":"field","vlessRoute":"2","domain":["domain:youtube.com","keyword:chat"],"outboundTag":"exit-2"},{"type":"field","domain":["domain:youtube.com","keyword:chat"],"outboundTag":"exit-1"},{"type":"field","domain":["domain:bank.example.ru","full:pay.example.ru"],"outboundTag":"direct"},{"type":"field","domain":["geosite:category-ru","geosite:category-gov-ru"],"outboundTag":"direct"},{"type":"field","ip":["geoip:ru"],"outboundTag":"direct"},{"type":"field","vlessRoute":"1","outboundTag":"exit-1"},{"type":"field","vlessRoute":"2","outboundTag":"exit-2"},{"type":"field","network":"tcp,udp","outboundTag":"exit-1"}]}}""";
const string GoldenEntryC = """{"log":{"loglevel":"warning","access":"none"},"api":{"tag":"api","listen":"127.0.0.1:10085","services":["HandlerService","StatsService"]},"stats":{},"policy":{"levels":{"0":{"statsUserUplink":true,"statsUserDownlink":true}}},"dns":{"servers":["https\u002Blocal://1.1.1.1/dns-query","https\u002Blocal://8.8.8.8/dns-query"],"queryStrategy":"UseIPv4"},"inbounds":[{"tag":"vless-xhttp","listen":"0.0.0.0","port":443,"protocol":"vless","settings":{"clients":[{"id":"11111111-2222-3333-4444-555555555555","email":"sub-abc","level":0},{"id":"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee","email":"sub-def","level":0}],"decryption":"none"},"streamSettings":{"network":"xhttp","security":"reality","realitySettings":{"target":"127.0.0.1:8443","serverNames":["entry.example.com"],"privateKey":"CCjvIm9FrG2plFwEag9_EIjqZ5YegsIIzTRa7ysTNF8","shortIds":["0a1b2c3d4e5f6071"]},"xhttpSettings":{"path":"/entrypath01234567","mode":"auto"}},"sniffing":{"enabled":true,"destOverride":["http","tls","quic"],"routeOnly":true}}],"outbounds":[{"tag":"direct","protocol":"freedom"},{"tag":"block","protocol":"blackhole"}],"routing":{"domainStrategy":"IPIfNonMatch","rules":[{"type":"field","ip":["127.0.0.0/8","10.0.0.0/8","172.16.0.0/12","192.168.0.0/16","169.254.0.0/16","100.64.0.0/10","0.0.0.0/8","::1/128","fc00::/7","fe80::/10"],"outboundTag":"block"},{"type":"field","network":"tcp,udp","outboundTag":"block"}]}}""";
const string GoldenEntryBSha = "d8a36f059b653cf84b37368297b94f4a20cb88e3315ce64dd5ae64501a2df646";
const string GoldenEntryDSha = "ce7f2330d2a01dfa639545f7ff915e80ed88350f9ce8ed95f4d02f830b972c76";

string Sha(string text) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(text)));
const string RfTag = "202610291019";

Check("вход без списков РФ: рендер побайтово равен образцу A, снятому до появления списков",
    entryRendered.Json == GoldenEntryA, entryRendered.Json.Length + " байт");
Check("вход без списков РФ и без выходов: образец C", closed.Json == GoldenEntryC);
Check("вход без списков РФ: варианты без «РФ напрямую» и без списков оператора — образцы B и D по SHA-256",
    Sha(noRu.Json) == GoldenEntryBSha && Sha(plain.Json) == GoldenEntryDSha);
Check("пустой тег эквивалентен отсутствию: тот же образец",
    XCoreConfigRenderer.RenderEntry(NewEntryNode(n => n.RfListsTag = ""), EntryPrivate, users, RelayUuid, twoExits).Json == GoldenEntryA);
Check("в образце без списков нет ни одной ссылки на ext:", !entryRendered.Json.Contains("ext:"));

var rfNode = NewEntryNode(n => n.RfListsTag = RfTag);
var rfRendered = XCoreConfigRenderer.RenderEntry(rfNode, EntryPrivate, users, RelayUuid, twoExits);
string[] expectedRfRules =
[
    PrivateRule,
    "vlessRoute=1;domain=domain:youtube.com|keyword:chat>exit-1",
    "vlessRoute=2;domain=domain:youtube.com|keyword:chat>exit-2",
    "domain=domain:youtube.com|keyword:chat>exit-1",
    "domain=domain:bank.example.ru|full:pay.example.ru>direct",
    // «Заблокировано в РФ»: после явных списков оператора, до российских «напрямую»; по маршрутам и общим правилом.
    "vlessRoute=1;domain=ext:rf-geosite.dat:ru-blocked>exit-1",
    "vlessRoute=2;domain=ext:rf-geosite.dat:ru-blocked>exit-2",
    "domain=ext:rf-geosite.dat:ru-blocked>exit-1",
    "vlessRoute=1;ip=ext:rf-geoip.dat:ru-blocked>exit-1",
    "vlessRoute=2;ip=ext:rf-geoip.dat:ru-blocked>exit-2",
    "ip=ext:rf-geoip.dat:ru-blocked>exit-1",
    "domain=geosite:category-ru|geosite:category-gov-ru|ext:rf-geosite.dat:ru-available-only-inside>direct",
    "ip=geoip:ru>direct",
    "vlessRoute=1>exit-1",
    "vlessRoute=2>exit-2",
    "network=tcp,udp>exit-1",
];
var rfRules = RulesOf(rfRendered.Json);
Check("со списками РФ: порядок правил (приватные, через VPN, напрямую оператора, заблокировано в РФ, РФ напрямую, маршруты, остальное)",
    rfRules.SequenceEqual(expectedRfRules), string.Join(" / ", rfRules));
Check("со списками РФ: ru-blocked выше любого российского «напрямую»",
    rfRules.Select((r, i) => (r, i)).Where(x => x.r.Contains("ru-blocked")).Max(x => x.i)
        < rfRules.ToList().FindIndex(r => r.Contains("geosite:category-ru")));
Check("со списками РФ: ru-available-only-inside только в правиле «напрямую», вместе с category-ru и category-gov-ru",
    rfRules.Count(r => r.Contains("ru-available-only-inside")) == 1
    && rfRules.Single(r => r.Contains("ru-available-only-inside")).EndsWith(">direct")
    && rfRules.Single(r => r.Contains("ru-available-only-inside")).Contains("geosite:category-gov-ru"));
Check("со списками РФ: ни одно правило с ext: не ведёт на direct, кроме ru-available-only-inside",
    rfRules.Where(r => r.Contains("ext:") && !r.Contains("ru-available-only-inside")).All(r => r.Contains(">exit-")));
Check("со списками РФ: ревизия другая, тег релиза в JSON не попадает (только имена файлов)",
    rfRendered.Revision != entryRendered.Revision && !rfRendered.Json.Contains(RfTag));
Check("RenderEntryWithRfLists(узел без тега, тег) = RenderEntry(узел с тегом); с null = без списков",
    XCoreConfigRenderer.RenderEntryWithRfLists(entryNode, EntryPrivate, users, RelayUuid, twoExits, RfTag).Json == rfRendered.Json
    && XCoreConfigRenderer.RenderEntryWithRfLists(rfNode, EntryPrivate, users, RelayUuid, twoExits, null).Json == GoldenEntryA);
Check("другой тег при тех же правилах конфиг не меняет (тег — признак наличия файлов)",
    XCoreConfigRenderer.RenderEntry(NewEntryNode(n => n.RfListsTag = "202611010000"), EntryPrivate, users, RelayUuid, twoExits).Json == rfRendered.Json);
Check("структурная ревизия входа меняется, когда появляются списки (применяется рестартом)",
    XCoreConfigRenderer.RenderEntryStructureRevision(rfNode, EntryPrivate, RelayUuid, twoExits)
        != XCoreConfigRenderer.RenderEntryStructureRevision(entryNode, EntryPrivate, RelayUuid, twoExits));

var rfNoRu = XCoreConfigRenderer.RenderEntry(NewEntryNode(n => { n.RfListsTag = RfTag; n.RuDirect = false; }), EntryPrivate, users, RelayUuid, twoExits);
Check("«РФ напрямую» выключена: со списками РФ конфиг тот же, что без них (ссылаться не на что)",
    rfNoRu.Json == noRu.Json && !rfNoRu.Json.Contains("ext:"));
var rfClosed = XCoreConfigRenderer.RenderEntry(NewEntryNode(n => n.RfListsTag = RfTag), EntryPrivate, users, RelayUuid, []);
Check("вход без выходов со списками РФ: конфиг тот же, закрытый, без ext:", rfClosed.Json == GoldenEntryC);
var rfOneExit = RulesOf(XCoreConfigRenderer.RenderEntry(NewEntryNode(n => n.RfListsTag = RfTag), EntryPrivate, users, RelayUuid, [ExitT(7)]).Json);
Check("один выход со списками РФ: все четыре ru-blocked-правила ведут на exit-7",
    rfOneExit.Count(r => r.Contains("ru-blocked")) == 4 && rfOneExit.Where(r => r.Contains("ru-blocked")).All(r => r.EndsWith(">exit-7")));
var rfExitNode = NewNode();
rfExitNode.RfListsTag = RfTag;
Check("выход с тегом в параметрах: рендер выхода не меняется",
    XCoreConfigRenderer.Render(rfExitNode, PrivateKey, users).Json == XCoreConfigRenderer.Render(NewNode(), PrivateKey, users).Json);

// Пробный конфиг ссылается ровно на те ext:-теги, которые способен выдать рендерер.
var renderedExt = Regex.Matches(rfRendered.Json, "ext:[^\"]+").Select(m => m.Value).ToHashSet();
var probeExt = Regex.Matches(XCoreRfLists.ProbeConfig(), "ext:[^\"]+").Select(m => m.Value).ToHashSet();
Check("пробный конфиг: JSON, ссылки на ext: те же, что в рендере входа (правило нельзя добавить, забыв про пробу)",
    JsonNode.Parse(XCoreRfLists.ProbeConfig()) is not null && renderedExt.SetEquals(probeExt) && probeExt.Count == 3,
    string.Join(",", probeExt));

// Разбор *.sha256sum.
const string Sum1 = "87bc066ce3afb07add67eb375f0ee31aad3aba418a322c7f164927be510698da";
const string Sum2 = "76fdbe01687a6cc7683b50c38ceea84941458e8371d215918daf555665a537cd";
Check("sha256sum: образец релиза — двоичный режим «hex *имя» (так публикует runetfreedom)",
    XCoreRfLists.ParseSha256Sum($"{Sum2} *geosite.dat\n", "geosite.dat") == Sum2);
Check("sha256sum: текстовый режим «hex  имя» (как в задании) и CRLF",
    XCoreRfLists.ParseSha256Sum($"{Sum1}  geoip.dat\r\n", "geoip.dat") == Sum1);
Check("sha256sum: из нескольких строк берётся строка нужного файла",
    XCoreRfLists.ParseSha256Sum($"{Sum1} *geoip.dat\n{Sum2} *geosite.dat\n", "geosite.dat") == Sum2);
Check("sha256sum: чужое имя, пустой текст, null, короткий hex, не-hex, имя с префиксом — null",
    XCoreRfLists.ParseSha256Sum($"{Sum1} *geoip.dat\n", "geosite.dat") is null
    && XCoreRfLists.ParseSha256Sum("", "geosite.dat") is null && XCoreRfLists.ParseSha256Sum(null, "geosite.dat") is null
    && XCoreRfLists.ParseSha256Sum($"{Sum1[..63]} *geosite.dat\n", "geosite.dat") is null
    && XCoreRfLists.ParseSha256Sum($"{new string('z', 64)} *geosite.dat\n", "geosite.dat") is null
    && XCoreRfLists.ParseSha256Sum($"{Sum1} *xgeosite.dat\n", "geosite.dat") is null);
Check("sha256sum: верхний регистр приводится к нижнему; путь перед именем отбрасывается",
    XCoreRfLists.ParseSha256Sum($"{Sum2.ToUpperInvariant()}  ./out/geosite.dat\n", "geosite.dat") == Sum2);
Check("вывод sha256sum <файл>: первое слово; мусор — null",
    XCoreRfLists.ParseSha256Output($"{Sum1}  /opt/amnezia-xcore/geo-stage/rf-geoip.dat.part\n") == Sum1
    && XCoreRfLists.ParseSha256Output("sha256sum: нет файла") is null && XCoreRfLists.ParseSha256Output("") is null);

// Что идёт в shell, проверяется.
Check("тег релиза: допустимые проходят, подстановки и пробелы — нет",
    new[] { "202610291019", "v1.2.3", "r_1-2" }.All(XCoreRfLists.IsSafeTag)
    && new[] { "", "a b", "1;rm -rf /", "$(x)", "`x`", "a'b", "../x", "-x", new string('1', 65) }.All(t => !XCoreRfLists.IsSafeTag(t))
    && !XCoreRfLists.IsSafeTag(null));
Check("репозиторий: владелец/имя проходят, остальное — нет",
    XCoreRfLists.IsSafeRepo("runetfreedom/russia-v2ray-rules-dat") && XCoreRfLists.IsSafeRepo(" a/b ")
    && new[] { "", "norepo", "a/b/c", "a b/c", "a/b;x", "a/$(x)", "/b", "a/", "https://x/y" }.All(r => !XCoreRfLists.IsSafeRepo(r)));
Check("адреса: файл релиза и API последнего релиза",
    XCoreRfLists.DownloadUrl("o/r", RfTag, "geosite.dat") == $"https://github.com/o/r/releases/download/{RfTag}/geosite.dat"
    && XCoreRfLists.LatestReleaseApiUrl("o/r") == "https://api.github.com/repos/o/r/releases/latest");
Check("«новее»: числовые теги сравниваются как числа, откат не происходит, пустой применённый — новее",
    XCoreRfLists.IsNewer("202610301000", "202610291019") && !XCoreRfLists.IsNewer("202610291019", "202610291019")
    && !XCoreRfLists.IsNewer("202610281000", "202610291019") && XCoreRfLists.IsNewer("x", null) && XCoreRfLists.IsNewer("v2", "v1")
    && !XCoreRfLists.IsNewer("99", "100"));

// Раскладка монтирования.
Check("монтирование: вход получает каталог списков только для чтения и XRAY_LOCATION_ASSET; выход и прежний вызов — нет",
    XCoreNode.MountArgs(XCoreNode.XrayContainer, XCoreRoles.Entry)
        == "-v /opt/amnezia-xcore/conf:/etc/xcore:ro -v /opt/amnezia-xcore/ops:/etc/xcore-ops:ro -v /opt/amnezia-xcore/geo:/etc/xcore-geo:ro -e XRAY_LOCATION_ASSET=/etc/xcore-geo"
    && XCoreNode.MountArgs(XCoreNode.XrayContainer, XCoreRoles.Exit) == "-v /opt/amnezia-xcore/conf:/etc/xcore:ro -v /opt/amnezia-xcore/ops:/etc/xcore-ops:ro"
    && XCoreNode.MountArgs(XCoreNode.XrayContainer) == XCoreNode.MountArgs(XCoreNode.XrayContainer, XCoreRoles.Exit)
    && !XCoreNode.MountArgs(XCoreNode.WebContainer, XCoreRoles.Entry).Contains("geo"));
Check("монтирование: каталог, а не файл; встроенные списки образа не затеняются (каталог не поверх /usr/local/share/xray)",
    !XCoreNode.MountArgs(XCoreNode.XrayContainer, XCoreRoles.Entry).Contains("/usr/local/share/xray")
    && !XCoreNode.MountArgs(XCoreNode.XrayContainer, XCoreRoles.Entry).Contains("rf-geo"));
Check("очистка узла признаёт монтирование списков своим; чужой путь — нет",
    XCoreNode.IsKnownMount(XCoreNode.XrayContainer, XCoreNode.GeoDir, XCoreNode.ContainerGeoDir)
    && !XCoreNode.IsKnownMount(XCoreNode.XrayContainer, "/etc", XCoreNode.ContainerGeoDir)
    && !XCoreNode.IsKnownMount(XCoreNode.WebContainer, XCoreNode.GeoDir, XCoreNode.ContainerGeoDir));
Check("run -test: без каталога списков команда прежняя дословно; с каталогом — окружение и монтирование только для чтения",
    XCoreNode.TestConfigCommand(XrayImage, "config.new.json")
        == $"sudo docker run --rm --user 0:0 -v /opt/amnezia-xcore/conf:/etc/xcore:ro {XrayImage} run -test -c /etc/xcore/config.new.json"
    && XCoreNode.TestConfigCommand(XrayImage, "config.new.json", XCoreNode.GeoStageDir)
        == $"sudo docker run --rm --user 0:0 -v /opt/amnezia-xcore/conf:/etc/xcore:ro -e XRAY_LOCATION_ASSET=/etc/xcore-geo -v /opt/amnezia-xcore/geo-stage:/etc/xcore-geo:ro {XrayImage} run -test -c /etc/xcore/config.new.json");
Check("каталог кандидатов вне каталога, который видит Xray, но под тем же корнем (одна файловая система)",
    XCoreNode.GeoStageDir.StartsWith(XCoreNode.Root + "/") && !XCoreNode.GeoStageDir.StartsWith(XCoreNode.GeoDir + "/")
    && XCoreNode.GeoDir.StartsWith(XCoreNode.Root + "/"));

// Отказы.
Check("вход: Render отвергает вход, RenderEntry — выход",
    Throws<NotSupportedException>(() => XCoreConfigRenderer.Render(entryNode, EntryPrivate, users))
    && Throws<NotSupportedException>(() => XCoreConfigRenderer.RenderEntry(NewNode(), EntryPrivate, users, RelayUuid, twoExits)));
Check("вход: пустой ключ, не-GUID служебный UUID, пустой путь отвергаются",
    Throws<InvalidOperationException>(() => XCoreConfigRenderer.RenderEntry(entryNode, " ", users, RelayUuid, twoExits))
    && Throws<InvalidOperationException>(() => XCoreConfigRenderer.RenderEntry(entryNode, EntryPrivate, users, "relay", twoExits))
    && Throws<InvalidOperationException>(() => XCoreConfigRenderer.RenderEntry(NewEntryNode(n => n.XhttpPath = null), EntryPrivate, users, RelayUuid, twoExits)));
Check("вход: два выхода с одним номером маршрута — отказ",
    Throws<InvalidOperationException>(() => XCoreConfigRenderer.RenderEntry(entryNode, EntryPrivate, users, RelayUuid, [ExitT(1), ExitT(1) with { Domain = "other.example.com" }])));
Check("вход: номер маршрута 0 и 65536 отвергаются, 1 и 65535 принимаются",
    Throws<InvalidOperationException>(() => XCoreConfigRenderer.RenderEntry(entryNode, EntryPrivate, users, RelayUuid, [ExitT(1) with { RouteId = 0 }]))
    && Throws<InvalidOperationException>(() => XCoreConfigRenderer.RenderEntry(entryNode, EntryPrivate, users, RelayUuid, [ExitT(1) with { RouteId = 65536 }]))
    && XCoreConfigRenderer.RenderEntry(entryNode, EntryPrivate, users, RelayUuid, [ExitT(1), ExitT(65535)]).Json.Contains("exit-65535"));
Check("вход: у выхода не хватает ключа, пути, домена или порта — отказ",
    new[] { ExitT(1) with { PublicKey = "" }, ExitT(1) with { XhttpPath = " " }, ExitT(1) with { Domain = "" }, ExitT(1) with { Port = 0 },
            ExitT(1) with { ShortId = "" }, ExitT(1) with { Fingerprint = "" } }
        .All(bad => Throws<InvalidOperationException>(() => XCoreConfigRenderer.RenderEntry(entryNode, EntryPrivate, users, RelayUuid, [bad]))));
var badLists = new[] { "regexp:.*", "geosite:cn", "http://x.com", "a b" };
Check("вход: невалидный домен в «напрямую» или «через VPN» — отказ рендера",
    badLists.All(bad => Throws<InvalidOperationException>(() => XCoreConfigRenderer.RenderEntry(
        NewEntryNode(n => n.DirectDomains = [bad]), EntryPrivate, users, RelayUuid, twoExits))
        && Throws<InvalidOperationException>(() => XCoreConfigRenderer.RenderEntry(
        NewEntryNode(n => n.ProxyDomains = [bad]), EntryPrivate, users, RelayUuid, twoExits))));
string? renderError = null;
try { XCoreConfigRenderer.RenderEntry(NewEntryNode(n => n.ProxyDomains = ["regexp:x"]), EntryPrivate, users, RelayUuid, twoExits); }
catch (InvalidOperationException ex) { renderError = ex.Message; }
Check("вход: текст ошибки не содержит ни приватного ключа, ни служебного UUID",
    renderError is not null && !renderError.Contains(EntryPrivate) && !renderError.Contains(RelayUuid), renderError);
Check("вход: приватный ключ в конфиге ровно один раз, служебный UUID — по разу на выход",
    Regex.Matches(entryRendered.Json, Regex.Escape(EntryPrivate)).Count == 1 && Regex.Matches(entryRendered.Json, Regex.Escape(RelayUuid)).Count == 2);

// ── Топология ────────────────────────────────────────────────────────────────

Console.WriteLine("Топология xcore");

VpnServer TopoNode(string id, string role, int? route, Action<ProtocolInstance>? tweak = null)
{
    var s = new VpnServer { Id = id, Name = "Node " + id[^2..], Host = "198.51.100.1" };
    var p = new ProtocolInstance
    {
        Id = "p" + id[^6..], Kind = ProtocolKinds.XCore, ContainerName = "amnezia-xcore", Port = "443", State = ProtocolStates.Installed,
        XCore = new XCoreProtocolParams
        {
            Role = role, Domain = $"n{id[^2..]}.example.com", ImageRef = XrayImage, RealityPublicKey = KeyOf(5), ShortIds = ["aabbccddeeff0011"],
            XhttpPath = "/p" + id[^6..], RouteId = route,
            RelayUuid = role == XCoreRoles.Entry ? protector.Protect($"00000000-0000-4000-8000-{id[^12..]}") : null,
        },
    };
    tweak?.Invoke(p);
    s.Protocols.Add(p);
    return s;
}

string TId(int n) => $"69ca5beaba00e3c10adc46{n:x2}";
var topoExit1 = TopoNode(TId(1), XCoreRoles.Exit, 1);
var topoExit2 = TopoNode(TId(2), XCoreRoles.Exit, 2);
var topoHidden = TopoNode(TId(3), XCoreRoles.Exit, 3, p => p.XCore!.SubscriptionEnabled = false);
var topoNoRoute = TopoNode(TId(4), XCoreRoles.Exit, null);
var topoOff = TopoNode(TId(5), XCoreRoles.Exit, 5, p => p.Enabled = false);
var topoIncomplete = TopoNode(TId(6), XCoreRoles.Exit, 6, p => p.XCore!.RealityPublicKey = null);
var topoInstalling = TopoNode(TId(7), XCoreRoles.Exit, 7, p => p.State = ProtocolStates.Installing);
var topoEntry = TopoNode(TId(8), XCoreRoles.Entry, null);
var topoEntryOff = TopoNode(TId(9), XCoreRoles.Entry, null, p => p.Enabled = false);
var topoEntryDisabledList = TopoNode(TId(10), XCoreRoles.Entry, null, p => { p.XCore!.SubscriptionEnabled = false; });
var topoAll = new[] { topoExit2, topoEntry, topoExit1, topoHidden, topoNoRoute, topoOff, topoIncomplete, topoInstalling, topoEntryOff, topoEntryDisabledList };

Check("топология: выходы входа — работающие, видимые, с номером и полными данными; порядок по номеру",
    XCoreTopology.ExitTargets(topoAll).Select(e => e.RouteId).SequenceEqual([1, 2]));
var target2 = XCoreTopology.ExitTargets(topoAll)[1];
Check("топология: параметры выхода берутся из его узла",
    target2 == new XCoreExitTarget(2, "n02.example.com", 443, KeyOf(5), "aabbccddeeff0011", "/p" + TId(2)[^6..], "firefox"));
Check("топология: занятые номера включают скрытые, выключенные и неполные выходы, но не входы",
    XCoreTopology.UsedRouteIds(topoAll).OrderBy(i => i).SequenceEqual([1, 2, 3, 5, 6, 7]));
var relays = XCoreTopology.RelayUsers(topoAll, protector);
Check("топология: служебные пользователи — по входу, который работает (в том числе скрытый из подписок)",
    relays.Select(r => r.Email).OrderBy(e => e).SequenceEqual(new[] { XCoreTopology.RelayEmail(TId(10)), XCoreTopology.RelayEmail(TId(8)) }.OrderBy(e => e)),
    string.Join(",", relays.Select(r => r.Email)));
Check("топология: UUID служебного пользователя — расшифрованный UUID входа",
    relays.Single(r => r.Email == "relay-" + TId(8)).Uuid == $"00000000-0000-4000-8000-{TId(8)[^12..]}");
Check("топология: служебный email не принимается за email подписки",
    relays.All(r => Subscription.IdFromXrayEmail(r.Email) is null && r.Email.StartsWith("relay-")));
Check("топология: вход без служебного UUID пропускается",
    XCoreTopology.RelayUsers([TopoNode(TId(11), XCoreRoles.Entry, null, p => p.XCore!.RelayUuid = null)], protector).Count == 0);
Check("топология: роли узла в подписках — IsSubscriptionNode для обеих, Exit/Entry по роли",
    topoExit1.Protocols.Any(topoExit1.IsSubscriptionExit) && !topoExit1.Protocols.Any(topoExit1.IsSubscriptionEntry)
    && topoEntry.Protocols.Any(topoEntry.IsSubscriptionEntry) && !topoEntry.Protocols.Any(topoEntry.IsSubscriptionExit)
    && topoEntry.Protocols.Any(topoEntry.IsSubscriptionNode)
    && !topoEntryOff.Protocols.Any(topoEntryOff.IsSubscriptionNode) && !topoEntryDisabledList.Protocols.Any(topoEntryDisabledList.IsSubscriptionNode));
Check("публикатор: SubscriptionNodes — выходы и входы, SubscriptionExits — только выходы",
    XCoreSyncPublisher.SubscriptionNodes(topoAll).Select(n => n.Server.Id).OrderBy(i => i)
        .SequenceEqual(new[] { TId(1), TId(2), TId(4), TId(6), TId(8) }.OrderBy(i => i))
    && XCoreSyncPublisher.SubscriptionExits(topoAll).Select(n => n.Server.Id).OrderBy(i => i)
        .SequenceEqual(new[] { TId(1), TId(2), TId(4), TId(6) }.OrderBy(i => i)));

// ── Установка входа ──────────────────────────────────────────────────────────

Console.WriteLine("Установка входа");

{
    var fake = new FakeNode();
    var spec = PreparedSpec();
    spec.Role = "entry";
    var progress = new RecordingProgress();
    var installed = await NewInstaller(GoodDns()).InstallAsync(fake.Session, NodeServer(), spec, progress);
    var x = installed.XCore!;
    var relay = protector.Unprotect(x.RelayUuid);
    var written = fake.Writes.Single(w => w.Path == XCoreNode.ConfigPath).Content;

    Check("вход: роль entry, домен, подписки включены, номера маршрута нет",
        x.Role == "entry" && x.Domain == XDomain && x.SubscriptionEnabled && x.RouteId is null);
    Check("вход: служебный UUID — GUID, в базе только зашифрованным",
        Guid.TryParse(relay, out _) && x.RelayUuid!.CipherText != relay);
    Check("вход: служебный UUID разный между установками",
        protector.Unprotect((await NewInstaller(GoodDns()).InstallAsync(new FakeNode().Session, NodeServer(), spec, new RecordingProgress())).XCore!.RelayUuid) != relay);
    Check("вход: ставится как выход — Caddy, ключи Reality, run -test, контейнер Xray",
        fake.Ran("--name amnezia-xcore-web") && fake.Ran(" x25519") && fake.Ran("run -test -c /etc/xcore/config.json")
        && fake.Ran("--name amnezia-xcore --network host"));
    Check("вход: первый конфиг — вход без выходов (закрыт), с sniffing и dns",
        RulesOf(written).SequenceEqual([PrivateRule, "network=tcp,udp>block"])
        && JsonNode.Parse(written)!["inbounds"]![0]!["sniffing"] is not null && JsonNode.Parse(written)!["dns"] is not null);
    var expectedFirst = XCoreConfigRenderer.RenderEntry(x, FakeNode.PrivateKey, [], relay!, []);
    Check("вход: ревизии установки = рендер входа без пользователей и выходов",
        written == expectedFirst.Json && x.AppliedRevision == expectedFirst.Revision && x.AppliedStructureRevision == expectedFirst.Revision);
    Check("вход: служебного UUID нет ни в командах, ни в метках, ни в ходе установки, ни в конфиге без выходов",
        !fake.Commands.Any(c => c.Contains(relay!)) && !fake.Labels.Any(l => l.Contains(relay!))
        && !progress.Texts.Any(t => t.Contains(relay!)) && !written.Contains(relay!));
    Check("вход: списки доменов пусты, РФ напрямую включено",
        x.RuDirect && x.DirectDomains.Count == 0 && x.ProxyDomains.Count == 0);

    var exitInstalled = await NewInstaller(GoodDns()).InstallAsync(new FakeNode().Session, NodeServer(), PreparedSpec(), new RecordingProgress());
    Check("выход: служебного UUID нет, номер маршрута установщик не назначает (знает оркестратор)",
        exitInstalled.XCore!.RelayUuid is null && exitInstalled.XCore.RouteId is null);

    var entryDto = System.Text.Json.JsonSerializer.Serialize(ProtocolDetailDto.From(installed));
    Check("DTO: служебный UUID и номер маршрута входа в панель не уходят", !entryDto.Contains(relay!) && !entryDto.Contains("relay", StringComparison.OrdinalIgnoreCase)
        && !entryDto.Contains(FakeNode.PrivateKey));
    var installedDoc = installed.ToBsonDocument();
    var entryRestored = BsonSerializer.Deserialize<ProtocolInstance>(installedDoc);
    Check("BSON: поля входа переживают круг, служебный UUID лежит зашифрованным",
        entryRestored.XCore!.RuDirect && entryRestored.XCore.RelayUuid is not null && protector.Unprotect(entryRestored.XCore.RelayUuid) == relay
        && !installedDoc.ToJson().Contains(relay!));
    var legacyDoc = new BsonDocument { ["role"] = "exit", ["domain"] = "d.example.com", ["imageRef"] = XrayImage };
    var legacy = BsonSerializer.Deserialize<XCoreProtocolParams>(legacyDoc);
    Check("BSON: документ без новых полей читается — RuDirect true, списки пусты, номера нет",
        legacy.RuDirect && legacy.DirectDomains.Count == 0 && legacy.ProxyDomains.Count == 0 && legacy.RouteId is null && legacy.RelayUuid is null);
    var exitBson = exitInstalled.ToBsonDocument()["xcore"].AsBsonDocument;
    Check("BSON: у выхода нет null-полей routeId и relayUuid", !exitBson.Contains("relayUuid") && !exitBson.Contains("routeId"));
}

// ── Синхронизация входа и выхода ─────────────────────────────────────────────

Console.WriteLine("Синхронизация входа и выхода");

async Task<(FakeNode Node, VpnServer Server, ProtocolInstance Protocol)> ProvisionRoleAsync(string role, string id)
{
    var fake = new FakeNode();
    var server = NodeServer();
    server.Id = id;
    var spec = PreparedSpec();
    spec.Role = role;
    var protocol = await NewInstaller(GoodDns()).InstallAsync(fake.Session, server, spec, new RecordingProgress());
    protocol.State = ProtocolStates.Installed;
    server.Protocols.Add(protocol);
    return (fake, server, protocol);
}

string[] OutboundTags(FakeNode fake) =>
    [.. JsonNode.Parse(fake.Files[XCoreNode.ConfigPath])!["outbounds"]!.AsArray().Select(o => o!["tag"]!.GetValue<string>())];

{
    // Выход получает служебных пользователей работающих входов.
    var (fake, server, protocol) = await ProvisionRoleAsync(XCoreRoles.Exit, TId(20));
    protocol.XCore!.RouteId = 1;
    var entryOn = TopoNode(TId(21), XCoreRoles.Entry, null);
    var entryOff = TopoNode(TId(22), XCoreRoles.Entry, null, p => p.Enabled = false);
    var entryInstalling = TopoNode(TId(23), XCoreRoles.Entry, null, p => p.State = ProtocolStates.Installing);
    var h = new SyncHarness(fake, server, NewSync(), protector);
    h.Others.AddRange([entryOn, entryOff, entryInstalling]);
    h.Desired.Add(Sub(SubIdAbc, UuidAbc));

    var result = await h.Handler.HandleAsync(SyncEvent(server, protocol), default);
    var relayOn = $"00000000-0000-4000-8000-{TId(21)[^12..]}";
    Check("выход: на узле подписчик и служебный пользователь работающего входа, без перезапуска",
        LiveIs(fake, ($"sub-{SubIdAbc}", UuidAbc), ("relay-" + TId(21), relayOn)) && Restarts(fake) == 0 && result!["action"] == "Diff",
        string.Join(",", fake.Live.Select(u => u.Email)));
    Check("выход: выключенный и ещё не установленный вход служебного пользователя не получает",
        !fake.Live.Any(u => u.Email.Contains(TId(22)) || u.Email.Contains(TId(23))));
    Check("выход: служебный пользователь попал и в файл конфига на хосте",
        fake.Files[XCoreNode.ConfigPath].Contains(relayOn));

    entryOn.Protocols[0].Enabled = false;
    result = await h.Handler.HandleAsync(SyncEvent(server, protocol), default);
    Check("выход: вход выключили — его служебный пользователь снят через API, без перезапуска",
        LiveIs(fake, ($"sub-{SubIdAbc}", UuidAbc)) && result!["removed"] == 1 && Restarts(fake) == 0);
    entryOn.Protocols[0].Enabled = true;
    result = await h.Handler.HandleAsync(SyncEvent(server, protocol), default);
    Check("выход: вход включили — служебный пользователь вернулся", fake.Live.Any(u => u.Email == "relay-" + TId(21)) && result!["added"] == 1);
    Check("выход: номер уже есть — повторного назначения и публикаций нет", h.RouteAssignments.Count == 0 && h.Events.Published.Count == 0);

    // Трафик: служебные пользователи не попадают в подписки.
    fake.Stats["relay-" + TId(21)] = (500, 5000);
    var poll = new PollHarness(fake);
    var a = Sub(SubIdAbc, UuidAbc);
    poll.Subscriptions[a.Id] = a;
    fake.Stats[a.XrayEmail] = (10, 100);
    await poll.PollAsync(server);
    Check("поллер: статистика служебного пользователя в подписки и в трафик узла не попадает",
        a.Usage is { RxBytes: 100, TxBytes: 10 } && poll.Updates.Count == 1 && poll.Updates[0].SubscriptionId == SubIdAbc
        && poll.ServerDaily is [var served] && served == (server.Id, 100, 10));
    Check("поллер: запрос счётчиков фильтрует по user>>>sub-", fake.Commands.Last(c => c.Contains("statsquery")).Contains("-pattern 'user>>>sub-'"));
    Check("поллер: служебный пользователь есть в ответе без фильтра — значит, отсекает именно шаблон",
        XrayApiOutput.ParseUserTraffic("{\"stat\":[{\"name\":\"user>>>relay-x>>>traffic>>>uplink\",\"value\":5},{\"name\":\"user>>>relay-x>>>traffic>>>downlink\",\"value\":7}]}")
            .Keys.Single() == "relay-x");
}

{
    // Вход: подписчики и выходы из базы.
    var (fake, server, protocol) = await ProvisionRoleAsync(XCoreRoles.Entry, TId(30));
    var exit1 = TopoNode(TId(31), XCoreRoles.Exit, 1);
    var exit2 = TopoNode(TId(32), XCoreRoles.Exit, 2);
    var hidden = TopoNode(TId(33), XCoreRoles.Exit, 3, p => p.XCore!.SubscriptionEnabled = false);
    var noRoute = TopoNode(TId(34), XCoreRoles.Exit, null);
    var off = TopoNode(TId(35), XCoreRoles.Exit, 4, p => p.Enabled = false);
    var otherEntry = TopoNode(TId(36), XCoreRoles.Entry, null);
    var h = new SyncHarness(fake, server, NewSync(), protector);
    h.Others.AddRange([exit1, exit2, hidden, noRoute, off, otherEntry]);
    h.Desired.Add(Sub(SubIdAbc, UuidAbc));
    var evt = SyncEvent(server, protocol);

    var result = await h.Handler.HandleAsync(evt, default);
    Check("вход: первая синхронизация меняет структуру (появились выходы) — перезапуск",
        result!["action"] == "Restart" && Restarts(fake) == 1);
    Check("вход: в конфиге только подходящие выходы — работающие, видимые, с номером",
        OutboundTags(fake).SequenceEqual(["direct", "block", "exit-1", "exit-2"]), string.Join(",", OutboundTags(fake)));
    Check("вход: на узле только подписчик — служебных пользователей и чужих входов нет",
        LiveIs(fake, ($"sub-{SubIdAbc}", UuidAbc)));
    var relayOfEntry = protector.Unprotect(protocol.XCore!.RelayUuid)!;
    Check("вход: в outbound-ах служебный UUID этого входа",
        Regex.Matches(fake.Files[XCoreNode.ConfigPath], Regex.Escape(relayOfEntry)).Count == 2);
    Check("вход: ревизии записаны, ошибки нет", h.Applied.Count == 1 && protocol.XCore.SyncError is null);

    result = await h.Handler.HandleAsync(evt, default);
    Check("вход: повтор — NoOp", result!["action"] == "NoOp" && Restarts(fake) == 1);

    h.Desired.Add(Sub(SubIdDef, UuidDef));
    result = await h.Handler.HandleAsync(evt, default);
    Check("вход: новый подписчик — через API, без перезапуска", result!["action"] == "Diff" && result["added"] == 1 && Restarts(fake) == 1);

    h.Others.Remove(exit2);
    result = await h.Handler.HandleAsync(evt, default);
    Check("вход: выход убрали из топологии — перезапуск с новым списком outbound-ов",
        result!["action"] == "Restart" && Restarts(fake) == 2 && OutboundTags(fake).SequenceEqual(["direct", "block", "exit-1"]));
    Check("вход: после перезапуска подписчики на месте",
        LiveIs(fake, ($"sub-{SubIdAbc}", UuidAbc), ($"sub-{SubIdDef}", UuidDef)));

    exit1.Protocols[0].Enabled = false;
    result = await h.Handler.HandleAsync(evt, default);
    var finalRules = RulesOf(fake.Files[XCoreNode.ConfigPath]);
    Check("вход: выходов не осталось — вход закрыт, а не открыт напрямую",
        result!["action"] == "Restart" && finalRules.SequenceEqual([PrivateRule, "network=tcp,udp>block"]) && OutboundTags(fake).SequenceEqual(["direct", "block"]));

    // Вход опрашивается как узел подписок: клиент подключается к нему, и счётчик подписчика живёт на нём.
    var entryPoll = new PollHarness(fake);
    var entrySub = Sub(SubIdAbc, UuidAbc);
    entryPoll.Subscriptions[entrySub.Id] = entrySub;
    fake.Stats[entrySub.XrayEmail] = (7, 70);
    fake.Stats["relay-" + TId(31)] = (1, 1);
    await entryPoll.PollAsync(server);
    Check("поллер: вход опрашивается как узел подписок — трафик записан по узлу входа",
        entrySub.RawByNode[server.Id] is { Rx: 70, Tx: 7 } && entrySub.Usage is { RxBytes: 70, TxBytes: 7 }
        && entryPoll.ServerDaily is [var entryDay] && entryDay == (server.Id, 70, 7));

    protocol.XCore.RelayUuid = null;
    var ex = await CatchAsync<XCoreSyncException>(() => h.Handler.HandleAsync(evt, default));
    Check("вход: без служебного UUID — понятная ошибка, а не открытый вход", ex is not null && ex.Message.Contains("служебного UUID"), ex?.Message);
}

{
    // Назначение номера маршрута выходу.
    var (fake, server, protocol) = await ProvisionRoleAsync(XCoreRoles.Exit, TId(40));
    var taken1 = TopoNode(TId(41), XCoreRoles.Exit, 1);
    var taken3 = TopoNode(TId(42), XCoreRoles.Exit, 3);
    var entry = TopoNode(TId(43), XCoreRoles.Entry, null);
    var disabledExit = TopoNode(TId(44), XCoreRoles.Exit, 2, p => p.Enabled = false);
    var h = new SyncHarness(fake, server, NewSync(), protector);
    h.Others.AddRange([taken1, taken3, entry]);
    h.Desired.Add(Sub(SubIdAbc, UuidAbc));
    var evt = SyncEvent(server, protocol);

    await h.Handler.HandleAsync(evt, default);
    Check("номер маршрута: наименьший свободный среди всех выходов (1 и 3 заняты — получает 2)",
        h.RouteAssignments is [var assigned] && assigned == (server.Id, protocol.Id, 2) && protocol.XCore!.RouteId == 2);
    Check("номер маршрута: после назначения синхронизируются все узлы xcore, включая вход и сам выход",
        h.Events.Published.Select(p => p.Partition).OrderBy(i => i)
            .SequenceEqual(new[] { server.Id, TId(41), TId(42), TId(43) }.OrderBy(i => i)));
    Check("номер маршрута: назначение одно, событий по одному на узел",
        h.Events.Published.Count == 4 && h.RouteAssignments.Count == 1);

    await h.Handler.HandleAsync(evt, default);
    Check("номер маршрута: повторная синхронизация номер не трогает", h.RouteAssignments.Count == 1 && h.Events.Published.Count == 4);

    // Освободившийся номер используется повторно; выключенный выход номер не отдаёт.
    var (fakeB, serverB, protocolB) = await ProvisionRoleAsync(XCoreRoles.Exit, TId(45));
    var hB = new SyncHarness(fakeB, serverB, NewSync(), protector);
    hB.Others.AddRange([taken1, disabledExit]);
    await hB.Handler.HandleAsync(SyncEvent(serverB, protocolB), default);
    Check("номер маршрута: номер выключенного выхода остаётся занятым (1 и 2 заняты — получает 3)", protocolB.XCore!.RouteId == 3);

    // Другой процесс успел назначить номер раньше: условная запись ничего не меняет.
    var (fakeC, serverC, protocolC) = await ProvisionRoleAsync(XCoreRoles.Exit, TId(46));
    var hC = new SyncHarness(fakeC, serverC, NewSync(), protector) { LoseRouteRace = true };
    var resultC = await hC.Handler.HandleAsync(SyncEvent(serverC, protocolC), default);
    Check("номер маршрута: запись проиграла гонку — не публикуем, синхронизация узла продолжается",
        hC.Events.Published.Count == 0 && hC.RouteAssignments.Count == 0 && resultC!["action"].AsString is "Diff" or "NoOp");

    // У входа номера быть не должно.
    var (fakeD, serverD, protocolD) = await ProvisionRoleAsync(XCoreRoles.Entry, TId(47));
    var hD = new SyncHarness(fakeD, serverD, NewSync(), protector);
    await hD.Handler.HandleAsync(SyncEvent(serverD, protocolD), default);
    Check("номер маршрута: входу не назначается", hD.RouteAssignments.Count == 0 && protocolD.XCore!.RouteId is null);
}

// ── Ссылки через оркестратор: номер маршрута и веер ─────────────────────────

Console.WriteLine("Оркестратор: номер маршрута и веерная синхронизация");

{
    var exit1 = TopoNode(TId(50), XCoreRoles.Exit, 1);
    var exit2 = TopoNode(TId(51), XCoreRoles.Exit, 2);
    var entry = TopoNode(TId(52), XCoreRoles.Entry, null);
    var offExit = TopoNode(TId(53), XCoreRoles.Exit, 4, p => p.Enabled = false);

    var fake = new FakeNode();
    var (orchestrator, job, server, events) = NewOrchestrator(fake, null, exit1, exit2, entry, offExit);
    await orchestrator.ExecuteAsync(job, default);
    var installedExit = server.Protocols.Single();
    Check("оркестратор: новый выход получает наименьший свободный номер среди всех выходов (3: 1, 2 и 4 заняты)",
        job.Status == InstallJobStatuses.Succeeded && installedExit.XCore!.RouteId == 3, job.Error);
    // Выключенный выход тоже синхронизируется: на нём остаётся живой Xray с подписчиками.
    Check("оркестратор: установка выхода публикует синхронизацию на все установленные узлы xcore, включая выключенный",
        events.Published.Select(p => p.Partition).OrderBy(i => i)
            .SequenceEqual(new[] { server.Id, TId(50), TId(51), TId(52), TId(53) }.OrderBy(i => i)),
        string.Join(",", events.Published.Select(p => p.Partition)));
    Check("оркестратор: на каждый узел ровно одно событие",
        events.Published.Count == 5 && events.Published.Select(p => p.Partition).Distinct().Count() == 5);
    Check("оркестратор: установка выхода российские списки не запрашивает (они только у входа)",
        !events.Published.Any(p => p.Type == DomainEventTypes.XCoreGeoUpdate));

    fake = new FakeNode();
    (orchestrator, job, server, events) = NewOrchestrator(fake, XCoreRoles.Entry, exit1, exit2);
    await orchestrator.ExecuteAsync(job, default);
    var installedEntry = server.Protocols.Single();
    Check("оркестратор: вход ставится с ролью entry, служебным UUID и без номера маршрута",
        job.Status == InstallJobStatuses.Succeeded && installedEntry.XCore is { Role: "entry", RouteId: null, RelayUuid: not null }, job.Error);
    Check("оркестратор: установка входа тоже синхронизирует все узлы (выходам нужен его служебный пользователь)",
        events.Published.Where(p => p.Type == DomainEventTypes.XCoreSync).Select(p => p.Partition).OrderBy(i => i)
            .SequenceEqual(new[] { server.Id, TId(50), TId(51) }.OrderBy(i => i)));
    Check("оркестратор: установка входа публикует первичную загрузку российских списков — одно xcore.geo_update на этот узел, тег не задан",
        events.Published.Where(p => p.Type == DomainEventTypes.XCoreGeoUpdate).ToList() is [var geoEvt]
        && Equals(geoEvt.Payload, new XCoreGeoUpdatePayload(server.Id, installedEntry.Id, null)) && geoEvt.Partition == server.Id);

    fake = new FakeNode();
    (orchestrator, job, server, events) = NewOrchestrator(fake, null, TopoNode(TId(54), XCoreRoles.Exit, null));
    await orchestrator.ExecuteAsync(job, default);
    Check("оркестратор: чужой выход без номера не занимает номеров — новый получает 1", server.Protocols.Single().XCore!.RouteId == 1);
}

// ── Caddyfile узла ───────────────────────────────────────────────────────────

Console.WriteLine("Caddyfile узла: рендер и применение");

// Прежний шаблон, набранный вручную, а не прочитанный из ресурса: проверка не должна повторять ошибку кода.
// Это текст, который установщик до появления домена подписки записывал на узел; для узла без домена подписки
// он должен остаться тем же до байта (Caddy на уже работающих узлах не должен заметить перехода).
const string GoldenCaddyfile =
    "{\n\thttp_port 80\n\thttps_port 8443\n\tadmin off\n\temail ops@example.com\n}\n\n" +
    "http://node1.example.com {\n\tbind 0.0.0.0 [::]\n\tredir https://{host}{uri} permanent\n}\n\n" +
    "https://node1.example.com:8443 {\n\tbind 127.0.0.1\n\ttls {\n\t\tissuer acme {\n\t\t\tdisable_tlsalpn_challenge\n\t\t}\n\t}\n" +
    "\troot * /srv/site\n\tfile_server\n\theader {\n\t\tStrict-Transport-Security \"max-age=31536000\"\n\t\t-Server\n\t}\n}\n";
const string GoldenSubscriptionSite =
    "\nhttp://sub.example.com {\n\tbind 0.0.0.0 [::]\n\tredir https://{host}{uri} permanent\n}\n\n" +
    "https://sub.example.com:8443 {\n\tbind 127.0.0.1\n\ttls {\n\t\tissuer acme {\n\t\t\tdisable_tlsalpn_challenge\n\t\t}\n\t}\n" +
    "\thandle /sub/* {\n\t\treverse_proxy https://sub-origin.example.com {\n\t\t\theader_up Host {upstream_hostport}\n\t\t}\n\t}\n" +
    "\thandle {\n\t\trespond 404\n\t}\n}\n";
const string SubHost = "sub.example.com";
const string SubUpstream = "https://sub-origin.example.com";

var caddyScripts = new ScriptRegistry();
var caddyPlain = XCoreCaddyRenderer.Render(caddyScripts, XDomain, "ops@example.com");
var caddyWithSub = XCoreCaddyRenderer.Render(caddyScripts, XDomain, "ops@example.com", SubHost, SubUpstream);
var legacyCaddyfile = ScriptTemplateRenderer.Render(caddyScripts.Read("xcore/Caddyfile"),
    new Dictionary<string, string> { ["DOMAIN"] = XDomain, ["ACME_EMAIL"] = "ops@example.com" });

Check("Caddyfile: без домена подписки — побайтово прежний текст (эталон, набранный вручную)",
    caddyPlain.Text == GoldenCaddyfile, caddyPlain.Text.Length + " байт");
Check("Caddyfile: без домена подписки — то же, что давала прежняя подстановка в шаблон xcore/Caddyfile",
    caddyPlain.Text == legacyCaddyfile);
Check("Caddyfile: ревизия — SHA-256 текста в нижнем регистре",
    caddyPlain.Revision == Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(caddyPlain.Text))).ToLowerInvariant());
Check("Caddyfile: с доменом подписки — прежний текст, пустая строка и сайт подписки (эталон)",
    caddyWithSub.Text == GoldenCaddyfile + GoldenSubscriptionSite);
Check("Caddyfile: сайт подписки — один reverse_proxy, только в handle /sub/*, остальное 404",
    Regex.Matches(caddyWithSub.Text, "reverse_proxy").Count == 1 && Regex.Matches(caddyWithSub.Text, "respond 404").Count == 1
    && Regex.IsMatch(caddyWithSub.Text, @"handle /sub/\* \{\n\t\treverse_proxy https://sub-origin\.example\.com \{\n\t\t\theader_up Host \{upstream_hostport\}"));
Check("Caddyfile: сайт подписки слушает 127.0.0.1:8443 (Reality отдаёт туда чужие рукопожатия), порт 80 — на редирект",
    caddyWithSub.Text.Contains($"https://{SubHost}:8443 {{\n\tbind 127.0.0.1\n")
    && caddyWithSub.Text.Contains($"http://{SubHost} {{\n\tbind 0.0.0.0 [::]\n\tredir https://{{host}}{{uri}} permanent\n}}"));
Check("Caddyfile: доступ-логов нет (токен подписки лежит в пути)",
    !Regex.IsMatch(caddyWithSub.Text, @"(?m)^\s*(log|output)\b") && !caddyWithSub.Text.Contains("access"));
Check("Caddyfile: незамещённых плейсхолдеров нет", !caddyWithSub.Text.Contains('$') && !caddyPlain.Text.Contains('$'));
Check("Caddyfile: ревизия зависит от домена подписки, адреса и почты, и только от них",
    caddyWithSub.Revision != caddyPlain.Revision
    && XCoreCaddyRenderer.Render(caddyScripts, XDomain, "ops@example.com", "sub2.example.com", SubUpstream).Revision != caddyWithSub.Revision
    && XCoreCaddyRenderer.Render(caddyScripts, XDomain, "ops@example.com", SubHost, "https://other.example.com").Revision != caddyWithSub.Revision
    && XCoreCaddyRenderer.Render(caddyScripts, XDomain, "ops@example.com", SubHost, SubUpstream).Revision == caddyWithSub.Revision
    && XCoreCaddyRenderer.Render(caddyScripts, XDomain, "ops2@example.com").Revision != caddyPlain.Revision);

string[] badCaddyInputs = ["node1.example.com {", "node1.example.com\nfoo", "NODE1.example.com", "1.2.3.4", "a b.example.com", ""];
Check("Caddyfile: домен узла, не прошедший проверку, в конфиг не попадает",
    badCaddyInputs.All(d => Throws<InvalidOperationException>(() => XCoreCaddyRenderer.Render(caddyScripts, d, "ops@example.com"))));
Check("Caddyfile: email с переводом строки и директивой отвергается",
    Throws<InvalidOperationException>(() => XCoreCaddyRenderer.Render(caddyScripts, XDomain, "x@example.com\n}\nhttp://evil {"))
    && Throws<InvalidOperationException>(() => XCoreCaddyRenderer.Render(caddyScripts, XDomain, "")));
Check("Caddyfile: домен подписки с директивой, пробелом, в верхнем регистре или равный домену узла отвергается",
    new[] { "sub.example.com {", "sub.example.com\n}", "SUB.example.com", "a b.example.com", "1.2.3.4", "", XDomain }
        .All(h => Throws<InvalidOperationException>(() => XCoreCaddyRenderer.Render(caddyScripts, XDomain, "ops@example.com", h, SubUpstream))));
Check("Caddyfile: адрес проксирования с путём, логином, переводом строки, без схемы или пустой отвергается",
    new[] { "https://o.example.com/x", "https://u:p@o.example.com", "https://o.example.com\n}\nrespond 200", "o.example.com", "", "ftp://o.example.com", "https://o.example.com?x=1", "https://o.example.com ", "https://1.2.3.4" }
        .All(u => Throws<InvalidOperationException>(() => XCoreCaddyRenderer.Render(caddyScripts, XDomain, "ops@example.com", SubHost, u)))
    && Throws<InvalidOperationException>(() => XCoreCaddyRenderer.Render(caddyScripts, XDomain, "ops@example.com", SubHost, null)));

(string Input, string? Expected)[] upstreamCases =
[
    ("https://sub-origin.example.com", "https://sub-origin.example.com"),
    ("  https://sub-origin.example.com/  ", "https://sub-origin.example.com"),
    ("HTTPS://Sub-Origin.Example.COM", "https://sub-origin.example.com"),
    ("https://sub-origin.example.com:443", "https://sub-origin.example.com"),
    ("https://sub-origin.example.com:8443", "https://sub-origin.example.com:8443"),
    ("http://api.example.com:8080/", "http://api.example.com:8080"),
    ("https://sub-origin.example.com/sub", null),
    ("https://sub-origin.example.com?a=1", null),
    ("https://sub-origin.example.com#x", null),
    ("https://user@sub-origin.example.com", null),
    ("sub-origin.example.com", null),
    ("//sub-origin.example.com", null),
    ("ftp://sub-origin.example.com", null),
    ("https://localhost", null),
    ("https://10.0.0.1:8443", null),
    ("https://a b.example.com", null),
    ("https://sub-origin.example.com\r\nrespond", null),
    ("", null),
];
var upstreamWrong = upstreamCases
    .Where(c => XCoreInput.TryNormalizeUpstream(c.Input, out var u) ? u != c.Expected : c.Expected is not null)
    .Select(c => c.Input).ToList();
Check($"адрес проксирования: {upstreamCases.Length} образцов нормализуются или отвергаются как задумано",
    upstreamWrong.Count == 0 && !XCoreInput.TryNormalizeUpstream(null, out _), string.Join(" | ", upstreamWrong));

XCoreSyncService NewSyncWith(string? upstream, string? email = "ops@example.com") =>
    new(protector, new ScriptRegistry(), Options.Create(new XCoreOptions { AcmeEmail = email, SubscriptionUpstream = upstream }))
    {
        RestartPollAttempts = 3, RestartPollInterval = TimeSpan.Zero, CertificateAttempts = 3, CertificatePollInterval = TimeSpan.Zero,
    };

{
    // Установщик пишет тот же текст и запоминает его ревизию.
    var (fake, server, protocol) = await ProvisionRoleAsync(XCoreRoles.Entry, TId(60));
    var written = fake.Writes.Single(w => w.Path == XCoreNode.CaddyfilePath).Content;
    Check("Caddyfile: установщик записал на узел тот же текст, что и рендерер, и запомнил ревизию",
        written == GoldenCaddyfile && protocol.XCore!.AppliedCaddyRevision == caddyPlain.Revision);

    var sync = NewSyncWith(SubUpstream);
    var start = fake.Commands.Count;
    var same = await sync.SyncCaddyAsync(fake.Session, protocol);
    Check("Caddy sync: ревизия совпала — ничего не выполняется на узле, перезапуска нет",
        same.Action == XCoreCaddyAction.NoOp && same.Revision == caddyPlain.Revision && fake.Commands.Count == start && fake.WebRestarts == 0);

    // Включили домен подписки.
    protocol.XCore!.SubscriptionHost = SubHost;
    start = fake.Commands.Count;
    var applied = await sync.SyncCaddyAsync(fake.Session, protocol);
    var steps = fake.Commands.Skip(start).ToList();
    int Step(string fragment) => steps.FindIndex(c => c.Contains(fragment, StringComparison.Ordinal));
    var order = new[] { Step("WRITE /opt/amnezia-xcore/caddy/Caddyfile.new"), Step("caddy validate"), Step("sudo cp -f"), Step("docker restart amnezia-xcore-web"), Step("curl ") };
    Check("Caddy sync: домен подписки добавлен — файл записан рядом, проверен, перезаписан на месте, Caddy перезапущен, сертификат опрошен (в этом порядке)",
        applied.Action == XCoreCaddyAction.Restart && applied.Revision == caddyWithSub.Revision
        && order.All(i => i >= 0) && order.SequenceEqual(order.Order()), string.Join(",", order));
    Check("Caddy sync: проверка — одноразовый контейнер того же образа с кандидатом под путём рабочего файла",
        steps[Step("caddy validate")] == $"sudo docker run --rm -v /opt/amnezia-xcore/caddy/Caddyfile.new:/etc/caddy/Caddyfile:ro {XCoreNode.CaddyImage} caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile");
    Check("Caddy sync: на узле новый текст, кандидата не осталось, Caddy его прочитал (перезапуск после записи)",
        fake.Files[XCoreNode.CaddyfilePath] == caddyWithSub.Text && !fake.Files.ContainsKey(XCoreNode.NewCaddyfilePath)
        && fake.LoadedCaddyfile == caddyWithSub.Text && fake.WebRestarts == 1 && fake.CaddyValidations == 1);
    var probeCommand = steps.Single(c => c.StartsWith("curl "));
    Check("Caddy sync: сертификат домена подписки опрошен именно по его имени и без -k (ответ 404 корня означает рабочий сертификат)",
        probeCommand.Contains($"--resolve {SubHost}:8443:127.0.0.1 https://{SubHost}:8443/") && !probeCommand.Contains(" -k"));
    Check("Caddy sync: Xray не трогали (ни перезапуска, ни команд api)", Restarts(fake) == 0 && !steps.Any(c => c.Contains("xray api")));

    protocol.XCore.AppliedCaddyRevision = applied.Revision;
    start = fake.Commands.Count;
    var repeated = await sync.SyncCaddyAsync(fake.Session, protocol);
    Check("Caddy sync: повтор после записи ревизии — NoOp без команд", repeated.Action == XCoreCaddyAction.NoOp && fake.Commands.Count == start);

    // Сменили адрес проксирования: ревизия другая, Caddy перезапускается снова.
    var moved = await NewSyncWith("https://other-origin.example.com").SyncCaddyAsync(fake.Session, protocol);
    Check("Caddy sync: изменился адрес проксирования — Caddyfile переписан и Caddy перезапущен",
        moved.Action == XCoreCaddyAction.Restart && fake.WebRestarts == 2 && fake.Files[XCoreNode.CaddyfilePath].Contains("reverse_proxy https://other-origin.example.com"));

    // Сняли домен подписки.
    protocol.XCore.AppliedCaddyRevision = moved.Revision;
    protocol.XCore.SubscriptionHost = null;
    var curlBefore = fake.CurlCalls;
    var removed = await sync.SyncCaddyAsync(fake.Session, protocol);
    Check("Caddy sync: домен подписки снят — на узле снова прежний текст, перезапуск, сертификат не опрашивается",
        removed.Action == XCoreCaddyAction.Restart && removed.Revision == caddyPlain.Revision
        && fake.Files[XCoreNode.CaddyfilePath] == GoldenCaddyfile && fake.CurlCalls == curlBefore && fake.WebRestarts == 3);
}

{
    // Отказ проверки: рабочий файл не тронут, Caddy не перезапущен, причина понятна.
    var (fake, server, protocol) = await ProvisionRoleAsync(XCoreRoles.Entry, TId(61));
    protocol.XCore!.SubscriptionHost = SubHost;
    fake.CaddyValidateFails = true;
    var ex = await CatchAsync<XCoreSyncException>(() => NewSyncWith(SubUpstream).SyncCaddyAsync(fake.Session, protocol));
    Check("Caddy sync: validate отклонил файл — XCoreSyncException с причиной, restart не выполнялся",
        ex is not null && ex.Message.Contains("Caddy отклонил") && ex.Message.Contains("wrong argument count") && fake.WebRestarts == 0, ex?.Message);
    Check("Caddy sync: рабочий Caddyfile прежний, кандидат удалён, Caddy работает со старым файлом",
        fake.Files[XCoreNode.CaddyfilePath] == GoldenCaddyfile && !fake.Files.ContainsKey(XCoreNode.NewCaddyfilePath)
        && fake.LoadedCaddyfile == GoldenCaddyfile && !fake.Ran("sudo cp -f"));
    Check("Caddy sync: ревизия в базе при отказе не меняется", protocol.XCore.AppliedCaddyRevision == caddyPlain.Revision);

    // Домен подписки без адреса проксирования: синхронизация сообщает об этом и ничего не делает на узле.
    (fake, server, protocol) = await ProvisionRoleAsync(XCoreRoles.Entry, TId(62));
    protocol.XCore!.SubscriptionHost = SubHost;
    var start = fake.Commands.Count;
    ex = await CatchAsync<XCoreSyncException>(() => NewSyncWith(null).SyncCaddyAsync(fake.Session, protocol));
    Check("Caddy sync: нет XCore:SubscriptionUpstream — ошибка с названием настройки, узел не тронут",
        ex is not null && ex.Message.Contains("XCore:SubscriptionUpstream") && fake.Commands.Count == start && fake.WebRestarts == 0, ex?.Message);

    // Сертификат не выпускается: Caddy перезапущен, но ревизия не засчитана.
    (fake, server, protocol) = await ProvisionRoleAsync(XCoreRoles.Entry, TId(63));
    protocol.XCore!.SubscriptionHost = SubHost;
    fake.CertificateNever = true;
    var curlAtStart = fake.CurlCalls;
    ex = await CatchAsync<XCoreSyncException>(() => NewSyncWith(SubUpstream).SyncCaddyAsync(fake.Session, protocol));
    Check("Caddy sync: сертификат домена подписки не получен — ошибка с доменом и подсказкой про A-запись и порт 80",
        ex is not null && ex.Message.Contains(SubHost) && ex.Message.Contains("порт 80") && fake.CurlCalls - curlAtStart == 3, ex?.Message);
    Check("Caddy sync: при этом рабочий файл новый, а повтор перезапишет и перезапустит снова (ревизия не засчитана)",
        fake.Files[XCoreNode.CaddyfilePath].Contains(SubHost) && protocol.XCore.AppliedCaddyRevision == caddyPlain.Revision && fake.WebRestarts == 1);

    // Нет curl на узле.
    (fake, server, protocol) = await ProvisionRoleAsync(XCoreRoles.Entry, TId(64));
    protocol.XCore!.SubscriptionHost = SubHost;
    var noCurlNode = fake;
    var noCurlSsh = Stub.Create<ISshSession>((method, a) =>
    {
        if (method.Name == nameof(ISshSession.RunAsync) && ((string)a[0]!).StartsWith("curl ", StringComparison.Ordinal))
            return Task.FromResult(new SshResult(127, "", "sh: curl: not found"));
        return method.Invoke(noCurlNode.Session, a);
    });
    ex = await CatchAsync<XCoreSyncException>(() => NewSyncWith(SubUpstream).SyncCaddyAsync(noCurlSsh, protocol));
    Check("Caddy sync: на узле нет curl — отдельное сообщение, а не «проверьте DNS»",
        ex is not null && ex.Message.Contains("curl") && !ex.Message.Contains("A-запись"), ex?.Message);

    // Выход с остатком домена подписки в базе: в конфиг он не попадает, прежний Caddyfile остаётся.
    (fake, server, protocol) = await ProvisionRoleAsync(XCoreRoles.Exit, TId(65));
    protocol.XCore!.SubscriptionHost = SubHost;
    start = fake.Commands.Count;
    var exitResult = await NewSyncWith(SubUpstream).SyncCaddyAsync(fake.Session, protocol);
    Check("Caddy sync: у выхода домен подписки игнорируется — NoOp",
        exitResult.Action == XCoreCaddyAction.NoOp && fake.Commands.Count == start);

    // Нет почты для сертификата: узел не трогается.
    (fake, server, protocol) = await ProvisionRoleAsync(XCoreRoles.Entry, TId(66));
    protocol.XCore!.AppliedCaddyRevision = "устарела";
    start = fake.Commands.Count;
    ex = await CatchAsync<XCoreSyncException>(() => NewSyncWith(SubUpstream, email: null).SyncCaddyAsync(fake.Session, protocol));
    Check("Caddy sync: нет XCore:AcmeEmail — ошибка, узел не тронут",
        ex is not null && ex.Message.Contains("XCore:AcmeEmail") && fake.Commands.Count == start, ex?.Message);
}

{
    // Обработчик события: Caddy применяется после Xray и записывается отдельно.
    var (fake, server, protocol) = await ProvisionRoleAsync(XCoreRoles.Entry, TId(67));
    var h = new SyncHarness(fake, server, NewSyncWith(SubUpstream), protector);
    h.Desired.Add(Sub(SubIdAbc, UuidAbc));
    var result = await h.Handler.HandleAsync(SyncEvent(server, protocol), default);
    Check("handler: Caddyfile не менялся — caddy NoOp, ревизия Caddy в базу не пишется",
        result!["caddy"] == "NoOp" && h.CaddyApplied.Count == 0 && fake.WebRestarts == 0);

    protocol.XCore!.SubscriptionHost = SubHost;
    result = await h.Handler.HandleAsync(SyncEvent(server, protocol), default);
    Check("handler: домен подписки задан — Caddy перезапущен, ревизия записана в базу",
        result!["caddy"] == "Restart" && h.CaddyApplied is [{ Revision: var rev }] && rev == caddyWithSub.Revision
        && protocol.XCore.AppliedCaddyRevision == rev && fake.WebRestarts == 1);
    result = await h.Handler.HandleAsync(SyncEvent(server, protocol), default);
    Check("handler: повтор — caddy NoOp, второй записи ревизии нет", result!["caddy"] == "NoOp" && h.CaddyApplied.Count == 1 && fake.WebRestarts == 1);

    // Caddy падает, а Xray уже применён: подписчик не ждёт, ошибка уходит событию.
    var (fake2, server2, protocol2) = await ProvisionRoleAsync(XCoreRoles.Entry, TId(68));
    protocol2.XCore!.SubscriptionHost = SubHost;
    fake2.CaddyValidateFails = true;
    var h2 = new SyncHarness(fake2, server2, NewSyncWith(SubUpstream), protector);
    h2.Desired.Add(Sub(SubIdAbc, UuidAbc));
    var failure = await CatchAsync<XCoreSyncException>(() => h2.Handler.HandleAsync(SyncEvent(server2, protocol2), default));
    Check("handler: Caddy отклонён — исключение для политики повторов, а подписчик уже на узле и ревизия Xray записана",
        failure is not null && h2.Applied.Count == 1 && h2.CaddyApplied.Count == 0 && LiveIs(fake2, ($"sub-{SubIdAbc}", UuidAbc)));
    await h2.Handler.OnFailedAsync(SyncEvent(server2, protocol2), failure!.Message, default);
    Check("handler: после окончательного провала причина Caddy видна в SyncError",
        protocol2.XCore.SyncError!.Contains("Caddy отклонил"), protocol2.XCore.SyncError);
}

// ── Здоровье плеч вход → выход ───────────────────────────────────────────────

Console.WriteLine("Здоровье плеч вход → выход");

Check("плечо: команда — curl с хоста входа на домен выхода, таймаут 8 с, только код ответа",
    XCoreExitProbe.Command("n01.example.com") == "curl -s -o /dev/null --max-time 8 -w '%{http_code}' https://n01.example.com/");

{
    var checkedAt = new DateTime(2026, 10, 29, 12, 0, 0, DateTimeKind.Utc);
    (int Exit, string Out, bool Ok, string? Error)[] cases =
    [
        (0, "200", true, null),
        (0, "200\n", true, null),
        (0, "404", false, "выход ответил кодом 404"),
        (0, "502", false, "выход ответил кодом 502"),
        (0, "000", false, "выход ответил кодом 000"),
        (0, "", false, "выход дал неожиданный ответ"),
        (0, "<html>", false, "выход дал неожиданный ответ"),
        (28, "000", false, "выход не ответил за 8 с"),
        (7, "000", false, "соединение с выходом отклонено"),
        (6, "000", false, "домен выхода не разрешается с входа"),
        (60, "000", false, "ошибка TLS при подключении к выходу"),
        (35, "000", false, "ошибка TLS при подключении к выходу"),
        (127, "", false, "на входе нет curl"),
        (56, "000", false, "curl завершился с кодом 56"),
        (28, "200", false, "выход не ответил за 8 с"),
    ];
    var wrong = cases
        .Select(c => (Case: c, Result: XCoreExitProbe.Interpret("s1", new SshResult(c.Exit, c.Out, "curl: (28) secret-stderr"), checkedAt)))
        .Where(r => r.Result.Ok != r.Case.Ok || r.Result.Error != r.Case.Error || r.Result.ServerId != "s1" || r.Result.CheckedAt != checkedAt)
        .Select(r => $"{r.Case.Exit}/{r.Case.Out} → {r.Result.Ok}/{r.Result.Error}").ToList();
    Check($"плечо: {cases.Length} образцов ответа curl разбираются как задумано (200 с кодом 0 — открыто, остальное — причина)",
        wrong.Count == 0, string.Join(" | ", wrong));
    Check("плечо: в тексте ошибки нет вывода curl (stderr) и текста команды",
        cases.Where(c => !c.Ok).All(c => XCoreExitProbe.Interpret("s1", new SshResult(c.Exit, c.Out, "secret-stderr"), checkedAt).Error is { } e
            && !e.Contains("secret") && !e.Contains("curl -s") && !e.Contains("https://")));

    XCoreExitHealth H(string id, bool ok) => new() { ServerId = id, Ok = ok, CheckedAt = checkedAt, Error = ok ? null : "x" };
    string Trans(IReadOnlyList<XCoreExitHealth> before, IReadOnlyList<XCoreExitHealth> after) =>
        string.Join(",", XCoreExitProbe.Transitions(before, after).Select(t => $"{t.ServerId}:{(t.NowOk ? "up" : "down")}"));
    Check("плечо: ok → ok и fail → fail переходов не дают (журнал не пополняется на каждом тике)",
        Trans([H("a", true), H("b", false)], [H("a", true), H("b", false)]) == "");
    Check("плечо: ok → fail — переход вниз, fail → ok — вверх",
        Trans([H("a", true), H("b", false)], [H("a", false), H("b", true)]) == "a:down,b:up");
    Check("плечо: нет прежнего результата — первая удачная проверка молчит, первая неудачная сообщает",
        Trans([], [H("a", true)]) == "" && Trans([], [H("a", false)]) == "a:down");
    Check("плечо: выход пропал из топологии — перехода нет, остальные считаются по своим результатам",
        Trans([H("a", false), H("b", true)], [H("b", true)]) == "" && Trans([H("a", true), H("b", true)], [H("b", false)]) == "b:down");

    var targetsServers = new[]
    {
        topoExit2, topoEntry, topoExit1, topoHidden, topoNoRoute, topoOff, topoIncomplete, topoInstalling, topoEntryOff,
        TopoNode(TId(11), XCoreRoles.Exit, 11, p => p.XCore!.Domain = "bad domain.example.com; rm -rf /"),
    };
    Check("плечо: проверяются те же выходы, что получает вход, по номеру маршрута; выход с негодным доменом пропущен",
        XCoreExitProbe.Targets(targetsServers).Select(t => t.Server.Id).SequenceEqual([TId(1), TId(2)]) && XCoreExitProbe.Targets([]).Count == 0);
}

{
    // Поллер здоровья на живом FakeNode: вход проверяет плечи, журнал пополняется только на переходах.
    var (fake, entryServer, entryProtocol) = await ProvisionRoleAsync(XCoreRoles.Entry, TId(70));
    entryServer.Name = "Вход";
    entryServer.Status = ServerStatuses.Ok;
    var exitA = TopoNode(TId(71), XCoreRoles.Exit, 1);
    var exitB = TopoNode(TId(72), XCoreRoles.Exit, 2);
    exitA.Name = "Выход А";
    exitB.Name = "Выход Б";
    var domainA = exitA.Protocols[0].XCore!.Domain;
    var domainB = exitB.Protocols[0].XCore!.Domain;

    var healthWrites = new List<List<XCoreExitHealth>>();
    var auditLog = new List<(string Event, string Message, string Level)>();
    var serverRepo = Stub.Create<IVpnServerRepository>((m, a) => m.Name switch
    {
        nameof(IVpnServerRepository.GetAllAsync) => Task.FromResult(new List<VpnServer> { entryServer, exitA, exitB }),
        nameof(IVpnServerRepository.UpdateHealthAsync) => Task.CompletedTask,
        nameof(IVpnServerRepository.SetXCoreExitHealthAsync) =>
            Task.Run(() => healthWrites.Add([.. ((IReadOnlyList<XCoreExitHealth>)a[2]!).Select(h => new XCoreExitHealth { ServerId = h.ServerId, Ok = h.Ok, CheckedAt = h.CheckedAt, Error = h.Error })])),
        _ => throw new NotSupportedException(m.Name),
    });
    var usageRepo = Stub.Create<IUsageRepository>((m, _) => m.Name == nameof(IUsageRepository.RecordHealthCheckAsync)
        ? Task.CompletedTask : throw new NotSupportedException(m.Name));
    var audit = Stub.Create<IAuditService>((m, a) =>
    {
        var level = m.GetParameters().ToList().FindIndex(p => p.Name == "level");
        auditLog.Add(((string)a[0]!, (string)a[1]!, (string)a[level]!));
        return Task.CompletedTask;
    });
    var sshFactory = Stub.Create<ISshSessionFactory>((_, _) => Task.FromResult(fake.Session));
    using var healthProvider = new ServiceCollection()
        .AddSingleton(serverRepo).AddSingleton(usageRepo).AddSingleton(audit).AddSingleton(sshFactory)
        .BuildServiceProvider();
    var poller = new HealthPollerService(
        healthProvider.GetRequiredService<IServiceScopeFactory>(), Options.Create(new PollingOptions()), NullLogger<HealthPollerService>.Instance);
    var check = typeof(HealthPollerService).GetMethod("CheckAsync", BindingFlags.NonPublic | BindingFlags.Instance)!;
    async Task Tick(VpnServer node) => await (Task)check.Invoke(poller, [healthProvider, node, CancellationToken.None])!;

    await Tick(entryServer);
    Check("поллер здоровья: оба плеча открыты — состояние записано (2 выхода), журнал молчит",
        healthWrites is [{ Count: 2 } first] && first.All(h => h.Ok) && auditLog.Count == 0
        && fake.ExitProbed.SequenceEqual([domainA, domainB]));

    fake.ExitProbes[domainB] = (28, "000");
    await Tick(entryServer);
    Check("поллер здоровья: плечо к «Выход Б» упало — одна запись warn с причиной, в состоянии ошибка",
        auditLog is [{ Event: "xcore.exit_down", Level: AuditLevels.Warn } down] && down.Message.Contains("Вход") && down.Message.Contains("Выход Б")
        && down.Message.Contains("не ответил за 8 с")
        && healthWrites[^1].Single(h => h.ServerId == exitB.Id) is { Ok: false, Error: "выход не ответил за 8 с" }
        && healthWrites[^1].Single(h => h.ServerId == exitA.Id).Ok);

    await Tick(entryServer);
    await Tick(entryServer);
    Check("поллер здоровья: плечо остаётся упавшим — новых записей в журнале нет, состояние обновляется каждый тик",
        auditLog.Count == 1 && healthWrites.Count == 4);

    fake.ExitProbes[domainB] = (0, "200");
    await Tick(entryServer);
    Check("поллер здоровья: плечо снова открыто — одна запись info",
        auditLog is [_, { Event: "xcore.exit_up", Level: AuditLevels.Info } up] && up.Message.Contains("Выход Б") && healthWrites[^1].All(h => h.Ok));
    await Tick(entryServer);
    Check("поллер здоровья: стабильное состояние журнал не пополняет", auditLog.Count == 2);
    Check("поллер здоровья: проверка шла с хоста входа теми командами, что описаны (curl с таймаутом 8 с)",
        fake.Commands.Count(c => c == XCoreExitProbe.Command(domainA)) == 6 && fake.Commands.Count(c => c == XCoreExitProbe.Command(domainB)) == 6);

    // Выход отключили от подписок — плеча к нему больше нет, и проверять его нечего.
    exitA.Protocols[0].XCore!.SubscriptionEnabled = false;
    await Tick(entryServer);
    Check("поллер здоровья: выход скрыт из подписок — в состоянии остался только «Выход Б»",
        healthWrites[^1].Select(h => h.ServerId).SequenceEqual([exitB.Id]));

    // Узел-выход плечей не проверяет: состояние не пишется.
    var writesBefore = healthWrites.Count;
    exitB.Status = ServerStatuses.Ok;
    await Tick(exitB);
    Check("поллер здоровья: у выхода плечи не проверяются и состояние не пишется", healthWrites.Count == writesBefore);
}

// ── Номер маршрута: гонка при установке ─────────────────────────────────────

Console.WriteLine("Номер маршрута: уникальный индекс и повтор");

{
    // Два выхода выбрали один номер: запись проигравшего отклонена индексом, он берёт следующий свободный.
    var fake = new FakeNode();
    var conflicts = 0;
    var (orchestrator, job, server, events) = NewOrchestrator(fake, null, TopoNode(TId(80), XCoreRoles.Exit, 1));
    orchestratorRaced = [];
    orchestratorUpdateHook = s =>
    {
        // Отклоняется только запись только что поставленного протокола (состояние «ставится»), а не последующие.
        if (conflicts >= 2 || s.Protocols.LastOrDefault() is not { State: ProtocolStates.Installing }) return Task.CompletedTask;
        conflicts++;
        var taken = s.Protocols.Last().XCore!.RouteId!.Value;
        orchestratorRaced.Add(TopoNode(TId(81 + conflicts), XCoreRoles.Exit, taken));
        return Task.FromException(new RouteIdTakenException());
    };
    await orchestrator.ExecuteAsync(job, default);
    Check("оркестратор: запись отклонена индексом дважды — берётся следующий свободный номер (заняты 1, затем 2 и 3 — итог 4)",
        job.Status == InstallJobStatuses.Succeeded && conflicts == 2 && server.Protocols.Single().XCore!.RouteId == 4,
        $"{job.Status}: {job.Error}; номер {server.Protocols.SingleOrDefault()?.XCore?.RouteId}");
    Check("оркестратор: после повторов в узле ровно один протокол xcore (неудачные попытки не накапливаются)", server.Protocols.Count == 1);

    // Проигрыш всех попыток подряд — задача проваливается, а не зацикливается.
    fake = new FakeNode();
    conflicts = 0;
    (orchestrator, job, server, events) = NewOrchestrator(fake, null);
    orchestratorRaced = [];
    orchestratorUpdateHook = s =>
    {
        if (s.Protocols.LastOrDefault() is not { State: ProtocolStates.Installing }) return Task.CompletedTask;
        conflicts++;
        orchestratorRaced.Add(TopoNode(TId(90 + conflicts), XCoreRoles.Exit, s.Protocols.Last().XCore!.RouteId!.Value));
        return Task.FromException(new RouteIdTakenException());
    };
    await orchestrator.ExecuteAsync(job, default);
    Check("оркестратор: все 5 попыток отклонены — ровно 5 записей и задача провалена",
        conflicts == XCoreRoute.AssignAttempts && job.Status == InstallJobStatuses.Failed, $"попыток {conflicts}, {job.Status}");
    orchestratorUpdateHook = null;
    orchestratorRaced = [];
}

{
    // Обработчик события: выход без номера проигрывает гонку индексу и берёт следующий.
    var (fake, server, protocol) = await ProvisionRoleAsync(XCoreRoles.Exit, TId(95));
    protocol.XCore!.RouteId = null;
    var h = new SyncHarness(fake, server, NewSync(), protector);
    h.Others.Add(TopoNode(TId(96), XCoreRoles.Exit, 1));
    h.RouteConflicts = 2;
    await h.Handler.HandleAsync(SyncEvent(server, protocol), default);
    Check("handler: номер отклонён индексом дважды — назначен следующий свободный (1 занят, 2 и 3 заняты соперниками)",
        h.RouteAssignments is [{ RouteId: 4 }] && protocol.XCore.RouteId == 4, string.Join(",", h.RouteAssignments.Select(a => a.RouteId)));

    protocol.XCore.RouteId = null;
    h.RouteAssignments.Clear();
    h.RouteConflicts = 99;
    var exhausted = await CatchAsync<RouteIdTakenException>(() => h.Handler.HandleAsync(SyncEvent(server, protocol), default));
    Check("handler: номер отклонён все 5 раз — исключение уходит политике повторов, номер не назначен",
        exhausted is not null && protocol.XCore.RouteId is null && h.RouteAssignments.Count == 0);
}

// ── Российские списки: установка, обновление, расписание ─────────────────────

Console.WriteLine("Российские списки входа: установка входа");

{
    var entryFake = new FakeNode();
    var entrySpec = PreparedSpec();
    entrySpec.Role = "entry";
    var entryInstalled = await NewInstaller(GoodDns()).InstallAsync(entryFake.Session, NodeServer(), entrySpec, new RecordingProgress());
    var mkdirGeo = entryFake.IndexOf("sudo mkdir -p /opt/amnezia-xcore/geo");
    var runEntry = entryFake.XrayRunCommand!;
    Check("вход: каталог списков создан до запуска контейнера; контейнер получил монтирование каталога и XRAY_LOCATION_ASSET",
        mkdirGeo >= 0 && mkdirGeo < entryFake.IndexOf("--name amnezia-xcore --network host")
        && runEntry.Contains("-v /opt/amnezia-xcore/geo:/etc/xcore-geo:ro") && runEntry.Contains("-e XRAY_LOCATION_ASSET=/etc/xcore-geo"));
    Check("вход: установка сама ничего не скачивает и не пишет файлов списков (первичную загрузку делает событие), тега нет",
        entryFake.Downloads.Count == 0 && !entryFake.Files.Keys.Any(k => k.Contains("rf-geo")) && entryInstalled.XCore!.RfListsTag is null);

    var exitFake = new FakeNode();
    await NewInstaller(GoodDns()).InstallAsync(exitFake.Session, NodeServer(), PreparedSpec(), new RecordingProgress());
    Check("выход: ни каталога списков, ни монтирования, ни окружения", !exitFake.Ran("xcore-geo") && !exitFake.Ran("/opt/amnezia-xcore/geo"));
}

Console.WriteLine("Российские списки входа: обновление");

const string GeoT1 = "202610291019";
const string GeoRepo = "runetfreedom/russia-v2ray-rules-dat";
string GeoUrl(string tag, string file) => XCoreRfLists.DownloadUrl(GeoRepo, tag, file);
void PublishRelease(FakeNode f, string tag, bool badSum = false)
{
    var geosite = $"GEOSITE-{tag}";
    var geoip = $"GEOIP-{tag}";
    f.Internet[GeoUrl(tag, "geosite.dat")] = geosite;
    f.Internet[GeoUrl(tag, "geoip.dat")] = geoip;
    f.Internet[GeoUrl(tag, "geosite.dat.sha256sum")] = $"{(badSum ? new string('0', 64) : Sha(geosite))} *geosite.dat\n";
    f.Internet[GeoUrl(tag, "geoip.dat.sha256sum")] = $"{Sha(geoip)} *geoip.dat\n";
}
DomainEvent GeoEvent(VpnServer s, ProtocolInstance p, string? tag) => new()
{
    Type = DomainEventTypes.XCoreGeoUpdate,
    Payload = new XCoreGeoUpdatePayload(s.Id, p.Id, tag).ToBsonDocument(),
};
async Task<(FakeNode Node, VpnServer Server, ProtocolInstance Protocol, SyncHarness H)> GeoSetupAsync(
    int n, XCoreOptions? options = null, bool withExits = true)
{
    var (fake, server, protocol) = await ProvisionRoleAsync(XCoreRoles.Entry, TId(100 + n));
    var h = new SyncHarness(fake, server, NewSync(), protector, options);
    if (withExits) h.Others.AddRange([TopoNode(TId(140), XCoreRoles.Exit, 1), TopoNode(TId(141), XCoreRoles.Exit, 2)]);
    return (fake, server, protocol, h);
}
bool GeoFilesAre(FakeNode f, string tag) =>
    f.Files.GetValueOrDefault(XCoreNode.GeoDir + "/rf-geosite.dat") == $"GEOSITE-{tag}"
    && f.Files.GetValueOrDefault(XCoreNode.GeoDir + "/rf-geoip.dat") == $"GEOIP-{tag}";
bool NoGeoLeftovers(FakeNode f) =>
    !f.Files.Keys.Any(k => k.StartsWith(XCoreNode.GeoStageDir, StringComparison.Ordinal) || k.Contains("config.geo-") || k.EndsWith(".part"));

{
    var (fake, server, protocol, h) = await GeoSetupAsync(1);
    var x = protocol.XCore!;
    var relay = protector.Unprotect(x.RelayUuid)!;
    PublishRelease(fake, GeoT1);
    h.Releases.Tag = GeoT1;
    h.Desired.Add(Sub(SubIdAbc, UuidAbc));

    // До списков: синхронизация входа идёт без каталога списков и без ext:.
    var first = await h.Handler.HandleAsync(SyncEvent(server, protocol), default);
    Check("до списков: синхронизация входа проверяет конфиг без каталога списков, в конфиге нет ext:",
        fake.ConfigTests.Last(t => t.File == XCoreNode.NewConfigFile).GeoDir == "" && !fake.Files[XCoreNode.ConfigPath].Contains("ext:")
        && first!["action"] == "Restart");

    var restartsBefore = fake.XrayRestarts;
    var published = h.Events.Published.Count;
    var mark = fake.Commands.Count;
    var testsBefore = fake.ConfigTests.Count;
    var result = await h.GeoHandler.HandleAsync(GeoEvent(server, protocol, null), default);

    Check("обновление: тег узнан у источника (payload без тега), записан в узел вместе с временем; ошибки нет",
        result!["tag"] == GeoT1 && x.RfListsTag == GeoT1 && x.RfListsAppliedAt is not null && x.RfListsCheckedAt is not null
        && x.GeoError is null && h.Releases.Calls == 1 && h.RfListsApplied.SequenceEqual([GeoT1]));
    Check("обновление: оба файла лежат в рабочем каталоге, кандидатов, недокачанных и тестовых конфигов на узле не осталось",
        GeoFilesAre(fake, GeoT1) && NoGeoLeftovers(fake));
    var order = new[]
    {
        At(fake, mark, "docker inspect"), At(fake, mark, "sudo curl -fsSL"), At(fake, mark, "sudo sha256sum"),
        At(fake, mark, "run -test -c /etc/xcore/config.geo-probe.json"), At(fake, mark, "run -test -c /etc/xcore/config.geo-test.json"),
        At(fake, mark, "geo-stage/rf-geosite.dat /opt/amnezia-xcore/geo/rf-geosite.dat"),
    };
    Check("обновление: порядок — проверка монтирования, скачивание, сумма, пробный конфиг, будущий конфиг, и только затем подмена файлов",
        order.All(i => i >= 0) && order.SequenceEqual(order.Order()), string.Join(",", order));
    Check("обновление: обе проверки идут с каталогом кандидатов, не с рабочим",
        fake.ConfigTests.Skip(testsBefore).SequenceEqual([("config.geo-probe.json", XCoreNode.GeoStageDir), ("config.geo-test.json", XCoreNode.GeoStageDir)]));
    var futureWrite = fake.Writes.Last(w => w.Path.EndsWith("config.geo-test.json")).Content;
    Check("обновление: будущий конфиг — настоящий конфиг входа с ext-правилами и закрыт (600), после проверки удалён",
        futureWrite.Contains("ext:rf-geosite.dat:ru-blocked") && futureWrite.Contains("exit-1") && fake.Modes[XCoreNode.ConfDir + "/config.geo-test.json"] == "600");
    Check("обновление: скачивание — curl с таймаутом, без повторов, сначала сумма релиза; скачано 4 адреса нужного тега",
        fake.Commands.Skip(mark).Where(c => c.Contains("curl -fsSL")).All(c => c.Contains("--max-time") && !c.Contains("--retry"))
        && fake.Downloads.OrderBy(d => d).SequenceEqual(new[]
            { GeoUrl(GeoT1, "geoip.dat"), GeoUrl(GeoT1, "geoip.dat.sha256sum"), GeoUrl(GeoT1, "geosite.dat"), GeoUrl(GeoT1, "geosite.dat.sha256sum") }.OrderBy(d => d)));
    Check("обновление: контейнер не перезапускался и не пересоздавался (рестарт — дело синхронизации)",
        fake.XrayRestarts == restartsBefore && !fake.Commands.Skip(mark).Any(c => c.Contains("docker restart") || c.Contains("docker rm") || c.Contains("docker run -d")));
    Check("обновление: опубликована ровно одна синхронизация этого узла",
        h.Events.Published.Skip(published).ToList() is [{ Type: DomainEventTypes.XCoreSync, Partition: var syncPartition }] && syncPartition == server.Id);
    Check("обновление: ни приватного ключа, ни служебного UUID в командах, метках и результате",
        !fake.Commands.Skip(mark).Any(c => c.Contains(FakeNode.PrivateKey) || c.Contains(relay)) && !fake.Labels.Any(l => l.Contains(relay))
        && !result.ToJson().Contains(relay));

    // Следом синхронизация применяет конфиг со списками: проверка с рабочим каталогом, рестарт.
    var applied = await h.Handler.HandleAsync(SyncEvent(server, protocol), default);
    var newConfigTest = fake.ConfigTests.Last(t => t.File == XCoreNode.NewConfigFile);
    Check("после обновления синхронизация входа: конфиг с ext-правилами проверен с рабочим каталогом списков и применён рестартом",
        applied!["action"] == "Restart" && newConfigTest.GeoDir == XCoreNode.GeoDir && fake.Files[XCoreNode.ConfigPath].Contains("ext:rf-geosite.dat:ru-blocked")
        && fake.XrayRestarts == restartsBefore + 1);
    var syncAgain = await h.Handler.HandleAsync(SyncEvent(server, protocol), default);
    Check("и снова синхронизация: ничего не изменилось — NoOp без рестарта", syncAgain!["action"] == "NoOp" && fake.XrayRestarts == restartsBefore + 1);

    // Тот же тег: ни одной команды на узле.
    mark = fake.Commands.Count;
    published = h.Events.Published.Count;
    var checkedBefore = x.RfListsCheckedAt;
    await Task.Delay(5);
    var sameTag = await h.GeoHandler.HandleAsync(GeoEvent(server, protocol, GeoT1), default);
    Check("тот же тег: на узле ни одной команды, новых синхронизаций нет, обновлена только дата проверки",
        sameTag!["skipped"] == "same_tag" && fake.Commands.Count == mark && h.Events.Published.Count == published
        && x.RfListsCheckedAt > checkedBefore && x.RfListsTag == GeoT1 && GeoFilesAre(fake, GeoT1));
    var sameViaSource = await h.GeoHandler.HandleAsync(GeoEvent(server, protocol, null), default);
    Check("тот же тег из источника (кнопка «обновить сейчас»): тоже ничего на узле", sameViaSource!["skipped"] == "same_tag" && fake.Commands.Count == mark);

    // Несовпадение суммы: прежние файлы нетронуты, контейнер не перезапущен, ошибка видна.
    const string GeoT2 = "202610301000";
    PublishRelease(fake, GeoT2, badSum: true);
    mark = fake.Commands.Count;
    published = h.Events.Published.Count;
    testsBefore = fake.ConfigTests.Count;
    restartsBefore = fake.XrayRestarts;
    var badSum = await h.GeoHandler.HandleAsync(GeoEvent(server, protocol, GeoT2), default);
    Check("сумма не совпала: прежние файлы и тег нетронуты, команд run -test не было, рестарта нет, синхронизация не просилась",
        badSum!.Contains("error") && GeoFilesAre(fake, GeoT1) && x.RfListsTag == GeoT1 && fake.ConfigTests.Count == testsBefore
        && fake.XrayRestarts == restartsBefore && h.Events.Published.Count == published && NoGeoLeftovers(fake)
        && !fake.Commands.Skip(mark).Any(c => c.Contains("xcore/geo/rf-")));
    Check("сумма не совпала: причина в GeoError, а не в SyncError; без секретов",
        x.GeoError!.Contains("Контрольная сумма") && x.SyncError is null && !x.GeoError.Contains(relay));

    // Релиз без нужных тегов: пробный конфиг отвергнут.
    const string GeoT3 = "202610311000";
    PublishRelease(fake, GeoT3);
    fake.RfListsLackTags = true;
    testsBefore = fake.ConfigTests.Count;
    await h.GeoHandler.HandleAsync(GeoEvent(server, protocol, GeoT3), default);
    Check("релиз без нужных тегов: отвергнут пробой, будущий конфиг не запускался, файлы и тег прежние",
        x.GeoError!.Contains("не хватает нужных тегов") && fake.ConfigTests.Count == testsBefore + 1
        && GeoFilesAre(fake, GeoT1) && x.RfListsTag == GeoT1 && NoGeoLeftovers(fake) && fake.XrayRestarts == restartsBefore);
    fake.RfListsLackTags = false;

    // Будущий конфиг отвергнут: run -test упал, контейнер не перезапущен, файлы прежние.
    fake.FutureConfigTestFails = true;
    testsBefore = fake.ConfigTests.Count;
    mark = fake.Commands.Count;
    await h.GeoHandler.HandleAsync(GeoEvent(server, protocol, GeoT3), default);
    Check("run -test будущего конфига упал: файлы и тег прежние, рестарта нет, тестовые файлы убраны, причина в GeoError",
        fake.ConfigTests.Count == testsBefore + 2 && GeoFilesAre(fake, GeoT1) && x.RfListsTag == GeoT1 && NoGeoLeftovers(fake)
        && fake.XrayRestarts == restartsBefore && x.GeoError!.Contains("отклонил конфиг входа с новыми списками")
        && !fake.Commands.Skip(mark).Any(c => c.Contains("xcore/geo/rf-")));
    fake.FutureConfigTestFails = false;

    // Скачивание файла не удалось.
    const string GeoT4 = "202611010900";
    PublishRelease(fake, GeoT4);
    fake.Internet.Remove(GeoUrl(GeoT4, "geoip.dat"));
    await h.GeoHandler.HandleAsync(GeoEvent(server, protocol, GeoT4), default);
    Check("скачивание geoip.dat не удалось: файлы прежние, кандидаты убраны, сообщение с названием файла",
        x.GeoError!.Contains("geoip.dat") && GeoFilesAre(fake, GeoT1) && NoGeoLeftovers(fake) && x.RfListsTag == GeoT1);
    PublishRelease(fake, "202611020900");
    fake.Internet.Remove(GeoUrl("202611020900", "geosite.dat.sha256sum"));
    await h.GeoHandler.HandleAsync(GeoEvent(server, protocol, "202611020900"), default);
    Check("нет файла контрольных сумм: релиз не применяется", x.GeoError!.Contains("контрольную сумму") && GeoFilesAre(fake, GeoT1));

    // Нет curl на узле; контейнер без каталога списков; небезопасный тег.
    var downloads = fake.Downloads.Count;
    fake.CurlMissing = true;
    await h.GeoHandler.HandleAsync(GeoEvent(server, protocol, GeoT3), default);
    Check("на узле нет curl: отдельное сообщение, обращений в сеть нет", x.GeoError!.Contains("нет curl") && fake.Downloads.Count == downloads);
    fake.CurlMissing = false;
    fake.GeoNotMounted = true;
    await h.GeoHandler.HandleAsync(GeoEvent(server, protocol, GeoT3), default);
    Check("контейнер создан до списков (нет монтирования): понятный отказ до скачивания, тег не записан",
        x.GeoError!.Contains("создан до поддержки") && fake.Downloads.Count == downloads && x.RfListsTag == GeoT1);
    fake.GeoNotMounted = false;
    mark = fake.Commands.Count;
    await h.GeoHandler.HandleAsync(GeoEvent(server, protocol, "1;rm -rf /"), default);
    Check("небезопасный тег в событии: отказ до первой команды на узле", fake.Commands.Count == mark && x.GeoError!.Contains("недопустимые"));

    // Источник релизов недоступен: узел не трогаем.
    var connections = h.Connections;
    h.Releases.Fail = true;
    await h.GeoHandler.HandleAsync(GeoEvent(server, protocol, null), default);
    Check("GitHub недоступен: ошибка в GeoError, соединения с узлом не было", x.GeoError!.Contains("GitHub") && h.Connections == connections);
    h.Releases.Fail = false;

    // Успех после ошибок снимает GeoError и вносит новый релиз.
    const string GeoT5 = "202611030900";
    PublishRelease(fake, GeoT5);
    var okAgain = await h.GeoHandler.HandleAsync(GeoEvent(server, protocol, GeoT5), default);
    Check("после ошибок успешное обновление снимает GeoError и подменяет оба файла на новый релиз",
        okAgain!["tag"] == GeoT5 && x.GeoError is null && x.RfListsTag == GeoT5 && GeoFilesAre(fake, GeoT5) && NoGeoLeftovers(fake));

    // Окончательный провал события (узел недоступен): оператор видит причину без UUID.
    await h.GeoHandler.OnFailedAsync(GeoEvent(server, protocol, null), $"SSH: не удалось подключиться, {UuidAbc}", default);
    Check("OnFailed: причина в GeoError, UUID вырезан", x.GeoError!.Contains("SSH") && !x.GeoError.Contains(UuidAbc));
    await h.GeoHandler.OnFailedAsync(GeoEvent(server, protocol, null), "  ", default);
    Check("OnFailed: пустая причина получает текст по умолчанию", x.GeoError!.Length > 0);

    Check("политика события: идемпотентное, с повторами, возвращается при потере аренды",
        h.GeoHandler.Policy is { MaxAttempts: 3, RetryOnLeaseExpiry: true } && h.GeoHandler.EventType == "xcore.geo_update");
}

{
    // Вход без выходов: пробы достаточно, список применяется, будущего конфига нет.
    var (fake, server, protocol, h) = await GeoSetupAsync(2, withExits: false);
    PublishRelease(fake, GeoT1);
    await h.GeoHandler.HandleAsync(GeoEvent(server, protocol, GeoT1), default);
    Check("вход без выходов: проверена только проба, списки положены, тег записан",
        fake.ConfigTests.Where(t => t.File.StartsWith("config.geo")).Select(t => t.File).SequenceEqual(["config.geo-probe.json"]) && GeoFilesAre(fake, GeoT1) && protocol.XCore!.RfListsTag == GeoT1);

    // Не вход, не установлен, выключено настройкой.
    var (exitFake, exitServer, exitProtocol) = await ProvisionRoleAsync(XCoreRoles.Exit, TId(110));
    var exitHarness = new SyncHarness(exitFake, exitServer, NewSync(), protector);
    var exitResult = await exitHarness.GeoHandler.HandleAsync(GeoEvent(exitServer, exitProtocol, GeoT1), default);
    Check("выход: обновление не применимо, узел не трогается", exitResult!["skipped"] == "not_applicable" && exitHarness.Connections == 0);

    var (_, instServer, instProtocol, instHarness) = await GeoSetupAsync(3);
    instProtocol.State = ProtocolStates.Installing;
    var instResult = await instHarness.GeoHandler.HandleAsync(GeoEvent(instServer, instProtocol, GeoT1), default);
    Check("вход ещё не установлен: пропуск, узел не трогается", instResult!["skipped"] == "not_applicable" && instHarness.Connections == 0);

    var (offFake, offServer, offProtocol, offHarness) = await GeoSetupAsync(4, new XCoreOptions { RfListsEnabled = false });
    var offCommands = offFake.Commands.Count;
    var offResult = await offHarness.GeoHandler.HandleAsync(GeoEvent(offServer, offProtocol, null), default);
    Check("XCore:RfListsEnabled=false: событие пропущено, к GitHub и к узлу не обращались",
        offResult!["skipped"] == "disabled" && offHarness.Connections == 0 && offHarness.Releases.Calls == 0 && offFake.Commands.Count == offCommands);
}

Console.WriteLine("Российские списки входа: расписание");

(XCoreGeoUpdateService Service, ServiceProvider Provider, RecordingEvents Events, FakeReleases Releases, List<string> Checked) NewGeoService(
    List<VpnServer> servers, XCoreOptions? options = null)
{
    var checkedNodes = new List<string>();
    var repo = Stub.Create<IVpnServerRepository>((m, a) =>
    {
        if (m.Name == nameof(IVpnServerRepository.GetAllAsync)) return Task.FromResult(servers.ToList());
        if (m.Name == nameof(IVpnServerRepository.SetXCoreRfListsCheckedAsync))
        {
            checkedNodes.Add((string)a[0]!);
            return Task.CompletedTask;
        }
        throw new NotSupportedException(m.Name);
    });
    var events = new RecordingEvents();
    var releases = new FakeReleases { Tag = "202610291019" };
    var provider = new ServiceCollection()
        .AddSingleton(repo)
        .AddSingleton(new XCoreSyncPublisher(repo, events.Publisher, NullLogger<XCoreSyncPublisher>.Instance))
        .AddSingleton<IXCoreReleaseSource>(releases)
        .AddSingleton<IOptions<XCoreOptions>>(Options.Create(options ?? new XCoreOptions()))
        .BuildServiceProvider();
    var service = new XCoreGeoUpdateService(
        provider.GetRequiredService<IServiceScopeFactory>(), Options.Create(new PollingOptions()), NullLogger<XCoreGeoUpdateService>.Instance);
    return (service, provider, events, releases, checkedNodes);
}
VpnServer GeoEntry(int n, string? tag, TimeSpan? appliedAgo, Action<ProtocolInstance>? tweak = null) =>
    TopoNode(TId(120 + n), XCoreRoles.Entry, null, p =>
    {
        p.XCore!.RfListsTag = tag;
        p.XCore.RfListsAppliedAt = appliedAgo is { } ago ? DateTime.UtcNow - ago : null;
        tweak?.Invoke(p);
    });

{
    var now = DateTime.UtcNow;
    var never = GeoEntry(1, null, null);
    var old8 = GeoEntry(2, "202610201000", TimeSpan.FromDays(8));
    var old3 = GeoEntry(3, "202610261000", TimeSpan.FromDays(3));
    var current = GeoEntry(4, "202610291019", TimeSpan.FromDays(30));
    var ahead = GeoEntry(5, "202611011000", TimeSpan.FromDays(30));
    var noDate = GeoEntry(6, "202610201000", null);
    var hidden = GeoEntry(7, null, null, p => { p.Enabled = false; p.XCore!.SubscriptionEnabled = false; });
    var installing = GeoEntry(8, null, null, p => p.State = ProtocolStates.Installing);
    var exit = TopoNode(TId(129), XCoreRoles.Exit, 1);

    var (service, provider, events, releases, checkedNodes) = NewGeoService([never, old8, old3, current, ahead, noDate, hidden, installing, exit]);
    var count = await service.CheckAsync(provider, now, default);
    var geo = events.Published.Where(p => p.Type == DomainEventTypes.XCoreGeoUpdate).ToList();
    var partitions = geo.Select(p => p.Partition).Order().ToList();
    Check("расписание: публикуются первая загрузка, релиз старше срока, без даты применения, а также выключенный вход",
        count == 4 && partitions.SequenceEqual(new[] { never.Id, old8.Id, noDate.Id, hidden.Id }.Order()), string.Join(",", partitions));
    Check("расписание: тег в событии — последний релиз, определённый worker (один запрос к GitHub на проход)",
        geo.All(p => ((XCoreGeoUpdatePayload)p.Payload).Tag == "202610291019") && releases.Calls == 1);
    Check("расписание: свежий релиз не ждёт срока (3 дня < 7) и актуальный/опережающий — не публикуются, но проверка отмечена",
        checkedNodes.Order().SequenceEqual(new[] { old3.Id, current.Id, ahead.Id }.Order()));
    Check("расписание: выход и не установленный вход не затрагиваются",
        !partitions.Contains(exit.Id) && !partitions.Contains(installing.Id) && !checkedNodes.Contains(exit.Id) && !checkedNodes.Contains(installing.Id));

    (service, provider, events, releases, checkedNodes) = NewGeoService([old3], new XCoreOptions { RfListsMinAgeDays = 2 });
    Check("расписание: срок настраивается (XCore:RfListsMinAgeDays=2 — релиз 3-дневной давности применяется)",
        await service.CheckAsync(provider, now, default) == 1);

    (service, provider, events, releases, checkedNodes) = NewGeoService([never], new XCoreOptions { RfListsEnabled = false });
    Check("расписание: XCore:RfListsEnabled=false — ничего, GitHub не опрашивается",
        await service.CheckAsync(provider, now, default) == 0 && releases.Calls == 0 && events.Published.Count == 0);

    (service, provider, events, releases, checkedNodes) = NewGeoService([never, old8]);
    releases.Fail = true;
    Check("расписание: GitHub недоступен — ничего не публикуется и не отмечается",
        await service.CheckAsync(provider, now, default) == 0 && events.Published.Count == 0 && checkedNodes.Count == 0);

    (service, provider, events, releases, checkedNodes) = NewGeoService([exit]);
    Check("расписание: входов нет — GitHub не опрашивается", await service.CheckAsync(provider, now, default) == 0 && releases.Calls == 0);

    (service, provider, events, releases, checkedNodes) = NewGeoService([old8]);
    events.Fail = true;
    Check("расписание: недоступная публикация не бросает (повторит следующий проход)",
        await service.CheckAsync(provider, now, default) == 0);
}

Console.WriteLine("Пауза между неудачными выпусками сертификата");

{
    async Task<(FakeNode Node, VpnServer Server, ProtocolInstance Protocol, SyncHarness H)> PauseSetupAsync(int n, XCoreOptions? options = null)
    {
        var (fake, server, protocol) = await ProvisionRoleAsync(XCoreRoles.Entry, TId(150 + n));
        protocol.XCore!.SubscriptionHost = SubHost;
        fake.CertificateNever = true;
        var sync = new XCoreSyncService(protector, new ScriptRegistry(),
            Options.Create(options ?? new XCoreOptions { AcmeEmail = "ops@example.com", SubscriptionUpstream = SubUpstream }))
        { RestartPollAttempts = 3, RestartPollInterval = TimeSpan.Zero, CertificateAttempts = 3, CertificatePollInterval = TimeSpan.Zero };
        var h = new SyncHarness(fake, server, sync, protector);
        h.Desired.Add(Sub(SubIdAbc, UuidAbc));
        return (fake, server, protocol, h);
    }

    var (fake, server, protocol, h) = await PauseSetupAsync(1);
    var x = protocol.XCore!;
    var failure = await CatchAsync<XCoreSyncException>(() => h.Handler.HandleAsync(SyncEvent(server, protocol), default));
    Check("пауза: сертификат не получен — исключение для политики повторов, ревизия и время неудачи записаны, Caddy перезапущен один раз",
        failure is not null && h.CaddyFailures is [var f1] && f1.Revision == caddyWithSub.Revision && x.CaddyFailedRevision == caddyWithSub.Revision
        && x.CaddyFailedAt is not null && fake.WebRestarts == 1 && h.CaddyApplied.Count == 0, failure?.Message);

    var curlBefore = fake.CurlCalls;
    var validations = fake.CaddyValidations;
    var paused = await h.Handler.HandleAsync(SyncEvent(server, protocol), default);
    var expectedRetry = x.CaddyFailedAt!.Value.AddMinutes(60).ToString("HH:mm");
    Check("пауза: повтор в окне — Caddy не перезапускается, сертификат не запрашивается, Caddyfile не проверяется заново",
        paused!["caddy"] == "Paused" && fake.WebRestarts == 1 && fake.CurlCalls == curlBefore && fake.CaddyValidations == validations);
    Check("пауза: SyncError с текстом «повтор не раньше HH:mm UTC» (время неудачи + 60 минут)",
        x.SyncError is not null && x.SyncError.Contains($"повтор не раньше {expectedRetry} UTC"), x.SyncError);
    Check("пауза: Xray-часть при этом применена (подписчик на узле), ревизия Caddy не засчитана",
        LiveIs(fake, ($"sub-{SubIdAbc}", UuidAbc)) && h.CaddyApplied.Count == 0 && x.AppliedCaddyRevision == caddyPlain.Revision);
    paused = await h.Handler.HandleAsync(SyncEvent(server, protocol), default);
    Check("пауза: сколько бы ни приходило событий в окне — рестартов Caddy по-прежнему один", fake.WebRestarts == 1 && h.CaddyFailures.Count == 1);

    // Граница окна.
    x.CaddyFailedAt = DateTime.UtcNow.AddMinutes(-59);
    paused = await h.Handler.HandleAsync(SyncEvent(server, protocol), default);
    Check("пауза: через 59 минут окно ещё действует", paused!["caddy"] == "Paused" && fake.WebRestarts == 1);
    x.CaddyFailedAt = DateTime.UtcNow.AddMinutes(-61);
    failure = await CatchAsync<XCoreSyncException>(() => h.Handler.HandleAsync(SyncEvent(server, protocol), default));
    Check("пауза: через 61 минуту попытка предпринимается снова (перезапуск), неудача запоминается заново",
        failure is not null && fake.WebRestarts == 2 && h.CaddyFailures.Count == 2 && x.CaddyFailedAt > DateTime.UtcNow.AddMinutes(-1));

    // Смена ревизии (оператор поправил домен) снимает паузу.
    x.SubscriptionHost = "sub2.example.com";
    failure = await CatchAsync<XCoreSyncException>(() => h.Handler.HandleAsync(SyncEvent(server, protocol), default));
    Check("пауза: другая ревизия Caddyfile (поправили домен) — попытка сразу, пауза не мешает",
        failure is not null && fake.WebRestarts == 3 && x.CaddyFailedRevision != caddyWithSub.Revision && h.CaddyFailures.Count == 3);

    // Успех после окна: перезапуск и ревизия засчитана.
    x.CaddyFailedAt = DateTime.UtcNow.AddMinutes(-61);
    fake.CertificateNever = false;
    var recovered = await h.Handler.HandleAsync(SyncEvent(server, protocol), default);
    Check("пауза: после окна и при рабочем сертификате — Restart, ревизия Caddy записана в базу",
        recovered!["caddy"] == "Restart" && h.CaddyApplied.Count == 1 && x.AppliedCaddyRevision == h.CaddyApplied[0].Revision && fake.WebRestarts == 4);
    var settled = await h.Handler.HandleAsync(SyncEvent(server, protocol), default);
    Check("пауза: после успеха повторные синхронизации — NoOp", settled!["caddy"] == "NoOp" && fake.WebRestarts == 4 && x.SyncError is null);
}

{
    // CaddyRetryMinutes=0 отключает паузу; сбой проверки Caddyfile паузу не заводит.
    var options = new XCoreOptions { AcmeEmail = "ops@example.com", SubscriptionUpstream = SubUpstream, CaddyRetryMinutes = 0 };
    var (fake, server, protocol) = await ProvisionRoleAsync(XCoreRoles.Entry, TId(170));
    protocol.XCore!.SubscriptionHost = SubHost;
    fake.CertificateNever = true;
    var sync = new XCoreSyncService(protector, new ScriptRegistry(), Options.Create(options))
    { RestartPollAttempts = 3, RestartPollInterval = TimeSpan.Zero, CertificateAttempts = 2, CertificatePollInterval = TimeSpan.Zero };
    var h = new SyncHarness(fake, server, sync, protector);
    await CatchAsync<XCoreSyncException>(() => h.Handler.HandleAsync(SyncEvent(server, protocol), default));
    await CatchAsync<XCoreSyncException>(() => h.Handler.HandleAsync(SyncEvent(server, protocol), default));
    Check("CaddyRetryMinutes=0: пауза выключена — каждая попытка перезапускает Caddy", fake.WebRestarts == 2);

    var (fake2, server2, protocol2) = await ProvisionRoleAsync(XCoreRoles.Entry, TId(171));
    protocol2.XCore!.SubscriptionHost = SubHost;
    fake2.CaddyValidateFails = true;
    var h2 = new SyncHarness(fake2, server2, NewSyncWith(SubUpstream), protector);
    await CatchAsync<XCoreSyncException>(() => h2.Handler.HandleAsync(SyncEvent(server2, protocol2), default));
    await CatchAsync<XCoreSyncException>(() => h2.Handler.HandleAsync(SyncEvent(server2, protocol2), default));
    Check("отказ validate паузу не заводит: Let's Encrypt не трогали, исправленный файл применится сразу",
        h2.CaddyFailures.Count == 0 && protocol2.XCore.CaddyFailedRevision is null && fake2.CaddyValidations == 2);
    Check("текст паузы: время в UTC в формате HH:mm",
        Regex.IsMatch(XCoreSyncService.CaddyPausedMessage(new DateTime(2026, 10, 29, 9, 5, 0, DateTimeKind.Utc)), @"повтор не раньше 09:05 UTC"));
}

// ── xray run -test в зафиксированном образе ──────────────────────────────────

// ── VLESS Encryption ─────────────────────────────────────────────────────────

Console.WriteLine("VLESS Encryption");

const string VlessDec = FakeNode.VlessEncDecryption;
const string VlessEnc = FakeNode.VlessEncEncryption;
const string VlessDec2 = "mlkem768x25519plus.native.600s.QeONN7DF1xZHgbkkIHPNTJ7r_cuw3tA_PRUUW7wAMLb";
const string VlessEnc2 = "mlkem768x25519plus.native.0rtt.1akUsCoDj_hAGuRfufUwJkE36zcq0rBC-ijLHYafqad";

// Разбор вывода xray vlessenc: образец живого запуска, обе секции.
var vless = XrayApiOutput.ParseVlessEnc(FakeNode.VlessEncOutput);
Check("vlessenc: берётся раздел X25519, не ML-KEM-768 (строки совпали с образцом)",
    vless.Decryption == VlessDec && vless.Encryption == VlessEnc, vless.Decryption);
var mlkemFirst = FakeNode.VlessEncOutput.Split("\nAuthentication: ML-KEM-768", 2);
var swapped = "Authentication: ML-KEM-768" + mlkemFirst[1] + "\nAuthentication: X25519" + mlkemFirst[0].Split("Authentication: X25519", 2)[1];
Check("vlessenc: порядок разделов не важен", XrayApiOutput.ParseVlessEnc(swapped) == vless);
Check("vlessenc: CRLF и пробелы вокруг строк не мешают",
    XrayApiOutput.ParseVlessEnc(FakeNode.VlessEncOutput.Replace("\n", " \r\n  ")) == vless);
Check("vlessenc: запятая после значения (JSON-подобный вывод) допустима",
    XrayApiOutput.ParseVlessEnc(FakeNode.VlessEncOutput.Replace(VlessDec + "\"", VlessDec + "\",")) == vless);

bool VlessRejected(string? output) => ThrowsWithoutText(() => XrayApiOutput.ParseVlessEnc(output), VlessDec[^20..]);
var x25519Section = $"Authentication: X25519, not Post-Quantum\n\"decryption\": \"{VlessDec}\"\n\"encryption\": \"{VlessEnc}\"\n";
Check("vlessenc: пустой и отсутствующий вывод отвергнуты", VlessRejected("") && VlessRejected(null) && VlessRejected("\n\n"));
Check("vlessenc: нет раздела X25519 (только ML-KEM) — отказ, а не выбор другого варианта",
    VlessRejected("Authentication: ML-KEM-768, Post-Quantum\n" + x25519Section.Split('\n', 2)[1]));
Check("vlessenc: два раздела X25519 — отказ (неясно, какой верный)", VlessRejected(x25519Section + x25519Section));
Check("vlessenc: нет строки encryption — отказ", VlessRejected(x25519Section.Replace($"\"encryption\": \"{VlessEnc}\"\n", "")));
Check("vlessenc: нет строки decryption — отказ", VlessRejected(x25519Section.Replace($"\"decryption\": \"{VlessDec}\"\n", "")));
Check("vlessenc: две строки decryption — отказ",
    VlessRejected(x25519Section + $"\"decryption\": \"{VlessDec2}\"\n"));
Check("vlessenc: строки с ключами вне раздела (до заголовка) не учитываются",
    VlessRejected($"\"decryption\": \"{VlessDec}\"\n\"encryption\": \"{VlessEnc}\"\n"));
Check("vlessenc: другой режим (xorpub) — отказ", VlessRejected(x25519Section.Replace(".native.", ".xorpub.")));
Check("vlessenc: ключ короче 43 символов — отказ", VlessRejected(x25519Section.Replace(VlessDec, VlessDec[..^1])));
Check("vlessenc: ключ длиннее 43 символов — отказ", VlessRejected(x25519Section.Replace(VlessEnc, VlessEnc + "A")));
Check("vlessenc: строки перепутаны местами — отказ",
    VlessRejected(x25519Section.Replace(VlessDec, "TMP").Replace(VlessEnc, VlessDec).Replace("TMP", VlessEnc)));
Check("vlessenc: символ вне base64url в ключе — отказ", VlessRejected(x25519Section.Replace("sPv_Ei", "sPv+Ei")));
Check("vlessenc: клиентская строка с сроком вместо 0rtt — отказ", VlessRejected(x25519Section.Replace(".0rtt.", ".600s.")));
Check("vlessenc: IsVlessDecryption/IsVlessEncryption различают вид строки",
    XrayApiOutput.IsVlessDecryption(VlessDec) && !XrayApiOutput.IsVlessDecryption(VlessEnc)
    && XrayApiOutput.IsVlessEncryption(VlessEnc) && !XrayApiOutput.IsVlessEncryption(VlessDec)
    && !XrayApiOutput.IsVlessEncryption(null) && !XrayApiOutput.IsVlessDecryption("none")
    && !XrayApiOutput.IsVlessEncryption(VlessEnc + "\n\"evil\""));

// Рендер выхода.
XCoreProtocolParams EncExit(bool on = true, string? client = VlessEnc)
{
    var n = NewNode();
    n.VlessEncryption = on;
    n.VlessEncryptionClient = client;
    return n;
}

var plainExitCfg = XCoreConfigRenderer.Render(NewNode(), PrivateKey, users);
var encExitCfg = XCoreConfigRenderer.Render(EncExit(), PrivateKey, users, VlessDec);
string DecryptionOf(string json) => JsonNode.Parse(json)!["inbounds"]![0]!["settings"]!["decryption"]!.GetValue<string>();
Check("выход без шифрования: decryption = none, строк mlkem в конфиге нет",
    DecryptionOf(plainExitCfg.Json) == "none" && !plainExitCfg.Json.Contains("mlkem768x25519plus"));
Check("выход с шифрованием: decryption = серверная строка", DecryptionOf(encExitCfg.Json) == VlessDec);
Check("выход с шифрованием: клиенты, порт, Reality и XHTTP те же, что без него",
    plainExitCfg.Json.Replace("\"decryption\":\"none\"", $"\"decryption\":\"{VlessDec}\"") == encExitCfg.Json);
Check("выход: смена флага меняет и полную ревизию, и ревизию структуры (узел перезапускается, а не получает diff)",
    plainExitCfg.Revision != encExitCfg.Revision
    && XCoreConfigRenderer.RenderStructureRevision(NewNode(), PrivateKey) != XCoreConfigRenderer.RenderStructureRevision(EncExit(), PrivateKey, VlessDec));
Check("выход: ревизия без флага не изменилась от появления поля (побайтово прежний конфиг)",
    XCoreConfigRenderer.Render(NewNode(), PrivateKey, users).Revision == plainExitCfg.Revision
    && !XCoreConfigRenderer.Render(NewNode(), PrivateKey, users).Json.Contains("encryption"));
Check("выход: флаг есть, серверной строки нет — отказ, а не молчаливый none",
    Throws<InvalidOperationException>(() => XCoreConfigRenderer.Render(EncExit(), PrivateKey, users))
    && Throws<InvalidOperationException>(() => XCoreConfigRenderer.Render(EncExit(), PrivateKey, users, "")));
Check("выход: серверная строка не в формате vlessenc не попадает в конфиг",
    Throws<InvalidOperationException>(() => XCoreConfigRenderer.Render(EncExit(), PrivateKey, users, "none\",\"x\":\"y"))
    && Throws<InvalidOperationException>(() => XCoreConfigRenderer.Render(EncExit(), PrivateKey, users, VlessEnc)));
Check("выход: флаг выключен — переданная строка игнорируется (флаг главнее)",
    XCoreConfigRenderer.Render(NewNode(), PrivateKey, users, VlessDec).Json == plainExitCfg.Json);
Check("файл для adu всегда с decryption=none и без секретной строки (UUID на узле на время одной команды, а ключ — нет)",
    XCoreConfigRenderer.RenderUsersFile(EncExit(), users).Contains("\"decryption\":\"none\"")
    && !XCoreConfigRenderer.RenderUsersFile(EncExit(), users).Contains("mlkem"));

// Рендер входа: свой inbound и outbound-ы к выходам.
XCoreExitTarget ExitEnc(int route) => ExitT(route) with { Encryption = VlessEnc };
var entryEncNode = NewEntryNode(n => { n.VlessEncryption = true; n.VlessEncryptionClient = VlessEnc2; });
var entryEncCfg = XCoreConfigRenderer.RenderEntry(entryEncNode, EntryPrivate, users, RelayUuid, [ExitEnc(1), ExitT(2)], VlessDec2);
var entryEncJson = JsonNode.Parse(entryEncCfg.Json)!.AsObject();
string OutboundEncryption(JsonObject cfg, int route) =>
    cfg["outbounds"]!.AsArray().Single(o => o!["tag"]!.GetValue<string>() == XCoreConfigRenderer.ExitTag(route))!
        ["settings"]!["vnext"]![0]!["users"]![0]!["encryption"]!.GetValue<string>();
Check("вход: decryption inbound-а — его собственная серверная строка",
    entryEncJson["inbounds"]![0]!["settings"]!["decryption"]!.GetValue<string>() == VlessDec2);
Check("вход: outbound к зашифрованному выходу несёт его клиентскую строку, к обычному — none",
    OutboundEncryption(entryEncJson, 1) == VlessEnc && OutboundEncryption(entryEncJson, 2) == "none");
Check("вход: серверной строки выхода в конфиге входа нет, а собственная — только в decryption",
    !entryEncCfg.Json.Contains(VlessDec) && entryEncCfg.Json.Split(VlessDec2).Length == 2);
var entryPlainCfg = XCoreConfigRenderer.RenderEntry(NewEntryNode(), EntryPrivate, users, RelayUuid, [ExitT(1), ExitT(2)]);
Check("вход без шифрования к обычным выходам: encryption=none везде, decryption=none",
    DecryptionOf(entryPlainCfg.Json) == "none" && OutboundEncryption(JsonNode.Parse(entryPlainCfg.Json)!.AsObject(), 1) == "none"
    && !entryPlainCfg.Json.Contains("mlkem768x25519plus"));
Check("вход: зашифровался выход — ревизия структуры входа меняется (вход перезапускается и перерисовывается)",
    XCoreConfigRenderer.RenderEntryStructureRevision(NewEntryNode(), EntryPrivate, RelayUuid, [ExitT(1), ExitT(2)])
        != XCoreConfigRenderer.RenderEntryStructureRevision(NewEntryNode(), EntryPrivate, RelayUuid, [ExitEnc(1), ExitT(2)])
    && XCoreConfigRenderer.RenderEntryStructureRevision(NewEntryNode(), EntryPrivate, RelayUuid, [ExitEnc(1), ExitT(2)])
        == XCoreConfigRenderer.RenderEntryStructureRevision(NewEntryNode(), EntryPrivate, RelayUuid, [ExitEnc(1), ExitT(2)]));
Check("вход: флаг без серверной строки — отказ; выход со строкой не того вида — отказ",
    Throws<InvalidOperationException>(() => XCoreConfigRenderer.RenderEntry(entryEncNode, EntryPrivate, users, RelayUuid, [ExitT(1)]))
    && Throws<InvalidOperationException>(() => XCoreConfigRenderer.RenderEntry(
        NewEntryNode(), EntryPrivate, users, RelayUuid, [ExitT(1) with { Encryption = VlessDec }]))
    && Throws<InvalidOperationException>(() => XCoreConfigRenderer.RenderEntry(
        NewEntryNode(), EntryPrivate, users, RelayUuid, [ExitT(1) with { Encryption = "none" }])));
Check("вход с будущими списками: шифрование сохраняется (проба обновления видит тот же inbound)",
    DecryptionOf(XCoreConfigRenderer.RenderEntryWithRfLists(entryEncNode, EntryPrivate, users, RelayUuid, [ExitT(1)], "202610290000", VlessDec2).Json) == VlessDec2);

// Топология: клиентская строка выхода доходит до входа только при включённом флаге.
{
    var tEnc = TopoNode(TId(40), XCoreRoles.Exit, 1, p => { p.XCore!.VlessEncryption = true; p.XCore.VlessEncryptionClient = VlessEnc; });
    var tPlain = TopoNode(TId(41), XCoreRoles.Exit, 2);
    var tLeftover = TopoNode(TId(42), XCoreRoles.Exit, 3, p => p.XCore!.VlessEncryptionClient = VlessEnc);
    var tNoClient = TopoNode(TId(43), XCoreRoles.Exit, 4, p => p.XCore!.VlessEncryption = true);
    var targets = XCoreTopology.ExitTargets([tEnc, tPlain, tLeftover, tNoClient]);
    Check("топология: у зашифрованного выхода в цели его клиентская строка, у обычного — null",
        targets.Single(t => t.RouteId == 1).Encryption == VlessEnc && targets.Single(t => t.RouteId == 2).Encryption is null);
    Check("топология: строка выключенного шифрования (остаток) во вход не попадает",
        targets.Single(t => t.RouteId == 3).Encryption is null);
    Check("топология: выход с включённым шифрованием без клиентской строки в маршрутизацию не попадает",
        targets.Select(t => t.RouteId).SequenceEqual([1, 2, 3]));
}

// Ссылки подписки.
{
    string Query(string link, string key) => Uri.UnescapeDataString(
        link.Split('#')[0].Split('?')[1].Split('&').Single(p => p.StartsWith(key + "=")).Split('=', 2)[1]);
    var encServer = new VpnServer { Id = TId(44), Name = "Enc" };
    var encNode = EncExit();
    var plainLink = SubscriptionRenderer.BuildLink(UuidAbc, encServer, NewNode())!;
    var encLink = SubscriptionRenderer.BuildLink(UuidAbc, encServer, encNode)!;
    Check("ссылка: обычный узел — encryption=none (прежний формат)", plainLink.Contains("?encryption=none&security=reality"));
    Check("ссылка: зашифрованный узел — encryption=<клиентская строка>, остальные параметры те же",
        encLink.Contains($"?encryption={VlessEnc}&security=reality") && Query(encLink, "encryption") == VlessEnc
        && encLink.Replace(VlessEnc, "none") == plainLink);
    Check("ссылка: параметр кодируется как любой другой (Uri.EscapeDataString) и разбирается обратно",
        encLink.Contains("encryption=" + Uri.EscapeDataString(VlessEnc) + "&") && Query(encLink, "encryption") == VlessEnc);
    Check("ссылка: флаг без клиентской строки или со строкой не того вида — ссылки нет",
        SubscriptionRenderer.BuildLink(UuidAbc, encServer, EncExit(client: null)) is null
        && SubscriptionRenderer.BuildLink(UuidAbc, encServer, EncExit(client: VlessDec)) is null
        && SubscriptionRenderer.BuildLink(UuidAbc, encServer, EncExit(client: VlessEnc + "&flow=x")) is null);
    var entryPlainParams = NewEntryNode();
    var entryLinkToEnc = SubscriptionRenderer.BuildEntryLink(UuidAbc, entryPlainParams, encServer, new XCoreProtocolParams
    {
        Role = XCoreRoles.Exit, Domain = "e.example.com", RouteId = 1, VlessEncryption = true, VlessEncryptionClient = VlessEnc2,
    })!;
    Check("ссылка через открытый вход на зашифрованный выход — encryption=none: шифрование клиент↔вход определяет вход",
        Query(entryLinkToEnc, "encryption") == "none" && !entryLinkToEnc.Contains("mlkem"));
    var entryLinkViaEnc = SubscriptionRenderer.BuildEntryLink(UuidAbc, entryEncNode, encServer, new XCoreProtocolParams
    {
        Role = XCoreRoles.Exit, Domain = "e.example.com", RouteId = 1,
    })!;
    Check("ссылка через зашифрованный вход на обычный выход — клиентская строка входа",
        Query(entryLinkViaEnc, "encryption") == VlessEnc2);
}

// Настройки панели.
{
    var offKeys = NewNode();
    var onKeys = EncExit();
    onKeys.VlessDecryption = protector.Protect(VlessDec);
    var onNoKeys = NewNode();
    onNoKeys.VlessEncryption = true;
    var offLeftover = NewNode();
    offLeftover.VlessDecryption = protector.Protect(VlessDec);
    offLeftover.VlessEncryptionClient = VlessEnc;
    Check("настройки: включить выключенное — сгенерировать (true)", XCoreSettingsRules.VlessEncryptionAction(offKeys, true) == true);
    Check("настройки: включить уже включённое с ключами — ничего (ключи не пересоздаются, ссылки не ломаются)",
        XCoreSettingsRules.VlessEncryptionAction(onKeys, true) is null);
    Check("настройки: флаг включён, а ключей нет — достроить (true)",
        XCoreSettingsRules.VlessEncryptionAction(onNoKeys, true) == true);
    Check("настройки: выключить включённое — false", XCoreSettingsRules.VlessEncryptionAction(onKeys, false) == false);
    Check("настройки: выключить выключенное без ключей — ничего", XCoreSettingsRules.VlessEncryptionAction(offKeys, false) is null);
    Check("настройки: выключено, но остались ключи — выключение стирает их (false)",
        XCoreSettingsRules.VlessEncryptionAction(offLeftover, false) == false);
    Check("настройки: поле не передано — ничего при любом состоянии",
        XCoreSettingsRules.VlessEncryptionAction(onKeys, null) is null && XCoreSettingsRules.VlessEncryptionAction(offKeys, null) is null);

    foreach (var role in new[] { XCoreRoles.Exit, XCoreRoles.Entry })
    {
        var protocol = new ProtocolInstance { Kind = ProtocolKinds.XCore, XCore = role == XCoreRoles.Exit ? NewNode() : NewEntryNode() };
        var update = XCoreSettingsRules.Validate(protocol, new XCoreSettingsRequest { VlessEncryption = true }, null);
        Check($"настройки ({role}): флаг принят обеими ролями, ключи Validate не создаёт (чистая функция без SSH)",
            update.VlessEncryption is null);
        Check($"настройки ({role}): ChangedFields называет vlessEncryption, только когда шифрование меняется",
            XCoreSettingsRules.ChangedFields(protocol.XCore!, update with { VlessEncryption = new XCoreVlessEncryptionChange(true, null, null) }).Contains("vlessEncryption")
            && !XCoreSettingsRules.ChangedFields(protocol.XCore!, update).Contains("vlessEncryption"));
    }
}

// DTO: наружу только факт включения.
{
    var dtoNode = TopoNode(TId(45), XCoreRoles.Exit, 1, p =>
    {
        p.XCore!.VlessEncryption = true;
        p.XCore.VlessDecryption = protector.Protect(VlessDec);
        p.XCore.VlessEncryptionClient = VlessEnc;
    });
    var dtoJson = JsonSerializer.Serialize(ServerDetailDto.From(dtoNode, new ServerKpiDto(null, 0, 0)))
        + JsonSerializer.Serialize(ServerListItemDto.From(dtoNode, 0, 0))
        + JsonSerializer.Serialize(XCoreInfoDto.From(dtoNode.Protocols[0].XCore!));
    Check("DTO: шифрование VLESS показано флагом, строк mlkem, ключей и шифротекста нет",
        dtoJson.Contains("\"VlessEncryption\":true") && !dtoJson.Contains("mlkem", StringComparison.OrdinalIgnoreCase)
        && !dtoJson.Contains(VlessDec[^20..]) && !dtoJson.Contains(VlessEnc[^20..])
        && !dtoJson.Contains(dtoNode.Protocols[0].XCore!.VlessDecryption!.CipherText, StringComparison.Ordinal)
        && !dtoJson.Contains("vlessDecryption", StringComparison.OrdinalIgnoreCase));
    var bsonNode = BsonSerializer.Deserialize<VpnServer>(dtoNode.ToBsonDocument()).Protocols[0].XCore!;
    Check("BSON: флаг, зашифрованная серверная строка и клиентская строка переживают круг, открытого текста серверной нет",
        bsonNode.VlessEncryption && protector.Unprotect(bsonNode.VlessDecryption) == VlessDec && bsonNode.VlessEncryptionClient == VlessEnc
        && !dtoNode.ToBsonDocument().ToJson().Contains(VlessDec, StringComparison.Ordinal));
    var oldDoc = dtoNode.ToBsonDocument();
    var oldXCore = oldDoc["protocols"].AsBsonArray[0].AsBsonDocument["xcore"].AsBsonDocument;
    oldXCore.Remove("vlessEncryption");
    oldXCore.Remove("vlessDecryption");
    oldXCore.Remove("vlessEncryptionClient");
    var oldRestored = BsonSerializer.Deserialize<VpnServer>(oldDoc).Protocols[0].XCore!;
    Check("BSON: документ узла до появления шифрования читается как «выключено», без ключей",
        !oldRestored.VlessEncryption && oldRestored.VlessDecryption is null && oldRestored.VlessEncryptionClient is null);
    var plainBson = TopoNode(TId(46), XCoreRoles.Exit, 1).ToBsonDocument()["protocols"].AsBsonArray[0].AsBsonDocument["xcore"].AsBsonDocument;
    Check("BSON: у узла без шифрования секретных полей в документе нет", !plainBson.Contains("vlessDecryption") && !plainBson.Contains("vlessEncryptionClient"));
}

// Фильтр секретов.
{
    string Lower43 = new('a', 43);
    Check("секреты: серверная строка в JSON вырезается целиком",
        Redact($"\"decryption\": \"{VlessDec}\"") == "\"decryption\": \"mlkem768x25519plus.***\"");
    Check("секреты: клиентская строка вырезается тоже", !Redact($"link encryption={VlessEnc}&security=reality").Contains(VlessEnc[^20..]));
    Check("секреты: ключ из строчных букв (общее правило 43 символов его не ловит) вырезается",
        Redact($"x mlkem768x25519plus.native.600s.{Lower43} y") == "x mlkem768x25519plus.*** y");
    Check("секреты: ML-KEM-768 (длинный ключ) и заполнение между режимом и ключом вырезаются",
        !Redact("mlkem768x25519plus.native.600s." + new string('Q', 86)).Contains("QQQQ")
        && !Redact("mlkem768x25519plus.random.100-111-1111.75-0-111." + KeyOf(7)).Contains(KeyOf(7)[..20]));
    Check("секреты: строка в команде docker и в тексте исключения вырезается",
        !Redact($"sudo docker run --rm img run -c x # decryption {VlessDec} end").Contains(VlessDec[^20..]));
    Check("секреты: соседний текст не страдает", Redact($"before {VlessDec} after") == "before mlkem768x25519plus.*** after");
}

// Генерация ключей через ISshSession.
{
    var fake = new FakeNode();
    var change = await XCoreVlessEncryption.GenerateAsync(fake.Session, XCoreNode.XrayImage, protector);
    Check("генерация: команда — одноразовый контейнер образа узла, одна команда на узле",
        fake.Commands.SequenceEqual([$"sudo docker run --rm {XCoreNode.XrayImage} vlessenc"]));
    Check("генерация: результат — включено, серверная строка зашифрована, клиентская открыта",
        change.Enabled && change.Client == VlessEnc && protector.Unprotect(change.Decryption) == VlessDec
        && change.Decryption!.CipherText != VlessDec);

    var badFake = new FakeNode();
    var genFail = await CatchAsync<BadRequestException>(() => XCoreVlessEncryption.GenerateAsync(badFake.Session, "image;reboot", protector));
    Check("генерация: небезопасная ссылка на образ отвергнута до команд на узле", genFail is not null && badFake.Commands.Count == 0);

    var garbage = Stub.Create<ISshSession>((m, a) => m.Name == nameof(ISshSession.RunCheckedAsync)
        ? Task.FromResult($"Authentication: X25519\n\"decryption\": \"{VlessDec[..^3]}\"\n\"encryption\": \"{VlessEnc}\"\n")
        : throw new NotSupportedException(m.Name));
    genFail = await CatchAsync<BadRequestException>(() => XCoreVlessEncryption.GenerateAsync(garbage, XCoreNode.XrayImage, protector));
    Check("генерация: нераспознанный вывод — отказ с понятным текстом, без вывода команды",
        genFail is not null && genFail.Message.Contains("ключи шифрования VLESS") && !genFail.Message.Contains(VlessEnc[^20..]), genFail?.Message);
}

// Синхронизация узла с шифрованием.
{
    var (fake, server, protocol) = await ProvisionAsync();
    var sync = NewSync();
    var x = protocol.XCore!;
    var before = x.AppliedStructureRevision;

    x.VlessEncryption = true;
    x.VlessDecryption = protector.Protect(VlessDec);
    x.VlessEncryptionClient = VlessEnc;
    var start = fake.Commands.Count;
    var result = await sync.SyncAsync(fake.Session, server, protocol, [], default);
    Check("sync: включённое шифрование — структура изменилась, узел перезапущен, а не получил diff",
        result.Action == XCoreSyncAction.Restart && result.StructureRevision != before && fake.Ran("sudo docker restart amnezia-xcore"));
    Check("sync: на хост записан конфиг с серверной строкой в decryption",
        DecryptionOf(fake.Files[XCoreNode.ConfigPath]) == VlessDec);
    Check("sync: конфиг перед заменой проверен Xray, строка шифрования попала в файл на хосте, а не в аргументы команд",
        At(fake, start, "run -test -c /etc/xcore/config.new.json") >= 0
        && !fake.Commands.Skip(start).Any(c => !c.StartsWith("WRITE") && c.Contains("mlkem768x25519plus")));
    Applied(protocol, result);

    start = fake.Commands.Count;
    result = await sync.SyncAsync(fake.Session, server, protocol, [], default);
    Check("sync: повтор с теми же настройками — NoOp (шифрование не вызывает лишних перезапусков)",
        result.Action == XCoreSyncAction.NoOp && !fake.Commands.Skip(start).Any(c => c.Contains("restart")));

    x.VlessEncryption = false;
    x.VlessDecryption = null;
    x.VlessEncryptionClient = null;
    result = await sync.SyncAsync(fake.Session, server, protocol, [], default);
    Check("sync: шифрование выключено — снова Restart, на хосте decryption = none и строки mlkem нет",
        result.Action == XCoreSyncAction.Restart && DecryptionOf(fake.Files[XCoreNode.ConfigPath]) == "none"
        && !fake.Files[XCoreNode.ConfigPath].Contains("mlkem"));
    Applied(protocol, result);

    x.VlessEncryption = true;
    var broken = await CatchAsync<XCoreSyncException>(() => sync.SyncAsync(fake.Session, server, protocol, [], default));
    Check("sync: флаг без ключей — XCoreSyncException с причиной, конфиг на хосте не тронут",
        broken is not null && broken.Message.Contains("нет серверной строки") && DecryptionOf(fake.Files[XCoreNode.ConfigPath]) == "none", broken?.Message);
}

Console.WriteLine("xray run -test в Docker");

if (!args.Contains("--docker"))
{
    Console.WriteLine("  [ПРОПУСК] без флага --docker; запуск: dotnet run --project tools/VerifyXCore -- --docker");
}
else
{
    var dir = Path.Combine(Path.GetTempPath(), "verify-xcore-" + Guid.NewGuid().ToString("N"));
    Directory.CreateDirectory(dir);
    try
    {
        // Ключи из фикстуры x25519; пользователи нужны, чтобы проверить и массив clients.
        var full = XCoreConfigRenderer.Render(node, PrivateKey, users);
        File.WriteAllText(Path.Combine(dir, "config.json"), full.Json);
        var (code, output) = RunDocker(dir);
        var result = XrayApiOutput.ParseConfigTest(output);
        Check("docker: рендер с пользователями принят xray (Configuration OK.)", result.Ok, result.Ok ? null : $"код {code}: {result.Error}");

        File.WriteAllText(Path.Combine(dir, "config.json"), XCoreConfigRenderer.Render(node, PrivateKey, []).Json);
        (code, output) = RunDocker(dir);
        result = XrayApiOutput.ParseConfigTest(output);
        Check("docker: рендер без пользователей принят xray", result.Ok, result.Ok ? null : $"код {code}: {result.Error}");

        // Контроль чувствительности: без него «Configuration OK.» мог бы быть просто строкой по умолчанию.
        File.WriteAllText(Path.Combine(dir, "config.json"), """{"inbounds":[{"tag":"x","protocol":"nope","port":1}]}""");
        (code, output) = RunDocker(dir);
        result = XrayApiOutput.ParseConfigTest(output);
        Check("docker: заведомо плохой конфиг не принят", !result.Ok, result.Error);

        // Вход: рендер целиком проходит `run -test`. Это единственная проверка, что Xray принимает vlessRoute
        // вместе с domain, geosite/geoip из встроенных файлов, https+local в dns и правило по network.
        (string Label, string Json)[] entryVariants =
        [
            ("вход с двумя выходами, списками доменов и РФ напрямую", entryRendered.Json),
            ("вход без РФ напрямую", noRu.Json),
            ("вход без списков доменов", plain.Json),
            ("вход с одним выходом на предельном номере", XCoreConfigRenderer.RenderEntry(entryNode, EntryPrivate, users, RelayUuid, [ExitT(65535)]).Json),
            ("вход без выходов (закрытый)", closed.Json),
            ("вход без выходов и пользователей", XCoreConfigRenderer.RenderEntry(entryNode, EntryPrivate, [], RelayUuid, []).Json),
        ];
        foreach (var (label, entryJson) in entryVariants)
        {
            File.WriteAllText(Path.Combine(dir, "config.json"), entryJson);
            (code, output) = RunDocker(dir);
            result = XrayApiOutput.ParseConfigTest(output);
            Check($"docker: {label} принят xray", result.Ok, result.Ok ? null : $"код {code}: {result.Error}");
        }

        // Контроль чувствительности правила «всё остальное»: правило вовсе без условий Xray отвергает,
        // а network «tcp,udp» принимает — на этом держится последнее правило входа.
        const string RuleProbe = """{"inbounds":[{"port":1080,"protocol":"socks"}],"outbounds":[{"protocol":"freedom","tag":"direct"}],"routing":{"rules":[{RULE,"outboundTag":"direct"}]}}""";
        File.WriteAllText(Path.Combine(dir, "config.json"), RuleProbe.Replace("{RULE,", "{"));
        (code, output) = RunDocker(dir);
        result = XrayApiOutput.ParseConfigTest(output);
        Check("docker: правило без условий Xray отвергает (поэтому «всё остальное» — по network)",
            !result.Ok && result.Error!.Contains("no effective fields"), result.Error);
        File.WriteAllText(Path.Combine(dir, "config.json"), RuleProbe.Replace("{RULE,", """{"type":"field","network":"tcp,udp","""));
        (code, output) = RunDocker(dir);
        Check("docker: правило network «tcp,udp» принято", XrayApiOutput.ParseConfigTest(output).Ok);
        File.WriteAllText(Path.Combine(dir, "config.json"), entryRendered.Json.Replace("geosite:category-ru", "geosite:no-such-list-xyz"));
        (code, output) = RunDocker(dir);
        Check("docker: несуществующий geosite-список Xray отвергает (контроль чувствительности)", !XrayApiOutput.ParseConfigTest(output).Ok);

        // Caddyfile: та же команда проверки, что уходит на узел (подставлен только путь к файлу).
        var caddyDir = Path.Combine(dir, "caddy");
        Directory.CreateDirectory(caddyDir);
        var caddyFile = Path.Combine(caddyDir, "Caddyfile.new");
        string CaddyValidate(string text, string? extraRunArgs = null)
        {
            File.WriteAllText(caddyFile, text);
            var command = XCoreNode.ValidateCaddyfileCommand.Replace(XCoreNode.NewCaddyfilePath, caddyFile).Replace("sudo docker", "docker");
            if (extraRunArgs is not null) command = command.Replace(" --rm ", $" --rm {extraRunArgs} ");
            var run = RunLocal(command);
            return run.Code == 0 && (run.Out + run.Err).Contains("Valid configuration") ? "ok" : $"код {run.Code}: {SecretRedactor.Tail(run.Out + run.Err, 300)}";
        }

        Check("docker: Caddyfile без домена подписки принят caddy validate (команда установщика и синхронизации)",
            CaddyValidate(caddyPlain.Text) == "ok", CaddyValidate(caddyPlain.Text));
        Check("docker: Caddyfile с доменом подписки принят caddy validate",
            CaddyValidate(caddyWithSub.Text) == "ok", CaddyValidate(caddyWithSub.Text));
        Check("docker: проверка не требует сети (--network none): на узле без исходящего DNS она не ломается",
            CaddyValidate(caddyWithSub.Text, "--network none") == "ok", CaddyValidate(caddyWithSub.Text, "--network none"));
        Check("docker: заведомо плохие Caddyfile не приняты (контроль чувствительности: опечатка в директиве, опечатка в параметре tls)",
            CaddyValidate(caddyWithSub.Text.Replace("\thandle /sub/*", "\thandel /sub/*")) != "ok"
            && CaddyValidate(caddyWithSub.Text.Replace("disable_tlsalpn_challenge", "disable_tlsalpn_challenje")) != "ok");

        // Российские списки: настоящий релиз runetfreedom и закреплённый образ. Скачивание — только здесь, под --docker.
        (string Label, string Json)[] rfConfigs =
        [
            ("вход с двумя выходами, списками оператора и «РФ напрямую»", rfRendered.Json),
            ("вход без списков доменов оператора",
                XCoreConfigRenderer.RenderEntry(NewEntryNode(n => { n.RfListsTag = RfTag; n.ProxyDomains = []; n.DirectDomains = []; }), EntryPrivate, users, RelayUuid, twoExits).Json),
            ("вход с одним выходом на предельном номере",
                XCoreConfigRenderer.RenderEntry(rfNode, EntryPrivate, users, RelayUuid, [ExitT(65535)]).Json),
        ];
        foreach (var (name, ok, detail) in await RunRfListsDockerAsync(dir, rfConfigs, entryRendered.Json, XCoreRfLists.ProbeConfig(), GeoRepo, node.ApiPort))
            Check(name, ok, detail);

        // Сквозной тест: три узла, клиент и цель в изолированной сети Docker.
        foreach (var (name, ok, detail) in RunEndToEnd(dir, PrivateKey, PublicKey, UuidAbc, "sub-" + SubIdAbc, RelayUuid))
            Check(name, ok, detail);

        // VLESS Encryption: те же приёмы, но с шифрованием на выходе и входах.
        foreach (var (name, ok, detail) in await VlessEncryptionE2E.RunAsync(
                     dir, XrayImage, PrivateKey, PublicKey, UuidAbc, "sub-" + SubIdAbc, RelayUuid))
            Check(name, ok, detail);

        // Дальше исполняются те же строки команд, что уходят на боевой узел (с подменой путей и
        // имени контейнера). Так проверяется синтаксис xray api, а не только наш разбор вывода.
        var liveDir = Path.Combine(dir, "live");
        var confDir = Path.Combine(liveDir, "conf");
        var opsDir = Path.Combine(liveDir, "ops");
        Directory.CreateDirectory(confDir);
        Directory.CreateDirectory(opsDir);
        var cname = "verify-xcore-" + Guid.NewGuid().ToString("N")[..12];
        var oneUser = XCoreConfigRenderer.Render(node, PrivateKey, [new("sub-abc", UuidAbc)]).Json;
        File.WriteAllText(Path.Combine(confDir, "config.json"), oneUser);
        File.WriteAllText(Path.Combine(confDir, XCoreNode.NewConfigFile), oneUser);
        File.WriteAllText(Path.Combine(confDir, "config.json.new"), oneUser);

        string Local(string command) => command
            .Replace(XCoreNode.ConfDir, confDir).Replace(XCoreNode.OpsDir, opsDir)
            .Replace("sudo docker exec amnezia-xcore ", $"docker exec {cname} ")
            .Replace("sudo docker", "docker");

        var viaSync = RunLocal(Local(XCoreNode.TestConfigCommand(XCoreNode.XrayImage, XCoreNode.NewConfigFile)));
        var viaSyncVerdict = XrayApiOutput.ParseConfigTest(viaSync.Out + "\n" + viaSync.Err);
        Check("docker: команда проверки из синхронизации принимает config.new.json", viaSyncVerdict.Ok, viaSyncVerdict.Error);
        var viaSuffix = RunLocal(Local(XCoreNode.TestConfigCommand(XCoreNode.XrayImage, "config.json.new")));
        Check("docker: «config.json.new» Xray не читает — поэтому файл называется config.new.json",
            !XrayApiOutput.ParseConfigTest(viaSuffix.Out + "\n" + viaSuffix.Err).Ok);

        try
        {
            var launch = $"sudo docker run -d --name {XCoreNode.XrayContainer} --user 0:0 {XCoreNode.MountArgs(XCoreNode.XrayContainer)} " +
                         $"{XCoreNode.XrayImage} run -c {XCoreNode.ContainerConfDir}/config.json";
            var started = RunLocal(Local(launch).Replace($"--name {XCoreNode.XrayContainer} ", $"--name {cname} "));
            Check("docker: контейнер с монтированиями установщика запущен", started.Code == 0, started.Err);

            (int Code, string Out, string Err) count = (1, "", "");
            for (var i = 0; i < 20 && count.Code != 0; i++)
            {
                count = RunLocal(Local(XCoreNode.InboundUserCountCommand(node.ApiPort)));
                if (count.Code != 0) Thread.Sleep(500);
            }
            Check("docker: inboundusercount по команде установщика отвечает", count.Code == 0 && XrayApiOutput.ParseInboundUserCount(count.Out) == 1, count.Err);

            var liveUsers = XrayApiOutput.ParseInboundUsers(RunLocal(Local(XCoreNode.InboundUsersCommand(node.ApiPort))).Out);
            Check("docker: inbounduser по команде синхронизации возвращает пользователя из конфига",
                liveUsers.Count == 1 && liveUsers[0] == new XCoreUser("sub-abc", UuidAbc));

            File.WriteAllText(Path.Combine(opsDir, "adu-test.json"), XCoreConfigRenderer.RenderUsersFile(node, [new("sub-def", UuidDef)]));
            var aduCommand = Local(XCoreNode.ApiCommand(node.ApiPort, "adu", $"{XCoreNode.ContainerOpsDir}/adu-test.json"));
            var added = XrayApiOutput.ParseAddUsers(RunLocal(aduCommand).Out);
            Check("docker: adu с файлом из ops (смонтирован только для чтения) добавляет пользователя", added.Added == 1 && added.IsSuccess);
            added = XrayApiOutput.ParseAddUsers(RunLocal(aduCommand).Out);
            Check("docker: повторный adu — «already exists», не ошибка", added.Added == 0 && added.AlreadyExisted.SequenceEqual(["sub-def"]) && added.IsSuccess);
            Check("docker: после adu inboundusercount = 2",
                XrayApiOutput.ParseInboundUserCount(RunLocal(Local(XCoreNode.InboundUserCountCommand(node.ApiPort))).Out) == 2);

            var rmuCommand = Local(XCoreNode.ApiCommand(node.ApiPort, "rmu",
                $"-tag={XCoreConfigRenderer.InboundTag} {XCoreNode.Quote("sub-def")}"));
            var removedUsers = XrayApiOutput.ParseRemoveUsers(RunLocal(rmuCommand).Out);
            Check("docker: rmu с квотированным email удаляет пользователя", removedUsers.Removed == 1 && removedUsers.IsSuccess);
            removedUsers = XrayApiOutput.ParseRemoveUsers(RunLocal(rmuCommand).Out);
            Check("docker: повторный rmu — «not found», не ошибка", removedUsers.Removed == 0 && removedUsers.NotFound.SequenceEqual(["sub-def"]) && removedUsers.IsSuccess);

            var statsQuery = RunLocal(Local(XCoreNode.UserStatsCommand(node.ApiPort)));
            Check("docker: statsquery по команде поллера (шаблон в кавычках, без -reset) отвечает разбираемым JSON",
                statsQuery.Code == 0 && XrayApiOutput.ParseUserTraffic(statsQuery.Out).Count == 0, statsQuery.Err);

            var deadApi = RunLocal(Local(XCoreNode.InboundUserCountCommand(1)));
            Check("docker: недоступный API даёт ненулевой код (синхронизация на него полагается)", deadApi.Code != 0);

            var version = RunLocal(Local(XCoreNode.VersionCommand));
            Check("docker: xray version — первая строка с версией образа",
                version.Out.Split('\n')[0].StartsWith("Xray 26.10.21"), version.Out.Split('\n')[0]);
        }
        finally
        {
            RunLocal($"docker rm -f {cname}");
        }
    }
    finally
    {
        try { Directory.Delete(dir, recursive: true); } catch (IOException) { }
    }
}

Console.WriteLine();
Console.WriteLine($"Проверок: {checks}, провалено: {failures.Count}");
if (failures.Count > 0)
{
    Console.WriteLine("Провалились:");
    foreach (var f in failures) Console.WriteLine($"  - {f}");
    return 1;
}

Console.WriteLine("xcore соответствует ожиданиям.");
return 0;

static (int Code, string Output) RunDocker(string dir)
{
    var psi = new ProcessStartInfo("docker")
    {
        RedirectStandardOutput = true,
        RedirectStandardError = true,
        UseShellExecute = false,
    };
    // Путь отдаётся как есть: Docker Desktop понимает и C:\..., и /c/....
    foreach (var a in new[] { "run", "--rm", "-v", $"{dir}:/c:ro", XrayImage, "run", "-test", "-c", "/c/config.json" })
        psi.ArgumentList.Add(a);

    using var process = Process.Start(psi)!;
    var stdout = process.StandardOutput.ReadToEndAsync();
    var stderr = process.StandardError.ReadToEndAsync();
    process.WaitForExit();
    return (process.ExitCode, stdout.Result + "\n" + stderr.Result);
}

/// <summary>Запускает «docker …» из готовой строки команды; одинарные кавычки раскрываются как в shell.</summary>
static (int Code, string Out, string Err) RunLocal(string commandLine)
{
    var tokens = new List<string>();
    var current = new StringBuilder();
    var inToken = false;
    var quoted = false;
    for (var i = 0; i < commandLine.Length; i++)
    {
        var c = commandLine[i];
        if (quoted)
        {
            if (c == '\'') quoted = false; else current.Append(c);
        }
        else if (c == '\'') { quoted = true; inToken = true; }
        // Обратная косая значима только перед кавычкой (форма '\'' из Quote): пути Windows содержат «\».
        else if (c == '\\' && i + 1 < commandLine.Length && commandLine[i + 1] == '\'') { current.Append('\''); i++; inToken = true; }
        else if (c == ' ')
        {
            if (inToken) tokens.Add(current.ToString());
            current.Clear();
            inToken = false;
        }
        else { current.Append(c); inToken = true; }
    }
    if (inToken) tokens.Add(current.ToString());

    var psi = new ProcessStartInfo(tokens[0])
    {
        RedirectStandardOutput = true,
        RedirectStandardError = true,
        UseShellExecute = false,
    };
    foreach (var token in tokens.Skip(1)) psi.ArgumentList.Add(token);

    using var process = Process.Start(psi)!;
    var stdout = process.StandardOutput.ReadToEndAsync();
    var stderr = process.StandardError.ReadToEndAsync();
    process.WaitForExit();
    return (process.ExitCode, stdout.Result, stderr.Result);
}


/// <summary>
/// Российские списки на настоящем Xray: скачивается последний релиз runetfreedom (сверяется с *.sha256sum),
/// затем в закреплённом образе проверяются раскладка и команды, которыми пользуются установщик и обновление.
/// Подтверждается то, что нельзя вывести из документации: встроенные списки образа продолжают работать при
/// XRAY_LOCATION_ASSET (каталог содержит только rf-файлы), ext:-теги проходят run -test, отсутствующий или
/// повреждённый файл отвергается, а контейнер входа с этими монтированиями стартует и переживает рестарт после
/// замены файла в каталоге. Без сети шаг пропускается.
/// </summary>
static async Task<List<(string Name, bool Ok, string? Detail)>> RunRfListsDockerAsync(
    string workDir, (string Label, string Json)[] configs, string plainConfig, string probeConfig, string repo, int apiPort)
{
    var results = new List<(string Name, bool Ok, string? Detail)>();
    void Add(string name, bool ok, string? detail = null) => results.Add((name, ok, detail));

    var root = Path.Combine(workDir, "rf");
    var geo = Path.Combine(root, "geo");
    var conf = Path.Combine(root, "conf");
    var ops = Path.Combine(root, "ops");
    Directory.CreateDirectory(geo);
    Directory.CreateDirectory(conf);
    Directory.CreateDirectory(ops);

    using var http = new HttpClient { Timeout = TimeSpan.FromMinutes(10) };
    string tag;
    try
    {
        tag = await LatestTagAsync(repo);
        foreach (var (remote, local) in XCoreRfLists.Files)
        {
            var sums = await http.GetStringAsync(XCoreRfLists.DownloadUrl(repo, tag, remote + ".sha256sum"));
            var expected = XCoreRfLists.ParseSha256Sum(sums, remote);
            await using (var target = File.Create(Path.Combine(geo, local)))
            await using (var source = await http.GetStreamAsync(XCoreRfLists.DownloadUrl(repo, tag, remote)))
                await source.CopyToAsync(target);
            await using var check = File.OpenRead(Path.Combine(geo, local));
            var actual = Convert.ToHexStringLower(await SHA256.HashDataAsync(check));
            Add($"docker: {remote} релиза {tag} скачан, сумма совпала с опубликованной в *.sha256sum ({new FileInfo(Path.Combine(geo, local)).Length / 1024 / 1024} МБ)",
                expected is not null && actual == expected, $"ожидалась {expected}, получена {actual}");
        }
    }
    catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or XCoreGeoException)
    {
        Console.WriteLine($"  [ПРОПУСК] российские списки в Docker: нет доступа к GitHub ({ex.GetType().Name}: {ex.Message})");
        return results;
    }

    // Те же команды, что уходят на узел, с подменой путей хоста на каталоги временной раскладки.
    string? lastVerdict = null;
    string Local(string command, string? geoOverride = null) => command
        .Replace(XCoreNode.GeoStageDir, geoOverride ?? geo).Replace(XCoreNode.GeoDir, geoOverride ?? geo)
        .Replace(XCoreNode.ConfDir, conf).Replace(XCoreNode.OpsDir, ops)
        .Replace("sudo docker", "docker");
    bool TestOk(string json, string? geoCommandDir, string? geoReplacement = null)
    {
        File.WriteAllText(Path.Combine(conf, "t.json"), json);
        var run = RunLocal(Local(XCoreNode.TestConfigCommand(XCoreNode.XrayImage, "t.json", geoCommandDir), geoReplacement));
        var verdict = XrayApiOutput.ParseConfigTest(run.Out + "\n" + run.Err);
        lastVerdict = verdict.Ok ? "Configuration OK." : verdict.Error;
        return verdict.Ok;
    }

    foreach (var (label, json) in configs)
        Add($"docker: {label}: run -test с ext-списками релиза {tag} и рабочим каталогом по команде синхронизации — принят",
            TestOk(json, XCoreNode.GeoDir), lastVerdict);
    Add("docker: пробный конфиг (все теги рендерера) принят с каталогом кандидатов по команде обновления",
        TestOk(probeConfig, XCoreNode.GeoStageDir), lastVerdict);

    // Контроль чувствительности: без подключения каталога, с пустым каталогом, с обрезанным файлом, с релизом без тегов.
    Add("docker: тот же конфиг без подключения каталога списков Xray отвергает (поэтому синхронизация подключает каталог, когда тег есть)",
        !TestOk(configs[0].Json, null), lastVerdict);
    var empty = Path.Combine(root, "empty");
    Directory.CreateDirectory(empty);
    Add("docker: пустой каталог списков (вход до первой загрузки) — ссылки на ext: отвергаются, поэтому рендерер обязан молчать без тега",
        !TestOk(configs[0].Json, XCoreNode.GeoDir, empty), lastVerdict);
    Add("docker: пустой каталог списков и конфиг без ext: принят — встроенные geosite:/geoip: берутся из образа (XRAY_LOCATION_ASSET не затеняет их)",
        TestOk(plainConfig, XCoreNode.GeoDir, empty), lastVerdict);

    var truncated = Path.Combine(root, "truncated");
    Directory.CreateDirectory(truncated);
    await using (var src = File.OpenRead(Path.Combine(geo, "rf-geosite.dat")))
    await using (var dst = File.Create(Path.Combine(truncated, "rf-geosite.dat")))
    {
        var head = new byte[4096];
        var n = await src.ReadAsync(head);
        await dst.WriteAsync(head.AsMemory(0, n));
    }
    File.Copy(Path.Combine(geo, "rf-geoip.dat"), Path.Combine(truncated, "rf-geoip.dat"), overwrite: true);
    Add("docker: обрезанный rf-geosite.dat проба отвергает (повреждённый файл не попадёт в рабочий каталог)",
        !TestOk(probeConfig, XCoreNode.GeoStageDir, truncated), lastVerdict);

    // Релиз без нужных тегов: встроенный geosite.dat образа под именем rf-geosite.dat.
    var builtin = Path.Combine(root, "builtin");
    Directory.CreateDirectory(builtin);
    var created = RunLocal($"docker create {XCoreNode.XrayImage}");
    var containerId = created.Out.Trim();
    try
    {
        var copied = RunLocal($"docker cp {containerId}:/usr/local/share/xray/geosite.dat {Path.Combine(builtin, "rf-geosite.dat")}");
        File.Copy(Path.Combine(geo, "rf-geoip.dat"), Path.Combine(builtin, "rf-geoip.dat"), overwrite: true);
        Add("docker: встроенный geosite.dat образа извлечён (контрольный образец релиза без ru-blocked)",
            copied.Code == 0 && File.Exists(Path.Combine(builtin, "rf-geosite.dat")), copied.Err);
    }
    finally
    {
        RunLocal($"docker rm -f {containerId}");
    }
    var lacking = TestOk(probeConfig, XCoreNode.GeoStageDir, builtin);
    Add("docker: релиз без тегов ru-blocked/ru-available-only-inside проба отвергает, причина — отсутствующий тег",
        !lacking && lastVerdict!.Contains("RU-", StringComparison.OrdinalIgnoreCase), lastVerdict);

    // Живой контейнер входа с монтированиями установщика.
    var name = "verify-xcore-geo-" + Guid.NewGuid().ToString("N")[..10];
    File.WriteAllText(Path.Combine(conf, "config.json"), configs[0].Json);
    try
    {
        var launch = Local($"sudo docker run -d --name {name} --user 0:0 {XCoreNode.MountArgs(XCoreNode.XrayContainer, XCoreRoles.Entry)} " +
                           $"{XCoreNode.XrayImage} run -c {XCoreNode.ContainerConfDir}/config.json");
        var started = RunLocal(launch);
        Add("docker: контейнер входа с монтированием каталога списков и XRAY_LOCATION_ASSET запущен", started.Code == 0, started.Err);

        bool ApiAnswers()
        {
            var command = Local(XCoreNode.InboundUserCountCommand(apiPort)).Replace("docker exec amnezia-xcore ", $"docker exec {name} ");
            for (var i = 0; i < 20; i++)
            {
                var r = RunLocal(command);
                if (r.Code == 0) return true;
                Thread.Sleep(500);
            }
            return false;
        }

        Add("docker: Xray с ext-списками поднял API (конфиг прочитан вместе с rf-файлами)", ApiAnswers());

        // Замена файла в каталоге переименованием (как делает обновление) и рестарт контейнера.
        var replacement = Path.Combine(geo, "rf-geosite.dat.new");
        File.Copy(Path.Combine(geo, "rf-geosite.dat"), replacement, overwrite: true);
        File.Move(replacement, Path.Combine(geo, "rf-geosite.dat"), overwrite: true);
        var restart = RunLocal($"docker restart {name}");
        Add("docker: после замены rf-geosite.dat в каталоге и docker restart контейнер снова отвечает на API",
            restart.Code == 0 && ApiAnswers(), restart.Err);
        var state = RunLocal($"docker inspect -f {{{{.State.Running}}}} {name}");
        Add("docker: контейнер входа работает после рестарта", state.Out.Trim() == "true", state.Out + state.Err);

        var logs = RunLocal($"docker logs {name}");
        Add("docker: в журнале контейнера нет ошибок загрузки списков",
            !(logs.Out + logs.Err).Contains("failed to", StringComparison.OrdinalIgnoreCase), SecretRedactor.Tail(logs.Out + logs.Err, 200));
        var stats = RunLocal($"docker stats --no-stream --format {{{{.MemUsage}}}} {name}");
        Add($"docker: память Xray с ext-списками (справочно): {stats.Out.Trim()}", stats.Code == 0, stats.Err);
    }
    finally
    {
        RunLocal($"docker rm -f {name}");
    }

    return results;
}

/// <summary>
/// Тег последнего релиза для проверки в Docker: API GitHub, а если анонимный лимит (60 запросов в час на адрес)
/// исчерпан — переадресация страницы /releases/latest. Рабочий код опрашивает API раз в сутки и до лимита не доходит.
/// </summary>
static async Task<string> LatestTagAsync(string repo)
{
    try
    {
        return await new GitHubReleaseSource(new HttpClient { Timeout = TimeSpan.FromSeconds(20) }).GetLatestTagAsync(repo);
    }
    catch (XCoreGeoException)
    {
        using var noRedirect = new HttpClient(new HttpClientHandler { AllowAutoRedirect = false }) { Timeout = TimeSpan.FromSeconds(20) };
        using var response = await noRedirect.GetAsync($"https://github.com/{repo}/releases/latest");
        var tag = response.Headers.Location?.Segments.LastOrDefault()?.Trim('/');
        return XCoreRfLists.IsSafeTag(tag) ? tag! : throw new XCoreGeoException("Не удалось определить последний релиз.");
    }
}

static bool ThrowsWithoutText(Action action, string forbidden)
{
    try { action(); return false; }
    catch (XrayOutputException ex) { return !ex.Message.Contains(forbidden, StringComparison.Ordinal); }
}

/// <summary>
/// Сквозная проверка маршрутизации входа на настоящем Xray: выходы exit1 и exit2, вход, закрытый вход без
/// выходов, клиент и цель — всё в изолированной сети Docker. Конфиги узлов — вывод боевых рендереров;
/// подменено только окружение: у каждого узла рядом работает «заглушка сайта» (TLS 1.3 + h2 на
/// 127.0.0.1:8443 в том же сетевом пространстве), потому что Reality берёт рукопожатие у target, а Caddy
/// с настоящим сертификатом здесь не нужен — клиент Reality сертификат цели не проверяет.
/// Что прошло через выход, видно по счётчикам служебного пользователя relay-* на нём: Xray считает трафик
/// пользователя того inbound-а, в который он вошёл. Сеть с адресами из 21.0.0.0/8 (в интернете не
/// маршрутизируется, но и не зарезервирована): адреса Docker по умолчанию (172.16/12, 192.168/16) выход закрывает
/// своим правилом приватных адресов, а freedom в Xray 26 сам не пускает на зарезервированные диапазоны, включая
/// 198.18/15, — в логе «blocked target … blackholing connection», цель оказывалась недоступной.
/// </summary>
static List<(string Name, bool Ok, string? Detail)> RunEndToEnd(
    string dir, string privateKey, string publicKey, string subUuid, string subEmail, string relayUuid)
{
    const string CurlImage = "curlimages/curl:8.11.1";
    var results = new List<(string, bool, string?)>();
    void Report(string name, bool ok, string? detail = null) => results.Add((name, ok, ok ? null : detail));
    static string Tail((int Code, string Out, string Err) r, int lines = 4) =>
        string.Join(" ", (r.Out + r.Err).Split('\n').TakeLast(4)).Trim();

    var id = Guid.NewGuid().ToString("N")[..8];
    var net = "vx-e2e-" + id;
    var containers = new List<string>();
    string Name(string role) { var n = $"vx-e2e-{id}-{role}"; containers.Add(n); return n; }

    var configDir = Path.Combine(dir, "e2e");
    Directory.CreateDirectory(configDir);
    var mount = $"{configDir}:/c:ro";

    try
    {
        var subnet = "";
        for (var i = 0; i < 20 && subnet.Length == 0; i++)
        {
            var candidate = $"21.{(Convert.ToInt32(id[..2], 16) + i * 7) % 256}.0.0/24";
            if (DockerCmd("network", "create", "--subnet", candidate, net).Code == 0) subnet = candidate;
        }
        if (subnet.Length == 0) { Report("e2e: создана сеть Docker с публичными адресами", false, "не удалось подобрать свободную подсеть"); return results; }

        // Заглушка сайта для Reality.
        var cert = JsonNode.Parse(DockerCmd("run", "--rm", XrayImage, "tls", "cert", "-domain=e2e.test", "-expire=2h").Out)!.AsObject();
        var dest = new JsonObject
        {
            ["log"] = new JsonObject { ["loglevel"] = "warning" },
            ["inbounds"] = new JsonArray(new JsonObject
            {
                ["listen"] = "127.0.0.1", ["port"] = 8443, ["protocol"] = "socks",
                ["settings"] = new JsonObject { ["auth"] = "noauth" },
                ["streamSettings"] = new JsonObject
                {
                    ["network"] = "tcp", ["security"] = "tls",
                    ["tlsSettings"] = new JsonObject
                    {
                        ["alpn"] = new JsonArray("h2", "http/1.1"),
                        ["certificates"] = new JsonArray(new JsonObject
                        {
                            ["certificate"] = cert["certificate"]!.DeepClone(), ["key"] = cert["key"]!.DeepClone(),
                        }),
                    },
                },
            }),
            ["outbounds"] = new JsonArray(new JsonObject { ["protocol"] = "blackhole" }),
        };
        File.WriteAllText(Path.Combine(configDir, "dest.json"), dest.ToJsonString());

        // Цель: отвечает HTTP 403 на любой запрос, поэтому видно, дошёл ли запрос.
        var target = new JsonObject
        {
            ["log"] = new JsonObject { ["loglevel"] = "warning" },
            ["inbounds"] = new JsonArray(new JsonObject
            {
                ["listen"] = "0.0.0.0", ["port"] = 8080, ["protocol"] = "dokodemo-door",
                ["settings"] = new JsonObject { ["address"] = "127.0.0.1", ["port"] = 9, ["network"] = "tcp" },
            }),
            ["outbounds"] = new JsonArray(new JsonObject
            {
                ["protocol"] = "blackhole",
                ["settings"] = new JsonObject { ["response"] = new JsonObject { ["type"] = "http" } },
            }),
        };
        File.WriteAllText(Path.Combine(configDir, "target.json"), target.ToJsonString());

        XCoreProtocolParams NodeOf(string role, string domain, string shortId, string path) => new()
        {
            Role = role, Domain = domain, ImageRef = XrayImage, RealityPublicKey = publicKey, ShortIds = [shortId], XhttpPath = path,
        };

        var exit1Node = NodeOf(XCoreRoles.Exit, "exit1.test", "1111111111111111", "/exit1path");
        var exit2Node = NodeOf(XCoreRoles.Exit, "exit2.test", "2222222222222222", "/exit2path");
        XCoreUser[] relay = [new("relay-e2e", relayUuid)];
        File.WriteAllText(Path.Combine(configDir, "exit1.json"), XCoreConfigRenderer.Render(exit1Node, privateKey, relay).Json);
        File.WriteAllText(Path.Combine(configDir, "exit2.json"), XCoreConfigRenderer.Render(exit2Node, privateKey, relay).Json);

        XCoreExitTarget[] targets =
        [
            new(1, "exit1.test", 443, publicKey, "1111111111111111", "/exit1path", "firefox"),
            new(2, "exit2.test", 443, publicKey, "2222222222222222", "/exit2path", "firefox"),
        ];
        // proxy.test есть и в «напрямую», и в «через VPN»: «через VPN» обязано победить.
        XCoreProtocolParams EntryOf(string domain, string shortId, string path)
        {
            var n = NodeOf(XCoreRoles.Entry, domain, shortId, path);
            n.DirectDomains = ["direct.test", "proxy.test"];
            n.ProxyDomains = ["proxy.test"];
            return n;
        }
        XCoreUser[] subscriber = [new(subEmail, subUuid)];
        File.WriteAllText(Path.Combine(configDir, "entry.json"),
            XCoreConfigRenderer.RenderEntry(EntryOf("entry.test", "e0e0e0e0e0e0e0e0", "/entrypath"), privateKey, subscriber, relayUuid, targets).Json);
        File.WriteAllText(Path.Combine(configDir, "entry0.json"),
            XCoreConfigRenderer.RenderEntry(EntryOf("entry0.test", "f0f0f0f0f0f0f0f0", "/entry0path"), privateKey, subscriber, relayUuid, []).Json);

        // Клиент: по одному socks-входу на вариант UUID.
        const string ForeignUuid = "deadbeef-dead-4ead-8ead-deadbeefdead";
        (string Tag, int Port, string Host, string ShortId, string Path, string Uuid)[] variants =
        [
            ("r1", 1081, "entry.test", "e0e0e0e0e0e0e0e0", "/entrypath", XCoreRoute.WithRoute(subUuid, 1)),
            ("r2", 1082, "entry.test", "e0e0e0e0e0e0e0e0", "/entrypath", XCoreRoute.WithRoute(subUuid, 2)),
            ("r0", 1083, "entry.test", "e0e0e0e0e0e0e0e0", "/entrypath", subUuid),
            ("r7", 1084, "entry.test", "e0e0e0e0e0e0e0e0", "/entrypath", XCoreRoute.WithRoute(subUuid, 7)),
            ("foreign", 1085, "entry.test", "e0e0e0e0e0e0e0e0", "/entrypath", ForeignUuid),
            ("relay", 1086, "entry.test", "e0e0e0e0e0e0e0e0", "/entrypath", relayUuid),
            ("closed", 1087, "entry0.test", "f0f0f0f0f0f0f0f0", "/entry0path", XCoreRoute.WithRoute(subUuid, 1)),
        ];
        var client = new JsonObject
        {
            ["log"] = new JsonObject { ["loglevel"] = "warning" },
            ["inbounds"] = new JsonArray([.. variants.Select(v => (JsonNode)new JsonObject
            {
                ["tag"] = "in-" + v.Tag, ["listen"] = "0.0.0.0", ["port"] = v.Port, ["protocol"] = "socks",
                ["settings"] = new JsonObject { ["auth"] = "noauth", ["udp"] = false },
            })]),
            ["outbounds"] = new JsonArray([.. variants.Select(v => (JsonNode)new JsonObject
            {
                ["tag"] = "out-" + v.Tag, ["protocol"] = "vless",
                ["settings"] = new JsonObject
                {
                    ["vnext"] = new JsonArray(new JsonObject
                    {
                        ["address"] = v.Host, ["port"] = 443,
                        ["users"] = new JsonArray(new JsonObject { ["id"] = v.Uuid, ["encryption"] = "none" }),
                    }),
                },
                ["streamSettings"] = new JsonObject
                {
                    ["network"] = "xhttp", ["security"] = "reality",
                    ["realitySettings"] = new JsonObject
                    {
                        ["serverName"] = v.Host, ["publicKey"] = publicKey, ["shortId"] = v.ShortId,
                        ["fingerprint"] = "firefox", ["spiderX"] = "",
                    },
                    ["xhttpSettings"] = new JsonObject { ["path"] = v.Path, ["mode"] = "auto" },
                },
            })]),
            ["routing"] = new JsonObject
            {
                ["rules"] = new JsonArray([.. variants.Select(v => (JsonNode)new JsonObject
                {
                    ["type"] = "field", ["inboundTag"] = new JsonArray("in-" + v.Tag), ["outboundTag"] = "out-" + v.Tag,
                })]),
            },
        };
        File.WriteAllText(Path.Combine(configDir, "client.json"), client.ToJsonString());

        // Запуск. Узел и его заглушка делят сетевое пространство (Reality берёт цель по 127.0.0.1:8443).
        string Start(string role, string alias, string config, params string[] extraAliases)
        {
            var name = Name(role);
            var args = new List<string> { "run", "-d", "--name", name, "--network", net, "--network-alias", alias };
            foreach (var a in extraAliases) { args.Add("--network-alias"); args.Add(a); }
            args.AddRange(["--user", "0:0", "-v", mount, XrayImage, "run", "-c", $"/c/{config}"]);
            var started = DockerCmd([.. args]);
            if (started.Code != 0) Report($"e2e: контейнер {role} запущен", false, started.Err);
            return name;
        }
        void StartDest(string node)
        {
            var started = DockerCmd("run", "-d", "--name", Name("dest-" + node.Split('-')[^1]), "--network", "container:" + node, "--user", "0:0",
                "-v", mount, XrayImage, "run", "-c", "/c/dest.json");
            if (started.Code != 0) Report($"e2e: заглушка сайта для {node} запущена", false, started.Err);
        }

        var exit1 = Start("exit1", "exit1.test", "exit1.json");
        var exit2 = Start("exit2", "exit2.test", "exit2.json");
        var entry = Start("entry", "entry.test", "entry.json");
        var entry0 = Start("entry0", "entry0.test", "entry0.json");
        foreach (var node in new[] { exit1, exit2, entry, entry0 }) StartDest(node);
        Start("target", "target.test", "target.json", "direct.test", "proxy.test");
        var clientName = Start("client", "client.test", "client.json");

        bool Ready(string container)
        {
            for (var i = 0; i < 30; i++)
            {
                if (DockerCmd("exec", container, "xray", "api", "inboundusercount", "--server=127.0.0.1:10085",
                        $"-tag={XCoreConfigRenderer.InboundTag}").Code == 0) return true;
                Thread.Sleep(500);
            }
            return false;
        }
        var ready = new[] { exit1, exit2, entry, entry0 }.All(Ready);
        Report("e2e: четыре узла (два выхода, вход, закрытый вход) подняты с боевыми конфигами", ready,
            string.Join(" | ", new[] { exit1, exit2, entry, entry0 }.Select(c => c[^6..] + ": " + Tail(DockerCmd("logs", c)))));
        if (!ready) return results;
        Thread.Sleep(1500);

        long Counter(string container, string prefix)
        {
            var q = DockerCmd("exec", container, "xray", "api", "statsquery", "--server=127.0.0.1:10085", "-pattern", $"user>>>{prefix}");
            return q.Code != 0 ? -1 : XrayApiOutput.ParseUserTraffic(q.Out).Values.Sum(t => t.Uplink + t.Downlink);
        }

        string Fetch(int port, string url, int attempts = 1)
        {
            var status = "000";
            for (var i = 0; i < attempts && status == "000"; i++)
            {
                var r = DockerCmd("run", "--rm", "--network", net, CurlImage, "-s", "-o", "/dev/null", "-w", "%{http_code}",
                    "--max-time", "45", "--socks5-hostname", $"{clientName}:{port}", url);
                status = r.Out.Trim().Length == 0 ? "000" : r.Out.Trim();
            }
            return status;
        }

        (long E1, long E2, long Sub) Snapshot() => (Counter(exit1, "relay-"), Counter(exit2, "relay-"), Counter(entry, "sub-"));
        void Scenario(string title, int port, string url, string expectedStatus, bool exit1Grows, bool exit2Grows, bool? subGrows, int attempts = 1)
        {
            var before = Snapshot();
            var status = Fetch(port, url, attempts);
            var after = Snapshot();
            Report($"e2e: {title} — ответ {expectedStatus}", status == expectedStatus,
                $"получено {status}; вход: {Tail(DockerCmd("logs", entry), 8)}; выход 1: {Tail(DockerCmd("logs", exit1), 6)}; клиент: {Tail(DockerCmd("logs", clientName), 8)}");
            Report($"e2e: {title} — трафик выхода 1 {(exit1Grows ? "вырос" : "не изменился")}", (after.E1 > before.E1) == exit1Grows,
                $"{before.E1} → {after.E1}");
            Report($"e2e: {title} — трафик выхода 2 {(exit2Grows ? "вырос" : "не изменился")}", (after.E2 > before.E2) == exit2Grows,
                $"{before.E2} → {after.E2}");
            if (subGrows is { } grows)
                Report($"e2e: {title} — счётчик подписчика на входе {(grows ? "вырос" : "не изменился")}", (after.Sub > before.Sub) == grows,
                    $"{before.Sub} → {after.Sub}");
        }

        const string TargetUrl = "http://target.test:8080/";
        Scenario("маршрут 1 → цель идёт через выход 1", 1081, TargetUrl, "403", true, false, true, attempts: 3);
        Scenario("маршрут 2 → цель идёт через выход 2", 1082, TargetUrl, "403", false, true, true);
        Scenario("маршрут 0 (UUID без подмены) → выход с наименьшим номером", 1083, TargetUrl, "403", true, false, true);
        Scenario("неизвестный маршрут 7 → тоже выход с наименьшим номером", 1084, TargetUrl, "403", true, false, true);
        Scenario("direct.test из списка «напрямую» уходит со входа, минуя выходы", 1081, "http://direct.test:8080/", "403", false, false, true);
        Scenario("proxy.test есть в обоих списках — «через VPN» побеждает, маршрут 2 → выход 2", 1082, "http://proxy.test:8080/", "403", false, true, true);
        Scenario("proxy.test на маршруте 1 → выход 1", 1081, "http://proxy.test:8080/", "403", true, false, true);
        Scenario("proxy.test на маршруте 0: «через VPN» сильнее «напрямую» и здесь → выход с наименьшим номером",
            1083, "http://proxy.test:8080/", "403", true, false, true);

        var beforeBad = Snapshot();
        var foreign = Fetch(1085, TargetUrl);
        var afterForeign = Snapshot();
        Report("e2e: чужой UUID на входе отвергнут, трафика нет", foreign == "000" && afterForeign == beforeBad, $"ответ {foreign}");
        var relayAtEntry = Fetch(1086, TargetUrl);
        Report("e2e: служебный UUID входа на самом входе не принимается (он только для выходов)", relayAtEntry == "000", $"ответ {relayAtEntry}");

        var closedTarget = Fetch(1087, TargetUrl);
        var closedDirect = Fetch(1087, "http://direct.test:8080/");
        Report("e2e: вход без выходов не пропускает трафик ни через VPN, ни напрямую", closedTarget == "000" && closedDirect == "000",
            $"target {closedTarget}, direct {closedDirect}");
    }
    finally
    {
        if (containers.Count > 0) DockerCmd(["rm", "-f", .. containers]);
        DockerCmd("network", "rm", net);
    }

    return results;
}

static (int Code, string Out, string Err) DockerCmd(params string[] args)
{
    var psi = new ProcessStartInfo("docker")
    {
        RedirectStandardOutput = true,
        RedirectStandardError = true,
        UseShellExecute = false,
    };
    foreach (var a in args) psi.ArgumentList.Add(a);
    using var process = Process.Start(psi)!;
    var stdout = process.StandardOutput.ReadToEndAsync();
    var stderr = process.StandardError.ReadToEndAsync();
    process.WaitForExit();
    return (process.ExitCode, stdout.Result, stderr.Result);
}
