using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Web;
using AmneziaKeyService.Api.Controllers;
using AmneziaKeyService.Api.Infrastructure;
using AmneziaKeyService.Core.DTOs.Panel;
using AmneziaKeyService.Core.Exceptions;
using AmneziaKeyService.Core.Interfaces;
using AmneziaKeyService.Core.Models;
using AmneziaKeyService.Infrastructure.DependencyInjection;
using AmneziaKeyService.Infrastructure.Events;
using AmneziaKeyService.Infrastructure.Logging;
using AmneziaKeyService.Infrastructure.Migrations;
using AmneziaKeyService.Infrastructure.Monitoring;
using AmneziaKeyService.Infrastructure.Protocols.XCore;
using AmneziaKeyService.Infrastructure.Services;
using AmneziaKeyService.Infrastructure.Subscriptions;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using MongoDB.Bson;
using MongoDB.Driver;
using Serilog.Events;
using Serilog.Parsing;

// Проверяет подписки Happ: токен, ссылки vless://, заголовки, ответ для отозванной подписки,
// выбор узлов, редактирование токена в логах — офлайн; с --mongo=<url> — ещё индексы M016,
// публикацию xcore.sync без дублей, желаемый список узла и принуждение на временной базе.
//
// Зачем: всё это ошибается молча. Ссылка с лишним или потерянным параметром импортируется и не
// подключается; заголовок с кириллицей Kestrel не отправляет вовсе; токен в логе — это
// утёкшая подписка; а индекс «одна активная подписка на пользователя» держит инвариант, который
// проверка в коде не удержит при двух одновременных запросах бота.
//
// Эталонная ссылка ниже набрана вручную, а не получена из рендерера: иначе проверка повторяла бы
// ошибку кода, а не ловила её.

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

async Task<T?> CatchAsync<T>(Func<Task> action) where T : Exception
{
    try { await action(); return null; }
    catch (T ex) { return ex; }
}

bool IsAsciiHeader(string value) => value.All(c => c is >= ' ' and <= '~');
string Base64Text(string encoded) => Encoding.UTF8.GetString(Convert.FromBase64String(encoded));

Console.OutputEncoding = Encoding.UTF8;

// ── Тестовые данные ──────────────────────────────────────────────────────────

const string PublicKey = "vN5-VmKdoRXOgLJeJ1n3uX2nGxzPDE48X9qHZUT32is";
const string Uuid1 = "11111111-2222-3333-4444-555555555555";
const string Uuid2 = "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE";
const string XCoreImage = "ghcr.io/xtls/xray-core:26.10.21";
var epoch2030 = new DateTime(2030, 1, 1, 0, 0, 0, DateTimeKind.Utc);
var now = new DateTime(2026, 10, 29, 12, 0, 0, DateTimeKind.Utc);

XCoreProtocolParams NodeParams(Action<XCoreProtocolParams>? tweak = null)
{
    var p = new XCoreProtocolParams
    {
        Role = XCoreRoles.Exit,
        Domain = "node1.example.com",
        ImageRef = XCoreImage,
        RealityPublicKey = PublicKey,
        ShortIds = ["a1b2c3d4e5f60718", "ffffffffffffffff"],
        XhttpPath = "/x7Kq2mPz",
        Title = "Нидерланды",
        SortOrder = 0,
        SubscriptionEnabled = true,
    };
    tweak?.Invoke(p);
    return p;
}

ProtocolInstance XCoreProtocol(string id, Action<XCoreProtocolParams>? tweak = null, Action<ProtocolInstance>? tweakProtocol = null)
{
    var p = new ProtocolInstance
    {
        Id = id, Kind = ProtocolKinds.XCore, ContainerName = "amnezia-xcore", Port = "443",
        TransportProto = "tcp", State = ProtocolStates.Installed, Enabled = true, XCore = NodeParams(tweak),
    };
    tweakProtocol?.Invoke(p);
    return p;
}

VpnServer Server(string id, string name, params ProtocolInstance[] protocols) =>
    new() { Id = id, Name = name, Host = "203.0.113.10", Protocols = [.. protocols] };

Subscription Sub(Action<Subscription>? tweak = null)
{
    var s = new Subscription
    {
        Id = "69ca5beaba00e3c10adc4591", UserId = "69ca5beaba00e3c10adc4599", XrayUuid = Uuid1,
        TokenHash = "x", CreatedAt = now.AddDays(-1),
    };
    tweak?.Invoke(s);
    return s;
}

// Образец вывода xray vlessenc (образ 26.10.21): раздел X25519 и сокращённый ML-KEM-768. Ключи одноразовые.
const string VlessEncServer = "mlkem768x25519plus.native.600s.sPv_EiUoTTSalsbq-6-eyImENJ7r1Dq03mTkHEaEz3s";
const string VlessEncClient = "mlkem768x25519plus.native.0rtt.SbrjbVAwvkucHzXzSUC52rCKMdM-ZRKiduLBlpzzzjo";
string VlessEncSample =
    "Authentication: X25519, not Post-Quantum\n" +
    $"\"decryption\": \"{VlessEncServer}\"\n\"encryption\": \"{VlessEncClient}\"\n\n" +
    "Authentication: ML-KEM-768, Post-Quantum\n" +
    $"\"decryption\": \"mlkem768x25519plus.native.600s.{new string('Q', 86)}\"\n" +
    $"\"encryption\": \"mlkem768x25519plus.native.0rtt.{new string('1', 1568)}\"\n";

SubscriptionOptions Options0(Action<SubscriptionOptions>? tweak = null)
{
    var o = new SubscriptionOptions { PublicBaseUrl = "https://sub.example.com" };
    tweak?.Invoke(o);
    return o;
}

// ── Токен ────────────────────────────────────────────────────────────────────

Console.WriteLine("Токен подписки");

{
    var tokens = Enumerable.Range(0, 2000).Select(_ => SubscriptionTokenCrypto.Create()).ToList();
    Check("токен: 43 символа base64url без '='", tokens.All(t => t.Length == 43 && SubscriptionTokenCrypto.IsWellFormed(t)
        && t.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_')));
    Check("токен: 2000 штук без повторов (256 бит случайности)", tokens.Distinct().Count() == 2000);
    var raw = Convert.FromBase64String(tokens[0].Replace('-', '+').Replace('_', '/') + "=");
    Check("токен: декодируется ровно в 32 байта", raw.Length == 32);

    // Эталон SHA-256("abc") из FIPS 180-2.
    Check("хеш: SHA-256 hex от 'abc' совпадает с эталоном",
        SubscriptionTokenCrypto.Hash("abc") == "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD");
    var hash = SubscriptionTokenCrypto.Hash(tokens[0]);
    Check("хеш: 64 hex-символа, детерминирован", hash.Length == 64 && hash == SubscriptionTokenCrypto.Hash(tokens[0]));
    Check("сравнение: верный токен подходит, чужой нет",
        SubscriptionTokenCrypto.Matches(tokens[0], hash) && !SubscriptionTokenCrypto.Matches(tokens[1], hash));
    Check("сравнение: мусор вместо хеша — false, а не исключение",
        !SubscriptionTokenCrypto.Matches(tokens[0], "not-hex") && !SubscriptionTokenCrypto.Matches(tokens[0], ""));
    Check("токен: проверка формы отсекает мусор в пути",
        !SubscriptionTokenCrypto.IsWellFormed(null) && !SubscriptionTokenCrypto.IsWellFormed("")
        && !SubscriptionTokenCrypto.IsWellFormed(new string('a', 42)) && !SubscriptionTokenCrypto.IsWellFormed(new string('a', 44))
        && !SubscriptionTokenCrypto.IsWellFormed(new string('a', 42) + "=") && !SubscriptionTokenCrypto.IsWellFormed(new string('a', 42) + "+")
        && !SubscriptionTokenCrypto.IsWellFormed(new string('a', 42) + "/") && !SubscriptionTokenCrypto.IsWellFormed(new string('a', 42) + "%")
        && SubscriptionTokenCrypto.IsWellFormed(new string('a', 43)));
}

// ── Публичная ссылка ─────────────────────────────────────────────────────────

Console.WriteLine("Публичная ссылка подписки");

{
    var token = SubscriptionTokenCrypto.Create();
    Check("адрес: {PublicBaseUrl}/sub/{token}",
        Options0().TryBuildUrl(token, out var url) && url == $"https://sub.example.com/sub/{token}");
    Check("адрес: слэш в конце базового адреса не удваивается",
        Options0(o => o.PublicBaseUrl = "https://sub.example.com/").TryBuildUrl("T", out url) && url == "https://sub.example.com/sub/T");
    Check("адрес: путь-префикс сохраняется (сервис под /vpn)",
        Options0(o => o.PublicBaseUrl = "https://example.com/vpn/").TryBuildUrl("T", out url) && url == "https://example.com/vpn/sub/T");
    Check("адрес: не задан / пробелы / не URL / не http(s) — ссылка не строится",
        !Options0(o => o.PublicBaseUrl = null).TryBuildUrl("T", out _) && !Options0(o => o.PublicBaseUrl = "  ").TryBuildUrl("T", out _)
        && !Options0(o => o.PublicBaseUrl = "sub.example.com").TryBuildUrl("T", out _)
        && !Options0(o => o.PublicBaseUrl = "ftp://sub.example.com").TryBuildUrl("T", out _)
        && !Options0(o => o.PublicBaseUrl = "https://sub.example.com/?a=1").TryBuildUrl("T", out _));
    Check("настройки: по умолчанию название «VPN» и обновление раз в 12 часов",
        new SubscriptionOptions().ProfileTitle == "VPN" && new SubscriptionOptions().UpdateIntervalHours == 12);
}

// ── Ссылка на узел ───────────────────────────────────────────────────────────

Console.WriteLine("Ссылка vless:// на узел");

{
    var server = Server("s1", "NL-1");
    var node = NodeParams();

    // Эталон, набранный вручную. Порядок параметров — как в плане; extra и flow отсутствуют.
    const string Expected =
        "vless://11111111-2222-3333-4444-555555555555@node1.example.com:443" +
        "?encryption=none&security=reality&sni=node1.example.com&fp=firefox" +
        "&pbk=vN5-VmKdoRXOgLJeJ1n3uX2nGxzPDE48X9qHZUT32is&sid=a1b2c3d4e5f60718&type=xhttp" +
        "&path=%2Fx7Kq2mPz&mode=auto" +
        "#%D0%9D%D0%B8%D0%B4%D0%B5%D1%80%D0%BB%D0%B0%D0%BD%D0%B4%D1%8B";
    var link = SubscriptionRenderer.BuildLink(Uuid1, server, node)!;
    Check("ссылка: совпадает с эталоном посимвольно", link == Expected, link);

    var uri = new Uri(link);
    var query = HttpUtility.ParseQueryString(uri.Query);
    Check("ссылка: схема vless, UUID в userinfo, домен узла, порт 443",
        uri.Scheme == "vless" && uri.UserInfo == Uuid1 && uri.Host == "node1.example.com" && uri.Port == 443);
    Check("ссылка: encryption=none, security=reality, type=xhttp, mode=auto",
        query["encryption"] == "none" && query["security"] == "reality" && query["type"] == "xhttp" && query["mode"] == "auto");
    Check("ссылка: sni = домен узла, fp = отпечаток узла, pbk = публичный ключ, sid = первый shortId",
        query["sni"] == "node1.example.com" && query["fp"] == "firefox" && query["pbk"] == PublicKey && query["sid"] == "a1b2c3d4e5f60718");
    Check("ссылка: path после декодирования равен пути узла", query["path"] == "/x7Kq2mPz");
    Check("ссылка: ровно 9 плоских параметров, без extra и flow",
        query.AllKeys.Length == 9 && query["extra"] is null && query["flow"] is null && !link.Contains("extra"));
    Check("ссылка: название в #фрагменте декодируется в «Нидерланды»", Uri.UnescapeDataString(uri.Fragment[1..]) == "Нидерланды");

    // Адрес — домен, а не IP: смена IP узла ссылок не меняет.
    var moved = Server("s1", "NL-1");
    moved.Host = "198.51.100.77";
    Check("адрес: IP узла в ссылку не попадает, при смене IP ссылка прежняя",
        !link.Contains(server.Host) && SubscriptionRenderer.BuildLink(Uuid1, moved, node) == link);
    Check("UUID нормализуется к нижнему регистру через дефисы",
        SubscriptionRenderer.BuildLink(Uuid2, server, node)!.StartsWith("vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@"));

    // Путь и название с пробелами, кириллицей и служебными символами не ломают ссылку.
    var awkward = NodeParams(n =>
    {
        n.XhttpPath = "/путь с пробелом?a=b&c#d";
        n.Title = "Nederland 1 / fast & cheap #1";
    });
    var awkwardLink = SubscriptionRenderer.BuildLink(Uuid1, server, awkward)!;
    var awkwardUri = new Uri(awkwardLink);
    var awkwardQuery = HttpUtility.ParseQueryString(awkwardUri.Query);
    Check("кодирование: путь с пробелом, кириллицей, ?&# восстанавливается без потерь",
        awkwardQuery["path"] == "/путь с пробелом?a=b&c#d" && awkwardQuery.AllKeys.Length == 9);
    Check("кодирование: в запросе нет сырых пробелов, '#' и кириллицы",
        !awkwardLink.Contains(' ') && awkwardLink.Count(c => c == '#') == 1 && awkwardLink.All(c => c < 128));
    Check("кодирование: название с пробелами, '/', '&' и '#' восстанавливается без потерь",
        Uri.UnescapeDataString(awkwardUri.Fragment[1..]) == "Nederland 1 / fast & cheap #1");

    // Обрезка названия до 30 символов.
    var longTitle = new string('я', 40);
    Check("название: 40 символов обрезается до 30",
        SubscriptionRenderer.NodeTitle(server, NodeParams(n => n.Title = longTitle)) == new string('я', 30));
    Check("название: ровно 30 символов не меняется",
        SubscriptionRenderer.NodeTitle(server, NodeParams(n => n.Title = new string('z', 30))).Length == 30);
    var emoji = new string('a', 29) + "😀";
    Check("название: суррогатная пара на границе не разрывается", SubscriptionRenderer.NodeTitle(server, NodeParams(n => n.Title = emoji)) == new string('a', 29));
    Check("название: без Title берётся имя узла, тоже до 30",
        SubscriptionRenderer.NodeTitle(Server("s", new string('N', 50)), NodeParams(n => n.Title = null)) == new string('N', 30)
        && SubscriptionRenderer.NodeTitle(server, NodeParams(n => n.Title = "  ")) == "NL-1");
    var longLink = SubscriptionRenderer.BuildLink(Uuid1, server, NodeParams(n => n.Title = longTitle))!;
    Check("название: в ссылку попадают те же 30 символов",
        Uri.UnescapeDataString(new Uri(longLink).Fragment[1..]) == new string('я', 30));

    // Узел без нужных данных ссылки не даёт: импортируется и не подключается.
    Check("неполный узел (нет pbk / shortId / пути / домена) — ссылки нет",
        SubscriptionRenderer.BuildLink(Uuid1, server, NodeParams(n => n.RealityPublicKey = null)) is null
        && SubscriptionRenderer.BuildLink(Uuid1, server, NodeParams(n => n.ShortIds = [])) is null
        && SubscriptionRenderer.BuildLink(Uuid1, server, NodeParams(n => n.XhttpPath = " ")) is null
        && SubscriptionRenderer.BuildLink(Uuid1, server, NodeParams(n => n.Domain = "")) is null
        && SubscriptionRenderer.BuildLink("not-a-uuid", server, node) is null);
}

// ── Выбор узлов ──────────────────────────────────────────────────────────────

Console.WriteLine("Выбор узлов для подписки");

{
    VpnServer WithDisabled(VpnServer s, string protocolId) { s.DisabledProtocolIds.Add(protocolId); return s; }

    var awg = new ProtocolInstance { Id = "awg", Kind = ProtocolKinds.Awg2, ContainerName = "amnezia-awg2", Port = "40000", State = ProtocolStates.Installed };
    var servers = new List<VpnServer>
    {
        Server("a", "B-server", XCoreProtocol("pa", n => n.SortOrder = 2)),
        Server("b", "Z-server", XCoreProtocol("pb", n => n.SortOrder = 1)),
        Server("c", "A-server", XCoreProtocol("pc", n => n.SortOrder = 1)),
        Server("d-off", "SubscriptionOff", XCoreProtocol("pd", n => n.SubscriptionEnabled = false)),
        Server("e-disabled", "Disabled", XCoreProtocol("pe", tweakProtocol: p => p.Enabled = false)),
        WithDisabled(Server("e2-disabled", "DisabledByOperator", XCoreProtocol("pe2")), "pe2"),
        Server("f-installing", "Installing", XCoreProtocol("pf", tweakProtocol: p => p.State = ProtocolStates.Installing)),
        Server("g-entry", "Entry", XCoreProtocol("pg", n => n.Role = XCoreRoles.Entry)),
        Server("h-awg", "OnlyAwg", awg),
        Server("i-mixed", "Mixed-server", awg, XCoreProtocol("pi", n => n.SortOrder = 5)),
    };

    var selected = SubscriptionRenderer.SelectNodes(servers);
    Check("узлы: exit + работает + SubscriptionEnabled; порядок — SortOrder, затем имя",
        selected.Select(n => n.Server.Id).SequenceEqual(["c", "b", "a", "i-mixed"]), string.Join(",", selected.Select(n => n.Server.Id)));
    Check("узлы: у смешанного узла берётся xcore, а не awg2", selected[3].Protocol.Kind == ProtocolKinds.XCore);
    Check("узлы: xcore с SubscriptionEnabled=false, выключенный, скрытый оператором, устанавливающийся, entry и не-xcore исключены",
        selected.Count == 4);
    Check("узлы: публикатор синхронизирует выходы и работающий вход, а выходы для ссылок и кнопки бота — только exit",
        XCoreSyncPublisher.SubscriptionNodes(servers).Select(n => n.Server.Id).OrderBy(i => i).SequenceEqual(["a", "b", "c", "g-entry", "i-mixed"])
        && XCoreSyncPublisher.SubscriptionExits(servers).Select(n => n.Server.Id).OrderBy(i => i).SequenceEqual(["a", "b", "c", "i-mixed"]));
    Check("узлы: вход не попадает в выходы подписки, но отдельно выбирается SelectEntries",
        string.Join(",", SubscriptionRenderer.SelectEntries(servers).Select(n => n.Server.Id)) == "g-entry");
    Check("узлы: без подходящих — пустой список", SubscriptionRenderer.SelectNodes([Server("x", "x", awg)]).Count == 0);
}

// ── Ссылки через вход ────────────────────────────────────────────────────────

Console.WriteLine("Ссылки через вход");

{
    const string EntryKey = "Zz-VmKdoRXOgLJeJ1n3uX2nGxzPDE48X9qHZUT32is";

    VpnServer Exit(string id, string name, int sort, int? route, Action<XCoreProtocolParams>? tweak = null) =>
        Server(id, name, XCoreProtocol("p" + id, n =>
        {
            n.Role = XCoreRoles.Exit; n.SortOrder = sort; n.RouteId = route; n.Domain = $"{id}.example.com"; n.Title = name;
            tweak?.Invoke(n);
        }));
    VpnServer Entry(string id, string name, int sort, Action<XCoreProtocolParams>? tweak = null, Action<ProtocolInstance>? tweakProtocol = null) =>
        Server(id, name, XCoreProtocol("p" + id, n =>
        {
            n.Role = XCoreRoles.Entry; n.SortOrder = sort; n.Domain = $"{id}.example.ru"; n.Title = name;
            n.RealityPublicKey = EntryKey; n.ShortIds = ["0a1b2c3d4e5f6071"]; n.XhttpPath = "/entry" + id;
            tweak?.Invoke(n);
        }, tweakProtocol));

    var exitA = Exit("ea", "Alpha", 1, 1);
    var exitB = Exit("eb", "Beta", 2, 2);
    var exitNoRoute = Exit("ec", "Gamma", 3, null);
    var entryOne = Entry("n1", "Entry-B", 0);
    var entryTwo = Entry("n2", "Entry-A", 0);
    var entryOff = Entry("n3", "Entry-off", 0, tweakProtocol: p => p.Enabled = false);
    var entryHidden = Entry("n4", "Entry-hidden", 0, n => n.SubscriptionEnabled = false);
    var entryBroken = Entry("n5", "Entry-broken", 0, n => n.RealityPublicKey = null);
    var all = new List<VpnServer> { exitB, entryOne, exitNoRoute, exitA, entryTwo, entryOff, entryHidden, entryBroken };

    var links = SubscriptionRenderer.BuildLinks(Uuid1, all);
    string HostOf(string link) => new Uri(link).Host;
    string TitleOf(string link) => Uri.UnescapeDataString(new Uri(link).Fragment[1..]);
    string UuidOf(string link) => new Uri(link).UserInfo;

    Check("через вход: порядок — входы (SortOrder, имя) × выходы (SortOrder, имя), затем прямые ссылки",
        links.Select(l => HostOf(l) + "|" + TitleOf(l)).SequenceEqual(
        [
            "n2.example.ru|Alpha · РФ", "n2.example.ru|Beta · РФ",
            "n1.example.ru|Alpha · РФ", "n1.example.ru|Beta · РФ",
            "ea.example.com|Alpha", "eb.example.com|Beta", "ec.example.com|Gamma",
        ]), string.Join(" / ", links.Select(l => HostOf(l) + "|" + TitleOf(l))));
    Check("через вход: выключенный, скрытый и неполный вход ссылок не дают",
        !links.Any(l => HostOf(l) is "n3.example.ru" or "n4.example.ru" or "n5.example.ru"));
    Check("через вход: выход без номера маршрута есть только среди прямых", links.Count(l => HostOf(l) == "ec.example.com") == 1
        && !links.Take(4).Any(l => TitleOf(l).StartsWith("Gamma")));

    const string ExpectedViaEntry =
        "vless://11111111-2222-0001-4444-555555555555@n2.example.ru:443" +
        "?encryption=none&security=reality&sni=n2.example.ru&fp=firefox" +
        "&pbk=Zz-VmKdoRXOgLJeJ1n3uX2nGxzPDE48X9qHZUT32is&sid=0a1b2c3d4e5f6071&type=xhttp" +
        "&path=%2Fentryn2&mode=auto" +
        "#Alpha%20%C2%B7%20%D0%A0%D0%A4";
    Check("через вход: ссылка совпадает с эталоном посимвольно (адрес, ключи и путь входа, маршрут в UUID, название с «· РФ»)",
        links[0] == ExpectedViaEntry, links[0]);
    Check("через вход: UUID — подписки с третьей группой = номер маршрута выхода (0001 и 0002)",
        UuidOf(links[0]) == "11111111-2222-0001-4444-555555555555" && UuidOf(links[1]) == "11111111-2222-0002-4444-555555555555");
    Check("прямые ссылки: UUID подписки без подмены, адрес и ключи выхода",
        UuidOf(links[4]) == Uuid1 && links[4] == SubscriptionRenderer.BuildLink(Uuid1, exitA, exitA.Protocols[0].XCore!));
    Check("через вход: остальные части ссылки (всё, кроме UUID и названия) у плеч одного входа совпадают",
        links[0].Replace("0001", "0002")[..links[0].IndexOf('#')] == links[1][..links[1].IndexOf('#')]);

    var viaUuid = Guid.Parse(UuidOf(links[1])).ToString("D");
    Check("через вход: у UUID с маршрутом остальные группы равны UUID подписки",
        viaUuid[..14] == Uuid1[..14] && viaUuid[18..] == Uuid1[18..]);

    // Название: «{выход} · РФ» не длиннее 30; обрезается имя выхода, суффикс сохраняется.
    string EntryTitle(string exitTitle) => SubscriptionRenderer.EntryLinkTitle(exitA, NodeParams(n => n.Title = exitTitle));
    Check("название: короткое — имя выхода и суффикс", EntryTitle("Нидерланды") == "Нидерланды · РФ");
    Check("название: длинное — имя выхода урезано до 25, суффикс цел, всего 30",
        EntryTitle(new string('x', 40)) == new string('x', 25) + " · РФ" && EntryTitle(new string('x', 40)).Length == 30);
    Check("название: ровно 25 символов имени не урезается", EntryTitle(new string('y', 25)) == new string('y', 25) + " · РФ");
    Check("название: 26 символов имени — урезается до 25", EntryTitle(new string('y', 26)) == new string('y', 25) + " · РФ");
    Check("название: пробел на границе обрезки не оставляет двойного пробела перед «·»",
        EntryTitle(new string('a', 24) + " bbb") == new string('a', 24) + " · РФ");
    Check("название: суррогатная пара на границе не разрывается",
        EntryTitle(new string('a', 24) + "😀😀") == new string('a', 24) + " · РФ");
    Check("название: кириллица считается символами, а не байтами",
        EntryTitle(new string('я', 40)) == new string('я', 25) + " · РФ");
    Check("название: без Title берётся имя узла выхода", SubscriptionRenderer.EntryLinkTitle(Server("s", "Имя узла"), NodeParams(n => n.Title = null)) == "Имя узла · РФ");
    Check("название: в ссылке то же самое, не длиннее 30",
        links.Where(l => HostOf(l).EndsWith(".ru")).All(l => TitleOf(l).Length <= 30 && TitleOf(l).EndsWith(" · РФ")));

    // Состав подписки.
    Check("вход без выходов в подписку не попадает",
        SubscriptionRenderer.BuildLinks(Uuid1, [entryOne]).Count == 0 && SubscriptionRenderer.BuildLinks(Uuid1, [entryOne, exitNoRoute]).Count == 1
        && HostOf(SubscriptionRenderer.BuildLinks(Uuid1, [entryOne, exitNoRoute])[0]) == "ec.example.com");
    Check("без входов — только прямые ссылки, как раньше",
        SubscriptionRenderer.BuildLinks(Uuid1, [exitA, exitB]).Select(HostOf).SequenceEqual(["ea.example.com", "eb.example.com"]));
    Check("выход с неполными данными не даёт плеча (вход не получил бы его в конфиг)",
        SubscriptionRenderer.BuildLinks(Uuid1, [entryOne, Exit("ex", "Broken", 1, 1, n => n.RealityPublicKey = null)]).Count == 0);
    Check("скрытый и выключенный выходы не дают плеч",
        SubscriptionRenderer.BuildLinks(Uuid1, [entryOne, Exit("ex", "Hidden", 1, 1, n => n.SubscriptionEnabled = false)]).Count == 0
        && SubscriptionRenderer.BuildLinks(Uuid1, [entryOne, Server("ey", "Off", XCoreProtocol("pey", n => n.RouteId = 1, p => p.Enabled = false))]).Count == 0);
    Check("список плеч и список outbound-ов входа совпадают (одно правило отбора)",
        XCoreTopology.RoutableExits(all).Select(n => n.Server.Id).SequenceEqual(["ea", "eb"])
        && XCoreTopology.ExitTargets(all).Select(t => t.RouteId).SequenceEqual([1, 2]));
    Check("кнопка бота: вход без выходов узлом не считается, выход — считается",
        !XCoreSyncPublisher.SubscriptionExits([entryOne]).Any() && XCoreSyncPublisher.SubscriptionExits([entryOne, exitA]).Any());

    // Тело и заголовки.
    var feed = SubscriptionRenderer.Render(Sub(), all, Options0(), now);
    var feedLines = Base64Text(feed.Body).Split('\n');
    Check("тело: 4 ссылки через вход и 3 прямых, base64 как прежде", feedLines.Length == 7 && feedLines.All(l => l.StartsWith("vless://"))
        && feedLines.SequenceEqual(links));
    Check("отозванная подписка: ссылок нет и через вход, announce есть",
        SubscriptionRenderer.Render(Sub(s => s.Status = SubscriptionStatuses.Revoked), all, Options0(), now) is { Body: "" } revokedFeed
        && revokedFeed.Headers.ContainsKey("announce"));
    Check("перевыпуск: новый UUID подписки меняет UUID во всех ссылках, включая плечи",
        SubscriptionRenderer.BuildLinks(Uuid2, all).All(l => !UuidOf(l).StartsWith("11111111"))
        && UuidOf(SubscriptionRenderer.BuildLinks(Uuid2, all)[0]) == "aaaaaaaa-bbbb-0001-dddd-eeeeeeeeeeee");
    Check("BuildEntryLink: выход без номера или UUID не GUID — ссылки нет",
        SubscriptionRenderer.BuildEntryLink(Uuid1, entryOne.Protocols[0].XCore!, exitNoRoute, exitNoRoute.Protocols[0].XCore!) is null
        && SubscriptionRenderer.BuildEntryLink("bad", entryOne.Protocols[0].XCore!, exitA, exitA.Protocols[0].XCore!) is null);
}

// ── Тело и заголовки ─────────────────────────────────────────────────────────

Console.WriteLine("Тело и заголовки подписки");

{
    var servers = new List<VpnServer>
    {
        Server("a", "Beta", XCoreProtocol("pa", n => { n.SortOrder = 2; n.Domain = "b.example.com"; n.Title = "Beta"; })),
        Server("c", "Alpha", XCoreProtocol("pc", n => { n.SortOrder = 1; n.Domain = "a.example.com"; n.Title = "Alpha"; })),
    };
    var active = Sub(s => { s.Usage.RxBytes = 1000; s.Usage.TxBytes = 100; });
    var feed = SubscriptionRenderer.Render(active, servers, Options0(), now);

    var lines = Base64Text(feed.Body).Split('\n');
    Check("тело: base64 от строк-ссылок через \\n, в порядке узлов",
        lines.Length == 2 && lines[0].Contains("@a.example.com:") && lines[1].Contains("@b.example.com:") && lines.All(l => l.StartsWith("vless://")));
    Check("тело: стандартный base64 с padding (длина кратна 4, алфавит +/=)",
        feed.Body.Length % 4 == 0 && feed.Body.All(c => char.IsAsciiLetterOrDigit(c) || c is '+' or '/' or '='));
    Check("тело: строго декодируется стандартным декодером", Convert.FromBase64String(feed.Body).Length > 0);
    Check("тело: строки не заканчиваются переводом строки", !Base64Text(feed.Body).EndsWith('\n'));
    var oneLine = SubscriptionRenderer.EncodeBody(["x"]);
    Check("тело: padding на коротком образце", oneLine == "eA==");
    Check("тело: пустой список — пустая строка (base64 пустой строки)", SubscriptionRenderer.EncodeBody([]) == "");

    Check("заголовки: profile-title ASCII «VPN» как есть", feed.Headers["profile-title"] == "VPN");
    Check("заголовки: profile-update-interval по умолчанию 12", feed.Headers["profile-update-interval"] == "12");
    Check("заголовки: support-url не задан — заголовка нет; announce у активной нет",
        !feed.Headers.ContainsKey("support-url") && !feed.Headers.ContainsKey("announce"));
    Check("заголовки: все значения — печатный ASCII", feed.Headers.Values.All(IsAsciiHeader));
    Check("заголовки: имена в нижнем регистре, content-disposition нет",
        feed.Headers.Keys.All(k => k == k.ToLowerInvariant()) && !feed.Headers.ContainsKey("content-disposition"));

    // profile-title: ASCII как есть, иначе base64:, ≤25 символов до кодирования.
    string Title(string t) => SubscriptionRenderer.Render(active, [], Options0(o => o.ProfileTitle = t), now).Headers["profile-title"];
    Check("profile-title: ASCII «My VPN» как есть", Title("My VPN") == "My VPN");
    var cyrillic = Title("Мой VPN");
    Check("profile-title: кириллица → base64: + UTF-8 в base64",
        cyrillic == "base64:" + Convert.ToBase64String(Encoding.UTF8.GetBytes("Мой VPN")) && Base64Text(cyrillic["base64:".Length..]) == "Мой VPN");
    Check("profile-title: ASCII длиннее 25 обрезается до 25", Title(new string('x', 40)) == new string('x', 25));
    Check("profile-title: кириллица длиннее 25 обрезается до 25 символов до кодирования",
        Base64Text(Title(new string('ж', 40))["base64:".Length..]) == new string('ж', 25));
    Check("profile-title: пустое название заменяется на «VPN»", Title("   ") == "VPN");
    Check("profile-title: эмодзи на границе 25 не разрывается (остаётся чистый ASCII без base64:)",
        Title(new string('a', 24) + "😀") == new string('a', 24)
        && Base64Text(Title(new string('ж', 24) + "😀")["base64:".Length..]) == new string('ж', 24));

    // subscription-userinfo: upload — отправленное клиентом (tx), download — полученное им (rx).
    Check("userinfo: безлимитная подписка — total=0, expire=0",
        feed.Headers["subscription-userinfo"] == "upload=100; download=1000; total=0; expire=0", feed.Headers["subscription-userinfo"]);
    var limited = Sub(s => { s.Usage.RxBytes = 5000; s.Usage.TxBytes = 700; s.TrafficLimitBytes = 1073741824; s.ExpiresAt = epoch2030; });
    var limitedFeed = SubscriptionRenderer.Render(limited, servers, Options0(), now);
    Check("userinfo: лимитированная — total=квота, expire=unix-время",
        limitedFeed.Headers["subscription-userinfo"] == "upload=700; download=5000; total=1073741824; expire=1893456000",
        limitedFeed.Headers["subscription-userinfo"]);
    Check("userinfo: expire не зависит от Kind даты из базы (Unspecified)",
        SubscriptionRenderer.UserInfo(Sub(s => s.ExpiresAt = DateTime.SpecifyKind(epoch2030, DateTimeKind.Unspecified))).EndsWith("expire=1893456000"));

    var interval = (int h) => SubscriptionRenderer.Render(active, [], Options0(o => o.UpdateIntervalHours = h), now).Headers["profile-update-interval"];
    Check("profile-update-interval: из настроек; ноль и отрицательные поднимаются до 1", interval(6) == "6" && interval(0) == "1" && interval(-5) == "1");
    Check("support-url: из настроек, нормализуется Uri",
        SubscriptionRenderer.Render(active, [], Options0(o => o.SupportUrl = "https://t.me/support"), now).Headers["support-url"] == "https://t.me/support");
    Check("support-url: не URL и не http(s) — заголовка нет",
        !SubscriptionRenderer.Render(active, [], Options0(o => o.SupportUrl = "техподдержка"), now).Headers.ContainsKey("support-url")
        && !SubscriptionRenderer.Render(active, [], Options0(o => o.SupportUrl = "javascript:alert(1)"), now).Headers.ContainsKey("support-url"));

    // Отозванная и истёкшая: 200, пустой список, announce, userinfo с expire.
    var revoked = Sub(s => { s.Status = SubscriptionStatuses.Revoked; s.RevokeReason = RevokeReasons.Manual; s.ExpiresAt = epoch2030; s.Usage.RxBytes = 9; });
    var revokedFeed = SubscriptionRenderer.Render(revoked, servers, Options0(), now);
    Check("отозванная: список пустой, хотя узлы есть", revokedFeed.Body == "");
    Check("отозванная: announce — «Подписка отключена. Обратитесь в поддержку.» в base64:",
        revokedFeed.Headers["announce"] == "base64:" + Convert.ToBase64String(Encoding.UTF8.GetBytes(SubscriptionRenderer.DisabledAnnounce))
        && SubscriptionRenderer.DisabledAnnounce == "Подписка отключена. Обратитесь в поддержку.");
    Check("отозванная: userinfo сохраняет expire и использование",
        revokedFeed.Headers["subscription-userinfo"] == "upload=0; download=9; total=0; expire=1893456000");
    Check("отозванная: заголовки по-прежнему ASCII и profile-title на месте",
        revokedFeed.Headers.Values.All(IsAsciiHeader) && revokedFeed.Headers["profile-title"] == "VPN");
    Check("announce: не длиннее 200 символов", SubscriptionRenderer.DisabledAnnounce.Length <= SubscriptionRenderer.AnnounceMaxLength);
    var expiredFeed = SubscriptionRenderer.Render(Sub(s => s.ExpiresAt = now.AddMinutes(-1)), servers, Options0(), now);
    Check("истёкшая, но ещё не отозванная воркером: тот же ответ, что у отозванной",
        expiredFeed.Body == "" && expiredFeed.Headers.ContainsKey("announce"));
    var noNodes = SubscriptionRenderer.Render(active, [], Options0(), now);
    Check("активная без доступных узлов: 200, пустой список, без announce",
        noNodes.Body == "" && !noNodes.Headers.ContainsKey("announce"));
    Check("EncodeHeaderText: ASCII не кодируется, кириллица кодируется, длинный announce обрезается до 200",
        SubscriptionRenderer.EncodeHeaderText("abc", 25) == "abc" && SubscriptionRenderer.EncodeHeaderText("абв", 25).StartsWith("base64:")
        && Base64Text(SubscriptionRenderer.EncodeHeaderText(new string('я', 500), SubscriptionRenderer.AnnounceMaxLength)["base64:".Length..]).Length == 200);

    // ── Профиль маршрутизации Happ (заголовок routing) ───────────────────────

    Check("routing: по умолчанию выключен — заголовка нет ни у активной, ни у отозванной",
        !new SubscriptionOptions().HappRoutingEnabled && new SubscriptionOptions().HappRoutingName == "RU direct"
        && !feed.Headers.ContainsKey("routing") && !revokedFeed.Headers.ContainsKey("routing"));

    var routingOn = Options0(o => o.HappRoutingEnabled = true);
    var routingFeed = SubscriptionRenderer.Render(active, servers, routingOn, now);
    var routingHeader = routingFeed.Headers.GetValueOrDefault("routing");
    Check("routing: включён — заголовок happ://routing/add/{base64}, только ASCII, длина разумна (< 2 КБ)",
        routingHeader is not null && routingHeader.StartsWith("happ://routing/add/") && IsAsciiHeader(routingHeader) && routingHeader.Length < 2048,
        routingHeader?.Length + " символов");
    var profileJson = Base64Text(routingHeader!["happ://routing/add/".Length..]);
    var profile = JsonDocument.Parse(profileJson).RootElement;
    string[] profileKeys =
    [
        "Name", "GlobalProxy", "DomainStrategy", "FakeDNS", "LastUpdated", "RemoteDNSType", "RemoteDNSDomain", "RemoteDNSIP",
        "DomesticDNSType", "DomesticDNSDomain", "DomesticDNSIP", "DnsHosts", "Geoipurl", "Geositeurl", "DirectSites", "DirectIp",
        "ProxySites", "ProxyIp", "BlockSites", "BlockIp",
    ];
    Check("routing: base64 декодируется в JSON со всеми ключами профиля Happ в заданном порядке",
        profile.EnumerateObject().Select(p => p.Name).SequenceEqual(profileKeys));
    string[] Strs(string key) => [.. profile.GetProperty(key).EnumerateArray().Select(e => e.GetString()!)];
    Check("routing: GlobalProxy true, IPIfNonMatch, FakeDNS false (строками, как в документации Happ), имя по умолчанию",
        profile.GetProperty("GlobalProxy").GetString() == "true" && profile.GetProperty("DomainStrategy").GetString() == "IPIfNonMatch"
        && profile.GetProperty("FakeDNS").GetString() == "false" && profile.GetProperty("Name").GetString() == "RU direct");
    Check("routing: DirectSites — category-ru, category-gov-ru, ru-available-only-inside; DirectIp — geoip:ru и geoip:private; ProxySites — ru-blocked",
        Strs("DirectSites").SequenceEqual(["geosite:category-ru", "geosite:category-gov-ru", "geosite:ru-available-only-inside"])
        && Strs("DirectIp").SequenceEqual(["geoip:ru", "geoip:private"]) && Strs("ProxySites").SequenceEqual(["geosite:ru-blocked"])
        && Strs("ProxyIp").Length == 0 && Strs("BlockSites").Length == 0 && Strs("BlockIp").Length == 0);
    Check("routing: geo-файлы — latest/download/geoip.dat и geosite.dat репозитория runetfreedom",
        profile.GetProperty("Geoipurl").GetString() == "https://github.com/runetfreedom/russia-v2ray-rules-dat/releases/latest/download/geoip.dat"
        && profile.GetProperty("Geositeurl").GetString() == "https://github.com/runetfreedom/russia-v2ray-rules-dat/releases/latest/download/geosite.dat");
    Check("routing: DNS — Cloudflare DoH для туннеля, российский резолвер по IP для прямых запросов, DnsHosts без запроса имени",
        profile.GetProperty("RemoteDNSType").GetString() == "DoH" && profile.GetProperty("RemoteDNSDomain").GetString() == "https://cloudflare-dns.com/dns-query"
        && profile.GetProperty("RemoteDNSIP").GetString() == "1.1.1.1" && profile.GetProperty("DomesticDNSType").GetString() == "DoU"
        && profile.GetProperty("DomesticDNSIP").GetString() == "77.88.8.8" && profile.GetProperty("DnsHosts").GetProperty("cloudflare-dns.com").GetString() == "1.1.1.1");

    // LastUpdated не «сейчас»: иначе Happ перекачивал бы geo-файлы при каждом обновлении подписки.
    var routingLater = SubscriptionRenderer.Render(
        Sub(s => { s.Usage.RxBytes = 5_000_000; s.Usage.TxBytes = 7; }), servers, routingOn, now.AddDays(3));
    Check("routing: два ответа подряд, и через три дня с другим трафиком, дают байт в байт один заголовок (LastUpdated стабилен)",
        routingFeed.Headers["routing"] == SubscriptionRenderer.Render(active, servers, routingOn, now).Headers["routing"]
        && routingFeed.Headers["routing"] == routingLater.Headers["routing"]
        && profile.GetProperty("LastUpdated").GetString() == HappRoutingProfile.LastUpdated.ToString());
    Check("routing: LastUpdated — число (unix, секунды) в строке, не из будущего относительно сборки",
        long.TryParse(profile.GetProperty("LastUpdated").GetString(), out var lastUpdated) && lastUpdated is > 1_700_000_000 and < 4_000_000_000
        && lastUpdated <= DateTimeOffset.UtcNow.ToUnixTimeSeconds());

    // Образец содержимого. Правка профиля без подъёма LastUpdated осталась бы незамеченной приложениями.
    Check("routing: образец профиля дословно (LastUpdated 1793232000 = 2026-10-29 UTC)",
        profileJson == """{"Name":"RU direct","GlobalProxy":"true","DomainStrategy":"IPIfNonMatch","FakeDNS":"false","LastUpdated":"1793232000","RemoteDNSType":"DoH","RemoteDNSDomain":"https://cloudflare-dns.com/dns-query","RemoteDNSIP":"1.1.1.1","DomesticDNSType":"DoU","DomesticDNSDomain":"","DomesticDNSIP":"77.88.8.8","DnsHosts":{"cloudflare-dns.com":"1.1.1.1"},"Geoipurl":"https://github.com/runetfreedom/russia-v2ray-rules-dat/releases/latest/download/geoip.dat","Geositeurl":"https://github.com/runetfreedom/russia-v2ray-rules-dat/releases/latest/download/geosite.dat","DirectSites":["geosite:category-ru","geosite:category-gov-ru","geosite:ru-available-only-inside"],"DirectIp":["geoip:ru","geoip:private"],"ProxySites":["geosite:ru-blocked"],"ProxyIp":[],"BlockSites":[],"BlockIp":[]}""");
    const string PinnedProfileFingerprint = "3b7d9317f67d00145a3b091f637c65b265bb0dfd3abfc3d77bce0ae093553f0a";
    const long PinnedLastUpdated = 1793232000;
    Check("routing: содержимое профиля изменилось — поднимите HappRoutingProfile.LastUpdated и обновите отпечаток в этой проверке",
        HappRoutingProfile.ContentFingerprint() == PinnedProfileFingerprint && HappRoutingProfile.LastUpdated == PinnedLastUpdated);

    string RoutingName(string? name) => JsonDocument.Parse(Base64Text(SubscriptionRenderer.Render(
        active, servers, Options0(o => { o.HappRoutingEnabled = true; o.HappRoutingName = name!; }), now).Headers["routing"]["happ://routing/add/".Length..]))
        .RootElement.GetProperty("Name").GetString()!;
    Check("routing: название из настройки; пустое — по умолчанию; длиннее 30 символов обрезается; кириллица остаётся валидным JSON и ASCII-заголовком",
        RoutingName("Мой профиль") == "Мой профиль" && RoutingName("") == "RU direct" && RoutingName("   ") == "RU direct" && RoutingName(null) == "RU direct"
        && RoutingName(new string('x', 80)).Length == HappRoutingProfile.NameMaxLength
        && SubscriptionRenderer.Render(active, servers, Options0(o => { o.HappRoutingEnabled = true; o.HappRoutingName = "Мой профиль"; }), now)
            .Headers.Values.All(IsAsciiHeader));
    Check("routing: другое название — другой заголовок (Happ заведёт профиль с тем именем), остальное содержимое то же",
        SubscriptionRenderer.Render(active, servers, Options0(o => { o.HappRoutingEnabled = true; o.HappRoutingName = "Home"; }), now).Headers["routing"]
            != routingFeed.Headers["routing"]);

    // Отозванная и истёкшая подписки профиль не получают.
    var routingRevoked = SubscriptionRenderer.Render(revoked, servers, routingOn, now);
    var routingExpired = SubscriptionRenderer.Render(Sub(s => s.ExpiresAt = now.AddMinutes(-1)), servers, routingOn, now);
    Check("routing: отозванная и истёкшая подписки заголовка не получают, остальные заголовки на месте",
        !routingRevoked.Headers.ContainsKey("routing") && !routingExpired.Headers.ContainsKey("routing")
        && routingRevoked.Headers.ContainsKey("announce") && routingRevoked.Headers.ContainsKey("subscription-userinfo"));
    Check("routing: профиль не затрагивает прочие заголовки и тело ответа",
        routingFeed.Body == feed.Body && routingFeed.Headers.Where(h => h.Key != "routing").OrderBy(h => h.Key)
            .SequenceEqual(feed.Headers.OrderBy(h => h.Key)));
}

// ── Модель подписки ──────────────────────────────────────────────────────────

Console.WriteLine("Модель подписки");

{
    var s = Sub();
    Check("email Xray = sub-{Id}", s.XrayEmail == "sub-69ca5beaba00e3c10adc4591");
    Check("Id из email: корректный разбирается, мусор — нет",
        Subscription.IdFromXrayEmail("sub-69ca5beaba00e3c10adc4591") == "69ca5beaba00e3c10adc4591"
        && Subscription.IdFromXrayEmail("sub-xyz") is null && Subscription.IdFromXrayEmail("other") is null
        && Subscription.IdFromXrayEmail("sub-") is null);
    Check("активна и без срока — отдаёт ссылки", s.IsServing(now));
    Check("срок истёк — не отдаёт; срок впереди — отдаёт",
        !Sub(x => x.ExpiresAt = now.AddSeconds(-1)).IsServing(now) && Sub(x => x.ExpiresAt = now.AddSeconds(1)).IsServing(now));
    Check("отозванная — не отдаёт", !Sub(x => x.Status = SubscriptionStatuses.Revoked).IsServing(now));
    Check("квота исчерпана при использовании ≥ лимита",
        Sub(x => { x.TrafficLimitBytes = 100; x.Usage.RxBytes = 60; x.Usage.TxBytes = 40; }).IsOverQuota
        && !Sub(x => { x.TrafficLimitBytes = 100; x.Usage.RxBytes = 60; x.Usage.TxBytes = 39; }).IsOverQuota
        && !Sub().IsOverQuota);

    var bson = Sub(x => { x.RawByNode["69ca5beaba00e3c10adc4530"] = new SubscriptionNodeRaw { Rx = 5, Tx = 6 }; }).ToBsonDocument();
    Check("BSON: raw по узлам — вложенный документ rawByNode.{serverId}.{rx,tx}",
        bson["rawByNode"]["69ca5beaba00e3c10adc4530"]["rx"].ToInt64() == 5 && bson["rawByNode"]["69ca5beaba00e3c10adc4530"]["tx"].ToInt64() == 6);
    Check("BSON: Id и userId — ObjectId", bson["_id"].BsonType == BsonType.ObjectId && bson["userId"].BsonType == BsonType.ObjectId);
}

// ── DTO панели ───────────────────────────────────────────────────────────────

Console.WriteLine("DTO панели");

{
    var token = SubscriptionTokenCrypto.Create();
    var s = Sub(x => { x.TokenHash = SubscriptionTokenCrypto.Hash(token); x.Usage.RxBytes = 3; });
    var json = JsonSerializer.Serialize(SubscriptionDetailDto.From(s, "Иван")) + JsonSerializer.Serialize(SubscriptionListItemDto.From(s, "Иван"));
    Check("DTO подписки: ни токена, ни хеша, ни UUID, ни зашифрованного токена",
        !json.Contains(token) && !json.Contains(s.TokenHash) && !json.Contains(Uuid1)
        && !json.Contains("TokenHash") && !json.Contains("TokenEncrypted") && !json.Contains("XrayUuid"));
    Check("DTO подписки: статус и использование на месте", json.Contains("\"Status\":\"active\"") && json.Contains("\"TrafficBytes\":3"));

    var detail = ProtocolDetailDto.From(XCoreProtocol("px", n => { n.SyncError = "ошибка"; n.AppliedAt = now; }));
    var protoJson = JsonSerializer.Serialize(detail);
    Check("DTO узла: безопасные поля xcore — домен, роль, название, подписки, применение, ошибка",
        detail.XCore is { Role: "exit", Domain: "node1.example.com", Title: "Нидерланды", SubscriptionEnabled: true, SyncError: "ошибка" } && detail.XCore.AppliedAt == now);
    Check("DTO узла: ни приватного ключа, ни shortId, ни пути XHTTP, ни образа",
        !protoJson.Contains("Private", StringComparison.OrdinalIgnoreCase) && !protoJson.Contains("a1b2c3d4e5f60718")
        && !protoJson.Contains("x7Kq2mPz") && !protoJson.Contains(XCoreImage) && !protoJson.Contains(PublicKey));
    Check("DTO узла: у не-xcore протокола блок xcore пуст",
        ProtocolDetailDto.From(new ProtocolInstance { Kind = ProtocolKinds.Awg2, ContainerName = "c", Port = "1" }).XCore is null);

    // Панель читает поле как xcore; по умолчанию camelCase дал бы xCore, и блок молча остался бы пустым.
    var webJson = JsonSerializer.Serialize(detail, new JsonSerializerOptions(JsonSerializerDefaults.Web));
    Check("DTO узла: в JSON панели поле называется xcore (не xCore) при настройках ASP.NET",
        webJson.Contains("\"xcore\":{") && !webJson.Contains("\"xCore\""));
}

// ── Повторная выдача (самообслуживание в боте) ───────────────────────────────

Console.WriteLine("Повторная выдача подписки");

{
    const string UserId = "69ca5beaba00e3c10adc4599";
    var store = new List<Subscription>();
    var published = 0;

    // Репозиторий в памяти повторяет то, на чём держится правило: «последняя» — по времени создания,
    // а вторую активную подписку пользователя отклоняет, как уникальный индекс.
    var subscriptionsStub = Stub.Create<ISubscriptionRepository>((method, args) => method.Name switch
    {
        nameof(ISubscriptionRepository.FindActiveByUserAsync) =>
            Task.FromResult(store.FirstOrDefault(s => s.UserId == (string)args[0]! && s.IsActive)),
        nameof(ISubscriptionRepository.FindLatestByUserAsync) =>
            Task.FromResult(store.Where(s => s.UserId == (string)args[0]!).OrderByDescending(s => s.CreatedAt).FirstOrDefault()),
        nameof(ISubscriptionRepository.TryCreateAsync) =>
            Task.FromResult(TryCreate((Subscription)args[0]!)),
        _ => throw new NotSupportedException("Неожиданный вызов репозитория подписок: " + method.Name),
    });
    bool TryCreate(Subscription s)
    {
        if (s.IsActive && store.Any(x => x.UserId == s.UserId && x.IsActive)) return false;
        store.Add(s);
        return true;
    }

    var usersStub = Stub.Create<IUserRepository>((method, args) => method.Name == nameof(IUserRepository.FindByIdAsync)
        ? Task.FromResult((string)args[0]! == UserId ? new User { Id = UserId, Username = "tg_user", PasswordHash = "x" } : null)
        : throw new NotSupportedException("Неожиданный вызов репозитория пользователей: " + method.Name));
    var settingsStub = Stub.Create<IPanelSettingsRepository>((method, _) => method.Name == nameof(IPanelSettingsRepository.GetAsync)
        ? Task.FromResult(new PanelSettings { DefaultExpiryDays = 30, DefaultTrafficLimitBytes = 5L * 1024 * 1024 * 1024 })
        : throw new NotSupportedException("Неожиданный вызов настроек: " + method.Name));
    var secretsStub = Stub.Create<ISecretProtector>((method, _) => method.Name == nameof(ISecretProtector.Protect)
        ? new EncryptedValue { KeyId = "k" }
        : throw new NotSupportedException("Неожиданный вызов шифрования: " + method.Name));
    var auditStub = Stub.Create<IAuditService>((method, _) => method.ReturnType == typeof(Task)
        ? Task.CompletedTask
        : throw new NotSupportedException("Неожиданный вызов журнала: " + method.Name));
    var serversStub = Stub.Create<IVpnServerRepository>((method, _) => method.Name == nameof(IVpnServerRepository.GetAllAsync)
        ? Task.FromResult(new List<VpnServer> { Server("n", "Node", XCoreProtocol("p")) })
        : throw new NotSupportedException("Неожиданный вызов репозитория узлов: " + method.Name));
    var eventsStub = Stub.Create<IDomainEventPublisher>((method, _) =>
    {
        if (method.Name != nameof(IDomainEventPublisher.PublishIfNoPendingAsync))
            throw new NotSupportedException("Неожиданный вызов публикатора: " + method.Name);
        published++;
        return Task.FromResult<DomainEvent?>(new DomainEvent());
    });

    var service = new SubscriptionService(subscriptionsStub, usersStub, settingsStub, serversStub, secretsStub, auditStub,
        new XCoreSyncPublisher(serversStub, eventsStub, NullLogger<XCoreSyncPublisher>.Instance),
        Options.Create(Options0()), NullLogger<SubscriptionService>.Instance);

    Subscription Old(string status, string? reason, int createdDaysAgo) => new()
    {
        Id = ObjectId.GenerateNewId().ToString(), UserId = UserId, XrayUuid = Guid.NewGuid().ToString("D"), TokenHash = Guid.NewGuid().ToString("N"),
        Status = status, RevokeReason = reason, CreatedAt = DateTime.UtcNow.AddDays(-createdDaysAgo),
        RevokedAt = status == SubscriptionStatuses.Revoked ? DateTime.UtcNow.AddDays(-createdDaysAgo + 1) : null,
    };

    // Ветка 4: подписок не было.
    var first = await service.GetOrCreateForUserAsync(UserId, KeySources.Telegram);
    Check("выдача боту: подписок не было — создаётся новая (источник telegram, срок и квота из настроек)",
        first is SelfServiceSubscriptionResult.Granted { Created: true, Subscription: { Source: KeySources.Telegram, TrafficLimitBytes: 5368709120, IsActive: true } g }
        && g.ExpiresAt is { } e && (e - DateTime.UtcNow.AddDays(30)).Duration() < TimeSpan.FromMinutes(1) && store.Count == 1 && published == 1);

    // Ветка 1: активная есть.
    var again = await service.GetOrCreateForUserAsync(UserId, KeySources.Telegram);
    Check("выдача боту: активная есть — возвращается она же, новая не создаётся, синхронизация не публикуется",
        again is SelfServiceSubscriptionResult.Granted { Created: false } same && same.Subscription.Id == store[0].Id && store.Count == 1 && published == 1);

    // Ветка 2: последняя истекла — выдаётся новая, старая остаётся в истории.
    store.Clear();
    var expired = Old(SubscriptionStatuses.Revoked, RevokeReasons.Expired, 40);
    store.Add(expired);
    var afterExpired = await service.GetOrCreateForUserAsync(UserId, KeySources.Telegram);
    Check("выдача боту: последняя отозвана по сроку — создаётся новая, прежняя остаётся отозванной",
        afterExpired is SelfServiceSubscriptionResult.Granted { Created: true } renewed && renewed.Subscription.Id != expired.Id
        && store.Count == 2 && !expired.IsActive && renewed.Subscription.IsActive);

    // Ветка 3: квота и ручной отзыв — отказ, ничего не создаётся и ничего не публикуется.
    foreach (var reason in new[] { RevokeReasons.Quota, RevokeReasons.Manual })
    {
        store.Clear();
        store.Add(Old(SubscriptionStatuses.Revoked, reason, 5));
        var before = published;
        var denied = await service.GetOrCreateForUserAsync(UserId, KeySources.Telegram);
        Check($"выдача боту: последняя отозвана по причине {reason} — отказ с этой причиной, подписка не создаётся",
            denied is SelfServiceSubscriptionResult.Denied d && d.Reason == reason && store.Count == 1 && published == before);
    }

    // Решает именно последняя: старая «manual» не мешает, если после неё была выдача и срок вышел.
    store.Clear();
    store.Add(Old(SubscriptionStatuses.Revoked, RevokeReasons.Manual, 100));
    store.Add(Old(SubscriptionStatuses.Revoked, RevokeReasons.Expired, 10));
    Check("выдача боту: решает последняя по времени создания, а не любая из прежних",
        await service.GetOrCreateForUserAsync(UserId, KeySources.Telegram) is SelfServiceSubscriptionResult.Granted { Created: true });
    store.Clear();
    store.Add(Old(SubscriptionStatuses.Revoked, RevokeReasons.Expired, 100));
    store.Add(Old(SubscriptionStatuses.Revoked, RevokeReasons.Quota, 10));
    Check("выдача боту: старый «expired» не отменяет свежий отказ по квоте",
        await service.GetOrCreateForUserAsync(UserId, KeySources.Telegram) is SelfServiceSubscriptionResult.Denied { Reason: RevokeReasons.Quota });

    // Данные без причины отзыва безопаснее считать отключением администратором.
    store.Clear();
    store.Add(Old(SubscriptionStatuses.Revoked, null, 3));
    Check("выдача боту: отозвана без причины — отказ как при ручном отзыве",
        await service.GetOrCreateForUserAsync(UserId, KeySources.Telegram) is SelfServiceSubscriptionResult.Denied { Reason: RevokeReasons.Manual });

    // Панель правило не затрагивает: администратор выдаёт подписку при любой истории.
    store.Clear();
    store.Add(Old(SubscriptionStatuses.Revoked, RevokeReasons.Quota, 5));
    var byAdmin = await service.CreateAsync(UserId, new SubscriptionCreateOptions(Actor: new AuditActor("admin-id", "admin")));
    Check("выдача боту: администратор из панели создаёт подписку и после отзыва по квоте",
        byAdmin is { Source: KeySources.Panel, IsActive: true } && store.Count == 2);

    Check("выдача боту: несуществующий пользователь — NotFound, а не отказ",
        await CatchAsync<NotFoundException>(() => service.GetOrCreateForUserAsync(ObjectId.GenerateNewId().ToString(), KeySources.Telegram)) is not null);

    // Тексты бота.
    var granted = Sub(x => { x.ExpiresAt = new DateTime(2026, 12, 31, 8, 30, 0, DateTimeKind.Utc); x.TrafficLimitBytes = 10L * 1024 * 1024 * 1024; x.Usage.RxBytes = 1_610_612_736; });
    var message = AmneziaKeyService.Bot.Services.SubscriptionBotMessages.Granted(granted, "https://sub.example.com/sub/TOKEN");
    Check("текст бота: ссылка, срок, трафик из лимита, три шага и предупреждение «не пересылайте»",
        message.Contains("https://sub.example.com/sub/TOKEN") && message.Contains("31.12.2026 08:30 UTC") && message.Contains("1.5 ГиБ из 10 ГиБ")
        && message.Contains("1. Установите приложение Happ (https://www.happ.su).") && message.Contains("3. В Happ нажмите «+» → «Вставить из буфера».")
        && message.Contains("Ссылку не пересылайте: по ней подключается любой."));
    Check("текст бота: без deep link happ://", !message.Contains("happ://"));
    var unlimited = AmneziaKeyService.Bot.Services.SubscriptionBotMessages.Granted(Sub(), "https://sub.example.com/sub/T");
    Check("текст бота: без срока и квоты — «бессрочно», «без ограничения»", unlimited.Contains("бессрочно") && unlimited.Contains("0 Б, без ограничения"));
    var quotaDenied = AmneziaKeyService.Bot.Services.SubscriptionBotMessages.Denied(RevokeReasons.Quota);
    var manualDenied = AmneziaKeyService.Bot.Services.SubscriptionBotMessages.Denied(RevokeReasons.Manual);
    Check("текст бота: отказ называет причину, зовёт администратора и не содержит ссылки",
        quotaDenied == "Подписка отключена (исчерпана квота трафика). Обратитесь к администратору."
        && manualDenied == "Подписка отключена (отключена администратором). Обратитесь к администратору." && !quotaDenied.Contains("/sub/"));
    Check("бот: кнопка меню cmd:sub укладывается в 64 байта callback data",
        Encoding.UTF8.GetByteCount(AmneziaKeyService.Bot.Services.SubscriptionBotMessages.MenuCallback) <= 64
        && AmneziaKeyService.Bot.Services.SubscriptionBotMessages.MenuCallback == "cmd:sub");
    var realLink = Options0().TryBuildUrl(SubscriptionTokenCrypto.Create(), out var botLink) ? botLink : "";
    Check("бот: ссылка с 43-символьным токеном помещается в кнопку копирования (≤ 256)",
        realLink.Length is > 0 and <= AmneziaKeyService.Bot.Services.SubscriptionBotMessages.CopyTextMaxLength, realLink.Length.ToString());

    // QR-код ссылки.
    var qrCaption = AmneziaKeyService.Bot.Services.SubscriptionBotMessages.QrCaption;
    Check("QR: подпись без ссылки и токена, в пределах лимита подписи Telegram (1024)",
        qrCaption == "QR-код подписки — отсканируйте в Happ" && !qrCaption.Contains("http") && !qrCaption.Contains("/sub/") && qrCaption.Length <= 1024);
    var qrPng = AmneziaKeyService.Bot.Services.SubscriptionQr.RenderPng(realLink);
    var qrInfo = QrCheck.ReadHeader(qrPng);
    Check("QR: PNG — сигнатура 89 50 4E 47 0D 0A 1A 0A, заголовок IHDR, квадрат, конец IEND",
        qrPng.AsSpan(0, 8).SequenceEqual(new byte[] { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A }) && qrInfo.Width == qrInfo.Height
        && qrPng.AsSpan(qrPng.Length - 8, 4).SequenceEqual("IEND"u8.ToArray()),
        $"{qrInfo.Width}x{qrInfo.Height}, тип {qrInfo.ColorType}, глубина {qrInfo.BitDepth}");
    Check("QR: размер картинки разумен для чтения с экрана и для Telegram (200..1500 px, меньше 20 КБ)",
        qrInfo.Width is >= 200 and <= 1500 && qrPng.Length < 20 * 1024, $"{qrInfo.Width} px, {qrPng.Length} байт");
    var decoded = QrCheck.Decode(qrPng);
    Check("QR: PNG декодируется обратно в ту же ссылку (ZXing.Net)", decoded == realLink, decoded is null ? "не декодирован" : "ссылка отличается");
    var decoded2 = QrCheck.Decode(AmneziaKeyService.Bot.Services.SubscriptionQr.RenderPng(realLink));
    Check("QR: тот же вход даёт тот же результат (детерминирован)",
        AmneziaKeyService.Bot.Services.SubscriptionQr.RenderPng(realLink).AsSpan().SequenceEqual(qrPng) && decoded2 == realLink);
    var entryLink = "https://sub.entry.example.com/sub/" + SubscriptionTokenCrypto.Create();
    Check("QR: ссылка на домен входа (другая длина) тоже читается",
        QrCheck.Decode(AmneziaKeyService.Bot.Services.SubscriptionQr.RenderPng(entryLink)) == entryLink);
    Check("QR: слишком длинный текст — исключение, а не битая картинка",
        Throws<Exception>(() => AmneziaKeyService.Bot.Services.SubscriptionQr.RenderPng(new string('x', 5000))));
}

// ── Контроллеры ──────────────────────────────────────────────────────────────

Console.WriteLine("Контроллеры");

{
    var feedType = typeof(SubscriptionFeedController);
    var get = feedType.GetMethod(nameof(SubscriptionFeedController.Get))!;
    Check("лента: маршрут GET /sub/{token} — вне /api", get.GetCustomAttribute<HttpGetAttribute>()?.Template == "/sub/{token}"
        && feedType.GetCustomAttribute<RouteAttribute>() is null);
    Check("лента: AllowAnonymous", feedType.GetCustomAttribute<AllowAnonymousAttribute>() is not null);
    Check("лента: политика частоты «subscription»", get.GetCustomAttribute<EnableRateLimitingAttribute>()?.PolicyName == RateLimitPolicies.Subscription
        && RateLimitPolicies.Subscription == "subscription");
    Check("лента: без [ApiController] — иначе 404 получил бы тело ProblemDetails", feedType.GetCustomAttribute<ApiControllerAttribute>() is null);

    var panel = typeof(SubscriptionsController);
    string? PolicyOf(string method) => panel.GetMethod(method)!.GetCustomAttribute<AuthorizeAttribute>()?.Policy;
    Check("панель: маршрут /api/subscriptions, чтение — PanelRead на классе",
        panel.GetCustomAttribute<RouteAttribute>()?.Template == "api/subscriptions"
        && panel.GetCustomAttribute<AuthorizeAttribute>()?.Policy == AuthPolicies.PanelRead);
    Check("панель: список и карточка — только PanelRead (без своей политики)",
        PolicyOf(nameof(SubscriptionsController.GetAll)) is null && PolicyOf(nameof(SubscriptionsController.GetById)) is null);
    Check("панель: ссылка, выдача, отзыв, перевыпуск, лимиты — PanelWrite",
        new[] { nameof(SubscriptionsController.GetLink), nameof(SubscriptionsController.Create), nameof(SubscriptionsController.Revoke),
                nameof(SubscriptionsController.Regenerate), nameof(SubscriptionsController.UpdateLimits) }
            .All(m => PolicyOf(m) == AuthPolicies.PanelWrite));
    Check("панель: маршруты {id}/link, {id}/revoke, {id}/regenerate, {id}/limits",
        panel.GetMethod(nameof(SubscriptionsController.GetLink))!.GetCustomAttribute<HttpGetAttribute>()?.Template == "{id}/link"
        && panel.GetMethod(nameof(SubscriptionsController.Revoke))!.GetCustomAttribute<HttpPostAttribute>()?.Template == "{id}/revoke"
        && panel.GetMethod(nameof(SubscriptionsController.Regenerate))!.GetCustomAttribute<HttpPostAttribute>()?.Template == "{id}/regenerate"
        && panel.GetMethod(nameof(SubscriptionsController.UpdateLimits))!.GetCustomAttribute<HttpPutAttribute>()?.Template == "{id}/limits");

    var apiProgram = File.ReadAllText(Path.Combine(RepoRoot(), "src", "AmneziaKeyService.Api", "Program.cs"));
    Check("Program.cs api: политика частоты «subscription» зарегистрирована (иначе первый же запрос падает)",
        apiProgram.Contains("AddPolicy(RateLimitPolicies.Subscription"));
}

// Переключатель доступности протокола: для xcore это вход или выход топологии, и все узлы xcore
// должны узнать об изменении; для остальных протоколов события не нужны.
{
    var toggled = new List<(string ServerId, string ProtocolId, bool Enabled)>();
    var exitNode = Server("tg-exit", "Exit", XCoreProtocol("tg-xc", n => n.RouteId = 1));
    var awgNode = Server("tg-awg", "Awg", new ProtocolInstance { Id = "tg-awg-p", Kind = ProtocolKinds.Awg2, ContainerName = "amnezia-awg2", Port = "40000", State = ProtocolStates.Installed });
    var entryNode = Server("tg-entry", "Entry", XCoreProtocol("tg-xe", n => n.Role = XCoreRoles.Entry));
    var published = new List<(string Partition, string? Actor)>();

    var serverRepo = Stub.Create<IVpnServerRepository>((m, a) => m.Name switch
    {
        nameof(IVpnServerRepository.GetByIdAsync) => Task.FromResult<VpnServer?>(new[] { exitNode, awgNode, entryNode }.FirstOrDefault(s => s.Id == (string)a[0]!)),
        nameof(IVpnServerRepository.SetProtocolEnabledAsync) => Task.FromResult(true),
        nameof(IVpnServerRepository.GetAllAsync) => Task.FromResult(new List<VpnServer> { exitNode, awgNode, entryNode }),
        _ => throw new NotSupportedException(m.Name),
    });
    var eventsRecorder = Stub.Create<IDomainEventPublisher>((m, a) =>
    {
        if (m.Name != nameof(IDomainEventPublisher.PublishIfNoPendingAsync)) throw new NotSupportedException(m.Name);
        published.Add(((string)a[2]!, (string?)a[4]));
        return Task.FromResult<DomainEvent?>(new DomainEvent());
    });
    var auditRecorder = Stub.Create<IAuditService>((m, _) => m.ReturnType == typeof(Task)
        ? Task.CompletedTask : throw new NotSupportedException(m.Name));
    var controller = new ServersController(
        serverRepo, Stub.Create<IVpnClientRepository>((m, _) => throw new NotSupportedException(m.Name)),
        Stub.Create<IUserRepository>((m, _) => throw new NotSupportedException(m.Name)),
        Stub.Create<IUsageRepository>((m, _) => throw new NotSupportedException(m.Name)),
        Stub.Create<IServerParamsService>((m, _) => throw new NotSupportedException(m.Name)),
        Stub.Create<IInstallService>((m, _) => throw new NotSupportedException(m.Name)),
        Stub.Create<ISecretProtector>((m, _) => throw new NotSupportedException(m.Name)),
        auditRecorder,
        new XCoreSyncPublisher(serverRepo, eventsRecorder, NullLogger<XCoreSyncPublisher>.Instance),
        Stub.Create<IDnsResolver>((m, _) => throw new NotSupportedException(m.Name)),
        Stub.Create<ISshSessionFactory>((m, _) => throw new NotSupportedException(m.Name)),
        Options.Create(new XCoreOptions()))
    {
        ControllerContext = new ControllerContext
        {
            HttpContext = new DefaultHttpContext
            {
                User = new System.Security.Claims.ClaimsPrincipal(new System.Security.Claims.ClaimsIdentity(
                    [new System.Security.Claims.Claim(System.Security.Claims.ClaimTypes.NameIdentifier, "admin-1")], "test")),
            },
        },
    };

    var noContent = await controller.SetProtocolAvailability("tg-awg", "tg-awg-p", new ProtocolAvailabilityRequest(false), default);
    Check("переключатель: протокол не xcore — событий нет", noContent is NoContentResult && published.Count == 0);

    noContent = await controller.SetProtocolAvailability("tg-exit", "tg-xc", new ProtocolAvailabilityRequest(false), default);
    Check("переключатель: выход xcore выключен — синхронизация публикуется на все работающие узлы xcore (с актором панели)",
        noContent is NoContentResult && published.Select(p => p.Partition).Order().SequenceEqual(["tg-entry", "tg-exit"])
        && published.All(p => p.Actor == "admin-1"));

    published.Clear();
    await controller.SetProtocolAvailability("tg-entry", "tg-xe", new ProtocolAvailabilityRequest(true), default);
    Check("переключатель: вход включён — тоже на все узлы xcore", published.Count == 2);
}

// Лента напрямую: контроллер на заглушках репозиториев.
{
    var token = SubscriptionTokenCrypto.Create();
    var stored = Sub(s => s.TokenHash = SubscriptionTokenCrypto.Hash(token));
    var servers = new List<VpnServer> { Server("a", "Alpha", XCoreProtocol("pa")) };
    var lookups = new List<string>();
    var serverReads = 0;

    var subscriptions = Stub.Create<ISubscriptionRepository>((m, a) =>
    {
        if (m.Name != nameof(ISubscriptionRepository.FindByTokenHashAsync)) throw new NotSupportedException(m.Name);
        lookups.Add((string)a[0]!);
        return Task.FromResult<Subscription?>(lookups[^1] == stored.TokenHash ? stored : null);
    });
    var serverRepo = Stub.Create<IVpnServerRepository>((m, _) =>
    {
        if (m.Name != nameof(IVpnServerRepository.GetAllAsync)) throw new NotSupportedException(m.Name);
        serverReads++;
        return Task.FromResult(servers);
    });

    SubscriptionFeedController NewController() => new(subscriptions, serverRepo, Options.Create(Options0()))
    {
        ControllerContext = new ControllerContext { HttpContext = new DefaultHttpContext() },
    };

    var c = NewController();
    var result = await c.Get(new string('a', 10), default);
    Check("лента: мусорный токен → 404 без обращения к базе", result is NotFoundResult && lookups.Count == 0);

    c = NewController();
    result = await c.Get(SubscriptionTokenCrypto.Create(), default);
    Check("лента: неизвестный токен → 404 без тела, поиск по хешу, а не по токену",
        result is NotFoundResult && lookups.Count == 1 && lookups[0].Length == 64);
    Check("лента: 404 тоже с Cache-Control: no-store", c.Response.Headers.CacheControl == "no-store");

    c = NewController();
    result = await c.Get(token, default);
    var content = result as ContentResult;
    Check("лента: активная → 200 с телом из ссылок, text/plain; utf-8",
        content is { StatusCode: null } && content.ContentType == "text/plain; charset=utf-8"
        && Base64Text(content.Content!).StartsWith("vless://"), content?.ContentType);
    Check("лента: Cache-Control: no-store и заголовки Happ в ответе",
        c.Response.Headers.CacheControl == "no-store" && c.Response.Headers["profile-title"] == "VPN"
        && c.Response.Headers["subscription-userinfo"].ToString().StartsWith("upload=") && c.Response.Headers["profile-update-interval"] == "12");
    Check("лента: токен в заголовки и тело открытым текстом не попадает",
        !content!.Content!.Contains(token) && !c.Response.Headers.Values.Any(v => v.ToString().Contains(token)));
    Check("лента: профиль маршрутизации выключен — заголовка routing в ответе нет", !c.Response.Headers.ContainsKey("routing"));

    SubscriptionFeedController RoutingController() => new(subscriptions, serverRepo, Options.Create(Options0(o => o.HappRoutingEnabled = true)))
    {
        ControllerContext = new ControllerContext { HttpContext = new DefaultHttpContext() },
    };
    var rc = RoutingController();
    await rc.Get(token, default);
    Check("лента: профиль включён — заголовок routing в HTTP-ответе (Kestrel принимает значение: ASCII, одна строка)",
        rc.Response.Headers["routing"].ToString().StartsWith("happ://routing/add/") && !rc.Response.Headers["routing"].ToString().Contains('\n')
        && rc.Response.Headers["routing"].ToString().All(ch => ch is >= ' ' and <= '~'));
    var rc2 = RoutingController();
    await rc2.Get(token, default);
    Check("лента: профиль в двух ответах подряд одинаков", rc.Response.Headers["routing"] == rc2.Response.Headers["routing"]);

    // Provider ID: заголовок в HTTP-ответе; fallback-url строится из токена запроса и совпадает с основным.
    var entryHostServers = new List<VpnServer>
    {
        Server("pe", "Entry", XCoreProtocol("ppe", p => { p.Role = XCoreRoles.Entry; p.SubscriptionHost = "sub.entry.example.com"; })),
        Server("px", "Exit", XCoreProtocol("ppx", p => p.RouteId = 1)),
    };
    var entryHostRepo = Stub.Create<IVpnServerRepository>((m, _) =>
        m.Name == nameof(IVpnServerRepository.GetAllAsync) ? Task.FromResult(entryHostServers) : throw new NotSupportedException(m.Name));
    SubscriptionFeedController ProviderController(IVpnServerRepository repo, Action<SubscriptionOptions>? tweak = null) =>
        new(subscriptions, repo, Options.Create(Options0(o => { o.HappProviderId = "ab12CD34"; tweak?.Invoke(o); })))
        {
            ControllerContext = new ControllerContext { HttpContext = new DefaultHttpContext() },
        };
    var pc = ProviderController(entryHostRepo);
    await pc.Get(token, default);
    Check("лента: Provider ID задан — providerid в HTTP-ответе, fallback-url ведёт на {PublicBaseUrl}/sub/{токен запроса}",
        pc.Response.Headers["providerid"] == "ab12CD34" && pc.Response.Headers["fallback-url"] == $"https://sub.example.com/sub/{token}");
    var pcPlain = ProviderController(serverRepo);
    await pcPlain.Get(token, default);
    Check("лента: у входа нет домена подписки — только providerid, fallback-url нет",
        pcPlain.Response.Headers["providerid"] == "ab12CD34" && !pcPlain.Response.Headers.ContainsKey("fallback-url"));
    var pcOff = new SubscriptionFeedController(subscriptions, entryHostRepo, Options.Create(Options0()))
    {
        ControllerContext = new ControllerContext { HttpContext = new DefaultHttpContext() },
    };
    await pcOff.Get(token, default);
    Check("лента: Provider ID не задан — ни providerid, ни fallback-url, хотя домен входа есть",
        !pcOff.Response.Headers.ContainsKey("providerid") && !pcOff.Response.Headers.ContainsKey("fallback-url"));

    stored.Status = SubscriptionStatuses.Revoked;
    serverReads = 0;
    c = NewController();
    content = await c.Get(token, default) as ContentResult;
    Check("лента: отозванная → 200, пустой список, announce; узлы из базы не читаются",
        content is { Content: "" } && c.Response.Headers.ContainsKey("announce") && serverReads == 0);
    rc = RoutingController();
    await rc.Get(token, default);
    Check("лента: отозванная подписка при включённом профиле маршрутизации заголовка routing не получает",
        !rc.Response.Headers.ContainsKey("routing") && rc.Response.Headers.ContainsKey("announce"));

    stored.Status = SubscriptionStatuses.Active;
    stored.TokenHash = SubscriptionTokenCrypto.Hash(SubscriptionTokenCrypto.Create());
    lookups.Clear();
    var forged = Stub.Create<ISubscriptionRepository>((m, _) => Task.FromResult<Subscription?>(stored));
    c = new SubscriptionFeedController(forged, serverRepo, Options.Create(Options0()))
    {
        ControllerContext = new ControllerContext { HttpContext = new DefaultHttpContext() },
    };
    Check("лента: найденная запись с чужим хешем (сбой индекса) не отдаётся", await c.Get(token, default) is NotFoundResult);
}

// ── Токен в логах ────────────────────────────────────────────────────────────

Console.WriteLine("Токен в логах");

{
    var token = SubscriptionTokenCrypto.Create();
    var mixedToken = "aB" + token[2..];
    foreach (var line in new[]
             {
                 $"Request starting HTTP/1.1 GET https://sub.example.com/sub/{mixedToken} - -",
                 $"GET /sub/{mixedToken}?x=1",
                 $"Необработанное исключение на GET /sub/{mixedToken}",
             })
    {
        var clean = SecretRedactor.Redact(line);
        Check($"редактор: токен вырезан из «{line[..Math.Min(34, line.Length)]}…»", !clean.Contains(mixedToken) && clean.Contains("/sub/***"), clean);
    }

    // Настоящий сток: свойства события и текст шаблона.
    var collected = new List<LogEvent>();
    var sink = new SecretRedactingSink(new CollectingSink(collected));
    var template = new MessageTemplateParser().Parse("Request starting {Method} {Path}");
    sink.Emit(new LogEvent(DateTimeOffset.UtcNow, LogEventLevel.Information, null, template,
    [
        new LogEventProperty("Method", new ScalarValue("GET")),
        new LogEventProperty("Path", new ScalarValue($"/sub/{mixedToken}")),
    ]));
    var interpolated = new MessageTemplateParser().Parse($"GET /sub/{mixedToken} rejected");
    sink.Emit(new LogEvent(DateTimeOffset.UtcNow, LogEventLevel.Warning, null, interpolated, []));
    Check("сток: токен вырезан и из свойства Path, и из текста интерполированного сообщения",
        collected.Count == 2 && collected.All(e => !e.RenderMessage().Contains(mixedToken))
        && !collected[0].Properties["Path"].ToString().Contains(mixedToken) && collected[0].RenderMessage().Contains("/sub/***"));

    // Журнал запросов ASP.NET на Information не должен включаться: путь с токеном остался бы в логах
    // тогда, когда редактор по какой-то причине не сработал.
    using var prod = JsonDocument.Parse(File.ReadAllText(Path.Combine(RepoRoot(), "src", "AmneziaKeyService.Api", "appsettings.json")));
    var overrides = prod.RootElement.GetProperty("Serilog").GetProperty("MinimumLevel").GetProperty("Override");
    Check("конфиг: Microsoft.AspNetCore не ниже Warning — «Request starting …» с путём не пишется",
        overrides.TryGetProperty("Microsoft.AspNetCore", out var level) && level.GetString() is "Warning" or "Error" or "Fatal");
    using var dev = JsonDocument.Parse(File.ReadAllText(Path.Combine(RepoRoot(), "src", "AmneziaKeyService.Api", "appsettings.Development.json")));
    var devOverrides = dev.RootElement.GetProperty("Serilog").GetProperty("MinimumLevel").GetProperty("Override");
    Check("конфиг (Development): Microsoft не ниже Warning",
        devOverrides.TryGetProperty("Microsoft", out var devLevel) && devLevel.GetString() is "Warning" or "Error" or "Fatal");
    Check("Program.cs api: собственного журнала запросов (UseSerilogRequestLogging) нет",
        !File.ReadAllText(Path.Combine(RepoRoot(), "src", "AmneziaKeyService.Api", "Program.cs")).Contains("UseSerilogRequestLogging"));
}

// ── Provider ID Happ ─────────────────────────────────────────────────────────

Console.WriteLine("Provider ID Happ: providerid и fallback-url");

{
    const string Token = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ";   // 43 символа base64url
    ProtocolInstance EntryWith(string id, string? host, Action<ProtocolInstance>? tweakProtocol = null) =>
        XCoreProtocol(id, p => { p.Role = XCoreRoles.Entry; p.SubscriptionHost = host; }, tweakProtocol);

    VpnServer[] withHost = [Server("e1", "Entry", EntryWith("pe1", "sub.entry.example.com")), Server("x1", "Exit", XCoreProtocol("px1", p => p.RouteId = 1))];
    VpnServer[] withoutHost = [Server("e0", "Entry", EntryWith("pe0", null)), Server("x1", "Exit", XCoreProtocol("px1", p => p.RouteId = 1))];
    var active = Sub();
    SubscriptionFeed Feed(Action<SubscriptionOptions>? tweak, VpnServer[] servers, Subscription? sub = null, string? token = Token) =>
        SubscriptionRenderer.Render(sub ?? active, servers, Options0(tweak), now, token);

    Check("provider id: по умолчанию выключен — ни providerid, ни fallback-url, даже если домен входа есть и токен известен",
        new SubscriptionOptions().HappProviderId is null
        && !Feed(null, withHost).Headers.ContainsKey("providerid") && !Feed(null, withHost).Headers.ContainsKey("fallback-url"));
    Check("provider id: пустая строка и пробелы — то же, что выключено",
        !Feed(o => o.HappProviderId = "", withHost).Headers.ContainsKey("providerid")
        && !Feed(o => o.HappProviderId = "   ", withHost).Headers.ContainsKey("fallback-url"));

    var withId = Feed(o => o.HappProviderId = "ab12CD34", withoutHost);
    Check("provider id: задан — заголовок providerid со значением как есть (имя в нижнем регистре, как у остальных)",
        withId.Headers["providerid"] == "ab12CD34" && withId.Headers.Keys.All(k => k == k.ToLowerInvariant()));
    Check("provider id: значение обрезается по краям", Feed(o => o.HappProviderId = "  ab12CD34 \n", withoutHost).Headers["providerid"] == "ab12CD34");
    Check("provider id: без домена подписки у входа запасного адреса нет — fallback-url не отправляется",
        !withId.Headers.ContainsKey("fallback-url"));

    var withFallback = Feed(o => o.HappProviderId = "ab12CD34", withHost);
    var primary = SubscriptionRenderer.TryBuildSubscriptionUrl(Token, withHost, Options0(), out var primaryUrl) ? primaryUrl : "";
    Check("fallback-url: основная ссылка на домене входа — запасная {PublicBaseUrl}/sub/{токен}",
        primary == $"https://sub.entry.example.com/sub/{Token}"
        && withFallback.Headers["fallback-url"] == $"https://sub.example.com/sub/{Token}");
    Check("fallback-url: токен запасной ссылки тот же, что в основной",
        withFallback.Headers["fallback-url"].Split("/sub/")[1] == primary.Split("/sub/")[1] && withFallback.Headers["fallback-url"].Split("/sub/")[1] == Token);
    Check("fallback-url: полный абсолютный URL, одна строка, только ASCII (Kestrel принимает)",
        Uri.TryCreate(withFallback.Headers["fallback-url"], UriKind.Absolute, out var fallbackUri) && fallbackUri.Scheme == "https"
        && withFallback.Headers.Values.All(IsAsciiHeader));
    Check("fallback-url: без токена (вызов без него) заголовка нет — токена открытым текстом в подписке нет",
        !Feed(o => o.HappProviderId = "ab12CD34", withHost, token: null).Headers.ContainsKey("fallback-url")
        && Feed(o => o.HappProviderId = "ab12CD34", withHost, token: null).Headers.ContainsKey("providerid"));
    Check("fallback-url: глобальный адрес не задан — запасной ссылки построить нельзя, заголовка нет",
        !Feed(o => { o.HappProviderId = "ab12CD34"; o.PublicBaseUrl = null; }, withHost).Headers.ContainsKey("fallback-url"));
    Check("fallback-url: домен входа совпал с глобальным адресом — основная и запасная одинаковы, заголовка нет",
        !Feed(o => { o.HappProviderId = "ab12CD34"; o.PublicBaseUrl = "https://sub.entry.example.com"; }, withHost).Headers.ContainsKey("fallback-url"));
    Check("fallback-url: без Provider ID он не отправляется (расширенные заголовки работают только с ним)",
        !Feed(null, withHost).Headers.ContainsKey("fallback-url"));

    var revokedWith = Feed(o => o.HappProviderId = "ab12CD34", withHost, Sub(s => s.Status = SubscriptionStatuses.Revoked));
    Check("отозванная подписка: providerid остаётся (привязка устройства к аккаунту), fallback-url — нет",
        revokedWith.Headers["providerid"] == "ab12CD34" && !revokedWith.Headers.ContainsKey("fallback-url") && revokedWith.Body == "");

    Check("provider id: значение с пробелом, переводом строки, табуляцией или не-ASCII считается невалидным — заголовка нет, ответ не ломается",
        new[] { "ab 12", "ab\r\nX-Evil: 1", "идентификатор", "ab\u007f", "ab\tcd" }.All(bad =>
            !Feed(o => o.HappProviderId = bad, withHost).Headers.ContainsKey("providerid")
            && !Feed(o => o.HappProviderId = bad, withHost).Headers.ContainsKey("fallback-url")));
    Check("provider id: лишних заголовков нет — ровно прежние плюс providerid и fallback-url",
        withFallback.Headers.Keys.Order().SequenceEqual(
            Feed(null, withHost).Headers.Keys.Concat(["fallback-url", "providerid"]).Order()));
}

// ── Ссылка подписки на домен входа ───────────────────────────────────────────

Console.WriteLine("Ссылка подписки: домен подписки входа");

{
    const string Token = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ";   // 43 символа base64url
    ProtocolInstance EntryWith(string id, int order, string? host, Action<ProtocolInstance>? tweakProtocol = null) =>
        XCoreProtocol(id, p => { p.Role = XCoreRoles.Entry; p.SortOrder = order; p.SubscriptionHost = host; }, tweakProtocol);

    var withoutHost = new[] { Server("e0", "Entry", EntryWith("pe0", 0, null)), Server("x0", "Exit", XCoreProtocol("px0", p => p.RouteId = 1)) };
    var global = Options0();
    Check("ссылка: ни у одного входа нет домена подписки — глобальный PublicBaseUrl",
        SubscriptionRenderer.TryBuildSubscriptionUrl(Token, withoutHost, global, out var url) && url == $"https://sub.example.com/sub/{Token}"
        && SubscriptionRenderer.SubscriptionHostOf(withoutHost) is null);

    var withHost = new[] { Server("e1", "Entry", EntryWith("pe1", 0, "sub.entry.example.com")) };
    Check("ссылка: у входа есть домен подписки — https://{домен}/sub/{токен}, глобальный адрес не нужен",
        SubscriptionRenderer.TryBuildSubscriptionUrl(Token, withHost, Options0(o => o.PublicBaseUrl = null), out url)
        && url == $"https://sub.entry.example.com/sub/{Token}");
    Check("ссылка: домен входа сильнее глобального адреса",
        SubscriptionRenderer.TryBuildSubscriptionUrl(Token, withHost, global, out url) && url.StartsWith("https://sub.entry.example.com/sub/"));

    var several = new[]
    {
        Server("e3", "Third", EntryWith("pe3", 5, "sub-c.example.com")),
        Server("e2", "Second", EntryWith("pe2", 2, "sub-b.example.com")),
        Server("e1", "First-no-host", EntryWith("pe1", 0, null)),
        Server("e4", "Hidden", EntryWith("pe4", 1, "sub-hidden.example.com", p => p.XCore!.SubscriptionEnabled = false)),
        Server("e5", "Off", EntryWith("pe5", 1, "sub-off.example.com", p => p.Enabled = false)),
        Server("e6", "Installing", EntryWith("pe6", 1, "sub-installing.example.com", p => p.State = ProtocolStates.Installing)),
        Server("x1", "Exit", XCoreProtocol("px1", p => { p.RouteId = 1; p.SortOrder = -5; p.SubscriptionHost = "sub-exit.example.com"; })),
    };
    Check("ссылка: берётся первый по порядку показа вход, обслуживающий подписки и имеющий домен подписки (без домена, скрытые, выключенные, ставящиеся и выходы пропускаются)",
        SubscriptionRenderer.SubscriptionHostOf(several) == "sub-b.example.com"
        && SubscriptionRenderer.TryBuildSubscriptionUrl(Token, several, global, out url) && url == $"https://sub-b.example.com/sub/{Token}",
        SubscriptionRenderer.SubscriptionHostOf(several));
    Check("ссылка: пустой домен подписки (пробелы) домена не задаёт",
        SubscriptionRenderer.SubscriptionHostOf([Server("e7", "Blank", EntryWith("pe7", 0, "  "))]) is null);
    Check("ссылка: нет ни домена входа, ни глобального адреса — построить нельзя",
        !SubscriptionRenderer.TryBuildSubscriptionUrl(Token, withoutHost, Options0(o => o.PublicBaseUrl = null), out url) && url == "");

    // Сервис: ссылка и проверка возможности её построить читают узлы из базы.
    var secrets = Stub.Create<ISecretProtector>((m, _) => m.Name == nameof(ISecretProtector.Unprotect)
        ? Token : throw new NotSupportedException(m.Name));
    var nodes = new List<VpnServer>(withoutHost);
    var nodeRepo = Stub.Create<IVpnServerRepository>((m, _) => m.Name == nameof(IVpnServerRepository.GetAllAsync)
        ? Task.FromResult(nodes.ToList()) : throw new NotSupportedException(m.Name));
    SubscriptionService LinkService(SubscriptionOptions options) => new(
        Stub.Create<ISubscriptionRepository>((m, _) => throw new NotSupportedException(m.Name)),
        Stub.Create<IUserRepository>((m, _) => throw new NotSupportedException(m.Name)),
        Stub.Create<IPanelSettingsRepository>((m, _) => throw new NotSupportedException(m.Name)),
        nodeRepo, secrets, Stub.Create<IAuditService>((m, _) => throw new NotSupportedException(m.Name)),
        new XCoreSyncPublisher(nodeRepo, Stub.Create<IDomainEventPublisher>((m, _) => throw new NotSupportedException(m.Name)), NullLogger<XCoreSyncPublisher>.Instance),
        Options.Create(options), NullLogger<SubscriptionService>.Instance);
    var active = Sub(s => { s.TokenEncrypted = new EncryptedValue { KeyId = "k" }; });

    var service = LinkService(Options0());
    Check("сервис: домена входа нет — ссылка на глобальный адрес",
        await service.BuildLinkAsync(active) == $"https://sub.example.com/sub/{Token}" && await service.CanBuildLinkAsync());
    nodes.Add(Server("e8", "With host", EntryWith("pe8", 0, "sub.entry.example.com")));
    Check("сервис: домен подписки появился у входа — та же подписка получает ссылку на него",
        await service.BuildLinkAsync(active) == $"https://sub.entry.example.com/sub/{Token}");
    var noGlobal = LinkService(Options0(o => o.PublicBaseUrl = null));
    Check("сервис: без глобального адреса, но с доменом входа ссылка строится (бот и панель не отказывают)",
        await noGlobal.BuildLinkAsync(active) == $"https://sub.entry.example.com/sub/{Token}" && await noGlobal.CanBuildLinkAsync());
    nodes.RemoveAt(nodes.Count - 1);
    var noAddress = await CatchAsync<BadRequestException>(() => noGlobal.BuildLinkAsync(active));
    Check("сервис: нет ни глобального адреса, ни домена входа — ошибка с названием настройки, и CanBuildLink = false",
        noAddress?.Message.Contains("Subscription:PublicBaseUrl") == true && !await noGlobal.CanBuildLinkAsync(), noAddress?.Message);
    var revokedLink = await CatchAsync<BadRequestException>(() => service.BuildLinkAsync(Sub(s => { s.Status = SubscriptionStatuses.Revoked; s.TokenEncrypted = new EncryptedValue { KeyId = "k" }; })));
    Check("сервис: ссылка отозванной подписки не выдаётся и с доменом входа", revokedLink is not null);
}

// ── Лимит частоты /sub/ по токену ────────────────────────────────────────────

Console.WriteLine("Лимит частоты /sub/");

{
    HttpContext Request(string? token, string ip, string path = "/sub/")
    {
        var context = new DefaultHttpContext();
        context.Connection.RemoteIpAddress = System.Net.IPAddress.Parse(ip);
        context.Request.Path = path + token;
        if (token is not null) context.Request.RouteValues["token"] = token;
        return context;
    }

    string TokenA = SubscriptionTokenCrypto.Create(), TokenB = SubscriptionTokenCrypto.Create();
    using var perToken = System.Threading.RateLimiting.PartitionedRateLimiter.Create<HttpContext, string>(SubscriptionRateLimiting.TokenPartition);
    int Permitted(HttpContext context, int attempts) =>
        Enumerable.Range(0, attempts).Count(_ => { using var lease = perToken.AttemptAcquire(context); return lease.IsAcquired; });

    // Все клиенты за прокси входа приходят с одного IP.
    const string ProxyIp = "198.51.100.7";
    Check("лимит: токен A исчерпывает свои 30 запросов в минуту — 31-й получает отказ (429)", Permitted(Request(TokenA, ProxyIp), 31) == 30);
    Check("лимит: токен B с того же IP не затронут исчерпанным токеном A — свои 30 запросов",
        Permitted(Request(TokenB, ProxyIp), 31) == 30);
    Check("лимит: токен A исчерпан и с другого IP — лимит принадлежит токену, а не адресу",
        Permitted(Request(TokenA, "203.0.113.50"), 5) == 0);
    Check("лимит: ключ партиции — SHA-256 токена, самого токена в ключе нет",
        SubscriptionRateLimiting.PartitionKey(Request(TokenA, ProxyIp)) == "token:" + SubscriptionTokenCrypto.Hash(TokenA)
        && !SubscriptionRateLimiting.PartitionKey(Request(TokenA, ProxyIp)).Contains(TokenA));

    // Токен не похож на настоящий: лимит по IP.
    foreach (var junk in new[] { "short", new string('a', 44), new string('!', 43) })
        Check($"лимит: токен «{(junk.Length > 8 ? junk[..8] + "…" : junk)}» ({junk.Length} симв.) не похож на настоящий — партиция по IP",
            SubscriptionRateLimiting.PartitionKey(Request(junk, ProxyIp)) == "ip:" + ProxyIp);
    Check("лимит: мусорные токены с одного IP делят 30 запросов, другой IP — отдельно",
        Enumerable.Range(0, 40).Count(i => { using var lease = perToken.AttemptAcquire(Request("junk" + i, "198.51.100.99")); return lease.IsAcquired; }) == 30
        && Permitted(Request("junk", "198.51.100.100"), 3) == 3);
    Check("лимит: без значения маршрута (запрос не дошёл до действия) — партиция по IP",
        SubscriptionRateLimiting.PartitionKey(Request(null, "198.51.100.5")) == "ip:198.51.100.5");

    // Общий лимит на маршрут против перебора.
    using var perRoute = System.Threading.RateLimiting.PartitionedRateLimiter.Create<HttpContext, string>(SubscriptionRateLimiting.RoutePartition);
    var routePermitted = Enumerable.Range(0, 650).Count(_ => { using var lease = perRoute.AttemptAcquire(Request(SubscriptionTokenCrypto.Create(), "198.51.100.8")); return lease.IsAcquired; });
    Check("лимит: общий лимит маршрута — 600 запросов в минуту суммарно, даже если каждый токен новый", routePermitted == 600, routePermitted.ToString());
    Check("лимит: общий лимит чужих путей не касается (1000 запросов к /api — все проходят)",
        Enumerable.Range(0, 1000).All(_ => { using var lease = perRoute.AttemptAcquire(Request(null, "198.51.100.8", "/api/servers")); return lease.IsAcquired; }));
    Check("лимит: константы — 30 на токен, 600 на маршрут, окно минута",
        SubscriptionRateLimiting.PerTokenPermitLimit == 30 && SubscriptionRateLimiting.RoutePermitLimit == 600 && SubscriptionRateLimiting.Window == TimeSpan.FromMinutes(1));

    // Цепочка, как в конвейере: общий лимит и лимит токена применяются вместе.
    using var chained = System.Threading.RateLimiting.PartitionedRateLimiter.CreateChained(
        System.Threading.RateLimiting.PartitionedRateLimiter.Create<HttpContext, string>(SubscriptionRateLimiting.RoutePartition),
        System.Threading.RateLimiting.PartitionedRateLimiter.Create<HttpContext, string>(SubscriptionRateLimiting.TokenPartition));
    var tokenC = SubscriptionTokenCrypto.Create();
    Check("лимит: в цепочке 31-й запрос одного токена получает отказ, а запрос другого токена проходит",
        Enumerable.Range(0, 31).Count(_ => { using var lease = chained.AttemptAcquire(Request(tokenC, "198.51.100.9")); return lease.IsAcquired; }) == 30
        && chained.AttemptAcquire(Request(SubscriptionTokenCrypto.Create(), "198.51.100.9")).IsAcquired);

    // Тот же порядок middleware, что в Program.cs, на настоящем Kestrel: значение маршрута {token} должно быть
    // доступно лимитеру к этому моменту, иначе партиция молча упадёт на IP и лимит снова станет общим для всех
    // клиентов за прокси входа.
    var builder = WebApplication.CreateBuilder();
    builder.WebHost.UseSetting(WebHostDefaults.ServerUrlsKey, "http://127.0.0.1:0");
    builder.Logging.ClearProviders();
    builder.Services.AddRateLimiter(options =>
    {
        options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
        options.AddPolicy(RateLimitPolicies.Subscription, SubscriptionRateLimiting.TokenPartition);
        options.GlobalLimiter = System.Threading.RateLimiting.PartitionedRateLimiter.Create<HttpContext, string>(SubscriptionRateLimiting.RoutePartition);
    });
    await using var pipeline = builder.Build();
    pipeline.UseRateLimiter();
    pipeline.MapGet("/sub/{token}", () => "ok").RequireRateLimiting(RateLimitPolicies.Subscription);
    await pipeline.StartAsync();
    using var http = new HttpClient { BaseAddress = new Uri(pipeline.Urls.First()) };
    async Task<int> Status(string token) => (int)(await http.GetAsync("/sub/" + token)).StatusCode;
    string pipeA = SubscriptionTokenCrypto.Create(), pipeB = SubscriptionTokenCrypto.Create();
    var statusesA = new List<int>();
    for (var i = 0; i < 31; i++) statusesA.Add(await Status(pipeA));
    Check("лимит в конвейере: 30 запросов токена проходят, 31-й получает 429",
        statusesA.Take(30).All(code => code == 200) && statusesA[30] == 429, string.Join(",", statusesA.TakeLast(3)));
    Check("лимит в конвейере: другой токен с того же IP не затронут", await Status(pipeB) == 200);
    await pipeline.StopAsync();

    // Подключение в конвейере.
    var apiProgram = File.ReadAllText(Path.Combine(RepoRoot(), "src", "AmneziaKeyService.Api", "Program.cs"));
    Check("Program.cs api: политика subscription берёт разделитель из SubscriptionRateLimiting, общий лимит — глобальный лимитер",
        apiProgram.Contains("AddPolicy(RateLimitPolicies.Subscription, SubscriptionRateLimiting.TokenPartition)")
        && apiProgram.Contains("GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(SubscriptionRateLimiting.RoutePartition)"));
}

// ── Настройки xcore: необязательный subscriptionEnabled ──────────────────────

Console.WriteLine("Настройки xcore");

{
    ProtocolInstance XcoreOf(bool enabled) => new()
    {
        Kind = ProtocolKinds.XCore, State = ProtocolStates.Installed,
        XCore = new XCoreProtocolParams { Role = XCoreRoles.Exit, Domain = "nl1.example.com", SubscriptionEnabled = enabled },
    };
    // Запрос, забывший поле, не должен молча убирать узел из подписок у всех пользователей.
    Check("настройки: без subscriptionEnabled включённый узел остаётся в подписках",
        XCoreSettingsRules.Validate(XcoreOf(true), new XCoreSettingsRequest { Title = "NL" }, null).SubscriptionEnabled);
    Check("настройки: без subscriptionEnabled выключенный узел остаётся выключенным",
        !XCoreSettingsRules.Validate(XcoreOf(false), new XCoreSettingsRequest(), null).SubscriptionEnabled);
    Check("настройки: явное значение применяется в обе стороны",
        !XCoreSettingsRules.Validate(XcoreOf(true), new XCoreSettingsRequest { SubscriptionEnabled = false }, null).SubscriptionEnabled
        && XCoreSettingsRules.Validate(XcoreOf(false), new XCoreSettingsRequest { SubscriptionEnabled = true }, null).SubscriptionEnabled);
}

// ── Регистрация в DI ─────────────────────────────────────────────────────────

Console.WriteLine("Регистрация в DI");

{
    var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
    {
        // Клиент MongoDB создаётся при построении контейнера, но к базе не подключается.
        ["MongoDb:ConnectionString"] = "mongodb://localhost:27017",
        ["Security:DataProtectionKey"] = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)),
        ["Subscription:PublicBaseUrl"] = "https://sub.example.com/",
        ["Subscription:ProfileTitle"] = "Мой VPN",
        ["Subscription:UpdateIntervalHours"] = "6",
    }).Build();
    var services = new ServiceCollection();
    services.AddLogging();
    services.AddAmneziaData(config);
    services.AddAmneziaMigrations();
    using var provider = services.BuildServiceProvider(new ServiceProviderOptions { ValidateScopes = true, ValidateOnBuild = true });
    using var scope = provider.CreateScope();

    Check("DI: SubscriptionService и ISubscriptionRepository разрешаются без SSH (AddAmneziaData)",
        scope.ServiceProvider.GetRequiredService<SubscriptionService>() is not null
        && provider.GetRequiredService<ISubscriptionRepository>() is not null && provider.GetRequiredService<XCoreSyncPublisher>() is not null);
    var options = scope.ServiceProvider.GetRequiredService<IOptions<SubscriptionOptions>>().Value;
    Check("DI: секция Subscription читается из конфигурации",
        options is { PublicBaseUrl: "https://sub.example.com/", ProfileTitle: "Мой VPN", UpdateIntervalHours: 6 });
    var migrations = provider.GetServices<IMongoMigration>().Select(m => m.Id).ToList();
    Check("DI: миграция 017_xcore_route_id_unique зарегистрирована последней, идентификаторы не повторяются",
        migrations[^1] == "017_xcore_route_id_unique" && migrations.Distinct().Count() == migrations.Count, string.Join(",", migrations.TakeLast(3)));
    Check("DI: общий API-ключ шифрования доступен сервису подписок", scope.ServiceProvider.GetRequiredService<ISecretProtector>() is not null);
}

// Состав бота повторяет его Program.cs: бот создаёт подписку сам, и без репозитория событий, настроек
// или шифрования она не собралась бы — а выяснилось бы это только при нажатии кнопки.
{
    var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
    {
        ["MongoDb:ConnectionString"] = "mongodb://localhost:27017",
        ["Security:DataProtectionKey"] = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)),
        ["Subscription:PublicBaseUrl"] = "https://sub.example.com",
    }).Build();
    var services = new ServiceCollection();
    services.AddLogging();
    services.AddAmneziaData(config);
    services.AddAmneziaMigrations();
    services.AddAmneziaProtocols();
    services.AddHostedService<AmneziaKeyService.Bot.Services.TelegramBotService>();
    using var provider = services.BuildServiceProvider(new ServiceProviderOptions { ValidateScopes = true, ValidateOnBuild = true });
    using var scope = provider.CreateScope();

    Check("DI бот: TelegramBotService собирается (адрес подписок, события, настройки, шифрование)",
        provider.GetServices<Microsoft.Extensions.Hosting.IHostedService>().Any(h => h is AmneziaKeyService.Bot.Services.TelegramBotService));
    Check("DI бот: SubscriptionService разрешается в области (так его берёт бот через IServiceScopeFactory)",
        scope.ServiceProvider.GetRequiredService<SubscriptionService>() is not null);
}

// Состав worker: обработчик и воркеры подписок должны и собираться, и быть зарегистрированы.
// Забытая регистрация обработчика не даёт ни ошибки, ни предупреждения: события xcore.sync
// накапливаются в очереди, а подписчики не доходят до узлов.
{
    var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
    {
        ["MongoDb:ConnectionString"] = "mongodb://localhost:27017",
        ["Security:DataProtectionKey"] = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)),
        ["XCore:AcmeEmail"] = "ops@example.com",
    }).Build();
    var services = new ServiceCollection();
    services.AddLogging();
    services.AddAmneziaData(config);
    services.AddAmneziaProtocols();
    services.AddAmneziaNodeAccess();
    services.AddAmneziaInstallExecution();
    services.AddAmneziaKeyIssuing();
    services.AddScoped<IDomainEventHandler, XCoreSyncHandler>();
    using var provider = services.BuildServiceProvider(new ServiceProviderOptions { ValidateScopes = true, ValidateOnBuild = true });
    using var scope = provider.CreateScope();

    Check("DI worker: обработчик xcore.sync собирается со всеми зависимостями (SSH, синхронизация, репозитории)",
        scope.ServiceProvider.GetServices<IDomainEventHandler>().Any(h => h.EventType == DomainEventTypes.XCoreSync));
    Check("DI worker: оркестратор установки получает публикатор синхронизации",
        scope.ServiceProvider.GetRequiredService<AmneziaKeyService.Infrastructure.Install.InstallOrchestrator>() is not null);
    var polling = Options.Create(new PollingOptions());
    var scopes = provider.GetRequiredService<IServiceScopeFactory>();
    Check("DI worker: воркеры учёта трафика и сверки xcore строятся",
        ActivatorUtilities.CreateInstance<XCoreStatsPoller>(provider, scopes, polling) is not null
        && ActivatorUtilities.CreateInstance<XCoreReconcileService>(provider, scopes, polling) is not null);

    var workerProgram = File.ReadAllText(Path.Combine(RepoRoot(), "src", "AmneziaKeyService.Worker", "Program.cs"));
    Check("Program.cs worker: зарегистрированы XCoreSyncHandler, XCoreStatsPoller и XCoreReconcileService",
        workerProgram.Contains("AddScoped<IDomainEventHandler, XCoreSyncHandler>()")
        && workerProgram.Contains("AddHostedService<XCoreStatsPoller>()") && workerProgram.Contains("AddHostedService<XCoreReconcileService>()"));
}

// ── MongoDB ──────────────────────────────────────────────────────────────────

Console.WriteLine("MongoDB (индексы, события, принуждение)");

var mongoArg = args.FirstOrDefault(a => a.StartsWith("--mongo=", StringComparison.Ordinal));
if (mongoArg is null)
{
    Console.WriteLine("  [ПРОПУСК] без флага --mongo=<url>; запуск: dotnet run --project tools/VerifySubscriptions -- --mongo=mongodb://localhost:27017");
}
else
{
    var connection = mongoArg["--mongo=".Length..];
    var database = $"amnezia_subscriptions_probe_{Guid.NewGuid().ToString("N")[..8]}";
    Console.WriteLine($"  База {database} на {connection}");
    var client = new MongoClient(connection);

    try
    {
        await RunMongoChecksAsync(connection, database, client);
        await RunXCoreSettingsMongoChecksAsync(connection, database, client);
    }
    finally
    {
        await client.DropDatabaseAsync(database);
        Console.WriteLine($"  Временная база {database} удалена.");
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

Console.WriteLine("Подписки соответствуют ожиданиям.");
return 0;

// ─────────────────────────────────────────────────────────────────────────────

// Этап C2 на реальной базе: уникальность номера маршрута (M017), точечные записи настроек xcore, здоровье плеч,
// ревизия Caddyfile и PUT настроек из панели целиком — от проверки запроса до события xcore.sync.
async Task RunXCoreSettingsMongoChecksAsync(string connection, string database, MongoClient client)
{
    var db = client.GetDatabase(database);
    var ct = CancellationToken.None;
    var mongoOptions = Options.Create(new MongoDbOptions { DatabaseName = database });
    await new M010_DomainEvents(mongoOptions).ApplyAsync(db, ct);

    var serversCollection = db.GetCollection<BsonDocument>(new MongoDbOptions().ServerConfigCollection);
    await serversCollection.DeleteManyAsync(FilterDefinition<BsonDocument>.Empty, ct);
    var eventsCollection = db.GetCollection<DomainEvent>("domain_events");
    await eventsCollection.DeleteManyAsync(FilterDefinition<DomainEvent>.Empty, ct);

    var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
    {
        ["MongoDb:ConnectionString"] = connection,
        ["MongoDb:DatabaseName"] = database,
        ["Security:DataProtectionKey"] = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)),
    }).Build();
    var services = new ServiceCollection();
    services.AddLogging();
    services.AddAmneziaData(config);
    using var provider = services.BuildServiceProvider(new ServiceProviderOptions { ValidateScopes = true });
    var serverRepo = provider.GetRequiredService<IVpnServerRepository>();
    var protector = provider.GetRequiredService<ISecretProtector>();

    // ── M017 ─────────────────────────────────────────────────────────────────

    // До миграции индекса нет: так выглядит база после M016.
    var m017 = new M017_XCoreRouteIdUnique(mongoOptions);
    await m017.ApplyAsync(db, ct);
    await m017.ApplyAsync(db, ct);   // повтор не должен падать: имя индекса автоматическое

    var serverIndexes = await (await serversCollection.Indexes.ListAsync(ct)).ToListAsync(ct);
    var routeIndex = serverIndexes.FirstOrDefault(i => i["key"].AsBsonDocument.ElementCount == 1 && i["key"].AsBsonDocument.Contains("protocols.xcore.routeId"));
    Check("M017: уникальный sparse-индекс по protocols.xcore.routeId, без partialFilterExpression",
        routeIndex is not null && routeIndex.GetValue("unique", false).ToBoolean() && routeIndex.GetValue("sparse", false).ToBoolean()
        && !routeIndex.Contains("partialFilterExpression"), routeIndex?.ToJson());

    ProtocolInstance Awg() => new() { Id = "awg-" + Guid.NewGuid().ToString("N")[..6], Kind = ProtocolKinds.Awg2, ContainerName = "amnezia-awg2", Port = "40000", State = ProtocolStates.Installed };
    ProtocolInstance XC(string role, int? route, Action<XCoreProtocolParams>? tweak = null)
    {
        var p = XCoreProtocol("xc-" + Guid.NewGuid().ToString("N")[..6], x =>
        {
            x.Role = role;
            x.RouteId = route;
            x.Domain = $"n{Guid.NewGuid().ToString("N")[..6]}.example.com";
            x.RelayUuid = role == XCoreRoles.Entry ? protector.Protect(Guid.NewGuid().ToString("D")) : null;
            x.RealityPrivateKey = protector.Protect("PRIVATE-KEY-" + Guid.NewGuid().ToString("N"));
            tweak?.Invoke(x);
        });
        return p;
    }
    async Task<VpnServer> Create(string name, params ProtocolInstance[] protocols)
    {
        var s = new VpnServer { Id = ObjectId.GenerateNewId().ToString(), Name = name, Host = "203.0.113.10", Protocols = [.. protocols] };
        return await serverRepo.CreateAsync(s, ct);
    }
    async Task<bool> Rejected(Func<Task> action)
    {
        try { await action(); return false; }
        catch (RouteIdTakenException) { return true; }
    }

    // Узлы, в которых есть и выход с номером, и другой протокол, не мешают друг другу: с индексом по частичному
    // фильтру два таких узла упирались на null (проверено на MongoDB 6.0.5), поэтому индекс sparse.
    var exitA = await Create("Exit A", XC(XCoreRoles.Exit, 1), Awg());
    var exitB = await Create("Exit B", XC(XCoreRoles.Exit, 2), Awg());
    var entryX = await Create("Entry X", XC(XCoreRoles.Entry, null), Awg());
    var entryY = await Create("Entry Y", XC(XCoreRoles.Entry, null), Awg());
    var onlyAwg1 = await Create("Awg 1", Awg());
    var onlyAwg2 = await Create("Awg 2", Awg());
    Check("M017: узлы с выходом и вторым протоколом, узлы с входом без номера и узлы без xcore сосуществуют (шесть узлов записаны)",
        (await serversCollection.CountDocumentsAsync(FilterDefinition<BsonDocument>.Empty, cancellationToken: ct)) == 6);

    var duplicateExit = new VpnServer { Id = ObjectId.GenerateNewId().ToString(), Name = "Dup", Host = "203.0.113.11", Protocols = [XC(XCoreRoles.Exit, 1)] };
    var insertDuplicate = await CatchAsync<MongoWriteException>(() => serverRepo.CreateAsync(duplicateExit, ct));
    Check("M017: второй выход с тем же номером маршрута отклонён индексом (DuplicateKey)",
        insertDuplicate?.WriteError.Category == ServerErrorCategory.DuplicateKey, insertDuplicate?.Message);

    // Выход без номера получает номер условной записью; занятый номер индекс не пропускает.
    var noNumber = await Create("Exit C", XC(XCoreRoles.Exit, null));
    Check("репозиторий: занятый номер маршрута — RouteIdTakenException, а не молчаливый false и не сырая ошибка драйвера",
        await Rejected(() => serverRepo.SetXCoreRouteIdAsync(noNumber.Id, noNumber.Protocols[0].Id, 1, ct)));
    Check("репозиторий: свободный номер записывается, повторное назначение уже имеющему номер — false",
        await serverRepo.SetXCoreRouteIdAsync(noNumber.Id, noNumber.Protocols[0].Id, 3, ct)
        && !await serverRepo.SetXCoreRouteIdAsync(noNumber.Id, noNumber.Protocols[0].Id, 4, ct));

    var installing = new VpnServer { Id = ObjectId.GenerateNewId().ToString(), Name = "Installing", Host = "203.0.113.12" };
    await serverRepo.CreateAsync(installing, ct);
    installing.Protocols.Add(XC(XCoreRoles.Exit, 2));
    Check("репозиторий: UpdateInstallationAsync с занятым номером выхода — RouteIdTakenException",
        await Rejected(() => serverRepo.UpdateInstallationAsync(installing, ct)));
    var installingStored = await serverRepo.GetByIdAsync(installing.Id, ct);
    Check("репозиторий: отклонённая запись ничего не оставила в узле", installingStored!.Protocols.Count == 0);
    installing.Protocols[0].XCore!.RouteId = 5;
    await serverRepo.UpdateInstallationAsync(installing, ct);
    Check("репозиторий: тот же узел с свободным номером записан", (await serverRepo.GetByIdAsync(installing.Id, ct))!.Protocols.Single().XCore!.RouteId == 5);

    // Два выхода без номера выбирают номер одновременно — как установка двух узлов в одну секунду.
    var racerOne = await Create("Racer 1", XC(XCoreRoles.Exit, null));
    var racerTwo = await Create("Racer 2", XC(XCoreRoles.Exit, null));
    // Барьер заставляет обоих прочитать снимок до того, как кто-то из них записал номер: гонка происходит наверняка.
    using var gate = new Barrier(2);
    async Task<(int RouteId, int Attempts)> AssignAsync(VpnServer racer)
    {
        for (var attempt = 1; ; attempt++)
        {
            var routeId = XCoreRoute.NextFree(XCoreTopology.UsedRouteIds(await serverRepo.GetAllAsync(ct)));
            if (attempt == 1) await Task.Run(() => gate.SignalAndWait(TimeSpan.FromSeconds(10)), ct);
            try
            {
                if (!await serverRepo.SetXCoreRouteIdAsync(racer.Id, racer.Protocols[0].Id, routeId, ct)) return (-1, attempt);
                return (routeId, attempt);
            }
            catch (RouteIdTakenException) when (attempt < XCoreRoute.AssignAttempts) { }
        }
    }
    // Занято 1, 2, 3 и 5: оба участника гонки выбирают 4; проигравший по новому снимку берёт 6.
    var assigned = await Task.WhenAll(AssignAsync(racerOne), AssignAsync(racerTwo));
    Check("M017: два выхода выбрали один свободный номер одновременно — индекс отклонил второго, он взял следующий свободный (4 и 6, ровно один повтор)",
        assigned.Select(a => a.RouteId).Order().SequenceEqual([4, 6]) && assigned.Select(a => a.Attempts).Order().SequenceEqual([1, 2]),
        string.Join(",", assigned.Select(a => $"{a.RouteId}/{a.Attempts}")));
    var allRoutes = XCoreTopology.UsedRouteIds(await serverRepo.GetAllAsync(ct));
    Check("M017: во всей базе нет повторяющихся номеров маршрута", allRoutes.Distinct().Count() == allRoutes.Count, string.Join(",", allRoutes.Order()));

    // ── Точечные записи ──────────────────────────────────────────────────────

    var entryNode = await Create("Entry Z", XC(XCoreRoles.Entry, null, x => { x.AppliedRevision = "rev"; x.SyncError = "err"; x.Title = "Старое"; }), Awg());
    var entryProtocolId = entryNode.Protocols[0].Id;
    var before = (await serversCollection.Find(Builders<BsonDocument>.Filter.Eq("_id", ObjectId.Parse(entryNode.Id))).FirstAsync(ct));

    await serverRepo.SetXCoreExitHealthAsync(entryNode.Id, entryProtocolId,
        [new XCoreExitHealth { ServerId = exitA.Id, Ok = false, CheckedAt = now, Error = "выход не ответил за 8 с" }, new XCoreExitHealth { ServerId = exitB.Id, Ok = true, CheckedAt = now }], ct);
    await serverRepo.MarkXCoreCaddyAppliedAsync(entryNode.Id, entryProtocolId, "caddy-rev-1", ct);
    var afterHealth = (await serverRepo.GetByIdAsync(entryNode.Id, ct))!.Protocols[0].XCore!;
    Check("здоровье плеч: состояние записано и читается (ошибка только у упавшего плеча)",
        afterHealth.ExitHealth is [{ Ok: false, Error: "выход не ответил за 8 с" } h1, { Ok: true, Error: null } h2] && h1.ServerId == exitA.Id && h2.ServerId == exitB.Id
        && h1.CheckedAt == now);
    Check("здоровье плеч и ревизия Caddyfile пишутся точечно: ревизия Xray, ошибка синхронизации, название и второй протокол узла не тронуты",
        afterHealth is { AppliedRevision: "rev", SyncError: "err", Title: "Старое", AppliedCaddyRevision: "caddy-rev-1" }
        && (await serverRepo.GetByIdAsync(entryNode.Id, ct))!.Protocols.Count == 2);

    var plainExit = await Create("Exit P", XC(XCoreRoles.Exit, null));
    Check("настройки в репозитории: записи с полями входа выходу не применяются (роль в фильтре) — false, документ не изменён",
        !await serverRepo.UpdateXCoreSettingsAsync(plainExit.Id, plainExit.Protocols[0].Id,
            new XCoreSettingsUpdate("X", 3, false, new XCoreEntrySettings(false, ["domain:a.ru"], [], "sub.example.com")), ct)
        && (await serverRepo.GetByIdAsync(plainExit.Id, ct))!.Protocols[0].XCore is { RuDirect: true, SubscriptionHost: null } plainNode && plainNode.DirectDomains.Count == 0);
    Check("настройки в репозитории: вход выходной записью (без полей входа) не обновляется — false",
        !await serverRepo.UpdateXCoreSettingsAsync(entryNode.Id, entryProtocolId, new XCoreSettingsUpdate("X", 3, false, null), ct));

    var afterBson = (await serversCollection.Find(Builders<BsonDocument>.Filter.Eq("_id", ObjectId.Parse(entryNode.Id))).FirstAsync(ct));
    Check("документ узла: кроме health/caddy-ревизии ничего не изменилось",
        before["protocols"].AsBsonArray[0].AsBsonDocument["xcore"].AsBsonDocument.Names.Except(afterBson["protocols"].AsBsonArray[0].AsBsonDocument["xcore"].AsBsonDocument.Names).Count() == 0);

    // ── PUT настроек из панели ───────────────────────────────────────────────

    var auditLog = new List<(string Event, string Message, string Level, Dictionary<string, string>? Meta)>();
    var audit = Stub.Create<IAuditService>((m, a) =>
    {
        var names = m.GetParameters().Select(p => p.Name).ToList();
        auditLog.Add(((string)a[0]!, (string)a[1]!, (string)a[names.IndexOf("level")]!, (Dictionary<string, string>?)a[names.IndexOf("meta")]));
        return Task.CompletedTask;
    });
    var eventsRepo = provider.GetRequiredService<IDomainEventRepository>();
    var publisher = new XCoreSyncPublisher(serverRepo, provider.GetRequiredService<IDomainEventPublisher>(), NullLogger<XCoreSyncPublisher>.Instance);

    var nodeServer = await Create("Panel entry", XC(XCoreRoles.Entry, null, x => { x.Title = "Вход"; x.AppliedRevision = "rev-1"; x.AppliedStructureRevision = "str-1"; x.SyncError = "прежняя"; }));
    nodeServer.Host = "203.0.113.10";
    var panelExit = await Create("Panel exit", XC(XCoreRoles.Exit, null, x => { x.Title = "Выход"; x.AppliedRevision = "rev-x"; }));
    var panelAwg = await Create("Panel awg", Awg());
    var entryId = nodeServer.Protocols[0].Id;
    var exitProtocolId = panelExit.Protocols[0].Id;
    var dnsAnswers = new Dictionary<string, string[]>
    {
        ["sub.entry.example.com"] = ["203.0.113.10"],
        ["wrong.entry.example.com"] = ["198.51.100.77"],
    };
    var dnsQueries = new List<string>();
    var dns = Stub.Create<IDnsResolver>((m, a) =>
    {
        var host = (string)a[0]!;
        dnsQueries.Add(host);
        IReadOnlyList<System.Net.IPAddress> ips = dnsAnswers.TryGetValue(host, out var values) ? [.. values.Select(System.Net.IPAddress.Parse)] : [];
        return Task.FromResult(ips);
    });
    // SSH панели нужен только для xray vlessenc при включении шифрования VLESS: заглушка отдаёт образец вывода.
    var vlessConnects = new List<string>();
    var vlessCommands = new List<string>();
    var vlessOutputFor = "good";
    var vlessSession = Stub.Create<ISshSession>((m, a) =>
    {
        switch (m.Name)
        {
            case nameof(ISshSession.RunCheckedAsync):
                vlessCommands.Add((string)a[0]!);
                return Task.FromResult(vlessOutputFor == "good" ? VlessEncSample : "Authentication: X25519\n\"decryption\": \"nope\"\n");
            case nameof(ISshSession.DisposeAsync):
                return ValueTask.CompletedTask;
            default:
                throw new NotSupportedException(m.Name);
        }
    });
    var sshFactory = Stub.Create<ISshSessionFactory>((m, a) =>
    {
        vlessConnects.Add(((VpnServer)a[0]!).Id);
        return vlessOutputFor == "down"
            ? Task.FromException<ISshSession>(new SshConnectionException("203.0.113.10"))
            : Task.FromResult(vlessSession);
    });
    ServersController Panel(string? upstream, bool rfLists = true) => new(
        serverRepo, Stub.Create<IVpnClientRepository>((m, _) => throw new NotSupportedException(m.Name)),
        Stub.Create<IUserRepository>((m, _) => throw new NotSupportedException(m.Name)),
        Stub.Create<IUsageRepository>((m, _) => throw new NotSupportedException(m.Name)),
        Stub.Create<IServerParamsService>((m, _) => throw new NotSupportedException(m.Name)),
        Stub.Create<IInstallService>((m, _) => throw new NotSupportedException(m.Name)),
        protector, audit, publisher, dns, sshFactory, Options.Create(new XCoreOptions { SubscriptionUpstream = upstream, RfListsEnabled = rfLists }))
    {
        ControllerContext = new ControllerContext
        {
            HttpContext = new DefaultHttpContext
            {
                User = new System.Security.Claims.ClaimsPrincipal(new System.Security.Claims.ClaimsIdentity(
                    [new System.Security.Claims.Claim(System.Security.Claims.ClaimTypes.NameIdentifier, "admin-1")], "test")),
            },
        },
    };
    var panel = Panel("https://sub-origin.example.com");
    long Pending() => eventsCollection.CountDocuments(e => e.Type == DomainEventTypes.XCoreSync && e.Status == DomainEventStatuses.Pending);
    async Task<BadRequestException?> Reject(Func<Task<IActionResult>> action) => await CatchAsync<BadRequestException>(async () => await action());
    async Task<XCoreProtocolParams> Stored(string serverId, string protocolId) =>
        (await serverRepo.GetByIdAsync(serverId, ct))!.FindProtocol(protocolId)!.XCore!;

    var put = typeof(ServersController).GetMethod(nameof(ServersController.UpdateXCoreSettings))!;
    Check("PUT: маршрут /api/servers/{id}/protocols/{protocolId}/xcore, доступ PanelAdmin на классе и не ослаблен на методе",
        put.GetCustomAttributes(typeof(HttpPutAttribute), false).Cast<HttpPutAttribute>().Single().Template == "{id}/protocols/{protocolId}/xcore"
        && typeof(ServersController).GetCustomAttributes(typeof(AuthorizeAttribute), true).Cast<AuthorizeAttribute>().Any(a => a.Policy == AuthPolicies.PanelAdmin)
        && !put.GetCustomAttributes(typeof(AuthorizeAttribute), true).Any() && !put.GetCustomAttributes(typeof(AllowAnonymousAttribute), true).Any());

    // Выход: три поля.
    var exitBefore = await Stored(panelExit.Id, exitProtocolId);
    var exitBsonBefore = (await serversCollection.Find(Builders<BsonDocument>.Filter.Eq("_id", ObjectId.Parse(panelExit.Id))).FirstAsync(ct))["protocols"][0]["xcore"].AsBsonDocument;
    var result = await panel.UpdateXCoreSettings(panelExit.Id, exitProtocolId,
        new XCoreSettingsRequest { Title = "  Нидерланды  ", SortOrder = 7, SubscriptionEnabled = false }, ct);
    var exitAfter = await Stored(panelExit.Id, exitProtocolId);
    Check("PUT выхода: название (без пробелов), порядок и участие в подписках записаны, ответ 204",
        result is NoContentResult && exitAfter is { Title: "Нидерланды", SortOrder: 7, SubscriptionEnabled: false });
    var exitBsonAfter = (await serversCollection.Find(Builders<BsonDocument>.Filter.Eq("_id", ObjectId.Parse(panelExit.Id))).FirstAsync(ct))["protocols"][0]["xcore"].AsBsonDocument;
    var untouched = new[] { "role", "domain", "imageRef", "realityPrivateKey", "realityPublicKey", "shortIds", "xhttpPath", "appliedRevision", "routeId", "fingerprint", "apiPort" };
    Check("PUT выхода: роль, домен, ключи, номер маршрута и ревизия не изменились (точечная запись)",
        untouched.All(f => exitBsonBefore.GetValue(f, BsonNull.Value) == exitBsonAfter.GetValue(f, BsonNull.Value)));
    Check("PUT выхода: полей входа у выхода в документе не появилось",
        !exitBsonAfter.Contains("subscriptionHost") && exitBsonAfter.GetValue("ruDirect", true).ToBoolean() == exitBsonBefore.GetValue("ruDirect", true).ToBoolean()
        && exitAfter.DirectDomains.Count == 0);
    Check("PUT: журнал server.xcore_settings_changed с перечнем изменённых полей, без значений и секретов",
        auditLog is [{ Event: "server.xcore_settings_changed", Level: AuditLevels.Info } a1]
        && a1.Meta!["fields"] == "title,sortOrder,subscriptionEnabled" && a1.Meta["role"] == "exit"
        && !a1.Message.Contains("PRIVATE") && !a1.Message.Contains("Нидерланды"), auditLog.FirstOrDefault().Message);
    long EventsFor(string serverId) => eventsCollection.CountDocuments(e => e.Type == DomainEventTypes.XCoreSync && e.PartitionKey == serverId);
    Check("PUT: после записи опубликован xcore.sync — по одному ожидающему событию на каждый работающий узел xcore базы (входы и выходы)",
        new[] { exitA.Id, exitB.Id, entryX.Id, entryY.Id, entryNode.Id, nodeServer.Id }.All(id => EventsFor(id) == 1),
        string.Join(",", new[] { exitA.Id, exitB.Id, entryX.Id, entryNode.Id, nodeServer.Id }.Select(EventsFor)));
    Check("PUT: узлы без xcore событий не получают",
        EventsFor(onlyAwg1.Id) == 0 && EventsFor(panelAwg.Id) == 0);
    // Иначе подписчики, отозванные после этого запроса, сохранили бы доступ к выходу.
    Check("PUT: выход, только что убранный из подписок этим же запросом, синхронизацию получает",
        EventsFor(panelExit.Id) == 1);

    // Повтор той же формы: журнал не пополняется, синхронизация не дублируется.
    var pendingBefore = Pending();
    await panel.UpdateXCoreSettings(panelExit.Id, exitProtocolId, new XCoreSettingsRequest { Title = "Нидерланды", SortOrder = 7, SubscriptionEnabled = false }, ct);
    Check("PUT: тот же запрос повторно — журнал не пополняется, ожидающие события не дублируются",
        auditLog.Count == 1 && Pending() == pendingBefore);

    // Отказы выходу.
    var onExit = await Reject(() => panel.UpdateXCoreSettings(panelExit.Id, exitProtocolId, new XCoreSettingsRequest { RuDirect = false }, ct));
    Check("PUT выхода: ruDirect выходу отклоняется с указанием поля", onExit?.Field == "ruDirect", onExit?.Message);
    onExit = await Reject(() => panel.UpdateXCoreSettings(panelExit.Id, exitProtocolId, new XCoreSettingsRequest { SubscriptionHost = "sub.entry.example.com" }, ct));
    Check("PUT выхода: домен подписки выходу отклоняется", onExit?.Field == "subscriptionHost");
    onExit = await Reject(() => panel.UpdateXCoreSettings(panelExit.Id, exitProtocolId, new XCoreSettingsRequest { DirectDomains = ["a.ru"] }, ct));
    Check("PUT выхода: списки доменов выходу отклоняются", onExit?.Field == "directDomains");
    var title31 = await Reject(() => panel.UpdateXCoreSettings(panelExit.Id, exitProtocolId, new XCoreSettingsRequest { Title = new string('я', 31) }, ct));
    Check("PUT: название 31 символ отклоняется с полем title, 30 символов принимается",
        title31?.Field == "title"
        && await panel.UpdateXCoreSettings(panelExit.Id, exitProtocolId, new XCoreSettingsRequest { Title = new string('я', 30), SortOrder = 7 }, ct) is NoContentResult);

    // Вход.
    var entryBefore = await Stored(nodeServer.Id, entryId);
    var full = new XCoreSettingsRequest
    {
        Title = "Москва", SortOrder = 1, SubscriptionEnabled = true, RuDirect = false,
        DirectDomains = ["Yandex.RU", "full:Bank.Example.com", "yandex.ru", "keyword:sber"],
        ProxyDomains = ["domain:example.org"], SubscriptionHost = "SUB.Entry.Example.com.",
    };
    auditLog.Clear();
    result = await panel.UpdateXCoreSettings(nodeServer.Id, entryId, full, ct);
    var entryAfter = await Stored(nodeServer.Id, entryId);
    Check("PUT входа: все поля записаны нормализованными (домены в нижнем регистре с префиксом domain:, повторы убраны, порядок сохранён)",
        result is NoContentResult && entryAfter is { Title: "Москва", SortOrder: 1, SubscriptionEnabled: true, RuDirect: false, SubscriptionHost: "sub.entry.example.com" }
        && entryAfter.DirectDomains.SequenceEqual(["domain:yandex.ru", "full:bank.example.com", "keyword:sber"])
        && entryAfter.ProxyDomains.SequenceEqual(["domain:example.org"]),
        string.Join("|", entryAfter.DirectDomains));
    Check("PUT входа: A-запись нового домена подписки проверена через IDnsResolver", dnsQueries.Contains("sub.entry.example.com"));
    Check("PUT входа: роль, домен узла, ключи, служебный UUID, ревизии и ошибка синхронизации не изменились",
        entryAfter.Role == XCoreRoles.Entry && entryAfter.Domain == entryBefore.Domain && entryAfter.RelayUuid!.CipherText == entryBefore.RelayUuid!.CipherText
        && entryAfter.RealityPrivateKey!.CipherText == entryBefore.RealityPrivateKey!.CipherText
        && entryAfter is { AppliedRevision: "rev-1", AppliedStructureRevision: "str-1", SyncError: "прежняя" });
    Check("PUT входа: журнал — одна запись со всеми изменёнными полями",
        auditLog is [{ Event: "server.xcore_settings_changed" } a2] && a2.Meta!["fields"] == "title,sortOrder,ruDirect,directDomains,proxyDomains,subscriptionHost" && a2.Meta["role"] == "entry",
        auditLog.FirstOrDefault().Meta?["fields"]);

    // Повторное сохранение того же домена: DNS не спрашивается, настройка upstream не требуется.
    dnsQueries.Clear();
    var noUpstream = Panel(null);
    var resave = await noUpstream.UpdateXCoreSettings(nodeServer.Id, entryId, new XCoreSettingsRequest
    {
        Title = "Москва 2", SortOrder = 1, SubscriptionEnabled = true, SubscriptionHost = "sub.entry.example.com",
    }, ct);
    var afterResave = await Stored(nodeServer.Id, entryId);
    Check("PUT входа: домен подписки не менялся — A-запись не проверяется и XCore:SubscriptionUpstream не требуется",
        resave is NoContentResult && dnsQueries.Count == 0 && afterResave is { Title: "Москва 2", SubscriptionHost: "sub.entry.example.com" });
    Check("PUT входа: поля, не переданные в запросе (ruDirect, списки), остаются прежними",
        afterResave is { RuDirect: false } && afterResave.DirectDomains.Count == 3 && afterResave.ProxyDomains.Count == 1);

    // Отказы входу: ничего не пишется.
    var snapshot = (await serversCollection.Find(Builders<BsonDocument>.Filter.Eq("_id", ObjectId.Parse(nodeServer.Id))).FirstAsync(ct)).ToJson();
    async Task<BadRequestException?> RejectEntry(XCoreSettingsRequest request, XCoreSyncPublisher? _ = null) =>
        await Reject(() => panel.UpdateXCoreSettings(nodeServer.Id, entryId, request, ct));
    var badDirect = await RejectEntry(new XCoreSettingsRequest { DirectDomains = ["ok.ru", "regexp:.*"] });
    Check("PUT входа: недопустимая запись в «Всегда напрямую» — отказ у поля directDomains с номером записи, без значения",
        badDirect?.Field == "directDomains" && badDirect.Message.Contains("запись 2") && badDirect.Message.Contains("Всегда напрямую") && !badDirect.Message.Contains("regexp"), badDirect?.Message);
    var badProxy = await RejectEntry(new XCoreSettingsRequest { ProxyDomains = ["geosite:cn"] });
    Check("PUT входа: недопустимая запись в «Всегда через VPN» — отказ у поля proxyDomains", badProxy?.Field == "proxyDomains" && badProxy.Message.Contains("Всегда через VPN"));
    var tooMany = await RejectEntry(new XCoreSettingsRequest { DirectDomains = [.. Enumerable.Range(0, XCoreRoutingDomains.MaxEntries + 1).Select(i => $"d{i}.example.com")] });
    Check("PUT входа: больше 1000 записей отклоняется", tooMany?.Field == "directDomains");
    var wrongA = await RejectEntry(new XCoreSettingsRequest { SubscriptionHost = "wrong.entry.example.com", Title = "Москва 2", SubscriptionEnabled = true });
    Check("PUT входа: A-запись домена подписки указывает на чужой адрес — отказ у поля subscriptionHost с обоими адресами",
        wrongA?.Field == "subscriptionHost" && wrongA.Message.Contains("198.51.100.77") && wrongA.Message.Contains("203.0.113.10"), wrongA?.Message);
    var noA = await RejectEntry(new XCoreSettingsRequest { SubscriptionHost = "none.entry.example.com", Title = "Москва 2", SubscriptionEnabled = true });
    Check("PUT входа: у домена подписки нет A-записи — отказ с подсказкой", noA?.Field == "subscriptionHost" && noA.Message.Contains("нет A-записи"), noA?.Message);
    var sameAsNode = await RejectEntry(new XCoreSettingsRequest { SubscriptionHost = entryAfter.Domain, Title = "Москва 2", SubscriptionEnabled = true });
    Check("PUT входа: домен подписки равен домену узла — отказ", sameAsNode?.Field == "subscriptionHost");
    var badHost = await RejectEntry(new XCoreSettingsRequest { SubscriptionHost = "1.2.3.4", Title = "Москва 2", SubscriptionEnabled = true });
    Check("PUT входа: IP-адрес вместо домена подписки — отказ", badHost?.Field == "subscriptionHost");
    var withoutUpstream = await Reject(() => noUpstream.UpdateXCoreSettings(nodeServer.Id, entryId,
        new XCoreSettingsRequest { SubscriptionHost = "sub.second.example.com", Title = "Москва 2", SubscriptionEnabled = true }, ct));
    Check("PUT входа: без XCore:SubscriptionUpstream новый домен подписки задать нельзя — понятная ошибка с названием настройки, DNS не спрашивался",
        withoutUpstream?.Field == "subscriptionHost" && withoutUpstream.Message.Contains("XCore:SubscriptionUpstream") && !dnsQueries.Contains("sub.second.example.com"), withoutUpstream?.Message);
    Check("PUT входа: после всех отказов документ узла побайтово прежний",
        (await serversCollection.Find(Builders<BsonDocument>.Filter.Eq("_id", ObjectId.Parse(nodeServer.Id))).FirstAsync(ct)).ToJson() == snapshot);

    // Снятие домена подписки.
    result = await panel.UpdateXCoreSettings(nodeServer.Id, entryId, new XCoreSettingsRequest { Title = "Москва 2", SortOrder = 1, SubscriptionEnabled = true, SubscriptionHost = null }, ct);
    var cleared = (await serversCollection.Find(Builders<BsonDocument>.Filter.Eq("_id", ObjectId.Parse(nodeServer.Id))).FirstAsync(ct))["protocols"][0]["xcore"].AsBsonDocument;
    Check("PUT входа: пустой домен подписки снимает его — поля в документе нет", result is NoContentResult && !cleared.Contains("subscriptionHost"));

    // ── VLESS Encryption: включение и выключение из панели ───────────────────

    var exitAt = await Stored(panelExit.Id, exitProtocolId);
    XCoreSettingsRequest SameExit(bool? vless) => new()
    {
        Title = exitAt.Title, SortOrder = exitAt.SortOrder, SubscriptionEnabled = exitAt.SubscriptionEnabled, VlessEncryption = vless,
    };
    async Task<BsonDocument> XCoreDoc(string serverId) =>
        (await serversCollection.Find(Builders<BsonDocument>.Filter.Eq("_id", ObjectId.Parse(serverId))).FirstAsync(ct))["protocols"][0]["xcore"].AsBsonDocument;
    auditLog.Clear();
    var exitCipherBefore = (await XCoreDoc(panelExit.Id)).Contains("vlessDecryption");

    result = await panel.UpdateXCoreSettings(panelExit.Id, exitProtocolId, SameExit(true), ct);
    var encExit = await Stored(panelExit.Id, exitProtocolId);
    var encExitDoc = await XCoreDoc(panelExit.Id);
    Check("PUT: vlessEncryption=true — флаг включён, на узле выполнена одна команда xray vlessenc образа узла, соединение одно",
        !exitCipherBefore && result is NoContentResult && encExit.VlessEncryption && vlessConnects.SequenceEqual([panelExit.Id])
        && vlessCommands.SequenceEqual([$"sudo docker run --rm {exitAt.ImageRef} vlessenc"]));
    Check("PUT: записаны клиентская строка и зашифрованная серверная; открытого текста серверной в документе нет",
        encExit.VlessEncryptionClient == VlessEncClient && protector.Unprotect(encExit.VlessDecryption) == VlessEncServer
        && encExitDoc["vlessDecryption"].IsBsonDocument && !encExitDoc.ToJson().Contains(VlessEncServer, StringComparison.Ordinal));
    Check("PUT: журнал — одна запись с полем vlessEncryption, ни одной строки mlkem в сообщении и метаданных",
        auditLog is [{ Event: "server.xcore_settings_changed" } a3] && a3.Meta!["fields"] == "vlessEncryption"
        && !a3.Message.Contains("mlkem") && !a3.Meta.Values.Any(v => v.Contains("mlkem")), auditLog.FirstOrDefault().Meta?["fields"]);
    Check("PUT: остальные поля узла не тронуты (ключи Reality, ревизия, название)",
        encExit.Title == exitAt.Title && encExit.RealityPrivateKey!.CipherText == exitAt.RealityPrivateKey!.CipherText && encExit.AppliedRevision == exitAt.AppliedRevision);
    Check("PUT: после включения опубликован xcore.sync на узлы (входы перерисовываются вместе с выходом)",
        new[] { exitA.Id, entryX.Id, nodeServer.Id, panelExit.Id }.All(id => EventsFor(id) == 1));
    // Узел, прочитанный из базы, с номером маршрута и видимый в подписках: так его увидит вход.
    var routable = (await serverRepo.GetByIdAsync(panelExit.Id, ct))!;
    routable.Protocols[0].XCore!.RouteId = 99;
    routable.Protocols[0].XCore!.SubscriptionEnabled = true;
    Check("топология из базы: у включённого выхода в цели входов его клиентская строка",
        XCoreTopology.ExitTargets([routable]) is [{ RouteId: 99 } target99] && target99.Encryption == VlessEncClient);

    auditLog.Clear();
    vlessConnects.Clear();
    var cipherAfterFirst = encExit.VlessDecryption!.CipherText;
    result = await panel.UpdateXCoreSettings(panelExit.Id, exitProtocolId, SameExit(true), ct);
    var again = await Stored(panelExit.Id, exitProtocolId);
    Check("PUT: повторное включение — ключи не пересоздаются, на узел не ходим, журнал не пополняется",
        result is NoContentResult && vlessConnects.Count == 0 && again.VlessDecryption!.CipherText == cipherAfterFirst && auditLog.Count == 0);
    result = await panel.UpdateXCoreSettings(panelExit.Id, exitProtocolId, SameExit(null), ct);
    again = await Stored(panelExit.Id, exitProtocolId);
    Check("PUT: поле не передано — шифрование и ключи остаются как были",
        result is NoContentResult && again.VlessEncryption && again.VlessDecryption!.CipherText == cipherAfterFirst && vlessConnects.Count == 0);

    result = await panel.UpdateXCoreSettings(panelExit.Id, exitProtocolId, SameExit(false), ct);
    var offExit = await Stored(panelExit.Id, exitProtocolId);
    var offExitDoc = await XCoreDoc(panelExit.Id);
    Check("PUT: vlessEncryption=false — флаг выключен, обе строки стёрты из документа, на узел не ходили",
        result is NoContentResult && !offExit.VlessEncryption && !offExitDoc.Contains("vlessDecryption") && !offExitDoc.Contains("vlessEncryptionClient")
        && vlessConnects.Count == 0 && auditLog is [{ } a4] && a4.Meta!["fields"] == "vlessEncryption");
    auditLog.Clear();
    await panel.UpdateXCoreSettings(panelExit.Id, exitProtocolId, SameExit(false), ct);
    Check("PUT: повторное выключение — ничего не меняется, журнал не пополняется", auditLog.Count == 0);

    // Вход тоже: роль не важна. Сбой узла и мусорный вывод ничего не пишут.
    XCoreSettingsRequest SameEntry(bool? vless) => new()
    {
        Title = "Москва 2", SortOrder = 1, SubscriptionEnabled = true, VlessEncryption = vless,
    };
    var entrySnapshot = (await serversCollection.Find(Builders<BsonDocument>.Filter.Eq("_id", ObjectId.Parse(nodeServer.Id))).FirstAsync(ct)).ToJson();
    vlessOutputFor = "down";
    var downFailure = await CatchAsync<SshConnectionException>(() => panel.UpdateXCoreSettings(nodeServer.Id, entryId, SameEntry(true), ct));
    Check("PUT: узел недоступен — SshConnectionException, документ узла побайтово прежний, синхронизацию не публикуем впустую",
        downFailure is not null && (await serversCollection.Find(Builders<BsonDocument>.Filter.Eq("_id", ObjectId.Parse(nodeServer.Id))).FirstAsync(ct)).ToJson() == entrySnapshot);
    vlessOutputFor = "garbage";
    var garbageFailure = await Reject(() => panel.UpdateXCoreSettings(nodeServer.Id, entryId, SameEntry(true), ct));
    Check("PUT: нераспознанный вывод xray vlessenc — BadRequest без вывода, документ прежний",
        garbageFailure is not null && garbageFailure.Message.Contains("ключи шифрования VLESS") && !garbageFailure.Message.Contains("nope")
        && (await serversCollection.Find(Builders<BsonDocument>.Filter.Eq("_id", ObjectId.Parse(nodeServer.Id))).FirstAsync(ct)).ToJson() == entrySnapshot);
    vlessOutputFor = "good";
    result = await panel.UpdateXCoreSettings(nodeServer.Id, entryId, SameEntry(true), ct);
    var encEntry = await Stored(nodeServer.Id, entryId);
    Check("PUT входа: шифрование включается так же, поля маршрутизации входа не тронуты",
        result is NoContentResult && encEntry.VlessEncryption && encEntry.VlessEncryptionClient == VlessEncClient
        && encEntry.DirectDomains.Count == 3 && encEntry.RuDirect == false);
    var encDetail = JsonSerializer.Serialize(ServerDetailDto.From((await serverRepo.GetByIdAsync(nodeServer.Id, ct))!, new ServerKpiDto(null, 0, 0)), new JsonSerializerOptions(JsonSerializerDefaults.Web));
    Check("DTO карточки: vlessEncryption=true, строк и шифротекста нет",
        JsonDocument.Parse(encDetail).RootElement.GetProperty("protocols")[0].GetProperty("xcore").GetProperty("vlessEncryption").GetBoolean()
        && !encDetail.Contains("mlkem") && !encDetail.Contains(encEntry.VlessDecryption!.CipherText));
    await panel.UpdateXCoreSettings(nodeServer.Id, entryId, SameEntry(false), ct);
    Check("PUT входа: выключение стирает ключи", !(await XCoreDoc(nodeServer.Id)).Contains("vlessDecryption"));

    // Остальные отказы.
    Check("PUT: несуществующий узел и протокол — NotFound",
        await CatchAsync<NotFoundException>(() => panel.UpdateXCoreSettings(ObjectId.GenerateNewId().ToString(), entryId, new XCoreSettingsRequest(), ct)) is not null
        && await CatchAsync<NotFoundException>(() => panel.UpdateXCoreSettings(nodeServer.Id, "нет-такого", new XCoreSettingsRequest(), ct)) is not null);
    var awgProtocol = await Reject(() => panel.UpdateXCoreSettings(panelAwg.Id, panelAwg.Protocols[0].Id, new XCoreSettingsRequest(), ct));
    Check("PUT: протокол не xcore — BadRequest, документ не тронут", awgProtocol is not null && (await serverRepo.GetByIdAsync(panelAwg.Id, ct))!.Protocols[0].XCore is null);

    // DTO карточки.
    await serverRepo.SetXCoreExitHealthAsync(nodeServer.Id, entryId, [new XCoreExitHealth { ServerId = panelExit.Id, Ok = false, CheckedAt = now, Error = "соединение с выходом отклонено" }], ct);
    var detail = ServerDetailDto.From((await serverRepo.GetByIdAsync(nodeServer.Id, ct))!, new ServerKpiDto(null, 0, 0));
    var web = new JsonSerializerOptions(JsonSerializerDefaults.Web);
    var detailJson = JsonSerializer.Serialize(detail, web);
    var xcoreJson = JsonDocument.Parse(detailJson).RootElement.GetProperty("protocols")[0].GetProperty("xcore");
    Check("DTO: карточка входа отдаёт routeId, title, sortOrder, ruDirect, списки, subscriptionHost и exitHealth (serverId, ok, checkedAt, error)",
        xcoreJson.TryGetProperty("routeId", out var rid) && rid.ValueKind == JsonValueKind.Null
        && xcoreJson.GetProperty("title").GetString() == "Москва 2" && xcoreJson.GetProperty("sortOrder").GetInt32() == 1
        && !xcoreJson.GetProperty("ruDirect").GetBoolean() && xcoreJson.GetProperty("directDomains").GetArrayLength() == 3
        && xcoreJson.GetProperty("proxyDomains").GetArrayLength() == 1 && xcoreJson.TryGetProperty("subscriptionHost", out var host) && host.ValueKind == JsonValueKind.Null
        && xcoreJson.GetProperty("exitHealth")[0] is { } eh && eh.GetProperty("serverId").GetString() == panelExit.Id && !eh.GetProperty("ok").GetBoolean()
        && eh.GetProperty("error").GetString() == "соединение с выходом отклонено" && eh.TryGetProperty("checkedAt", out _), xcoreJson.ToString());
    var plainRelay = protector.Unprotect(entryAfter.RelayUuid)!;
    var plainKey = protector.Unprotect(entryAfter.RealityPrivateKey)!;
    Check("DTO: служебный UUID входа, приватный ключ и их шифртекст в ответе отсутствуют",
        !detailJson.Contains(plainRelay) && !detailJson.Contains(plainKey) && !detailJson.Contains(entryAfter.RelayUuid!.CipherText)
        && !detailJson.Contains(entryAfter.RealityPrivateKey!.CipherText) && !detailJson.Contains("relayUuid", StringComparison.OrdinalIgnoreCase)
        && !detailJson.Contains("realityPrivateKey", StringComparison.OrdinalIgnoreCase));
    var exitJson = JsonSerializer.Serialize(ServerDetailDto.From((await serverRepo.GetByIdAsync(panelExit.Id, ct))!, new ServerKpiDto(null, 0, 0)), web);
    Check("DTO: карточка выхода отдаёт номер маршрута и пустое состояние плеч",
        JsonDocument.Parse(exitJson).RootElement.GetProperty("protocols")[0].GetProperty("xcore") is { } xe
        && xe.GetProperty("exitHealth").GetArrayLength() == 0 && xe.TryGetProperty("routeId", out _));

    // ── Российские списки и пауза Caddy: точечные записи и кнопка «обновить сейчас» ─────────────────

    var geoServer = await Create("Geo entry", XC(XCoreRoles.Entry, null, x => { x.Title = "Гео-вход"; x.SortOrder = 4; }));
    var geoId = geoServer.Protocols[0].Id;
    async Task<BsonDocument> GeoBson() =>
        (await serversCollection.Find(Builders<BsonDocument>.Filter.Eq("_id", ObjectId.Parse(geoServer.Id))).FirstAsync(ct))["protocols"][0]["xcore"].AsBsonDocument;

    var geoAt = new DateTime(2026, 10, 29, 12, 0, 0, DateTimeKind.Utc);
    var bsonBefore = await GeoBson();
    Check("списки РФ: у свежего входа полей списков и паузы в документе нет (BsonIgnoreIfNull)",
        new[] { "rfListsTag", "rfListsAppliedAt", "rfListsCheckedAt", "geoError", "caddyFailedRevision", "caddyFailedAt" }.All(f => !bsonBefore.Contains(f)));

    await serverRepo.SetXCoreGeoErrorAsync(geoServer.Id, geoId, "Контрольная сумма не совпала", ct);
    var geoStored = await Stored(geoServer.Id, geoId);
    Check("списки РФ: GeoError записывается точечно и отдельно от SyncError", geoStored.GeoError == "Контрольная сумма не совпала" && geoStored.SyncError is null && geoStored.RfListsTag is null);
    await serverRepo.MarkXCoreRfListsAppliedAsync(geoServer.Id, geoId, "202610291019", geoAt, ct);
    geoStored = await Stored(geoServer.Id, geoId);
    Check("списки РФ: применение записывает тег, время подмены и проверки и снимает GeoError",
        geoStored is { RfListsTag: "202610291019", GeoError: null } && geoStored.RfListsAppliedAt == geoAt && geoStored.RfListsCheckedAt == geoAt);
    var geoBsonAfter = await GeoBson();
    Check("списки РФ: остальные поля узла не затронуты (название, порядок, ключи, номер, ревизии)",
        new[] { "title", "sortOrder", "role", "domain", "realityPrivateKey", "relayUuid", "shortIds", "xhttpPath", "subscriptionEnabled" }
            .All(f => bsonBefore.GetValue(f, BsonNull.Value) == geoBsonAfter.GetValue(f, BsonNull.Value)));
    var laterCheck = geoAt.AddDays(1);
    await serverRepo.SetXCoreRfListsCheckedAsync(geoServer.Id, geoId, laterCheck, ct);
    geoStored = await Stored(geoServer.Id, geoId);
    Check("списки РФ: отметка проверки меняет только дату проверки (тег и дата подмены прежние)",
        geoStored.RfListsCheckedAt == laterCheck && geoStored.RfListsAppliedAt == geoAt && geoStored.RfListsTag == "202610291019");
    await serverRepo.SetXCoreGeoErrorAsync(geoServer.Id, geoId, null, ct);
    Check("списки РФ: null снимает GeoError — поля в документе нет", !(await GeoBson()).Contains("geoError"));
    await serverRepo.SetXCoreGeoErrorAsync(panelExit.Id, "нет-такого", "x", ct);
    Check("списки РФ: запись с неизвестным идентификатором протокола ничего не меняет и не создаёт полей",
        (await Stored(panelExit.Id, exitProtocolId)).GeoError is null);

    // DTO карточки.
    var geoDto = JsonSerializer.Serialize(ServerDetailDto.From((await serverRepo.GetByIdAsync(geoServer.Id, ct))!, new ServerKpiDto(null, 0, 0)), web);
    var geoJson = JsonDocument.Parse(geoDto).RootElement.GetProperty("protocols")[0].GetProperty("xcore");
    Check("DTO: карточка входа отдаёт rfListsTag, rfListsAppliedAt, rfListsCheckedAt и geoError",
        geoJson.GetProperty("rfListsTag").GetString() == "202610291019" && geoJson.TryGetProperty("rfListsAppliedAt", out _)
        && geoJson.TryGetProperty("rfListsCheckedAt", out _) && geoJson.TryGetProperty("geoError", out var geoErr) && geoErr.ValueKind == JsonValueKind.Null);

    // Пауза Caddy: запись неудачи, очистка успехом и явным сохранением настроек.
    await serverRepo.SetXCoreCaddyFailedAsync(geoServer.Id, geoId, "rev-fail", geoAt, ct);
    geoStored = await Stored(geoServer.Id, geoId);
    Check("пауза Caddy: ревизия и время неудачи записываются", geoStored.CaddyFailedRevision == "rev-fail" && geoStored.CaddyFailedAt == geoAt);
    await serverRepo.MarkXCoreCaddyAppliedAsync(geoServer.Id, geoId, "rev-ok", ct);
    geoStored = await Stored(geoServer.Id, geoId);
    var geoCaddyBson = await GeoBson();
    Check("пауза Caddy: успех записывает ревизию и очищает пометку неудачи (полей в документе нет)",
        geoStored.AppliedCaddyRevision == "rev-ok" && !geoCaddyBson.Contains("caddyFailedRevision") && !geoCaddyBson.Contains("caddyFailedAt"));
    await serverRepo.SetXCoreCaddyFailedAsync(geoServer.Id, geoId, "rev-fail", geoAt, ct);
    await panel.UpdateXCoreSettings(geoServer.Id, geoId, new XCoreSettingsRequest { Title = "Гео-вход", SortOrder = 4 }, ct);
    geoCaddyBson = await GeoBson();
    Check("пауза Caddy: явное сохранение настроек в панели (даже без изменений) снимает паузу",
        !geoCaddyBson.Contains("caddyFailedRevision") && !geoCaddyBson.Contains("caddyFailedAt") && geoCaddyBson["appliedCaddyRevision"] == "rev-ok");
    await serverRepo.SetXCoreCaddyFailedAsync(geoServer.Id, geoId, "rev-fail", geoAt, ct);
    await serverRepo.SetXCoreRfListsCheckedAsync(geoServer.Id, geoId, laterCheck, ct);
    Check("пауза Caddy: запись о списках пометку неудачи не трогает", (await Stored(geoServer.Id, geoId)).CaddyFailedRevision == "rev-fail");

    // Кнопка «Обновить списки сейчас».
    var rfMethod = typeof(ServersController).GetMethod(nameof(ServersController.UpdateXCoreRfLists))!;
    Check("POST rf-lists/update: маршрут /api/servers/{id}/protocols/{protocolId}/xcore/rf-lists/update, PanelAdmin на классе не ослаблен",
        rfMethod.GetCustomAttributes(typeof(HttpPostAttribute), false).Cast<HttpPostAttribute>().Single().Template == "{id}/protocols/{protocolId}/xcore/rf-lists/update"
        && typeof(ServersController).GetCustomAttributes(typeof(AuthorizeAttribute), true).Cast<AuthorizeAttribute>().Any(a => a.Policy == AuthPolicies.PanelAdmin)
        && !rfMethod.GetCustomAttributes(typeof(AuthorizeAttribute), true).Any() && !rfMethod.GetCustomAttributes(typeof(AllowAnonymousAttribute), true).Any());

    long GeoEvents(string serverId, string status = DomainEventStatuses.Pending) =>
        eventsCollection.CountDocuments(e => e.Type == DomainEventTypes.XCoreGeoUpdate && e.PartitionKey == serverId && e.Status == status);
    long SyncPending(string serverId) =>
        eventsCollection.CountDocuments(e => e.Type == DomainEventTypes.XCoreSync && e.PartitionKey == serverId && e.Status == DomainEventStatuses.Pending);
    var syncBefore = SyncPending(geoServer.Id);
    var auditBefore = auditLog.Count;
    var accepted = await panel.UpdateXCoreRfLists(geoServer.Id, geoId, ct);
    var geoEvent = await eventsCollection.Find(e => e.Type == DomainEventTypes.XCoreGeoUpdate && e.PartitionKey == geoServer.Id).FirstAsync(ct);
    var geoPayload = geoEvent.PayloadAs<XCoreGeoUpdatePayload>();
    Check("кнопка: 202, одно ожидающее xcore.geo_update на партиции узла, в событии тега нет (его определит worker), исполнитель записан",
        accepted is AcceptedResult or AcceptedAtActionResult or StatusCodeResult { StatusCode: 202 } && GeoEvents(geoServer.Id) == 1
        && geoPayload == new XCoreGeoUpdatePayload(geoServer.Id, geoId, null) && geoEvent.ActorUserId == "admin-1" && geoEvent.CorrelationId == geoServer.Id);
    await panel.UpdateXCoreRfLists(geoServer.Id, geoId, ct);
    Check("кнопка: повторное нажатие не плодит событий", GeoEvents(geoServer.Id) == 1);
    Check("кнопка: запись в журнале без значений и секретов",
        auditLog.Count == auditBefore + 2 && auditLog[auditBefore].Event == "server.xcore_rf_lists_requested" && !auditLog[auditBefore].Message.Contains("PRIVATE"));
    Check("кнопка: синхронизацию xcore она не публикует",
        eventsCollection.CountDocuments(e => e.Type == DomainEventTypes.XCoreSync && e.PartitionKey == geoServer.Id && e.Status == DomainEventStatuses.Pending) is var syncCount && syncCount <= 1);

    var geoOnExit = await Reject(async () => await panel.UpdateXCoreRfLists(panelExit.Id, exitProtocolId, ct));
    var geoOnAwg = await Reject(async () => await panel.UpdateXCoreRfLists(panelAwg.Id, panelAwg.Protocols[0].Id, ct));
    var installingEntry = XC(XCoreRoles.Entry, null);
    installingEntry.State = ProtocolStates.Installing;
    var installingServer = await Create("Geo installing", installingEntry);
    var geoInstalling = await Reject(async () => await panel.UpdateXCoreRfLists(installingServer.Id, installingEntry.Id, ct));
    var geoDisabled = await Reject(async () => await Panel("https://sub-origin.example.com", rfLists: false).UpdateXCoreRfLists(geoServer.Id, geoId, ct));
    Check("кнопка: у выхода, у не-xcore, у не установленного входа и при XCore:RfListsEnabled=false — BadRequest, событий нет",
        geoOnExit is not null && geoOnAwg is not null && geoInstalling is not null && geoDisabled is not null && geoDisabled.Message.Contains("RfListsEnabled")
        && GeoEvents(panelExit.Id) == 0 && GeoEvents(panelAwg.Id) == 0 && GeoEvents(installingServer.Id) == 0);
    Check("кнопка: несуществующий узел и протокол — NotFound",
        await CatchAsync<NotFoundException>(() => panel.UpdateXCoreRfLists(ObjectId.GenerateNewId().ToString(), geoId, ct)) is not null
        && await CatchAsync<NotFoundException>(() => panel.UpdateXCoreRfLists(geoServer.Id, "нет-такого", ct)) is not null);

    // Публикатор: явный тег доезжает до события, дубль на занятой партиции не создаётся, закрытое событие не мешает.
    var geoPublisher = provider.GetRequiredService<XCoreSyncPublisher>();
    var scheduled = await Create("Geo scheduled", XC(XCoreRoles.Entry, null));
    var scheduledId = scheduled.Protocols[0].Id;
    var first = await geoPublisher.PublishGeoUpdateAsync(scheduled.Id, scheduledId, "202610291019", null, ct);
    var second = await geoPublisher.PublishGeoUpdateAsync(scheduled.Id, scheduledId, "202610301000", null, ct);
    var scheduledEvent = await eventsCollection.Find(e => e.Type == DomainEventTypes.XCoreGeoUpdate && e.PartitionKey == scheduled.Id).FirstAsync(ct);
    Check("публикатор: тег из расписания записан в событие; второй запрос на ту же партицию дублем не становится (остаётся первый)",
        first && !second && GeoEvents(scheduled.Id) == 1 && scheduledEvent.PayloadAs<XCoreGeoUpdatePayload>() == new XCoreGeoUpdatePayload(scheduled.Id, scheduledId, "202610291019"));
    await eventsCollection.UpdateOneAsync(e => e.Id == scheduledEvent.Id, Builders<DomainEvent>.Update.Set(e => e.Status, DomainEventStatuses.Succeeded), cancellationToken: ct);
    Check("публикатор: после завершения прежнего события новое создаётся",
        await geoPublisher.PublishGeoUpdateAsync(scheduled.Id, scheduledId, "202610301000", null, ct) && GeoEvents(scheduled.Id) == 1);
    Check("публикатор: списки РФ и синхронизация узла — разные типы на одной партиции, не мешают друг другу",
        await geoPublisher.PublishForNodeAsync(scheduled.Id, scheduledId, null, ct) && GeoEvents(scheduled.Id) == 1);
}

async Task RunMongoChecksAsync(string connection, string database, MongoClient client)
{
    var db = client.GetDatabase(database);
    var mongoOptions = Options.Create(new MongoDbOptions { DatabaseName = database });
    var ct = CancellationToken.None;

    await new M010_DomainEvents(mongoOptions).ApplyAsync(db, ct);
    var migration = new M016_Subscriptions(mongoOptions);
    await migration.ApplyAsync(db, ct);
    await migration.ApplyAsync(db, ct);   // повторный запуск не должен падать: имена индексов автоматические

    // ── Индексы M016 ─────────────────────────────────────────────────────────

    async Task<List<BsonDocument>> IndexesAsync(string collection) =>
        await (await db.GetCollection<BsonDocument>(collection).Indexes.ListAsync(ct)).ToListAsync(ct);
    static string KeyOf(BsonDocument index) =>
        string.Join(",", index["key"].AsBsonDocument.Elements.Select(e => $"{e.Name}:{e.Value.ToInt32()}"));

    var subscriptionIndexes = await IndexesAsync("subscriptions");
    BsonDocument? IndexByKey(string key) => subscriptionIndexes.FirstOrDefault(i => KeyOf(i) == key);

    Check("M016: уникальный индекс tokenHash", IndexByKey("tokenHash:1") is { } t && t.GetValue("unique", false).ToBoolean());
    Check("M016: уникальный индекс xrayUuid", IndexByKey("xrayUuid:1") is { } u && u.GetValue("unique", false).ToBoolean());
    var userIndex = IndexByKey("userId:1");
    Check("M016: уникальный userId с partialFilterExpression status $in [active] (не $ne)",
        userIndex is not null && userIndex.GetValue("unique", false).ToBoolean()
        && userIndex["partialFilterExpression"].AsBsonDocument == new BsonDocument("status", new BsonDocument("$in", new BsonArray { "active" })),
        userIndex?.GetValue("partialFilterExpression", BsonNull.Value).ToJson());
    Check("M016: составной индекс status + expiresAt (не уникальный)",
        IndexByKey("status:1,expiresAt:1") is { } se && !se.GetValue("unique", false).ToBoolean());

    var usageIndexes = await IndexesAsync("subscription_usage_daily");
    Check("M016: subscription_usage_daily — индекс subscriptionId + date", usageIndexes.Any(i => KeyOf(i) == "subscriptionId:1,date:1"));
    Check("M016: subscription_usage_daily — TTL по expireAt (момент удаления в документе)",
        usageIndexes.FirstOrDefault(i => KeyOf(i) == "expireAt:1") is { } ttl && ttl.GetValue("expireAfterSeconds", -1).ToInt64() == 0);

    // ── Композиция на реальной базе ──────────────────────────────────────────

    var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
    {
        ["MongoDb:ConnectionString"] = connection,
        ["MongoDb:DatabaseName"] = database,
        ["Security:DataProtectionKey"] = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)),
        ["Subscription:PublicBaseUrl"] = "https://sub.example.com",
    }).Build();
    var services = new ServiceCollection();
    services.AddLogging();
    services.AddAmneziaData(config);
    using var provider = services.BuildServiceProvider(new ServiceProviderOptions { ValidateScopes = true });

    var repo = provider.GetRequiredService<ISubscriptionRepository>();
    var serverRepo = provider.GetRequiredService<IVpnServerRepository>();
    var userRepo = provider.GetRequiredService<IUserRepository>();
    var events = provider.GetRequiredService<IDomainEventRepository>();
    var protector = provider.GetRequiredService<ISecretProtector>();
    var eventsCollection = db.GetCollection<DomainEvent>("domain_events");

    Subscription NewSub(string userId, Action<Subscription>? tweak = null)
    {
        var token = SubscriptionTokenCrypto.Create();
        var s = new Subscription
        {
            Id = ObjectId.GenerateNewId().ToString(), UserId = userId, XrayUuid = Guid.NewGuid().ToString("D"),
            TokenHash = SubscriptionTokenCrypto.Hash(token), TokenEncrypted = protector.Protect(token),
        };
        tweak?.Invoke(s);
        return s;
    }

    async Task<User> NewUserAsync(string name)
    {
        var user = new User { Id = ObjectId.GenerateNewId().ToString(), Username = name, DisplayName = name, PasswordHash = "x" };
        await userRepo.CreateAsync(user, ct);
        return user;
    }

    // ── Уникальность ─────────────────────────────────────────────────────────

    var alice = await NewUserAsync("alice");
    var first = NewSub(alice.Id);
    Check("репозиторий: первая активная подписка пользователя создаётся", await repo.TryCreateAsync(first, ct));
    Check("индекс: вторая активная подписка того же пользователя отклоняется", !await repo.TryCreateAsync(NewSub(alice.Id), ct));
    Check("индекс: подписка другого пользователя не мешает", await repo.TryCreateAsync(NewSub((await NewUserAsync("bob")).Id), ct));
    Check("индекс: одинаковый tokenHash отклоняется даже у другого пользователя",
        !await repo.TryCreateAsync(NewSub((await NewUserAsync("carol")).Id, s => s.TokenHash = first.TokenHash), ct));
    Check("индекс: одинаковый xrayUuid отклоняется",
        !await repo.TryCreateAsync(NewSub((await NewUserAsync("dave")).Id, s => s.XrayUuid = first.XrayUuid), ct));
    Check("отзыв: активная → отозванная (один раз)", await repo.TryRevokeAsync(first.Id, RevokeReasons.Manual, now, ct)
        && !await repo.TryRevokeAsync(first.Id, RevokeReasons.Expired, now, ct));
    var revokedStored = await repo.FindByIdAsync(first.Id, ct);
    Check("отзыв: причина и время записаны, повторный отзыв причину не затёр",
        revokedStored is { Status: SubscriptionStatuses.Revoked, RevokeReason: RevokeReasons.Manual } && revokedStored.RevokedAt is not null);
    Check("индекс: после отзыва пользователь снова может получить активную подписку (отозванная в индекс не входит)",
        await repo.TryCreateAsync(NewSub(alice.Id), ct));
    Check("индекс: отозванных подписок у пользователя может быть сколько угодно",
        await repo.TryRevokeAsync((await repo.FindActiveByUserAsync(alice.Id, ct))!.Id, RevokeReasons.Manual, now, ct)
        && await repo.TryCreateAsync(NewSub(alice.Id), ct));
    Check("поиск: активная подписка пользователя находится, по токену и по id — тоже",
        await repo.FindActiveByUserAsync(alice.Id, ct) is { } active && await repo.FindByTokenHashAsync(active.TokenHash, ct) is { } byHash
        && byHash.Id == active.Id && await repo.FindByIdAsync(active.Id, ct) is not null
        && await repo.FindByIdAsync("not-an-object-id", ct) is null && await repo.FindActiveByUserAsync("junk", ct) is null);

    // ── PublishIfNoPendingAsync ──────────────────────────────────────────────

    await eventsCollection.DeleteManyAsync(FilterDefinition<DomainEvent>.Empty, ct);
    const string Syn = DomainEventTypes.XCoreSync;
    long Count(string partition, string? status = null) => eventsCollection.CountDocuments(e =>
        e.Type == Syn && e.PartitionKey == partition && (status == null || e.Status == status));

    var firstEvent = await events.PublishIfNoPendingAsync(Syn, new XCoreSyncPayload("srv1", "p1"), "srv1", "srv1", "actor-1", ct);
    Check("публикация без дублей: первое событие создаётся в статусе pending с партицией = узел",
        firstEvent is { Status: DomainEventStatuses.Pending, PartitionKey: "srv1", Type: Syn } && Count("srv1") == 1);
    Check("публикация без дублей: payload, correlationId и актор сохранены",
        firstEvent!.PayloadAs<XCoreSyncPayload>() == new XCoreSyncPayload("srv1", "p1") && firstEvent.CorrelationId == "srv1" && firstEvent.ActorUserId == "actor-1");
    var storedFirst = await events.GetByIdAsync(firstEvent.Id, ct);
    Check("публикация без дублей: событие читается репозиторием как обычное (попытки 0, доступно сразу, id — ObjectId)",
        storedFirst is { Attempt: 0, MaxAttempts: 1, Lease: null } && storedFirst.AvailableAt <= DateTime.UtcNow && ObjectId.TryParse(storedFirst.Id, out _));

    Check("публикация без дублей: при ожидающем событии новое не создаётся",
        await events.PublishIfNoPendingAsync(Syn, new XCoreSyncPayload("srv1", "p1"), "srv1", ct: ct) is null && Count("srv1") == 1);
    Check("публикация без дублей: другая партиция — своё событие",
        await events.PublishIfNoPendingAsync(Syn, new XCoreSyncPayload("srv2", "p2"), "srv2", ct: ct) is not null && Count("srv2") == 1);
    Check("публикация без дублей: другой тип той же партиции не считается дублем",
        await events.PublishIfNoPendingAsync("probe.other", new { x = 1 }, "srv1", ct: ct) is not null);

    var claimed = await events.ClaimAsync([Syn], "worker-1", TimeSpan.FromMinutes(1), ct);
    Check("захваченное событие больше не pending", claimed?.PartitionKey is "srv1" or "srv2" && claimed.Status == DomainEventStatuses.Claimed);
    var claimedPartition = claimed!.PartitionKey!;
    var created = await events.PublishIfNoPendingAsync(Syn, new XCoreSyncPayload(claimedPartition, "p"), claimedPartition, ct: ct);
    Check("публикация без дублей: захваченное (в работе) не считается — создаётся новое, его снимок мог устареть",
        created is not null && created.Id != claimed.Id && Count(claimedPartition) == 2
        && Count(claimedPartition, DomainEventStatuses.Claimed) == 1 && Count(claimedPartition, DomainEventStatuses.Pending) == 1);
    Check("публикация без дублей: теперь снова есть ожидающее — третье не создаётся",
        await events.PublishIfNoPendingAsync(Syn, new XCoreSyncPayload(claimedPartition, "p"), claimedPartition, ct: ct) is null && Count(claimedPartition) == 2);

    await events.CompleteAsync(claimed.Id, null, ct);
    Check("публикация без дублей: завершённое не мешает (ожидающее по-прежнему одно)", Count(claimedPartition, DomainEventStatuses.Pending) == 1);

    // Событие, возвращённое в очередь с отложенным временем, всё ещё pending: обработчик прочтёт базу позже нашей правки.
    var requeued = await events.ClaimAsync([Syn], "worker-1", TimeSpan.FromMinutes(1), ct);
    await events.RequeueAsync(requeued!.Id, DateTime.UtcNow.AddMinutes(5), countsAsAttempt: true, ct);
    Check("публикация без дублей: отложенное (backoff) ожидающее событие тоже закрывает публикацию",
        await events.PublishIfNoPendingAsync(Syn, new XCoreSyncPayload(requeued.PartitionKey!, "p"), requeued.PartitionKey!, ct: ct) is null);

    // Гонка без уникального индекса: допустимо редкое дублирование, недопустимо пропустить публикацию.
    await eventsCollection.DeleteManyAsync(FilterDefinition<DomainEvent>.Empty, ct);
    var parallel = await Task.WhenAll(Enumerable.Range(0, 24).Select(_ =>
        events.PublishIfNoPendingAsync(Syn, new XCoreSyncPayload("race", "p"), "race", ct: ct)));
    var raceCreated = parallel.Count(e => e is not null);
    var racePending = Count("race", DomainEventStatuses.Pending);
    Check("гонка: из 24 одновременных публикаций событие есть (не пропущено), создано не больше 24",
        raceCreated >= 1 && racePending == raceCreated, $"создано {raceCreated} из 24");
    Console.WriteLine($"  (справочно: параллельных дублей при 24 одновременных публикациях — {raceCreated - 1})");
    Check("после гонки последовательная публикация дубля не создаёт", await events.PublishIfNoPendingAsync(Syn, new XCoreSyncPayload("race", "p"), "race", ct: ct) is null);

    // ── Желаемый список узла ─────────────────────────────────────────────────

    await db.DropCollectionAsync("subscriptions", ct);
    await migration.ApplyAsync(db, ct);
    var users = new List<User>();
    for (var i = 0; i < 6; i++) users.Add(await NewUserAsync($"user{i}"));
    var healthy = NewSub(users[0].Id);
    var future = NewSub(users[1].Id, s => s.ExpiresAt = DateTime.UtcNow.AddDays(10));
    var expiredNotRevoked = NewSub(users[2].Id, s => s.ExpiresAt = DateTime.UtcNow.AddMinutes(-5));
    var revokedSub = NewSub(users[3].Id, s => { s.Status = SubscriptionStatuses.Revoked; s.RevokeReason = RevokeReasons.Manual; });
    var overQuota = NewSub(users[4].Id, s => { s.TrafficLimitBytes = 1000; s.Usage.RxBytes = 600; s.Usage.TxBytes = 400; });
    var underQuota = NewSub(users[5].Id, s => { s.TrafficLimitBytes = 1000; s.Usage.RxBytes = 600; s.Usage.TxBytes = 399; });
    foreach (var s in new[] { healthy, future, expiredNotRevoked, revokedSub, overQuota, underQuota }) await repo.TryCreateAsync(s, ct);

    var desired = (await repo.FindDesiredAsync(DateTime.UtcNow, ct)).Select(s => s.Id).ToHashSet();
    Check("желаемый список: активные без срока и с будущим сроком (и с квотой — её снимает принуждение)",
        desired.SetEquals([healthy.Id, future.Id, overQuota.Id, underQuota.Id]));
    Check("желаемый список: истёкшая (ещё не отозванная) и отозванная исключены",
        !desired.Contains(expiredNotRevoked.Id) && !desired.Contains(revokedSub.Id));
    var candidates = (await repo.FindEnforcementCandidatesAsync(DateTime.UtcNow, ct)).Select(s => s.Id).ToHashSet();
    Check("кандидаты на отзыв: истёкшая и исчерпавшая квоту (≥ лимита), но не недобравшая и не отозванная",
        candidates.SetEquals([expiredNotRevoked.Id, overQuota.Id]));

    // ── Поиск ────────────────────────────────────────────────────────────────

    var all = await repo.SearchAsync(new SubscriptionQuery(), ct);
    Check("список: без фильтров — все шесть, новые первыми", all.Total == 6 && all.Items.Count == 6);
    Check("список: по статусу", (await repo.SearchAsync(new SubscriptionQuery(Status: SubscriptionStatuses.Revoked), ct)).Items.Single().Id == revokedSub.Id);
    Check("список: по пользователям и по id — «или»",
        (await repo.SearchAsync(new SubscriptionQuery(Id: healthy.Id, UserIds: [users[1].Id]), ct)).Items.Select(s => s.Id).ToHashSet().SetEquals([healthy.Id, future.Id]));
    Check("список: поиск задан, а искать нечем — пусто, а не «всё подряд»",
        (await repo.SearchAsync(new SubscriptionQuery(Id: "junk", UserIds: []), ct)).Total == 0);
    Check("список: страница размера 2", (await repo.SearchAsync(new SubscriptionQuery(Page: 2, PageSize: 2), ct)) is { Total: 6, Items.Count: 2, Page: 2 });

    // ── Учёт использования ───────────────────────────────────────────────────

    var usageRepo = provider.GetRequiredService<IUsageRepository>();
    var today = DateOnly.FromDateTime(DateTime.UtcNow);
    await repo.ApplyUsageAsync([new SubscriptionUsageUpdate(healthy.Id, "69ca5beaba00e3c10adc4530", 600, 60, 600, 60, DateTime.UtcNow)], ct);
    await repo.ApplyUsageAsync([new SubscriptionUsageUpdate(healthy.Id, "69ca5beaba00e3c10adc4530", 400, 40, 1000, 100, DateTime.UtcNow),
                                new SubscriptionUsageUpdate(healthy.Id, "69ca5beaba00e3c10adc4531", 7, 0, 7, 0, DateTime.UtcNow)], ct);
    var withUsage = await repo.FindByIdAsync(healthy.Id, ct);
    Check("использование: приращения складываются ($inc), сырые значения заменяются по узлам",
        withUsage is { Usage: { RxBytes: 1007, TxBytes: 100 } }
        && withUsage.RawByNode["69ca5beaba00e3c10adc4530"] is { Rx: 1000, Tx: 100 } && withUsage.RawByNode["69ca5beaba00e3c10adc4531"] is { Rx: 7, Tx: 0 });
    Check("использование: lastSeenAt ставится, когда был трафик", withUsage!.Usage.LastSeenAt is not null);
    await repo.ApplyUsageAsync([new SubscriptionUsageUpdate(future.Id, "69ca5beaba00e3c10adc4530", 0, 0, 5, 5, DateTime.UtcNow)], ct);
    var idle = await repo.FindByIdAsync(future.Id, ct);
    Check("использование: без движения трафика сырые значения пишутся, lastSeenAt не трогается", idle!.RawByNode.Count == 1 && idle.Usage.LastSeenAt is null);

    await usageRepo.IncrementSubscriptionAsync(healthy.Id, today, 10, 1, ct);
    await usageRepo.IncrementSubscriptionAsync(healthy.Id, today, 5, 2, ct);
    await usageRepo.IncrementSubscriptionAsync(healthy.Id, today, 0, 0, ct);
    var dailyDocs = await db.GetCollection<SubscriptionUsageDaily>("subscription_usage_daily").Find(_ => true).ToListAsync(ct);
    Check("суточный срез: детерминированный _id {id}:{дата}, один документ, приращения сложены",
        dailyDocs is [{ RxBytes: 15, TxBytes: 3 } day] && day.Id == $"{healthy.Id}:{today:yyyy-MM-dd}" && day.SubscriptionId == healthy.Id
        && day.Date == $"{today:yyyy-MM-dd}" && day.ExpireAt > DateTime.UtcNow.AddDays(399));

    // ── Точечное обновление протокола узла ───────────────────────────────────

    var awgProtocol = new ProtocolInstance { Id = "awg-1", Kind = ProtocolKinds.Awg2, ContainerName = "amnezia-awg2", Port = "40000", State = ProtocolStates.Installed };
    var xcoreProtocol = XCoreProtocol("xc-1", n => n.SyncError = "старая ошибка");
    var node = new VpnServer
    {
        Id = ObjectId.GenerateNewId().ToString(), Name = "Node", Host = "203.0.113.20", Status = ServerStatuses.Ok,
        Protocols = [awgProtocol, xcoreProtocol],
    };
    await serverRepo.CreateAsync(node, ct);
    var appliedAt = new DateTime(2026, 10, 29, 10, 0, 0, DateTimeKind.Utc);
    await serverRepo.MarkXCoreAppliedAsync(node.Id, "xc-1", "rev-full", "rev-structure", appliedAt, ct);
    var reread = (await serverRepo.GetByIdAsync(node.Id, ct))!;
    var rx = reread.FindProtocol("xc-1")!.XCore!;
    Check("узел: ревизии, время применения записаны, SyncError сброшен",
        rx is { AppliedRevision: "rev-full", AppliedStructureRevision: "rev-structure", SyncError: null } && rx.AppliedAt == appliedAt);
    Check("узел: остальные поля протокола и соседний протокол не затронуты",
        rx.Domain == "node1.example.com" && rx.ShortIds.Count == 2 && rx.XhttpPath == "/x7Kq2mPz" && rx.Title == "Нидерланды"
        && reread.FindProtocol("awg-1") is { Kind: ProtocolKinds.Awg2, Port: "40000" } && reread.Protocols.Count == 2 && reread.Name == "Node");
    Check("узел: Id протокола сохранён (BsonNoId) после точечной записи", reread.Protocols.Select(p => p.Id).SequenceEqual(["awg-1", "xc-1"]));
    await serverRepo.SetXCoreSyncErrorAsync(node.Id, "xc-1", "Xray отклонил новый конфиг", ct);
    rx = (await serverRepo.GetByIdAsync(node.Id, ct))!.FindProtocol("xc-1")!.XCore!;
    Check("узел: ошибка записана, ревизии остались", rx.SyncError == "Xray отклонил новый конфиг" && rx.AppliedRevision == "rev-full");
    await serverRepo.MarkXCoreAppliedAsync(node.Id, "нет-такого", "x", "y", appliedAt, ct);
    await serverRepo.SetXCoreSyncErrorAsync(node.Id, "нет-такого", "z", ct);
    Check("узел: запись по несуществующему протоколу ничего не меняет",
        (await serverRepo.GetByIdAsync(node.Id, ct))!.FindProtocol("xc-1")!.XCore is { AppliedRevision: "rev-full", SyncError: "Xray отклонил новый конфиг" });

    // ── Номер маршрута и параметры входа ─────────────────────────────────────

    var routeServer = new VpnServer
    {
        Id = ObjectId.GenerateNewId().ToString(), Name = "Route", Host = "203.0.113.30", Status = ServerStatuses.Ok,
        Protocols = [awgProtocol, XCoreProtocol("xc-r1")],
    };
    var numberedServer = new VpnServer
    {
        Id = ObjectId.GenerateNewId().ToString(), Name = "Numbered", Host = "203.0.113.31", Status = ServerStatuses.Ok,
        Protocols = [XCoreProtocol("xc-r2", n => n.RouteId = 5)],
    };
    await serverRepo.CreateAsync(routeServer, ct);
    await serverRepo.CreateAsync(numberedServer, ct);
    Check("номер маршрута: выход без номера получает его условной записью",
        await serverRepo.SetXCoreRouteIdAsync(routeServer.Id, "xc-r1", 3, ct)
        && (await serverRepo.GetByIdAsync(routeServer.Id, ct))!.FindProtocol("xc-r1")!.XCore!.RouteId == 3);
    Check("номер маршрута: уже назначенный не перезаписывается (ни у выхода, получившего его выше, ни у поставленного с номером)",
        !await serverRepo.SetXCoreRouteIdAsync(routeServer.Id, "xc-r1", 4, ct)
        && !await serverRepo.SetXCoreRouteIdAsync(numberedServer.Id, "xc-r2", 4, ct)
        && (await serverRepo.GetByIdAsync(routeServer.Id, ct))!.FindProtocol("xc-r1")!.XCore!.RouteId == 3
        && (await serverRepo.GetByIdAsync(numberedServer.Id, ct))!.FindProtocol("xc-r2")!.XCore!.RouteId == 5);
    Check("номер маршрута: чужой или несуществующий протокол — ничего не меняется, соседний протокол цел",
        !await serverRepo.SetXCoreRouteIdAsync(routeServer.Id, "нет-такого", 9, ct)
        && !await serverRepo.SetXCoreRouteIdAsync(routeServer.Id, "awg-1", 9, ct)
        && !await serverRepo.SetXCoreRouteIdAsync(ObjectId.GenerateNewId().ToString(), "xc-r1", 9, ct)
        && (await serverRepo.GetByIdAsync(routeServer.Id, ct))!.FindProtocol("awg-1") is { Kind: ProtocolKinds.Awg2, Port: "40000" });
    var racers = await Task.WhenAll(Enumerable.Range(10, 8).Select(async i =>
    {
        var s = new VpnServer { Id = ObjectId.GenerateNewId().ToString(), Name = "R" + i, Host = "203.0.113.40", Protocols = [XCoreProtocol("xc-race")] };
        await serverRepo.CreateAsync(s, ct);
        var results = await Task.WhenAll(Enumerable.Range(0, 6).Select(k => serverRepo.SetXCoreRouteIdAsync(s.Id, "xc-race", 100 + k, ct)));
        var won = results.Count(r => r);
        var number = (await serverRepo.GetByIdAsync(s.Id, ct))!.FindProtocol("xc-race")!.XCore!.RouteId;
        await serverRepo.DeleteAsync(s.Id, ct);
        return (won, number);
    }));
    Check("номер маршрута: из шести одновременных записей на один выход побеждает ровно одна, номер не перезаписывается",
        racers.All(r => r.Item1 == 1 && r.Item2 is >= 100 and <= 105));

    var entryProtocol = XCoreProtocol("xc-entry", n =>
    {
        n.Role = XCoreRoles.Entry; n.RuDirect = false; n.DirectDomains = ["bank.example.ru"]; n.ProxyDomains = ["domain:example.com", "keyword:chat"];
        n.RelayUuid = protector.Protect("c0ffee00-1111-4222-8333-444444444444");
    });
    var entryNodeServer = new VpnServer
    {
        Id = ObjectId.GenerateNewId().ToString(), Name = "EntryNode", Host = "203.0.113.32", Status = ServerStatuses.Ok, Protocols = [entryProtocol],
    };
    await serverRepo.CreateAsync(entryNodeServer, ct);
    var entryBack = (await serverRepo.GetByIdAsync(entryNodeServer.Id, ct))!.FindProtocol("xc-entry")!.XCore!;
    Check("вход в базе: роль, РФ напрямую, списки доменов и зашифрованный служебный UUID переживают запись",
        entryBack is { Role: "entry", RuDirect: false, RouteId: null } && entryBack.DirectDomains.SequenceEqual(["bank.example.ru"])
        && entryBack.ProxyDomains.SequenceEqual(["domain:example.com", "keyword:chat"])
        && protector.Unprotect(entryBack.RelayUuid) == "c0ffee00-1111-4222-8333-444444444444");
    var rawEntry = (await db.GetCollection<BsonDocument>("server_config").Find(new BsonDocument("_id", ObjectId.Parse(entryNodeServer.Id))).FirstAsync(ct))["protocols"][0]["xcore"].AsBsonDocument;
    Check("вход в базе: служебный UUID лежит шифртекстом, номера маршрута у входа в документе нет",
        !rawEntry.ToJson().Contains("c0ffee00") && !rawEntry.Contains("routeId") && rawEntry["relayUuid"].IsBsonDocument);
    foreach (var cleanup in new[] { routeServer, numberedServer, entryNodeServer }) await serverRepo.DeleteAsync(cleanup.Id, ct);

    // ── Публикатор и сверка ──────────────────────────────────────────────────

    await eventsCollection.DeleteManyAsync(FilterDefinition<DomainEvent>.Empty, ct);
    var other = new VpnServer
    {
        Id = ObjectId.GenerateNewId().ToString(), Name = "NoSub", Host = "203.0.113.21", Status = ServerStatuses.Ok,
        Protocols = [XCoreProtocol("xc-2", n => n.SubscriptionEnabled = false)],
    };
    await serverRepo.CreateAsync(other, ct);

    var publisher = provider.GetRequiredService<XCoreSyncPublisher>();
    // Узел, исключённый из подписки, синхронизацию получает: иначе отозванный подписчик
    // сохранил бы на нём доступ по уже сохранённой ссылке.
    Check("публикатор: событие на каждый установленный xcore, включая исключённый из подписки",
        await publisher.PublishForAllAsync("actor", ct) == 2 && Count(node.Id, DomainEventStatuses.Pending) == 1
        && Count(other.Id, DomainEventStatuses.Pending) == 1);
    Check("публикатор: повторный вызов дубля не создаёт",
        await publisher.PublishForAllAsync(null, ct) == 0 && Count(node.Id) == 1 && Count(other.Id) == 1);

    // Вход тоже получает синхронизацию: топология меняется для обоих концов плеча.
    var entryForFanOut = new VpnServer
    {
        Id = ObjectId.GenerateNewId().ToString(), Name = "EntrySync", Host = "203.0.113.33", Status = ServerStatuses.Ok,
        Protocols = [XCoreProtocol("xc-e", n => { n.Role = XCoreRoles.Entry; n.RelayUuid = protector.Protect(Guid.NewGuid().ToString("D")); })],
    };
    await serverRepo.CreateAsync(entryForFanOut, ct);
    Check("публикатор: вход получает событие, выход с уже ожидающим — нет",
        await publisher.PublishForAllAsync(null, ct) == 1 && Count(entryForFanOut.Id, DomainEventStatuses.Pending) == 1 && Count(node.Id) == 1);
    await serverRepo.DeleteAsync(entryForFanOut.Id, ct);
    await eventsCollection.DeleteManyAsync(e => e.PartitionKey == entryForFanOut.Id, ct);

    await eventsCollection.DeleteManyAsync(FilterDefinition<DomainEvent>.Empty, ct);
    var reconcile = new TickableReconcile(provider.GetRequiredService<IServiceScopeFactory>(), Options.Create(new PollingOptions()),
        NullLogger<XCoreReconcileService>.Instance);
    using (var scope = provider.CreateScope()) await reconcile.RunAsync(scope.ServiceProvider, ct);
    var reconcileEvent = await eventsCollection.Find(e => e.Type == Syn && e.PartitionKey == node.Id).SingleOrDefaultAsync(ct);
    Check("сверка: публикует xcore.sync для узла с payload {ServerId, ProtocolId}",
        reconcileEvent is not null && reconcileEvent.PayloadAs<XCoreSyncPayload>() == new XCoreSyncPayload(node.Id, "xc-1"));
    Check("сверка: узел, исключённый из подписки, тоже сверяется", Count(other.Id) == 1);
    using (var scope = provider.CreateScope()) await reconcile.RunAsync(scope.ServiceProvider, ct);
    Check("сверка: второй тик при ожидающем событии не копит новые", Count(node.Id) == 1);
    var schedule = new PollingOptions { XCoreReconcileIntervalMinutes = 15 }.For(TimeSpan.FromMinutes(15));
    Check("сверка: интервал 15 минут по умолчанию, общий выключатель Polling:Enabled уважается",
        new PollingOptions().XCoreReconcileIntervalMinutes == 15 && schedule.Interval == TimeSpan.FromMinutes(15)
        && new PollingOptions { Enabled = false }.For(TimeSpan.FromMinutes(15)).Enabled == false);

    // ── SubscriptionService ──────────────────────────────────────────────────

    await db.DropCollectionAsync("subscriptions", ct);
    await migration.ApplyAsync(db, ct);
    await eventsCollection.DeleteManyAsync(FilterDefinition<DomainEvent>.Empty, ct);
    await db.DropCollectionAsync("audit_log", ct);

    var erin = await NewUserAsync("erin");
    var frank = await NewUserAsync("frank");
    var actor = new AuditActor("admin-id", "admin");

    using var serviceScope = provider.CreateScope();
    var service = serviceScope.ServiceProvider.GetRequiredService<SubscriptionService>();

    var created0 = DateTime.UtcNow;
    var s1 = await service.CreateAsync(erin.Id, new SubscriptionCreateOptions(Actor: actor), ct);
    Check("сервис: подписка создана активной, срок из настроек панели (90 дней), квота не задана",
        s1 is { Status: SubscriptionStatuses.Active, Source: KeySources.Panel, TrafficLimitBytes: null, CreatedByUserId: "admin-id" }
        && s1.ExpiresAt is { } e1 && (e1 - created0.AddDays(90)).Duration() < TimeSpan.FromMinutes(1));
    Check("сервис: UUID — валидный GUID, токен сохранён зашифрованным и расшифровывается в 43 символа",
        Guid.TryParse(s1.XrayUuid, out _) && protector.Unprotect(s1.TokenEncrypted) is { Length: 43 } tok
        && SubscriptionTokenCrypto.Matches(tok, s1.TokenHash));
    Check("сервис: после выдачи опубликован xcore.sync на подходящий узел", Count(node.Id, DomainEventStatuses.Pending) == 1);

    var link1 = await service.BuildLinkAsync(s1, ct);
    Check("сервис: ссылка подписки — {PublicBaseUrl}/sub/{токен}, показывается повторно без перевыпуска",
        link1 == $"https://sub.example.com/sub/{protector.Unprotect(s1.TokenEncrypted)}" && await service.BuildLinkAsync(s1, ct) == link1);
    Check("сервис: вторая активная подписка у пользователя — BadRequest",
        await CatchAsync<BadRequestException>(() => service.CreateAsync(erin.Id, new SubscriptionCreateOptions(), ct)) is not null);
    Check("сервис: несуществующий пользователь — NotFound",
        await CatchAsync<NotFoundException>(() => service.CreateAsync(ObjectId.GenerateNewId().ToString(), new SubscriptionCreateOptions(), ct)) is not null);

    var s2 = await service.CreateAsync(frank.Id, new SubscriptionCreateOptions(ExpiryDays: 0, TrafficLimitBytes: 5_000_000), ct);
    Check("сервис: 0 дней — бессрочно, явная квота сохраняется", s2.ExpiresAt is null && s2.TrafficLimitBytes == 5_000_000);

    var gina = await NewUserAsync("gina");
    var s3 = await service.CreateAsync(gina.Id, new SubscriptionCreateOptions(ExpiryDays: 7, TrafficLimitBytes: 0), ct);
    Check("сервис: 7 дней — срок через неделю, квота 0 — без ограничения",
        s3.TrafficLimitBytes is null && s3.ExpiresAt is { } e3 && (e3 - created0.AddDays(7)).Duration() < TimeSpan.FromMinutes(1));
    var hugo = await NewUserAsync("hugo");
    var ivan = await NewUserAsync("ivan");
    Check("сервис: срок и квота за пределами отклоняются",
        await CatchAsync<BadRequestException>(() => service.CreateAsync(hugo.Id, new SubscriptionCreateOptions(ExpiryDays: 99999), ct)) is not null
        && await CatchAsync<BadRequestException>(() => service.CreateAsync(ivan.Id, new SubscriptionCreateOptions(TrafficLimitBytes: long.MaxValue), ct)) is not null
        && await repo.FindActiveByUserAsync(hugo.Id, ct) is null);

    // Перевыпуск меняет и токен, и UUID.
    var before = (await repo.FindByIdAsync(s1.Id, ct))!;
    await eventsCollection.DeleteManyAsync(FilterDefinition<DomainEvent>.Empty, ct);
    var regenerated = await service.RegenerateAsync(s1.Id, actor, ct);
    Check("перевыпуск: токен, его хеш и UUID — новые; дата ротации проставлена",
        regenerated.TokenHash != before.TokenHash && regenerated.XrayUuid != before.XrayUuid
        && protector.Unprotect(regenerated.TokenEncrypted) != protector.Unprotect(before.TokenEncrypted) && regenerated.TokenRotatedAt is not null);
    Check("перевыпуск: старый токен по хешу больше не находится, новый находится",
        await repo.FindByTokenHashAsync(before.TokenHash, ct) is null && await repo.FindByTokenHashAsync(regenerated.TokenHash, ct) is not null);
    Check("перевыпуск: срок, квота и использование сохранены", regenerated.ExpiresAt == before.ExpiresAt && regenerated.Id == before.Id);
    Check("перевыпуск: опубликован xcore.sync", Count(node.Id, DomainEventStatuses.Pending) == 1);

    // Границы.
    var newExpiry = DateTime.UtcNow.AddDays(30);
    var limited = await service.UpdateLimitsAsync(s2.Id, newExpiry, 9_000_000, actor, ct);
    Check("границы: срок и квота заменены целиком", limited.ExpiresAt is { } le && (le - newExpiry).Duration() < TimeSpan.FromSeconds(1) && limited.TrafficLimitBytes == 9_000_000);
    var unlimited = await service.UpdateLimitsAsync(s2.Id, null, 0, actor, ct);
    Check("границы: null и 0 снимают ограничения", unlimited is { ExpiresAt: null, TrafficLimitBytes: null });
    Check("границы: срок в прошлом отклоняется",
        await CatchAsync<BadRequestException>(() => service.UpdateLimitsAsync(s2.Id, DateTime.UtcNow.AddDays(-1), null, actor, ct)) is not null);
    Check("границы: синхронизация не публикуется (список пользователей от границ не зависит)", Count(node.Id) == 1);

    // Отзыв.
    await eventsCollection.DeleteManyAsync(FilterDefinition<DomainEvent>.Empty, ct);
    var revoked = await service.RevokeAsync(s3.Id, RevokeReasons.Manual, actor, ct);
    Check("отзыв: статус, причина, время; опубликован xcore.sync",
        revoked is { Status: SubscriptionStatuses.Revoked, RevokeReason: RevokeReasons.Manual } && revoked.RevokedAt is not null
        && Count(node.Id, DomainEventStatuses.Pending) == 1);
    await eventsCollection.DeleteManyAsync(FilterDefinition<DomainEvent>.Empty, ct);
    var again = await service.RevokeAsync(s3.Id, RevokeReasons.Expired, actor, ct);
    Check("отзыв: повторный — идемпотентно, причина прежняя, синхронизация не публикуется",
        again.RevokeReason == RevokeReasons.Manual && Count(node.Id) == 0);
    Check("отзыв: ссылка отозванной подписки не выдаётся", await CatchAsync<BadRequestException>(() => service.BuildLinkAsync(revoked, ct)) is not null);
    Check("отзыв: перевыпуск и границы отозванной отклоняются",
        await CatchAsync<BadRequestException>(() => service.RegenerateAsync(s3.Id, actor, ct)) is not null
        && await CatchAsync<BadRequestException>(() => service.UpdateLimitsAsync(s3.Id, null, null, actor, ct)) is not null);
    Check("отзыв: неизвестная причина — ошибка вызывающего", await CatchAsync<ArgumentException>(() => service.RevokeAsync(s2.Id, "because", actor, ct)) is not null);
    Check("отзыв: несуществующая подписка — NotFound",
        await CatchAsync<NotFoundException>(() => service.RevokeAsync(ObjectId.GenerateNewId().ToString(), RevokeReasons.Manual, actor, ct)) is not null);

    // Для бота.
    var jack = await NewUserAsync("jack");
    static Subscription Granted(SelfServiceSubscriptionResult result) =>
        result is SelfServiceSubscriptionResult.Granted granted ? granted.Subscription : throw new InvalidOperationException($"Ожидалась выдача, получено {result}.");

    var viaBotResult = await service.GetOrCreateForUserAsync(jack.Id, KeySources.Telegram, ct);
    var viaBot = Granted(viaBotResult);
    var viaBotAgain = Granted(await service.GetOrCreateForUserAsync(jack.Id, KeySources.Telegram, ct));
    Check("бот: подписка создаётся при первом обращении, источник telegram; повторное обращение отдаёт ту же",
        viaBotResult is SelfServiceSubscriptionResult.Granted { Created: true }
        && viaBot.Source == KeySources.Telegram && viaBot.Id == viaBotAgain.Id && viaBot.CreatedByUserId == jack.Id);
    var existing = Granted(await service.GetOrCreateForUserAsync(erin.Id, KeySources.Telegram, ct));
    Check("бот: у пользователя с активной подпиской возвращается она, а не новая", existing.Id == s1.Id);
    Check("бот: несуществующий пользователь — NotFound",
        await CatchAsync<NotFoundException>(() => service.GetOrCreateForUserAsync(ObjectId.GenerateNewId().ToString(), KeySources.Telegram, ct)) is not null);

    // Правило повторной выдачи на реальной базе: «последняя» определяется запросом, а не списком в памяти.
    var lena = await NewUserAsync("lena");
    var lenaOld = NewSub(lena.Id, s => { s.CreatedAt = DateTime.UtcNow.AddDays(-60); });
    await repo.TryCreateAsync(lenaOld, ct);
    await repo.TryRevokeAsync(lenaOld.Id, RevokeReasons.Manual, DateTime.UtcNow.AddDays(-50), ct);
    var lenaLatest = NewSub(lena.Id, s => { s.CreatedAt = DateTime.UtcNow.AddDays(-40); });
    await repo.TryCreateAsync(lenaLatest, ct);
    await repo.TryRevokeAsync(lenaLatest.Id, RevokeReasons.Expired, DateTime.UtcNow.AddDays(-5), ct);
    Check("репозиторий: последняя подписка — по времени создания, независимо от статуса и порядка вставки",
        (await repo.FindLatestByUserAsync(lena.Id, ct))?.Id == lenaLatest.Id
        && await repo.FindLatestByUserAsync(ObjectId.GenerateNewId().ToString(), ct) is null && await repo.FindLatestByUserAsync("junk", ct) is null);
    Check("выдача боту: прежняя ручной отзыв, последняя — по сроку: создаётся новая",
        await service.GetOrCreateForUserAsync(lena.Id, KeySources.Telegram, ct) is SelfServiceSubscriptionResult.Granted { Created: true, Subscription.Status: SubscriptionStatuses.Active });

    var mark = await NewUserAsync("mark");
    var markQuota = NewSub(mark.Id);
    await repo.TryCreateAsync(markQuota, ct);
    await repo.TryRevokeAsync(markQuota.Id, RevokeReasons.Quota, DateTime.UtcNow, ct);
    var markDenied = await service.GetOrCreateForUserAsync(mark.Id, KeySources.Telegram, ct);
    Check("выдача боту: последняя отозвана по квоте — отказ, активной подписки не появилось",
        markDenied is SelfServiceSubscriptionResult.Denied { Reason: RevokeReasons.Quota } && await repo.FindActiveByUserAsync(mark.Id, ct) is null);

    var nina = await NewUserAsync("nina");
    var ninaManual = NewSub(nina.Id);
    await repo.TryCreateAsync(ninaManual, ct);
    await service.RevokeAsync(ninaManual.Id, RevokeReasons.Manual, actor, ct);
    Check("выдача боту: отозвана администратором через сервис — отказ с причиной manual",
        await service.GetOrCreateForUserAsync(nina.Id, KeySources.Telegram, ct) is SelfServiceSubscriptionResult.Denied { Reason: RevokeReasons.Manual }
        && await service.CreateAsync(nina.Id, new SubscriptionCreateOptions(Actor: actor), ct) is { IsActive: true });

    // Параллельные запросы бота не плодят подписки.
    var kate = await NewUserAsync("kate");
    var racing = await Task.WhenAll(Enumerable.Range(0, 8).Select(async _ =>
    {
        using var s = provider.CreateScope();
        return Granted(await s.ServiceProvider.GetRequiredService<SubscriptionService>().GetOrCreateForUserAsync(kate.Id, KeySources.Telegram, ct));
    }));
    Check("бот: 8 параллельных нажатий — одна активная подписка у всех",
        racing.Select(s => s.Id).Distinct().Count() == 1
        && await db.GetCollection<Subscription>("subscriptions").CountDocumentsAsync(s => s.UserId == kate.Id && s.Status == SubscriptionStatuses.Active, cancellationToken: ct) == 1);

    // Без адреса публикации ссылка не строится, подписка при этом создаётся.
    var noUrlServices = new ServiceCollection();
    noUrlServices.AddLogging();
    noUrlServices.AddAmneziaData(new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
    {
        ["MongoDb:ConnectionString"] = connection, ["MongoDb:DatabaseName"] = database,
        ["Security:DataProtectionKey"] = config["Security:DataProtectionKey"],
    }).Build());
    using var noUrlProvider = noUrlServices.BuildServiceProvider();
    using var noUrlScope = noUrlProvider.CreateScope();
    var noUrlService = noUrlScope.ServiceProvider.GetRequiredService<SubscriptionService>();
    string? noUrlMessage = null;
    try { await noUrlService.BuildLinkAsync(viaBot, ct); }
    catch (BadRequestException ex) { noUrlMessage = ex.Message; }
    Check("без Subscription:PublicBaseUrl: подписка создаётся, а ссылка — понятная ошибка с названием настройки",
        viaBot.IsActive && noUrlMessage?.Contains("Subscription:PublicBaseUrl") == true, noUrlMessage);

    // Журнал.
    var auditEntries = await db.GetCollection<AuditEntry>("audit_log").Find(_ => true).ToListAsync(ct);
    var auditEvents = auditEntries.Select(a => a.Event).ToHashSet();
    Check("журнал: subscription.created / .revoked / .regenerated / .limits_changed записаны",
        auditEvents.IsSupersetOf(["subscription.created", "subscription.revoked", "subscription.regenerated", "subscription.limits_changed"]),
        string.Join(",", auditEvents));
    Check("журнал: цель — subscription, актор записан",
        auditEntries.Where(a => a.Event == "subscription.revoked").All(a => a.TargetType == AuditTargets.Subscription && a.TargetId is not null && a.ActorName == "admin"));
    var auditJson = string.Join("\n", auditEntries.Select(a => a.ToJson()));
    var allSubscriptions = await db.GetCollection<Subscription>("subscriptions").Find(_ => true).ToListAsync(ct);
    var secretsInAudit = allSubscriptions.SelectMany(s => new[] { s.XrayUuid, protector.Unprotect(s.TokenEncrypted)!, s.TokenHash })
        .Concat([s1.XrayUuid, before.XrayUuid, protector.Unprotect(before.TokenEncrypted)!]).Where(v => auditJson.Contains(v)).ToList();
    Check("журнал: ни токена, ни его хеша, ни UUID (в том числе до перевыпуска)", secretsInAudit.Count == 0, string.Join(",", secretsInAudit));

    // ── Принуждение ──────────────────────────────────────────────────────────

    await db.DropCollectionAsync("subscriptions", ct);
    await migration.ApplyAsync(db, ct);
    await eventsCollection.DeleteManyAsync(FilterDefinition<DomainEvent>.Empty, ct);
    await db.DropCollectionAsync("audit_log", ct);

    var uExpired = NewSub((await NewUserAsync("e1")).Id, s => s.ExpiresAt = DateTime.UtcNow.AddMinutes(-3));
    var uQuota = NewSub((await NewUserAsync("e2")).Id, s => { s.TrafficLimitBytes = 100; s.Usage.RxBytes = 70; s.Usage.TxBytes = 30; });
    var uBoth = NewSub((await NewUserAsync("e3")).Id, s => { s.ExpiresAt = DateTime.UtcNow.AddMinutes(-1); s.TrafficLimitBytes = 10; s.Usage.RxBytes = 50; });
    var uFine = NewSub((await NewUserAsync("e4")).Id, s => { s.ExpiresAt = DateTime.UtcNow.AddDays(3); s.TrafficLimitBytes = 100; s.Usage.RxBytes = 10; });
    foreach (var s in new[] { uExpired, uQuota, uBoth, uFine }) await repo.TryCreateAsync(s, ct);

    var enforcement = new TickableEnforcement(provider.GetRequiredService<IServiceScopeFactory>(), Options.Create(new PollingOptions()),
        NullLogger<EnforcementService>.Instance);
    using (var scope = provider.CreateScope()) await enforcement.RunAsync(scope.ServiceProvider, ct);

    var afterTick = (await db.GetCollection<Subscription>("subscriptions").Find(_ => true).ToListAsync(ct)).ToDictionary(s => s.Id);
    Check("принуждение: истёкшая → revoked / expired",
        afterTick[uExpired.Id] is { Status: SubscriptionStatuses.Revoked, RevokeReason: RevokeReasons.Expired } && afterTick[uExpired.Id].RevokedAt is not null);
    Check("принуждение: исчерпавшая квоту → revoked / quota", afterTick[uQuota.Id] is { Status: SubscriptionStatuses.Revoked, RevokeReason: RevokeReasons.Quota });
    Check("принуждение: истёкшая и исчерпавшая квоту одновременно → причина «истёк срок»", afterTick[uBoth.Id].RevokeReason == RevokeReasons.Expired);
    Check("принуждение: здоровая подписка не тронута", afterTick[uFine.Id].Status == SubscriptionStatuses.Active);
    var tickEvents = await eventsCollection.Find(e => e.Type == Syn).ToListAsync(ct);
    var nodeEvents = tickEvents.Where(e => e.PartitionKey == node.Id).ToList();
    Check("принуждение: после отзыва ровно один xcore.sync на узел (три отзыва — одно событие)",
        nodeEvents is [{ Status: DomainEventStatuses.Pending } onlyEvent]
        && onlyEvent.PayloadAs<XCoreSyncPayload>() == new XCoreSyncPayload(node.Id, "xc-1")
        && tickEvents.GroupBy(e => e.PartitionKey).All(g => g.Count() == 1));
    Check("принуждение: узел, исключённый из подписки, тоже получает синхронизацию после отзыва",
        tickEvents.Any(e => e.PartitionKey == other.Id));
    var enforcementAudit = await db.GetCollection<AuditEntry>("audit_log").Find(a => a.Event == "subscription.revoked").ToListAsync(ct);
    Check("принуждение: три записи журнала, автор — сервис (без пользователя), причины в тексте",
        enforcementAudit.Count == 3 && enforcementAudit.All(a => a.ActorUserId is null && a.Level == AuditLevels.Warn)
        && enforcementAudit.Count(a => a.Message.Contains("истёк срок")) == 2 && enforcementAudit.Count(a => a.Message.Contains("квота")) == 1);

    await eventsCollection.DeleteManyAsync(FilterDefinition<DomainEvent>.Empty, ct);
    using (var scope = provider.CreateScope()) await enforcement.RunAsync(scope.ServiceProvider, ct);
    Check("принуждение: повторный тик ничего не отзывает и не публикует", await eventsCollection.CountDocumentsAsync(e => e.Type == Syn, cancellationToken: ct) == 0);

}

static string RepoRoot()
{
    var dir = new DirectoryInfo(AppContext.BaseDirectory);
    while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "AmneziaKeyService.sln"))) dir = dir.Parent;
    return dir?.FullName ?? throw new InvalidOperationException("Не найден корень репозитория (AmneziaKeyService.sln).");
}

/// <summary>Воркер сверки с открытым тиком: расписание в проверке не участвует.</summary>
file sealed class TickableReconcile(IServiceScopeFactory scopes, IOptions<PollingOptions> options, ILogger<XCoreReconcileService> logger)
    : XCoreReconcileService(scopes, options, logger)
{
    public Task RunAsync(IServiceProvider services, CancellationToken ct) => TickAsync(services, ct);
}

file sealed class TickableEnforcement(IServiceScopeFactory scopes, IOptions<PollingOptions> options, ILogger<EnforcementService> logger)
    : EnforcementService(scopes, options, logger)
{
    public Task RunAsync(IServiceProvider services, CancellationToken ct) => TickAsync(services, ct);
}

file sealed class CollectingSink(List<LogEvent> events) : Serilog.Core.ILogEventSink
{
    public void Emit(LogEvent logEvent) => events.Add(logEvent);
}

/// <summary>Заглушка интерфейса на DispatchProxy: неожиданный вызов — исключение, а не тихий успех.</summary>
public class Stub : DispatchProxy
{
    private Func<MethodInfo, object?[], object?> handler = null!;

    public static T Create<T>(Func<MethodInfo, object?[], object?> handler) where T : class
    {
        var value = Create<T, Stub>();
        ((Stub)(object)value).handler = handler;
        return value;
    }

    protected override object? Invoke(MethodInfo? method, object?[]? args) => handler(method!, args ?? []);
}
