using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using AmneziaKeyService.Core.Models;

namespace AmneziaKeyService.Infrastructure.Protocols.XCore;

/// <summary>Подписчик Xray: <c>email</c> служит ключом в счётчиках и в API, <c>uuid</c> — учётными данными VLESS.</summary>
public sealed record XCoreUser(string Email, string Uuid);

/// <summary>Конфиг для записи на узел и его ревизия.</summary>
/// <param name="Json">Компактный JSON с детерминированным порядком полей.</param>
/// <param name="Revision">SHA-256 (hex, нижний регистр) от <paramref name="Json"/>.</param>
public sealed record XCoreRenderedConfig(string Json, string Revision);

/// <summary>
/// Выход, к которому подключается вход: всё, что нужно для outbound XHTTP+Reality. Домен — он же
/// SNI Reality и адрес подключения; порядок в конфиге входа задаёт <paramref name="RouteId"/>.
/// </summary>
/// <param name="Encryption">
/// Клиентская строка VLESS Encryption выхода; null — выход без шифрования (<c>none</c>). Строка публичная,
/// поэтому ей место здесь, а серверная часть выхода (с приватным ключом) в ревизии входа не участвует.
/// </param>
public sealed record XCoreExitTarget(
    int RouteId, string Domain, int Port, string PublicKey, string ShortId, string XhttpPath, string Fingerprint,
    string? Encryption = null);

/// <summary>
/// Чистая функция (узел, пользователи, топология) → конфиг Xray: без SSH и без доступа к секретам.
/// Приватный ключ приходит уже расшифрованным и явным аргументом, чтобы рендерер
/// нельзя было вызвать, не решив, кто и когда его расшифровывает.
///
/// Результат обязан быть детерминированным: по его хешу синхронизация решает,
/// нужно ли что-то делать на узле. Поэтому порядок полей фиксирован кодом, порядок
/// пользователей — сортировкой по email, порядок выходов — по номеру маршрута, а JSON
/// компактный: отступы System.Text.Json берёт из Environment.NewLine, и на Windows и Linux
/// хеш разошёлся бы.
/// </summary>
public static class XCoreConfigRenderer
{
    public const string InboundTag = "vless-xhttp";
    public const string ApiTag = "api";
    public const string DirectTag = "direct";
    public const string BlockTag = "block";

    /// <summary>Caddy с настоящим сертификатом на домен узла: сюда Reality отдаёт чужие рукопожатия.</summary>
    public const string SelfStealTarget = "127.0.0.1:8443";

    /// <summary>Тег outbound-а входа, ведущего на выход с этим номером маршрута.</summary>
    public static string ExitTag(int routeId) => $"exit-{routeId}";

    /// <summary>
    /// Локальные и приватные адреса, закрытые для пользователей прокси.
    /// Без этого правила подписчик через прокси достучался бы до API Xray на
    /// 127.0.0.1 (HandlerService позволяет добавлять и удалять пользователей) и до
    /// локального Caddy, а в облаке — до служебных адресов соседей по подсети.
    /// Список явный, без geo-файлов: рендерер не должен зависеть от файлов на хосте.
    /// </summary>
    private static readonly string[] BlockedCidrs =
    [
        "127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16",
        "100.64.0.0/10", "0.0.0.0/8", "::1/128", "fc00::/7", "fe80::/10"
    ];

    /// <summary>
    /// DNS входа поверх DoH к публичным резолверам. При <c>IPIfNonMatch</c> вход резолвит домены,
    /// не попавшие в правила; через DNS российского хостера он раскрыл бы ему все посещаемые сайты.
    /// Если DoH недоступен, домен не резолвится и уходит на выход по правилу маршрута — безопасный
    /// исход. <c>https+local</c> — запрос идёт напрямую, а не через routing: иначе резолвер, чтобы
    /// ответить, ждал бы маршрутизации, которая ждёт резолвера.
    /// </summary>
    private static readonly string[] EntryDnsServers =
    [
        "https+local://1.1.1.1/dns-query", "https+local://8.8.8.8/dns-query"
    ];

    // Встроенные списки Xray, проверенные `run -test` в закреплённом образе. Намеренно не
    // настраиваются оператором: см. XCoreRoutingDomains.
    // category-gov-ru отдельно: госсервисы в category-ru входят не все, а им российский IP
    // нужнее всего — часть из них не пускает зарубежные адреса.
    private static readonly string[] RuDomainsLists = ["geosite:category-ru", "geosite:category-gov-ru"];
    private const string RuIpList = "geoip:ru";

    /// <summary>Конфиг выхода.</summary>
    /// <param name="vlessDecryption">
    /// Расшифрованная серверная строка VLESS Encryption. Обязательна, когда у узла включено шифрование: забытый
    /// аргумент не должен молча превратить зашифрованный узел в открытый.
    /// </param>
    public static XCoreRenderedConfig Render(
        XCoreProtocolParams node, string realityPrivateKey, IEnumerable<XCoreUser> users,
        string? vlessDecryption = null)
    {
        RequireRole(node, XCoreRoles.Exit, "RenderEntry");
        RequireNodeFields(node, realityPrivateKey);

        var root = Skeleton(node);
        root["inbounds"] = new JsonArray(Inbound(node, realityPrivateKey, Clients(users), sniffing: false, vlessDecryption));
        root["outbounds"] = new JsonArray(DirectOutbound(), BlockOutbound());
        root["routing"] = new JsonObject
        {
            // IPIfNonMatch: домен, не попавший ни в одно правило, резолвится и сверяется
            // с правилами ещё раз. Иначе имя, указывающее на 127.0.0.1, обошло бы блок.
            ["domainStrategy"] = "IPIfNonMatch",
            ["rules"] = new JsonArray(PrivateBlockRule()),
        };

        return Finish(root);
    }

    /// <summary>
    /// Конфиг входа. Правила маршрутизации строго в таком порядке, потому что первое совпавшее
    /// решает: приватные адреса закрыты раньше всего; «всегда через VPN» сильнее российских
    /// списков; «всегда напрямую» и российские списки — раньше общего правила выхода; «заблокировано в РФ»
    /// (российские списки релиза) — между явными списками оператора и российскими «напрямую»; вход без
    /// выходов не превращается в VPN с российским IP, а закрывает весь трафик.
    /// </summary>
    /// <remarks>
    /// Российские списки (<c>ext:rf-…</c>) подключаются, только когда у входа записан тег их релиза
    /// (<see cref="XCoreProtocolParams.RfListsTag"/>): без файла на узле ссылка на него не даёт Xray запуститься.
    /// Без тега конфиг побайтово такой же, каким был до появления списков.
    /// </remarks>
    /// <param name="relayUuid">Расшифрованный служебный UUID входа: под ним он подключается к выходам.</param>
    /// <param name="exits">Выходы входа; порядок значения не имеет, в конфиг они идут по номеру маршрута.</param>
    public static XCoreRenderedConfig RenderEntry(
        XCoreProtocolParams node, string realityPrivateKey, IEnumerable<XCoreUser> users,
        string relayUuid, IReadOnlyList<XCoreExitTarget> exits, string? vlessDecryption = null)
        => RenderEntryWithRfLists(node, realityPrivateKey, users, relayUuid, exits, node.RfListsTag, vlessDecryption);

    /// <summary>
    /// Конфиг входа так, как он будет выглядеть с российскими списками релиза <paramref name="rfListsTag"/>
    /// (null — без них). Нужен проверке нового релиза: тег в узле записывается только после того, как файлы
    /// прошли `run -test` именно с этим конфигом.
    /// </summary>
    public static XCoreRenderedConfig RenderEntryWithRfLists(
        XCoreProtocolParams node, string realityPrivateKey, IEnumerable<XCoreUser> users,
        string relayUuid, IReadOnlyList<XCoreExitTarget> exits, string? rfListsTag, string? vlessDecryption = null)
    {
        RequireRole(node, XCoreRoles.Entry, "Render");
        RequireNodeFields(node, realityPrivateKey);
        if (!Guid.TryParse(relayUuid, out var relayId))
            throw new InvalidOperationException("Служебный UUID входа не в формате GUID.");

        var targets = ValidatedExits(exits);
        var directDomains = XCoreRoutingDomains.Normalize(node.DirectDomains, "Всегда напрямую");
        var proxyDomains = XCoreRoutingDomains.Normalize(node.ProxyDomains, "Всегда через VPN");

        var root = Skeleton(node);
        root["dns"] = new JsonObject
        {
            ["servers"] = Strings(EntryDnsServers),
            ["queryStrategy"] = "UseIPv4",
        };
        root["inbounds"] = new JsonArray(Inbound(node, realityPrivateKey, Clients(users), sniffing: true, vlessDecryption));

        var outbounds = new JsonArray(DirectOutbound(), BlockOutbound());
        foreach (var target in targets)
            outbounds.Add(ExitOutbound(target, relayId.ToString("D")));
        root["outbounds"] = outbounds;

        root["routing"] = new JsonObject
        {
            ["domainStrategy"] = "IPIfNonMatch",
            ["rules"] = EntryRules(node.RuDirect, directDomains, proxyDomains, targets, !string.IsNullOrEmpty(rfListsTag)),
        };

        return Finish(root);
    }

    /// <summary>
    /// Ревизия конфига выхода без пользователей. Отдельной логики рендера нет: это рендер с
    /// пустым списком, поэтому структура не может разойтись с полной ревизией — любое
    /// поле, попавшее в конфиг, попадает и сюда.
    /// </summary>
    public static string RenderStructureRevision(
        XCoreProtocolParams node, string realityPrivateKey, string? vlessDecryption = null) =>
        Render(node, realityPrivateKey, [], vlessDecryption).Revision;

    /// <summary>
    /// То же для входа. Выходы входят в структуру: изменение топологии перезапускает вход. Это
    /// осознанно — outbound-ы через API Xray не меняются, а вход без перезапуска продолжал бы
    /// гнать трафик по устаревшему списку выходов.
    /// </summary>
    public static string RenderEntryStructureRevision(
        XCoreProtocolParams node, string realityPrivateKey, string relayUuid, IReadOnlyList<XCoreExitTarget> exits,
        string? vlessDecryption = null) =>
        RenderEntry(node, realityPrivateKey, [], relayUuid, exits, vlessDecryption).Revision;

    /// <summary>
    /// Файл для <c>xray api adu</c>. Команде нужны listen и port inbound-а: без них она
    /// отвечает «Listen on AnyIP but no Port(s) set», добавляет 0 пользователей и
    /// всё равно завершается с кодом 0. Для выхода и входа он одинаков: пользователи добавляются
    /// в тот же inbound.
    /// </summary>
    public static string RenderUsersFile(XCoreProtocolParams node, IEnumerable<XCoreUser> users)
    {
        if (node.Role is not (XCoreRoles.Exit or XCoreRoles.Entry))
            throw new NotSupportedException($"Неизвестная роль xcore «{node.Role}».");
        var file = new JsonObject
        {
            ["inbounds"] = new JsonArray(new JsonObject
            {
                ["tag"] = InboundTag,
                ["listen"] = "0.0.0.0",
                ["port"] = node.XhttpPort,
                ["protocol"] = "vless",
                ["settings"] = new JsonObject { ["clients"] = Clients(users), ["decryption"] = "none" },
            }),
        };
        return file.ToJsonString();
    }

    // ── Общие части ───────────────────────────────────────────────────────────

    private static void RequireRole(XCoreProtocolParams node, string expected, string otherMethod)
    {
        if (node.Role != expected)
            throw new NotSupportedException(
                $"Роль xcore «{node.Role}» этим методом не рендерится: нужна «{expected}» (для другой роли — {otherMethod}).");
    }

    private static void RequireNodeFields(XCoreProtocolParams node, string realityPrivateKey)
    {
        if (string.IsNullOrWhiteSpace(realityPrivateKey))
            throw new InvalidOperationException("Не задан приватный ключ Reality.");
        if (string.IsNullOrWhiteSpace(node.Domain))
            throw new InvalidOperationException("Не задан домен узла xcore.");
        if (string.IsNullOrWhiteSpace(node.XhttpPath))
            throw new InvalidOperationException("Не задан путь XHTTP узла xcore.");
        if (node.ShortIds.Count == 0)
            throw new InvalidOperationException("Не задан ни один shortId Reality.");
    }

    /// <summary>Часть конфига, одинаковая у выхода и входа, до inbound-ов.</summary>
    private static JsonObject Skeleton(XCoreProtocolParams node) => new()
    {
        ["log"] = new JsonObject { ["loglevel"] = "warning", ["access"] = "none" },
        ["api"] = new JsonObject
        {
            ["tag"] = ApiTag,
            // Только loopback: API без аутентификации.
            ["listen"] = $"127.0.0.1:{node.ApiPort}",
            ["services"] = new JsonArray("HandlerService", "StatsService"),
        },
        ["stats"] = new JsonObject(),
        ["policy"] = new JsonObject
        {
            ["levels"] = new JsonObject
            {
                ["0"] = new JsonObject { ["statsUserUplink"] = true, ["statsUserDownlink"] = true },
            },
        },
    };

    /// <param name="sniffing">
    /// Только у входа: без него Xray видит одни IP, и правила по доменам не срабатывают.
    /// <c>routeOnly</c> — домен нужен лишь для правил, адрес назначения не подменяется.
    /// </param>
    private static JsonObject Inbound(
        XCoreProtocolParams node, string realityPrivateKey, JsonArray clients, bool sniffing, string? vlessDecryption)
    {
        var inbound = new JsonObject
        {
            ["tag"] = InboundTag,
            ["listen"] = "0.0.0.0",
            ["port"] = node.XhttpPort,
            ["protocol"] = "vless",
            // Без flow: xtls-rprx-vision относится к TCP, XHTTP его не использует. С шифрованием VLESS он тоже не нужен:
            // проверено в Docker (tools/VerifyXCore, VlessEncryptionE2E) — с vision и без него на зашифрованном XHTTP
            // всё проходит, но vision потребовал бы flow у каждого клиента inbound-а, в файле adu и в каждой ссылке.
            ["settings"] = new JsonObject { ["clients"] = clients, ["decryption"] = Decryption(node, vlessDecryption) },
            ["streamSettings"] = new JsonObject
            {
                ["network"] = "xhttp",
                ["security"] = "reality",
                ["realitySettings"] = new JsonObject
                {
                    ["target"] = SelfStealTarget,
                    ["serverNames"] = new JsonArray(node.Domain),
                    ["privateKey"] = realityPrivateKey,
                    ["shortIds"] = Strings(node.ShortIds),
                },
                ["xhttpSettings"] = new JsonObject { ["path"] = node.XhttpPath, ["mode"] = "auto" },
            },
        };

        if (sniffing)
            inbound["sniffing"] = new JsonObject
            {
                ["enabled"] = true,
                ["destOverride"] = new JsonArray("http", "tls", "quic"),
                ["routeOnly"] = true,
            };
        return inbound;
    }

    /// <summary>
    /// Значение <c>decryption</c>: <c>none</c> или серверная строка VLESS Encryption. Включённое шифрование без
    /// строки — ошибка, а не <c>none</c>: клиенты получили бы ссылки с <c>encryption=…</c> к узлу, который
    /// их не принимает. Строка проверяется по формату, потому что попадает в конфиг как есть.
    /// </summary>
    private static string Decryption(XCoreProtocolParams node, string? vlessDecryption)
    {
        if (!node.VlessEncryption) return "none";
        if (string.IsNullOrEmpty(vlessDecryption))
            throw new InvalidOperationException("У узла включено шифрование VLESS, но нет серверной строки decryption.");
        if (!XrayApiOutput.IsVlessDecryption(vlessDecryption))
            throw new InvalidOperationException("Серверная строка шифрования VLESS не в ожидаемом формате.");
        return vlessDecryption;
    }

    private static JsonObject DirectOutbound() => new() { ["tag"] = DirectTag, ["protocol"] = "freedom" };

    private static JsonObject BlockOutbound() => new() { ["tag"] = BlockTag, ["protocol"] = "blackhole" };

    private static JsonObject PrivateBlockRule() => new()
    {
        ["type"] = "field",
        ["ip"] = Strings(BlockedCidrs),
        ["outboundTag"] = BlockTag,
    };

    // ── Вход ──────────────────────────────────────────────────────────────────

    private static List<XCoreExitTarget> ValidatedExits(IReadOnlyList<XCoreExitTarget> exits)
    {
        var sorted = exits.OrderBy(e => e.RouteId).ToList();
        for (var i = 0; i < sorted.Count; i++)
        {
            var exit = sorted[i];
            if (!XCoreRoute.IsValid(exit.RouteId))
                throw new InvalidOperationException(
                    $"Номер маршрута выхода {exit.RouteId} вне диапазона {XCoreRoute.MinRouteId}..{XCoreRoute.MaxRouteId}.");
            if (i > 0 && sorted[i - 1].RouteId == exit.RouteId)
                throw new InvalidOperationException(
                    $"Номер маршрута {exit.RouteId} назначен двум выходам: вход не смог бы выбрать между ними.");
            if (string.IsNullOrWhiteSpace(exit.Domain) || string.IsNullOrWhiteSpace(exit.PublicKey)
                || string.IsNullOrWhiteSpace(exit.ShortId) || string.IsNullOrWhiteSpace(exit.XhttpPath)
                || string.IsNullOrWhiteSpace(exit.Fingerprint) || exit.Port is < 1 or > 65535)
                throw new InvalidOperationException($"У выхода с маршрутом {exit.RouteId} не хватает параметров подключения.");
            if (exit.Encryption is not null && !XrayApiOutput.IsVlessEncryption(exit.Encryption))
                throw new InvalidOperationException($"У выхода с маршрутом {exit.RouteId} строка шифрования VLESS не в ожидаемом формате.");
        }

        return sorted;
    }

    private static JsonObject ExitOutbound(XCoreExitTarget exit, string relayUuid) => new()
    {
        ["tag"] = ExitTag(exit.RouteId),
        ["protocol"] = "vless",
        ["settings"] = new JsonObject
        {
            ["vnext"] = new JsonArray(new JsonObject
            {
                ["address"] = exit.Domain,
                ["port"] = exit.Port,
                ["users"] = new JsonArray(new JsonObject { ["id"] = relayUuid, ["encryption"] = exit.Encryption ?? "none" }),
            }),
        },
        ["streamSettings"] = new JsonObject
        {
            ["network"] = "xhttp",
            ["security"] = "reality",
            ["realitySettings"] = new JsonObject
            {
                ["serverName"] = exit.Domain,
                ["publicKey"] = exit.PublicKey,
                ["shortId"] = exit.ShortId,
                ["fingerprint"] = exit.Fingerprint,
                ["spiderX"] = "",
            },
            ["xhttpSettings"] = new JsonObject { ["path"] = exit.XhttpPath, ["mode"] = "auto" },
        },
    };

    /// <param name="rfLists">
    /// Подключены российские списки релиза. Домены и адреса «заблокировано в РФ» идут через выход и стоят выше
    /// российских «напрямую», но ниже явных списков оператора: «всегда напрямую» — исключение, которое
    /// оператор сделал сознательно, и общий список его перебивать не должен. «Доступно только изнутри РФ»
    /// добавляется к российским доменам «напрямую». Оба действуют только при «РФ напрямую»: без неё всё и так
    /// уходит на выход.
    /// </param>
    private static JsonArray EntryRules(
        bool ruDirect, List<string> directDomains, List<string> proxyDomains, List<XCoreExitTarget> exits, bool rfLists)
    {
        var rules = new JsonArray(PrivateBlockRule());

        if (exits.Count == 0)
        {
            // Вход без выходов не должен становиться VPN с российским IP: что бы ни просил
            // клиент, наружу ничего не уходит. Списки доменов при этом не применяются.
            rules.Add(NetworkRule(BlockTag));
            return rules;
        }

        if (proxyDomains.Count > 0)
        {
            foreach (var exit in exits)
                rules.Add(new JsonObject
                {
                    ["type"] = "field",
                    ["vlessRoute"] = exit.RouteId.ToString(),
                    ["domain"] = Strings(proxyDomains),
                    ["outboundTag"] = ExitTag(exit.RouteId),
                });

            // Маршрут 0 и неизвестный маршрут не совпадут ни с одним правилом выше, и без этого
            // «всегда через VPN» для них проиграло бы российским спискам ниже. Ведём их туда же,
            // куда их отправит финальное правило, — на выход с наименьшим номером.
            rules.Add(new JsonObject
            {
                ["type"] = "field",
                ["domain"] = Strings(proxyDomains),
                ["outboundTag"] = ExitTag(exits[0].RouteId),
            });
        }

        if (directDomains.Count > 0)
            rules.Add(new JsonObject { ["type"] = "field", ["domain"] = Strings(directDomains), ["outboundTag"] = DirectTag });

        if (ruDirect && rfLists)
            AddBlockedInRfRules(rules, exits);

        if (ruDirect)
        {
            string[] ruDomains = rfLists ? [.. RuDomainsLists, XCoreRfLists.AvailableOnlyInside] : RuDomainsLists;
            rules.Add(new JsonObject { ["type"] = "field", ["domain"] = Strings(ruDomains), ["outboundTag"] = DirectTag });
            rules.Add(new JsonObject { ["type"] = "field", ["ip"] = new JsonArray(RuIpList), ["outboundTag"] = DirectTag });
        }

        foreach (var exit in exits)
            rules.Add(new JsonObject
            {
                ["type"] = "field",
                ["vlessRoute"] = exit.RouteId.ToString(),
                ["outboundTag"] = ExitTag(exit.RouteId),
            });

        // Маршрут 0 (ссылка без подмены) и неизвестный (выход убрали, а ссылка осталась) идут на
        // выход с наименьшим номером: пользователь остаётся с интернетом вместо тихого обрыва.
        rules.Add(NetworkRule(ExitTag(exits[0].RouteId)));
        return rules;
    }

    /// <summary>
    /// «Заблокировано в РФ» — теми же правилами, что «всегда через VPN»: по маршрутам клиента, затем общим правилом
    /// на выход с наименьшим номером (для маршрута 0 и неизвестного). Домены и адреса — разными правилами:
    /// условия одного правила складываются по «и», а нужно «или».
    /// </summary>
    private static void AddBlockedInRfRules(JsonArray rules, List<XCoreExitTarget> exits)
    {
        foreach (var (field, list) in new[] { ("domain", XCoreRfLists.BlockedDomains), ("ip", XCoreRfLists.BlockedIps) })
        {
            foreach (var exit in exits)
                rules.Add(new JsonObject
                {
                    ["type"] = "field",
                    ["vlessRoute"] = exit.RouteId.ToString(),
                    [field] = new JsonArray(list),
                    ["outboundTag"] = ExitTag(exit.RouteId),
                });

            rules.Add(new JsonObject
            {
                ["type"] = "field",
                [field] = new JsonArray(list),
                ["outboundTag"] = ExitTag(exits[0].RouteId),
            });
        }
    }

    // Правило «всё остальное»: network «tcp,udp» совпадает с любым соединением, и Xray его
    // принимает (проверено `run -test` в закреплённом образе). Правило вовсе без условий
    // конфиг отклоняет.
    private static JsonObject NetworkRule(string outboundTag) => new()
    {
        ["type"] = "field",
        ["network"] = "tcp,udp",
        ["outboundTag"] = outboundTag,
    };

    // ── Пользователи ──────────────────────────────────────────────────────────

    /// <summary>Клиенты, отсортированные по email: порядок на входе не должен менять ревизию.</summary>
    private static JsonArray Clients(IEnumerable<XCoreUser> users)
    {
        var sorted = users.OrderBy(u => u.Email, StringComparer.Ordinal).ToList();
        for (var i = 0; i < sorted.Count; i++)
        {
            var user = sorted[i];
            if (string.IsNullOrWhiteSpace(user.Email))
                throw new InvalidOperationException("У пользователя xcore пустой email.");
            if (!Guid.TryParse(user.Uuid, out _))
                throw new InvalidOperationException($"У пользователя «{user.Email}» UUID не в формате GUID.");
            if (i > 0 && sorted[i - 1].Email == user.Email)
                throw new InvalidOperationException($"Email «{user.Email}» встречается дважды: счётчики Xray слились бы.");
        }

        var clients = new JsonArray();
        foreach (var user in sorted)
            clients.Add(new JsonObject
            {
                ["id"] = Guid.Parse(user.Uuid).ToString("D"),
                ["email"] = user.Email,
                ["level"] = 0,
            });
        return clients;
    }

    private static JsonArray Strings(IEnumerable<string> values) =>
        new([.. values.Select(v => (JsonNode)JsonValue.Create(v)!)]);

    private static XCoreRenderedConfig Finish(JsonObject root)
    {
        var json = root.ToJsonString();
        return new XCoreRenderedConfig(json, Sha256Hex(json));
    }

    private static string Sha256Hex(string text) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(text))).ToLowerInvariant();
}
