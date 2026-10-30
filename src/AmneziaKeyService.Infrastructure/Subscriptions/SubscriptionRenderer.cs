using System.Text;
using AmneziaKeyService.Core.Models;
using AmneziaKeyService.Infrastructure.Protocols.XCore;

namespace AmneziaKeyService.Infrastructure.Subscriptions;

/// <param name="Body">Тело ответа: base64 от ссылок, по одной в строке.</param>
/// <param name="Headers">Заголовки Happ; имена в нижнем регистре, значения только ASCII.</param>
public sealed record SubscriptionFeed(string Body, IReadOnlyDictionary<string, string> Headers);

/// <summary>
/// Превращает подписку и список узлов в ответ <c>/sub/{token}</c>: ссылки и заголовки Happ.
/// Чистая функция без SSH и без обращения к базе — поэтому проверяется на зафиксированных
/// образцах (tools/VerifySubscriptions): формат ссылки и заголовков ошибается молча, клиент
/// просто не подключается или показывает пустой профиль.
/// </summary>
public static class SubscriptionRenderer
{
    public const int NodeTitleMaxLength = 30;
    public const int ProfileTitleMaxLength = 25;
    public const int AnnounceMaxLength = 200;

    public const string DisabledAnnounce = "Подписка отключена. Обратитесь в поддержку.";

    private const string DefaultProfileTitle = "VPN";

    /// <summary>Суффикс названия подключения через вход: пользователь видит, что трафик идёт через РФ.</summary>
    public const string EntryTitleSuffix = " · РФ";

    /// <summary>
    /// Выходы подписки в порядке показа: по <c>SortOrder</c>, затем по имени. Порядок виден
    /// пользователю — клиенты показывают подключения в порядке строк.
    /// </summary>
    public static IReadOnlyList<(VpnServer Server, ProtocolInstance Protocol)> SelectNodes(
        IEnumerable<VpnServer> servers)
        => Ordered(XCoreSyncPublisher.SubscriptionExits(servers));

    /// <summary>Входы подписки в том же порядке показа.</summary>
    public static IReadOnlyList<(VpnServer Server, ProtocolInstance Protocol)> SelectEntries(
        IEnumerable<VpnServer> servers)
        => Ordered(XCoreSyncPublisher.SubscriptionNodes(servers).Where(n => n.Protocol.XCore!.Role == XCoreRoles.Entry));

    private static IReadOnlyList<(VpnServer Server, ProtocolInstance Protocol)> Ordered(
        IEnumerable<(VpnServer Server, ProtocolInstance Protocol)> nodes)
        => [.. nodes
            .OrderBy(n => n.Protocol.XCore!.SortOrder)
            .ThenBy(n => n.Server.Name, StringComparer.OrdinalIgnoreCase)
            .ThenBy(n => n.Server.Id, StringComparer.Ordinal)];

    /// <summary>
    /// Домен подписки: первого по порядку показа входа, который обслуживает подписки и у которого он задан.
    /// Null — ни у одного входа домена подписки нет.
    /// </summary>
    public static string? SubscriptionHostOf(IEnumerable<VpnServer> servers) =>
        SelectEntries(servers)
            .Select(n => n.Protocol.XCore!.SubscriptionHost)
            .FirstOrDefault(host => !string.IsNullOrWhiteSpace(host));

    /// <summary>
    /// Публичная ссылка подписки. Если у какого-то входа задан домен подписки, ссылка строится на него —
    /// <c>https://{домен}/sub/{токен}</c>: этот адрес открывается из РФ и в зонах белых списков, а сервер панели
    /// за рубежом нет. Иначе — на глобальный <see cref="SubscriptionOptions.PublicBaseUrl"/>.
    /// </summary>
    public static bool TryBuildSubscriptionUrl(
        string token, IEnumerable<VpnServer> servers, SubscriptionOptions options, out string url)
    {
        if (SubscriptionHostOf(servers) is { } host)
        {
            url = $"https://{host}/sub/{token}";
            return true;
        }

        return options.TryBuildUrl(token, out url);
    }

    /// <summary>
    /// Ссылки подписки: сначала плечи «вход × выход» (входы, внутри каждого — выходы), затем прямые
    /// ссылки на выходы как запасные. Вход без выходов ссылок не даёт; в плечи попадают только
    /// выходы с номером маршрута и полными параметрами — те же, что вход получает в конфиг.
    /// </summary>
    public static IReadOnlyList<string> BuildLinks(string uuid, IEnumerable<VpnServer> servers)
    {
        var all = servers as IReadOnlyCollection<VpnServer> ?? [.. servers];
        var exits = SelectNodes(all);
        var routable = XCoreTopology.RoutableExits(all)
            .Select(n => n.Protocol.Id)
            .ToHashSet(StringComparer.Ordinal);

        var links = new List<string>();
        foreach (var entry in SelectEntries(all))
            foreach (var exit in exits.Where(e => routable.Contains(e.Protocol.Id)))
                if (BuildEntryLink(uuid, entry.Protocol.XCore!, exit.Server, exit.Protocol.XCore!) is { } link)
                    links.Add(link);

        links.AddRange(exits.Select(e => BuildLink(uuid, e.Server, e.Protocol.XCore!)).OfType<string>());
        return links;
    }

    /// <param name="token">
    /// Токен из запрошенной ссылки. Нужен только для <c>fallback-url</c>: в подписке открытый токен не хранится,
    /// а запасной адрес — та же ссылка на другом домене. Без него заголовок не отправляется.
    /// </param>
    public static SubscriptionFeed Render(
        Subscription subscription, IEnumerable<VpnServer> servers, SubscriptionOptions options, DateTime now,
        string? token = null)
    {
        var serving = subscription.IsServing(now);
        var allServers = servers as IReadOnlyCollection<VpnServer> ?? [.. servers];
        IReadOnlyList<string> links = serving ? BuildLinks(subscription.XrayUuid, allServers) : [];

        var headers = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["profile-title"] = EncodeHeaderText(
                string.IsNullOrWhiteSpace(options.ProfileTitle) ? DefaultProfileTitle : options.ProfileTitle,
                ProfileTitleMaxLength),
            ["subscription-userinfo"] = UserInfo(subscription),
            ["profile-update-interval"] = Math.Max(1, options.UpdateIntervalHours).ToString(),
        };

        if (SupportUrl(options.SupportUrl) is { } supportUrl) headers["support-url"] = supportUrl;
        if (!serving) headers["announce"] = EncodeHeaderText(DisabledAnnounce, AnnounceMaxLength);

        // Профиль маршрутизации получает только живая подписка: отозванной он ни к чему, а лишний заголовок
        // заставил бы приложение скачивать geo-файлы ради ссылки, которой нечем пользоваться.
        if (serving && HappRoutingProfile.HeaderValue(options) is { } routing)
            headers[HappRoutingProfile.HeaderName] = routing;

        // Provider ID — только заголовок, не ссылка и не тело: так значение не попадёт в кэш приложения как часть
        // адреса подписки. Заголовок идёт и отозванной подписке: он привязывает устройство к аккаунту провайдера,
        // а не к состоянию подписки.
        if (HappProviderIdOf(options) is { } providerId)
        {
            headers[ProviderIdHeader] = providerId;
            if (serving && token is not null && FallbackUrl(token, allServers, options) is { } fallback)
                headers[FallbackUrlHeader] = fallback;
        }

        return new SubscriptionFeed(EncodeBody(links), headers);
    }

    public const string ProviderIdHeader = "providerid";
    public const string FallbackUrlHeader = "fallback-url";

    /// <summary>
    /// Provider ID для заголовка или null (выключено либо значение негодно). Значение приходит из настроек и
    /// попадает в HTTP-заголовок: пробел, перевод строки или не-ASCII заставили бы Kestrel не отправлять ответ
    /// вовсе, и подписка перестала бы открываться у всех. Поэтому негодное значение равносильно «выключено».
    /// </summary>
    public static string? HappProviderIdOf(SubscriptionOptions options)
    {
        var id = options.HappProviderId?.Trim();
        return !string.IsNullOrEmpty(id) && id.All(c => c is > ' ' and <= '~') ? id : null;
    }

    /// <summary>
    /// Запасной адрес подписки для Happ: полная ссылка (<c>fallback-url: https://домен/путь</c>, формат из
    /// app-management.md), на которую приложение переключится, если основная недоступна, ответила 300–599 или
    /// молчит 9 секунд. Нужен, когда основная ссылка построена на домен подписки входа: тогда запасная — адрес
    /// панели <c>{PublicBaseUrl}/sub/{токен}</c>. Обратное не нужно: если основная ссылка и так на
    /// <c>PublicBaseUrl</c>, запасного адреса нет. Токен тот же — подписка одна.
    /// </summary>
    public static string? FallbackUrl(string token, IEnumerable<VpnServer> servers, SubscriptionOptions options)
    {
        if (SubscriptionHostOf(servers) is null) return null;
        if (!options.TryBuildUrl(token, out var fallback)) return null;
        return TryBuildSubscriptionUrl(token, servers, options, out var primary) && primary != fallback
            ? fallback
            : null;
    }

    /// <summary>
    /// Ссылка на узел. Только плоские параметры, без <c>extra</c>: часть клиентов его не
    /// понимает. Адрес — домен узла, а не IP: при смене IP ссылки у пользователей не меняются.
    /// Null — у узла не хватает данных (ключ Reality, shortId, путь): ссылка с пустым
    /// параметром импортировалась бы и молча не подключалась. То же при включённом шифровании VLESS без
    /// клиентской строки.
    /// </summary>
    public static string? BuildLink(string uuid, VpnServer server, XCoreProtocolParams node) =>
        Guid.TryParse(uuid, out var id) ? Link(id.ToString("D"), node, NodeTitle(server, node)) : null;

    /// <summary>
    /// Ссылка на вход, ведущая на конкретный выход: адрес, ключи и путь — входа, а выход выбирает
    /// UUID с номером маршрута в третьей группе (<see cref="XCoreRoute.WithRoute"/>). Названием
    /// служит имя выхода с суффиксом «· РФ»; при нехватке места обрезается имя, а не суффикс —
    /// иначе подключения через вход и прямое к тому же выходу не различались бы.
    /// Null — у входа не хватает данных или у выхода нет номера маршрута.
    /// </summary>
    public static string? BuildEntryLink(
        string uuid, XCoreProtocolParams entryNode, VpnServer exit, XCoreProtocolParams exitNode)
    {
        if (exitNode.RouteId is not { } routeId || !XCoreRoute.IsValid(routeId) || !Guid.TryParse(uuid, out _))
            return null;

        return Link(XCoreRoute.WithRoute(uuid, routeId), entryNode, EntryLinkTitle(exit, exitNode));
    }

    public static string EntryLinkTitle(VpnServer exit, XCoreProtocolParams exitNode)
    {
        var name = NodeTitle(exit, exitNode);
        var room = NodeTitleMaxLength - EntryTitleSuffix.Length;
        return Truncate(name, room).TrimEnd() + EntryTitleSuffix;
    }

    private static string? Link(string uuid, XCoreProtocolParams node, string title)
    {
        if (string.IsNullOrWhiteSpace(node.Domain) || string.IsNullOrWhiteSpace(node.RealityPublicKey)
            || string.IsNullOrWhiteSpace(node.XhttpPath) || node.ShortIds.Count == 0)
            return null;

        // Строка шифрования — часть адреса узла: у зашифрованного узла «none» не подключится, а у открытого
        // строка не нужна. Кодируется как любой параметр, хотя в нынешнем формате спецсимволов в ней нет.
        if (node.VlessEncryption && !XrayApiOutput.IsVlessEncryption(node.VlessEncryptionClient))
            return null;
        var encryption = node.VlessEncryption ? Uri.EscapeDataString(node.VlessEncryptionClient!) : "none";

        return $"vless://{uuid}@{node.Domain}:{node.XhttpPort}" +
               $"?encryption={encryption}&security=reality&sni={node.Domain}&fp={Uri.EscapeDataString(node.Fingerprint)}" +
               $"&pbk={node.RealityPublicKey}&sid={node.ShortIds[0]}&type=xhttp" +
               $"&path={Uri.EscapeDataString(node.XhttpPath)}&mode=auto" +
               $"#{Uri.EscapeDataString(title)}";
    }

    /// <summary>Название подключения в приложении: заданное у узла или имя узла, до 30 символов.</summary>
    public static string NodeTitle(VpnServer server, XCoreProtocolParams node)
    {
        var title = !string.IsNullOrWhiteSpace(node.Title) ? node.Title
            : !string.IsNullOrWhiteSpace(server.Name) ? server.Name
            : node.Domain;
        return Truncate(title.Trim(), NodeTitleMaxLength);
    }

    /// <summary>
    /// Формат, который понимают Happ и v2ray-клиенты: строки ссылок через <c>\n</c>, затем base64
    /// (стандартный алфавит, с padding). Пустой список даёт пустую строку.
    /// </summary>
    public static string EncodeBody(IEnumerable<string> links) =>
        Convert.ToBase64String(Encoding.UTF8.GetBytes(string.Join('\n', links)));

    /// <summary>
    /// Использование и границы подписки. <c>upload</c> — отправленное клиентом (uplink Xray),
    /// <c>download</c> — полученное им (downlink); в <see cref="KeyUsage"/> подписки это
    /// <c>TxBytes</c> и <c>RxBytes</c>. Нули в <c>total</c> и <c>expire</c> означают «без ограничения».
    /// </summary>
    public static string UserInfo(Subscription subscription)
    {
        var expire = subscription.ExpiresAt is { } e
            ? new DateTimeOffset(DateTime.SpecifyKind(e, DateTimeKind.Utc)).ToUnixTimeSeconds()
            : 0;
        return $"upload={subscription.Usage.TxBytes}; download={subscription.Usage.RxBytes}; " +
               $"total={subscription.TrafficLimitBytes ?? 0}; expire={expire}";
    }

    /// <summary>
    /// Значение заголовка: ASCII как есть, иначе <c>base64:</c> и UTF-8 в base64. Заголовок HTTP
    /// не несёт кириллицу, а Kestrel на не-ASCII значении бросает исключение, не отправляя ответ.
    /// Длина ограничивается до кодирования: лимит Happ считается в символах текста.
    /// </summary>
    public static string EncodeHeaderText(string text, int maxLength)
    {
        var clipped = Truncate(text.Trim(), maxLength);
        return clipped.All(c => c is >= ' ' and <= '~')
            ? clipped
            : "base64:" + Convert.ToBase64String(Encoding.UTF8.GetBytes(clipped));
    }

    /// <summary>Обрезка по числу символов без разрыва суррогатной пары (эмодзи в названии).</summary>
    private static string Truncate(string text, int maxLength)
    {
        if (text.Length <= maxLength) return text;
        var cut = maxLength;
        if (char.IsHighSurrogate(text[cut - 1])) cut--;
        return text[..cut];
    }

    private static string? SupportUrl(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return null;
        return Uri.TryCreate(value.Trim(), UriKind.Absolute, out var uri) && uri.Scheme is "https" or "http"
            ? uri.AbsoluteUri
            : null;
    }
}
