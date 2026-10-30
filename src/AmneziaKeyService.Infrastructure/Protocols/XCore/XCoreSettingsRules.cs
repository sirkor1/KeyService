using AmneziaKeyService.Core.DTOs.Panel;
using AmneziaKeyService.Core.Exceptions;
using AmneziaKeyService.Core.Models;
using AmneziaKeyService.Infrastructure.Subscriptions;

namespace AmneziaKeyService.Infrastructure.Protocols.XCore;

/// <summary>
/// Правила для настроек xcore, которые оператор меняет из панели. Чистые функции: проверка и сравнение
/// не требуют ни базы, ни сети (A-запись домена подписки проверяет контроллер отдельно, через
/// <see cref="XCoreDomainCheck"/>). Отказ несёт имя поля — панель показывает текст у этого поля.
/// </summary>
public static class XCoreSettingsRules
{
    public const int TitleMaxLength = SubscriptionRenderer.NodeTitleMaxLength;

    /// <param name="upstreamSetting">Значение XCore:SubscriptionUpstream; нужно, чтобы задать домен подписки.</param>
    public static XCoreSettingsUpdate Validate(
        ProtocolInstance protocol, XCoreSettingsRequest request, string? upstreamSetting)
    {
        var current = protocol.XCore ?? throw new InvalidOperationException("Протокол не является xcore.");

        var subscriptionEnabled = request.SubscriptionEnabled ?? current.SubscriptionEnabled;
        var title = (request.Title ?? string.Empty).Trim();
        if (title.Length > TitleMaxLength)
            throw new BadRequestException($"Название не длиннее {TitleMaxLength} символов.", "title");

        if (current.Role != XCoreRoles.Entry)
        {
            RequireEntryOnly(request.RuDirect is not null, "ruDirect");
            RequireEntryOnly(request.DirectDomains is not null, "directDomains");
            RequireEntryOnly(request.ProxyDomains is not null, "proxyDomains");
            RequireEntryOnly(!string.IsNullOrWhiteSpace(request.SubscriptionHost), "subscriptionHost");
            return new XCoreSettingsUpdate(title.Length == 0 ? null : title, request.SortOrder, subscriptionEnabled, null);
        }

        var entry = new XCoreEntrySettings(
            request.RuDirect,
            request.DirectDomains is null ? null : NormalizeList(request.DirectDomains, "Всегда напрямую", "directDomains"),
            request.ProxyDomains is null ? null : NormalizeList(request.ProxyDomains, "Всегда через VPN", "proxyDomains"),
            NormalizeSubscriptionHost(request.SubscriptionHost, current, upstreamSetting));

        return new XCoreSettingsUpdate(
            title.Length == 0 ? null : title, request.SortOrder, subscriptionEnabled, entry);
    }

    /// <summary>
    /// Поля, значения которых действительно меняются. Список идёт в журнал: имена полей, без значений —
    /// журнал выгружается из панели целиком, а списки доменов оператора в нём не нужны.
    /// </summary>
    public static IReadOnlyList<string> ChangedFields(XCoreProtocolParams current, XCoreSettingsUpdate update)
    {
        var changed = new List<string>();
        if (!string.Equals(current.Title, update.Title, StringComparison.Ordinal)) changed.Add("title");
        if (current.SortOrder != update.SortOrder) changed.Add("sortOrder");
        if (current.SubscriptionEnabled != update.SubscriptionEnabled) changed.Add("subscriptionEnabled");

        if (update.VlessEncryption is not null) changed.Add("vlessEncryption");

        if (update.Entry is { } entry)
        {
            if (entry.RuDirect is { } ruDirect && current.RuDirect != ruDirect) changed.Add("ruDirect");
            if (entry.DirectDomains is { } direct && !current.DirectDomains.SequenceEqual(direct)) changed.Add("directDomains");
            if (entry.ProxyDomains is { } proxy && !current.ProxyDomains.SequenceEqual(proxy)) changed.Add("proxyDomains");
            if (!string.Equals(current.SubscriptionHost, entry.SubscriptionHost, StringComparison.Ordinal))
                changed.Add("subscriptionHost");
        }

        return changed;
    }

    /// <summary>
    /// Что делать с шифрованием VLESS: true — включить (сгенерировать ключи на узле), false — выключить и стереть
    /// ключи, null — ничего. Включение, когда ключи уже на месте, и выключение выключенного шифрования — не
    /// изменение: повтор формы не должен менять ключи, а значит, и перезапускать узлы и ломать выданные ссылки.
    /// Флаг без ключей (запись правили в обход панели) включение достраивает.
    /// </summary>
    public static bool? VlessEncryptionAction(XCoreProtocolParams current, bool? requested)
    {
        var hasKeys = current.VlessDecryption is not null && !string.IsNullOrEmpty(current.VlessEncryptionClient);
        return requested switch
        {
            true when current.VlessEncryption && hasKeys => null,
            true => true,
            false when !current.VlessEncryption && current.VlessDecryption is null && current.VlessEncryptionClient is null => null,
            false => false,
            null => null,
        };
    }

    /// <summary>Домен подписки меняется на новый непустой: тогда нужна проверка A-записи.</summary>
    public static string? NewSubscriptionHost(XCoreProtocolParams current, XCoreSettingsUpdate update) =>
        update.Entry?.SubscriptionHost is { } host && !string.Equals(host, current.SubscriptionHost, StringComparison.Ordinal)
            ? host
            : null;

    private static void RequireEntryOnly(bool provided, string field)
    {
        if (provided) throw new BadRequestException("Эта настройка есть только у входа.", field);
    }

    private static List<string> NormalizeList(IEnumerable<string> entries, string listName, string field)
    {
        try
        {
            return XCoreRoutingDomains.Normalize(entries, listName);
        }
        catch (InvalidOperationException ex)
        {
            // Текст рендерера говорит про номер записи и причину, самого значения в нём нет.
            throw new BadRequestException(ex.Message, field);
        }
    }

    private static string? NormalizeSubscriptionHost(string? value, XCoreProtocolParams current, string? upstreamSetting)
    {
        if (string.IsNullOrWhiteSpace(value)) return null;

        if (!XCoreInput.TryNormalizeDomain(value, out var host))
            throw new BadRequestException(
                "Укажите домен подписки, например sub.example.com: латинские буквы, цифры и дефисы, не IP-адрес; " +
                "кириллические домены — в формате xn--….", "subscriptionHost");
        if (host == current.Domain)
            throw new BadRequestException(
                "Домен подписки должен отличаться от домена узла: у них разные сайты в Caddy.", "subscriptionHost");

        // Требование к настройке сервера проверяется только при смене домена: сохранение остальных полей
        // входа не должно упираться в настройку, которую оператор мог убрать уже после включения домена.
        if (host != current.SubscriptionHost && !XCoreInput.TryNormalizeUpstream(upstreamSetting, out _))
            throw new BadRequestException(
                "Домен подписки нельзя задать, пока не настроено XCore:SubscriptionUpstream (переменная " +
                "XCore__SubscriptionUpstream) — адрес, куда вход проксирует /sub/, например https://sub-origin.example.com.",
                "subscriptionHost");

        return host;
    }
}
