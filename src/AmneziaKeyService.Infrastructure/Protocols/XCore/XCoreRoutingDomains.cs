using System.Text.RegularExpressions;

namespace AmneziaKeyService.Infrastructure.Protocols.XCore;

/// <summary>
/// Списки доменов «всегда напрямую» и «всегда через VPN», которые оператор задаёт входу.
/// Значения попадают в правила маршрутизации Xray, где у строки без префикса другой смысл,
/// чем ожидает человек: голое <c>yandex.ru</c> — это подстрока (keyword) и совпало бы с
/// <c>notyandex.ru.example.com</c>. Поэтому голое имя здесь превращается в <c>domain:</c>
/// (само имя и поддомены), а префиксы, открывающие произвольные правила (<c>regexp:</c>,
/// <c>geosite:</c>, <c>ext:</c>), оператору закрыты — встроенные списки задаёт код.
/// </summary>
public static partial class XCoreRoutingDomains
{
    public const int MaxEntries = 1000;
    private const int MaxEntryLength = 253;

    // Последняя метка начинается с буквы: «1.2.3.4» не принимается за домен.
    [GeneratedRegex(@"\A([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z]([a-z0-9-]{0,61}[a-z0-9])?\z")]
    private static partial Regex DnsName();

    [GeneratedRegex(@"\A[a-z0-9._-]{1,100}\z")]
    private static partial Regex Keyword();

    /// <summary>
    /// Приводит запись к виду для правила Xray. Причина отказа — текст для оператора, без значения
    /// записи: в нём может оказаться что угодно, и в лог ошибки синхронизации оно не нужно.
    /// </summary>
    public static bool TryNormalize(string? raw, out string normalized, out string error)
    {
        normalized = string.Empty;
        var text = (raw ?? string.Empty).Trim().ToLowerInvariant();
        if (text.Length == 0) { error = "пустая запись"; return false; }
        if (text.Length > MaxEntryLength) { error = "запись длиннее 253 символов"; return false; }

        var colon = text.IndexOf(':');
        var prefix = colon < 0 ? "domain" : text[..colon];
        var value = colon < 0 ? text : text[(colon + 1)..];

        switch (prefix)
        {
            case "domain" or "full":
                if (!DnsName().IsMatch(value)) { error = "ожидается имя DNS (латиница, цифры, дефисы)"; return false; }
                break;
            case "keyword":
                if (!Keyword().IsMatch(value)) { error = "в keyword допустимы латиница, цифры, точка, дефис и подчёркивание"; return false; }
                break;
            default:
                error = "допустимы имя DNS и префиксы domain:, full:, keyword:";
                return false;
        }

        normalized = prefix + ":" + value;
        error = string.Empty;
        return true;
    }

    /// <summary>
    /// Нормализует список: порядок сохраняется, повторы убираются. Бросает
    /// <see cref="InvalidOperationException"/> — так её превращает в SyncError синхронизация.
    /// </summary>
    public static List<string> Normalize(IEnumerable<string>? entries, string listName)
    {
        var result = new List<string>();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var index = 0;
        foreach (var raw in entries ?? [])
        {
            index++;
            if (!TryNormalize(raw, out var normalized, out var error))
                throw new InvalidOperationException($"Список «{listName}», запись {index}: {error}.");
            if (seen.Add(normalized)) result.Add(normalized);
        }

        if (result.Count > MaxEntries)
            throw new InvalidOperationException($"Список «{listName}» длиннее {MaxEntries} записей.");
        return result;
    }
}
