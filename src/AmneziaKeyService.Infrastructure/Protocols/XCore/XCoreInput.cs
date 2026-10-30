using System.Text.RegularExpressions;
using AmneziaKeyService.Core.Exceptions;

namespace AmneziaKeyService.Infrastructure.Protocols.XCore;

/// <summary>
/// Проверка того, что оператор вводит для xcore. Домен и email подставляются в
/// Caddyfile и в команды shell, поэтому проверка здесь — защита от подстановки, а не
/// только от опечатки.
/// </summary>
public static partial class XCoreInput
{
    // Метки по RFC 1035; последняя начинается с буквы — так «1.2.3.4» и «999.1.1.1»
    // не проходят за домен. Кириллические домены вводятся в punycode (xn--…).
    [GeneratedRegex(@"\A(?=.{4,253}\z)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]\z")]
    private static partial Regex DomainPattern();

    // Без пробелов, кавычек и скобок: адрес попадает в блок global Caddyfile.
    [GeneratedRegex(@"\A[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\z")]
    private static partial Regex EmailPattern();

    /// <summary>Приводит домен к нижнему регистру без точки на конце и проверяет его.</summary>
    public static bool TryNormalizeDomain(string? value, out string domain)
    {
        domain = (value ?? string.Empty).Trim().TrimEnd('.').ToLowerInvariant();
        return DomainPattern().IsMatch(domain);
    }

    /// <summary>
    /// Адрес, куда Caddy входа проксирует <c>/sub/</c>, приводится к виду <c>схема://хост[:порт]</c>.
    /// Значение подставляется в Caddyfile, поэтому путь, параметры, логин и любые пробелы или
    /// управляющие символы отклоняются: строка с переводом строки дописала бы в конфиг чужую директиву.
    /// </summary>
    public static bool TryNormalizeUpstream(string? value, out string upstream)
    {
        upstream = string.Empty;
        var text = (value ?? string.Empty).Trim();
        if (text.Length == 0 || text.Any(c => char.IsWhiteSpace(c) || char.IsControl(c))) return false;
        if (!Uri.TryCreate(text, UriKind.Absolute, out var uri)) return false;
        if (uri.Scheme is not ("https" or "http") || uri.UserInfo.Length > 0
            || uri.AbsolutePath != "/" || uri.Query.Length > 0 || uri.Fragment.Length > 0)
            return false;
        if (!TryNormalizeDomain(uri.IdnHost, out var host)) return false;

        upstream = $"{uri.Scheme}://{host}{(uri.IsDefaultPort ? "" : ":" + uri.Port)}";
        return true;
    }

    public static string RequireDomain(string? value) =>
        TryNormalizeDomain(value, out var domain)
            ? domain
            : throw new BadRequestException(
                "Укажите домен узла, например node1.example.com. Нужно имя из латинских букв, " +
                "цифр и дефисов, не IP-адрес; кириллические домены — в формате xn--….");

    public static bool TryNormalizeAcmeEmail(string? value, out string email)
    {
        email = (value ?? string.Empty).Trim();
        return EmailPattern().IsMatch(email);
    }

    public static string RequireAcmeEmail(string? value)
    {
        return TryNormalizeAcmeEmail(value, out var email)
            ? email
            : throw new BadRequestException(
                "Для xcore не задан email для сертификата Let's Encrypt: укажите настройку XCore:AcmeEmail " +
                "(переменная XCore__AcmeEmail) и повторите установку.");
    }
}
