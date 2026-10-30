using System.Security.Cryptography;
using System.Text;
using AmneziaKeyService.Infrastructure.Scripts;

namespace AmneziaKeyService.Infrastructure.Protocols.XCore;

/// <param name="Text">Содержимое Caddyfile.</param>
/// <param name="Revision">SHA-256 (hex, нижний регистр) от <paramref name="Text"/>.</param>
public sealed record XCoreRenderedCaddyfile(string Text, string Revision);

/// <summary>
/// Caddyfile узла xcore. Чистая функция от домена узла, почты для сертификата и (для входа) домена
/// подписки с адресом, куда её проксировать, — поэтому установщик и синхронизация пишут на узел один и
/// тот же текст, а различие между «что на узле» и «что нужно» сводится к сравнению хешей.
///
/// Без домена подписки результат побайтово равен прежнему шаблону <c>xcore/Caddyfile</c> с подстановкой:
/// выходы и входы без подписки не получают ни одного лишнего символа (проверяется в tools/VerifyXCore).
///
/// Сайт подписки отдаётся на 443 входа без отдельного порта. Xray принимает 443 и отдаёт рукопожатия,
/// которые не прошли Reality, в 127.0.0.1:8443 (<c>target</c>), а Caddy на 8443 выбирает сайт по SNI. Клиент
/// подписки (браузер или Happ) открывает https://{домен подписки}/ с обычным TLS: Reality не узнаёт в нём
/// своего, передаёт Caddy, и тот отвечает сертификатом домена подписки. Поэтому A-запись домена подписки
/// должна вести на этот же вход, а в <c>serverNames</c> Reality его добавлять нельзя.
///
/// Доступ-логи не включаются: токен подписки лежит в пути запроса и является учётными данными.
/// </summary>
public static class XCoreCaddyRenderer
{
    private const string MainTemplate = "xcore/Caddyfile";
    private const string SubscriptionTemplate = "xcore/Caddyfile.subscription";

    /// <param name="subscriptionHost">Домен подписки входа; null — сайт подписки не добавляется.</param>
    /// <param name="subscriptionUpstream">Адрес для проксирования; обязателен вместе с доменом подписки.</param>
    /// <exception cref="InvalidOperationException">
    /// Входные значения не проходят проверку: они подставляются в конфиг, и непроверенная строка могла бы
    /// дописать в него чужую директиву. Текст безопасен для показа оператору.
    /// </exception>
    public static XCoreRenderedCaddyfile Render(
        ScriptRegistry scripts, string domain, string acmeEmail,
        string? subscriptionHost = null, string? subscriptionUpstream = null)
    {
        if (!XCoreInput.TryNormalizeDomain(domain, out var normalizedDomain) || normalizedDomain != domain)
            throw new InvalidOperationException("Домен узла xcore не прошёл проверку: Caddyfile собрать нельзя.");
        if (!XCoreInput.TryNormalizeAcmeEmail(acmeEmail, out var email) || email != acmeEmail)
            throw new InvalidOperationException(
                "Не задан email для Let's Encrypt (XCore:AcmeEmail): Caddyfile собрать нельзя.");

        var text = Substitute(scripts.Read(MainTemplate), ("DOMAIN", domain), ("ACME_EMAIL", acmeEmail));

        if (subscriptionHost is not null)
        {
            if (!XCoreInput.TryNormalizeDomain(subscriptionHost, out var host) || host != subscriptionHost)
                throw new InvalidOperationException("Домен подписки входа не прошёл проверку: Caddyfile собрать нельзя.");
            if (host == domain)
                throw new InvalidOperationException("Домен подписки совпадает с доменом узла: Caddyfile собрать нельзя.");
            if (!XCoreInput.TryNormalizeUpstream(subscriptionUpstream, out var upstream) || upstream != subscriptionUpstream)
                throw new InvalidOperationException(
                    "Не задан адрес для проксирования подписки (XCore:SubscriptionUpstream): Caddyfile собрать нельзя.");

            text += "\n" + Substitute(scripts.Read(SubscriptionTemplate), ("SUB_HOST", host), ("UPSTREAM", upstream));
        }

        return new XCoreRenderedCaddyfile(text, Sha256Hex(text));
    }

    private static string Substitute(string template, params (string Name, string Value)[] values) =>
        ScriptTemplateRenderer.Render(template, values.ToDictionary(v => v.Name, v => v.Value));

    private static string Sha256Hex(string text) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(text))).ToLowerInvariant();
}
