using System.Net;
using AmneziaKeyService.Core.Exceptions;

namespace AmneziaKeyService.Infrastructure.Protocols.XCore;

/// <summary>
/// Проверка, что A-запись домена указывает на узел. Общая для домена узла (установка) и домена подписки
/// входа (настройки): Let's Encrypt проверяет домен по HTTP-01 с порта 80, и при чужой записи Caddy ушёл бы
/// в повторы, а ожидание сертификата закончилось бы таймаутом. Расхождение видно сразу и без обращения к узлу.
/// </summary>
public static class XCoreDomainCheck
{
    /// <param name="retryHint">Что сделать после исправления записи: «повторите установку», «повторите сохранение».</param>
    public static async Task EnsurePointsToNodeAsync(
        IDnsResolver dns, string serverHost, string domain, string retryHint, CancellationToken ct)
    {
        IReadOnlyList<IPAddress> nodeIps = IPAddress.TryParse(serverHost, out var literal)
            ? [literal]
            : await dns.ResolveIPv4Async(serverHost, ct);
        if (nodeIps.Count == 0 || nodeIps.Any(ip => ip.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork))
            throw new BadRequestException(
                $"Не удалось определить IPv4-адрес узла «{serverHost}»: для xcore нужна A-запись, а не AAAA.");

        var domainIps = await dns.ResolveIPv4Async(domain, ct);
        var expected = string.Join(", ", nodeIps);
        if (domainIps.Count == 0)
            throw new BadRequestException(
                $"У домена {domain} нет A-записи. Создайте её со значением {expected} и {retryHint}.");

        if (!domainIps.Any(d => nodeIps.Any(n => n.Equals(d))))
            throw new BadRequestException(
                $"A-запись домена {domain} указывает на {string.Join(", ", domainIps)}, " +
                $"а адрес узла — {expected}. Исправьте A-запись и {retryHint}.");
    }
}
