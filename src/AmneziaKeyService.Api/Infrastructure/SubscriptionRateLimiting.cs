using System.Threading.RateLimiting;
using AmneziaKeyService.Core.Models;

namespace AmneziaKeyService.Api.Infrastructure;

/// <summary>
/// Лимиты частоты для <c>GET /sub/{token}</c>. Через прокси входа API видит один и тот же IP у всех клиентов,
/// и лимит «на IP» задушил бы всех сразу, поэтому разделитель — токен: каждая подписка получает свои 30 запросов
/// в минуту. Токен, не похожий на настоящий, делит лимит с остальными того же IP — он всё равно ничего не найдёт.
///
/// Общий лимит на маршрут нужен против перебора: токенов у атакующего сколько угодно, и лимиты на каждый
/// отдельный не мешают ему гонять запросы с новыми. Он же ограничивает число партиций в памяти лимитера.
/// Политики вынесены сюда из Program.cs, чтобы tools/VerifySubscriptions вызывал именно их, а не копию.
/// </summary>
public static class SubscriptionRateLimiting
{
    public const int PerTokenPermitLimit = 30;
    public const int RoutePermitLimit = 600;
    public static readonly TimeSpan Window = TimeSpan.FromMinutes(1);

    /// <summary>Сегмент пути, на который действует общий лимит.</summary>
    private const string RoutePrefix = "/sub";

    /// <summary>
    /// Ключ партиции: хеш токена, если токен похож на настоящий, иначе IP. Хеш, а не сам токен: ключи живут
    /// в памяти лимитера и могут попасть в дамп или диагностику, а токен — учётные данные.
    /// </summary>
    public static string PartitionKey(HttpContext context)
    {
        var token = context.Request.RouteValues["token"] as string;
        return SubscriptionTokenCrypto.IsWellFormed(token)
            ? "token:" + SubscriptionTokenCrypto.Hash(token!)
            : "ip:" + (context.Connection.RemoteIpAddress?.ToString() ?? "unknown");
    }

    /// <summary>Политика <see cref="RateLimitPolicies.Subscription"/>: 30 запросов в минуту на токен.</summary>
    public static RateLimitPartition<string> TokenPartition(HttpContext context) =>
        RateLimitPartition.GetFixedWindowLimiter(PartitionKey(context), _ => TokenWindow());

    /// <summary>Общий лимитер приложения: 600 запросов в минуту суммарно на <c>/sub/*</c>, остальные пути не трогает.</summary>
    public static RateLimitPartition<string> RoutePartition(HttpContext context) =>
        context.Request.Path.StartsWithSegments(RoutePrefix, StringComparison.OrdinalIgnoreCase)
            ? RateLimitPartition.GetFixedWindowLimiter("subscription-route", _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = RoutePermitLimit,
                Window = Window,
                QueueLimit = 0,
            })
            : RateLimitPartition.GetNoLimiter("other");

    private static FixedWindowRateLimiterOptions TokenWindow() => new()
    {
        PermitLimit = PerTokenPermitLimit,
        Window = Window,
        QueueLimit = 0,
    };
}
