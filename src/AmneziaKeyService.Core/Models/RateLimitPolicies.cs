namespace AmneziaKeyService.Core.Models;

/// <summary>Имена политик ограничения частоты запросов. Регистрируются в Program.cs.</summary>
public static class RateLimitPolicies
{
    /// <summary>
    /// Логин и регистрация. Ограничение по IP — иначе пароль владельца
    /// подбирается перебором без каких-либо препятствий.
    /// </summary>
    public const string Auth = "auth";
    public const string Refresh = "refresh";

    /// <summary>Ссылка подписки /sub/{token}: анонимная, 30 запросов в минуту на токен (см. SubscriptionRateLimiting в Api).</summary>
    public const string Subscription = "subscription";
}
