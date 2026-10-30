using System.Text;
using AmneziaKeyService.Core.Interfaces;
using AmneziaKeyService.Core.Models;
using AmneziaKeyService.Infrastructure.Subscriptions;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.Options;

namespace AmneziaKeyService.Api.Controllers;

/// <summary>
/// Публичная ссылка подписки <c>GET /sub/{token}</c>. Маршрут вне <c>/api</c>: адрес вводят в
/// приложение, и он должен быть коротким; наружу на отдельном домене проксируется только он.
///
/// Токен в пути — это учётные данные, поэтому контроллер сам его нигде не логирует, а в логи
/// ASP.NET путь не попадает: уровень <c>Microsoft.AspNetCore</c> в конфиге поднят до Warning,
/// а если запись всё же появится, <see cref="AmneziaKeyService.Infrastructure.Services.SecretRedactor"/> заменит
/// токен на <c>/sub/***</c> (проверяется в tools/VerifySubscriptions).
///
/// Атрибута <c>[ApiController]</c> нет намеренно: он превращает любой 404 в ProblemDetails с
/// телом, а неизвестному токену нужен пустой ответ — по форме тела нельзя отличить «нет такой
/// подписки» от других отказов.
/// </summary>
[AllowAnonymous]
public class SubscriptionFeedController : ControllerBase
{
    private readonly ISubscriptionRepository _subscriptions;
    private readonly IVpnServerRepository _servers;
    private readonly SubscriptionOptions _options;

    public SubscriptionFeedController(
        ISubscriptionRepository subscriptions,
        IVpnServerRepository servers,
        IOptions<SubscriptionOptions> options)
    {
        _subscriptions = subscriptions;
        _servers       = servers;
        _options       = options.Value;
    }

    [HttpGet("/sub/{token}")]
    [EnableRateLimiting(RateLimitPolicies.Subscription)]
    public async Task<IActionResult> Get(string token, CancellationToken ct)
    {
        // Ответ зависит от состояния подписки и содержит учётные данные: ни браузерный кэш,
        // ни промежуточный прокси хранить его не должны.
        Response.Headers.CacheControl = "no-store";

        if (!SubscriptionTokenCrypto.IsWellFormed(token)) return NotFound();

        var subscription = await _subscriptions.FindByTokenHashAsync(SubscriptionTokenCrypto.Hash(token), ct);
        if (subscription is null || !SubscriptionTokenCrypto.Matches(token, subscription.TokenHash))
            return NotFound();

        // Узлы нужны, только если подписка отдаёт ссылки: ради отозванной базу не читаем.
        var servers = subscription.IsServing(DateTime.UtcNow)
            ? await _servers.GetAllAsync(ct)
            : [];

        var feed = SubscriptionRenderer.Render(subscription, servers, _options, DateTime.UtcNow, token);
        foreach (var (name, value) in feed.Headers) Response.Headers[name] = value;

        return Content(feed.Body, "text/plain", Encoding.UTF8);
    }
}
