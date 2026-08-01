using AmneziaKeyService.Core.DTOs;
using AmneziaKeyService.Core.Interfaces;
using AmneziaKeyService.Core.Models;
using AmneziaKeyService.Infrastructure.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.Options;

namespace AmneziaKeyService.Api.Controllers;

[ApiController]
[Route("api/auth")]
public class AuthController : ControllerBase
{
    private readonly AuthService _auth;
    private readonly JwtOptions _jwt;
    private readonly IWebHostEnvironment _env;
    private readonly IAuditService _audit;

    public AuthController(
        AuthService auth,
        IOptions<JwtOptions> jwt,
        IWebHostEnvironment env,
        IAuditService audit)
    {
        _auth  = auth;
        _jwt   = jwt.Value;
        _env   = env;
        _audit = audit;
    }

    /// <summary>
    /// Регистрирует нового VPN-пользователя по пригласительному коду и возвращает JWT.
    /// Создаётся всегда с ролью client — доступа к панели не даёт.
    /// </summary>
    [HttpPost("register")]
    [EnableRateLimiting(RateLimitPolicies.Auth)]
    [ProducesResponseType(typeof(TokenResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status409Conflict)]
    public async Task<IActionResult> Register([FromBody] RegisterRequest req, CancellationToken ct)
    {
        try
        {
            var token = await _auth.RegisterAsync(req.Username, req.Password, req.PassCode, ct);
            return Ok(new TokenResponse(token));
        }
        catch (InvalidOperationException ex)
        {
            return Conflict(new { error = ex.Message });
        }
    }

    /// <summary>
    /// Аутентификация. Возвращает JWT и профиль пользователя, а для пользователей
    /// панели дополнительно ставит httpOnly-куку — SPA не хранит токен в JS.
    /// </summary>
    [HttpPost("login")]
    [EnableRateLimiting(RateLimitPolicies.Auth)]
    [ProducesResponseType(typeof(LoginResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    public async Task<IActionResult> Login([FromBody] LoginRequest req, CancellationToken ct)
    {
        var login = await _auth.LoginAsync(req.Username, req.Password, ct);
        var token = login.AccessToken;
        var user = login.User;

        if (user.IsPanelUser)
        {
            Response.Cookies.Append(
                AuthCookies.AccessToken, token,
                BuildAccessCookieOptions(TimeSpan.FromMinutes(_jwt.PanelAccessExpiryMinutes)));
            Response.Cookies.Append(
                AuthCookies.RefreshToken, login.RefreshToken!,
                BuildRefreshCookieOptions(TimeSpan.FromDays(_jwt.RefreshTokenDays)));

            // Входы обычных VPN-клиентов в журнал не пишем: это шум,
            // журнал предназначен для действий в панели.
            await _audit.WriteAsync(AuditEvents.UserLoggedIn,
                $"Вход в панель: {user.Username}",
                targetType: AuditTargets.User, targetId: user.Id, targetName: user.Username, ct: ct);
        }

        // Existing VPN clients still receive their Bearer token. Panel credentials are cookie-only.
        return Ok(new LoginResponse(user.IsPanelUser ? null : token, MeResponse.From(user)));
    }

    /// <summary>
    /// Выход: удаляет куку доступа. Ранее выданный Bearer-токен остаётся валидным
    /// до истечения срока — отзыв появится вместе с refresh-токенами.
    /// </summary>
    [HttpPost("logout")]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    public async Task<IActionResult> Logout(CancellationToken ct)
    {
        if (Request.Headers.TryGetValue("X-Requested-With", out var requestedWith)
            && requestedWith == "panel"
            && Request.Cookies.TryGetValue(AuthCookies.RefreshToken, out var refresh))
        {
            await _auth.RevokeRefreshTokenAsync(refresh, "logout", ct);
        }
        Response.Cookies.Delete(AuthCookies.AccessToken, BuildAccessCookieOptions(null));
        Response.Cookies.Delete(AuthCookies.RefreshToken, BuildRefreshCookieOptions(null));
        return NoContent();
    }

    [HttpPost("refresh")]
    [EnableRateLimiting(RateLimitPolicies.Refresh)]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    public async Task<IActionResult> Refresh(CancellationToken ct)
    {
        if (!Request.Headers.TryGetValue("X-Requested-With", out var requestedWith) || requestedWith != "panel"
            || !Request.Cookies.TryGetValue(AuthCookies.RefreshToken, out var refreshToken))
            return Unauthorized();

        var pair = await _auth.RotatePanelSessionAsync(refreshToken, ct);
        if (pair is null)
        {
            Response.Cookies.Delete(AuthCookies.AccessToken, BuildAccessCookieOptions(null));
            Response.Cookies.Delete(AuthCookies.RefreshToken, BuildRefreshCookieOptions(null));
            return Unauthorized();
        }
        Response.Cookies.Append(AuthCookies.AccessToken, pair.AccessToken,
            BuildAccessCookieOptions(TimeSpan.FromMinutes(_jwt.PanelAccessExpiryMinutes)));
        Response.Cookies.Append(AuthCookies.RefreshToken, pair.RefreshToken,
            BuildRefreshCookieOptions(TimeSpan.FromDays(_jwt.RefreshTokenDays)));
        return NoContent();
    }

    /// <summary>Профиль текущего пользователя — панель запрашивает его после логина.</summary>
    [HttpGet("me")]
    [Authorize]
    [ProducesResponseType(typeof(MeResponse), StatusCodes.Status200OK)]
    public async Task<IActionResult> Me(CancellationToken ct)
    {
        var user = await _auth.GetCurrentUserAsync(User, ct);
        return user is null ? Unauthorized() : Ok(MeResponse.From(user));
    }

    private CookieOptions BuildAccessCookieOptions(TimeSpan? lifetime) => BuildCookieOptions(lifetime, "/");

    // Logout is under /api/auth too, so the browser presents this cookie for server-side revocation.
    private CookieOptions BuildRefreshCookieOptions(TimeSpan? lifetime) => BuildCookieOptions(lifetime, "/api/auth");

    private CookieOptions BuildCookieOptions(TimeSpan? lifetime, string path) => new()
    {
        HttpOnly = true,
        // Secure только вне разработки: по http://localhost браузер Secure-куку отбросит.
        Secure   = !_env.IsDevelopment(),
        SameSite = SameSiteMode.Strict,
        Path     = path,
        MaxAge   = lifetime
    };
}

public record TokenResponse(string Token);

public record LoginResponse(string? Token, MeResponse User);
