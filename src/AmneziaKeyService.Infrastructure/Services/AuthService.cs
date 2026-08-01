using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using AmneziaKeyService.Core.Interfaces;
using AmneziaKeyService.Core.Models;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace AmneziaKeyService.Infrastructure.Services;

public class AuthService
{
    private readonly IUserRepository _users;
    private readonly IPassCodeRepository _passCodes;
    private readonly IRefreshSessionRepository _sessions;
    private readonly JwtOptions _jwt;

    public AuthService(IUserRepository users, IPassCodeRepository passCodes, IRefreshSessionRepository sessions, IOptions<JwtOptions> jwt)
    {
        _users     = users;
        _passCodes = passCodes;
        _sessions  = sessions;
        _jwt       = jwt.Value;
    }

    /// <summary>
    /// Создаёт конечного VPN-пользователя по пригласительному коду.
    ///
    /// Роль всегда client: этот путь доступен без аутентификации, поэтому назначать
    /// через него роли панели нельзя даже теоретически. Пользователи панели
    /// создаются только администратором через /api/users.
    /// </summary>
    public async Task<string> RegisterAsync(
        string username, string password, string passCode, CancellationToken ct = default)
    {
        var code = await _passCodes.FindByCodeAsync(passCode, ct);
        if (code is null || code.IsRevoked)
            throw new UnauthorizedAccessException("Неверный или уже использованный пригласительный код.");

        var existing = await _users.FindByUsernameAsync(username, ct);
        if (code.IsUsed && code.UsedByUserId is not null)
        {
            // Успешный retry уже завершённой регистрации возвращает тот же доступ,
            // но только владельцу кода и с корректным паролем.
            if (existing?.Id == code.UsedByUserId
                && BCrypt.Net.BCrypt.Verify(password, existing.PasswordHash))
                return GenerateJwt(existing);

            throw new UnauthorizedAccessException("Неверный или уже использованный пригласительный код.");
        }

        if (code.IsUsed)
        {
            // Незавершённый резерв не отдают другому человеку, но исходный запрос
            // может продолжить регистрацию после сбоя между claim и CreateAsync.
            if (code is null || code.IsRevoked || code.UsedByUserId is not null
                || code.ClaimUsername != username || string.IsNullOrEmpty(code.ClaimToken)
                || string.IsNullOrEmpty(code.ClaimPasswordHash)
                || !BCrypt.Net.BCrypt.Verify(password, code.ClaimPasswordHash))
                throw new UnauthorizedAccessException("Неверный или уже использованный пригласительный код.");
        }

        if (existing is not null)
        {
            if (code.IsUsed && code.UsedByUserId is null && code.ClaimUsername == username
                && !string.IsNullOrEmpty(code.ClaimToken)
                && !string.IsNullOrEmpty(code.ClaimPasswordHash)
                && BCrypt.Net.BCrypt.Verify(password, code.ClaimPasswordHash)
                && existing.PasswordHash == code.ClaimPasswordHash
                && await _passCodes.CompleteClaimAsync(code.Id, code.ClaimToken, existing.Id, ct))
                return GenerateJwt(existing);

            throw new InvalidOperationException($"Пользователь '{username}' уже существует.");
        }

        var claimToken = code.ClaimToken ?? Guid.NewGuid().ToString("N");
        var passwordHash = code.ClaimPasswordHash ?? BCrypt.Net.BCrypt.HashPassword(password);
        if (!code.IsUsed && !await _passCodes.TryClaimAsync(code.Id, claimToken, username, passwordHash, null, ct))
        {
            code = await _passCodes.FindByCodeAsync(passCode, ct);
            if (code is null || code.IsRevoked || code.UsedByUserId is not null
                || code.ClaimUsername != username || string.IsNullOrEmpty(code.ClaimToken)
                || string.IsNullOrEmpty(code.ClaimPasswordHash)
                || !BCrypt.Net.BCrypt.Verify(password, code.ClaimPasswordHash))
                throw new UnauthorizedAccessException("Неверный или уже использованный пригласительный код.");

            claimToken = code.ClaimToken;
            passwordHash = code.ClaimPasswordHash;
        }

        var user = new User
        {
            Username     = username,
            PasswordHash = passwordHash,
            Role         = UserRoles.Client,
            Status       = UserStatuses.Active
        };

        var userCreated = false;
        try
        {
            await _users.CreateAsync(user, ct);
            userCreated = true;

            // Перечитываем чтобы получить сгенерированный Id.
            user = await _users.FindByUsernameAsync(username, ct)
                ?? throw new InvalidOperationException("Не удалось создать пользователя.");
            if (!await _passCodes.CompleteClaimAsync(code.Id, claimToken, user.Id, ct))
                throw new InvalidOperationException("Не удалось завершить регистрацию.");
        }
        catch
        {
            // Параллельный retry может получить duplicate-key уже после того, как
            // первый запрос вставил пользователя, но до завершения claim. В этом
            // случае резерв принадлежит найденной записи и освобождать его нельзя.
            if (!userCreated)
            {
                var claimedUser = await _users.FindByUsernameAsync(username, ct);
                if (claimedUser is null || claimedUser.PasswordHash != passwordHash)
                    await _passCodes.ReleaseClaimAsync(code.Id, claimToken, ct);
                else if (await _passCodes.CompleteClaimAsync(code.Id, claimToken, claimedUser.Id, ct))
                    return GenerateJwt(claimedUser);
            }
            throw;
        }

        return GenerateJwt(user);
    }

    public async Task<LoginResult> LoginAsync(string username, string password, CancellationToken ct = default)
    {
        var user = await _users.FindByUsernameAsync(username, ct)
            ?? throw new UnauthorizedAccessException("Неверный логин или пароль.");

        // Пользователи Telegram-бота не имеют пароля — BCrypt.Verify на пустом хэше бросает,
        // поэтому отсекаем их до проверки и отвечаем тем же обезличенным текстом.
        if (string.IsNullOrEmpty(user.PasswordHash))
            throw new UnauthorizedAccessException("Неверный логин или пароль.");

        if (!BCrypt.Net.BCrypt.Verify(password, user.PasswordHash))
            throw new UnauthorizedAccessException("Неверный логин или пароль.");

        if (user.Status == UserStatuses.Blocked)
            throw new UnauthorizedAccessException("Учётная запись заблокирована.");

        if (!user.IsPanelUser)
            return new LoginResult(GenerateJwt(user), user, null);

        var pair = await CreatePanelSessionAsync(user, ct);
        return new LoginResult(pair.AccessToken, user, pair.RefreshToken);
    }

    /// <summary>
    /// Пользователь, стоящий за токеном. Читается из базы, а не из claim-ов:
    /// роль и статус могли измениться после выдачи токена.
    /// </summary>
    public async Task<User?> GetCurrentUserAsync(ClaimsPrincipal principal, CancellationToken ct = default)
    {
        // FindFirst вместо FindFirstValue: расширение живёт в ASP.NET-сборках,
        // а Infrastructure на них не ссылается.
        var userId = PanelAccessClaims.FindUserId(principal);

        if (userId is null) return null;

        var user = await _users.FindByIdAsync(userId, ct);
        return user?.Status == UserStatuses.Blocked ? null : user;
    }

    public async Task<PanelTokenPair?> RotatePanelSessionAsync(string rawRefreshToken, CancellationToken ct = default)
    {
        var now = DateTime.UtcNow;
        var hash = RefreshTokenCrypto.Hash(rawRefreshToken);
        var session = await _sessions.FindByTokenHashAsync(hash, ct);
        var presentation = RefreshSessionRules.Classify(session, now);
        if (presentation == RefreshSessionPresentation.Invalid)
            return null;
        if (presentation == RefreshSessionPresentation.ReuseDetected)
        {
            // Child records are always written before their parent CAS. Revoking the whole family now
            // therefore catches both an already-active child and a child still awaiting activation.
            await _sessions.RevokeFamilyAsync(session!.FamilyId, now, "refresh_token_reuse", ct);
            return null;
        }
        var currentSession = session ?? throw new InvalidOperationException("Current refresh session is missing.");
        // A family's expiry is absolute, not sliding: all predecessors remain available as replay
        // evidence until the active token itself expires.
        var replacement = NewSession(currentSession.UserId, currentSession.FamilyId, now, currentSession.ExpiresAt, active: false);
        var rotation = await _sessions.RotateAsync(hash, replacement.Session, now, ct);
        if (rotation != RefreshRotationResult.Rotated)
            return null;

        var user = await _users.FindByIdAsync(currentSession.UserId, ct);
        if (user is null || !user.IsPanelUser || user.Status == UserStatuses.Blocked)
        {
            await _sessions.RevokeFamilyAsync(currentSession.FamilyId, now, "user_not_allowed", ct);
            return null;
        }
        return new PanelTokenPair(GenerateJwt(user, replacement.Session.Id), replacement.RawToken);
    }

    public Task RevokePanelSessionsAsync(string userId, string reason, CancellationToken ct = default) =>
        _sessions.RevokeAllForUserAsync(userId, DateTime.UtcNow, reason, ct);

    public Task RevokePanelSessionAsync(string sessionId, string reason, CancellationToken ct = default) =>
        _sessions.RevokeAsync(sessionId, DateTime.UtcNow, reason, ct);

    public async Task RevokeRefreshTokenAsync(string rawRefreshToken, string reason, CancellationToken ct = default)
    {
        var session = await _sessions.FindByTokenHashAsync(RefreshTokenCrypto.Hash(rawRefreshToken), ct);
        if (session is not null)
            await _sessions.RevokeAsync(session.Id, DateTime.UtcNow, reason, ct);
    }

    public async Task<bool> IsPanelAccessValidAsync(ClaimsPrincipal principal, CancellationToken ct = default)
    {
        var userId = PanelAccessClaims.FindUserId(principal);
        var sessionId = principal.FindFirst("sid")?.Value;
        if (string.IsNullOrWhiteSpace(userId) || string.IsNullOrWhiteSpace(sessionId)) return false;
        var user = await _users.FindByIdAsync(userId, ct);
        if (user is null || user.Status == UserStatuses.Blocked || !user.IsPanelUser) return false;
        // Policies are evaluated from token claims; reject a token after a role change, even before refresh.
        if (!string.Equals(PanelAccessClaims.FindRole(principal), user.Role, StringComparison.Ordinal)) return false;
        return await _sessions.IsActiveAsync(sessionId, userId, DateTime.UtcNow, ct);
    }

    public string GenerateJwt(User user, string? sessionId = null)
    {
        var key     = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwt.Secret));
        var creds   = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
        var expires = DateTime.UtcNow.AddMinutes(sessionId is null ? _jwt.ExpiryMinutes : _jwt.PanelAccessExpiryMinutes);

        var claims = new List<Claim>
        {
            new Claim(JwtRegisteredClaimNames.Sub, user.Id),
            new Claim(JwtRegisteredClaimNames.UniqueName, user.Username),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new Claim(ClaimTypes.Role, user.Role)
        };
        if (sessionId is not null) claims.Add(new Claim("sid", sessionId));

        var token = new JwtSecurityToken(
            issuer:   _jwt.Issuer,
            audience: _jwt.Audience,
            claims:   claims,
            expires:  expires,
            signingCredentials: creds);

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    private async Task<PanelTokenPair> CreatePanelSessionAsync(User user, CancellationToken ct)
    {
        var now = DateTime.UtcNow;
        var fresh = NewSession(user.Id, Guid.NewGuid().ToString("N"), now, now.AddDays(_jwt.RefreshTokenDays), active: true);
        await _sessions.CreateAsync(fresh.Session, ct);
        return new PanelTokenPair(GenerateJwt(user, fresh.Session.Id), fresh.RawToken);
    }

    private (RefreshSession Session, string RawToken) NewSession(
        string userId, string familyId, DateTime now, DateTime expiresAt, bool active)
    {
        var raw = RefreshTokenCrypto.Create();
        return (new RefreshSession
        {
            UserId = userId,
            FamilyId = familyId,
            TokenHash = RefreshTokenCrypto.Hash(raw),
            CreatedAt = now,
            ExpiresAt = expiresAt,
            ActivatedAt = active ? now : null
        }, raw);
    }

}

public record LoginResult(string AccessToken, User User, string? RefreshToken);
public record PanelTokenPair(string AccessToken, string RefreshToken);
