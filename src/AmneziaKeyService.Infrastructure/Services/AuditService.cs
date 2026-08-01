using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using AmneziaKeyService.Core.Interfaces;
using AmneziaKeyService.Core.Models;
using Microsoft.Extensions.Logging;

namespace AmneziaKeyService.Infrastructure.Services;

public class AuditService : IAuditService
{
    private readonly IAuditLogRepository _repo;
    private readonly ILogger<AuditService> _logger;

    public AuditService(IAuditLogRepository repo, ILogger<AuditService> logger)
    {
        _repo   = repo;
        _logger = logger;
    }

    public Task WriteAsync(
        string @event,
        string message,
        ClaimsPrincipal? actor = null,
        string? targetType = null,
        string? targetId = null,
        string? targetName = null,
        string level = AuditLevels.Info,
        Dictionary<string, string>? meta = null,
        CancellationToken ct = default)
    {
        // HTTP-принципал раскладывается в те же два поля, что и AuditActor —
        // сборка записи и проглатывание ошибок журнала живут в одном месте.
        var resolved = new AuditActor(
            actor?.FindFirst(ClaimTypes.NameIdentifier)?.Value
                ?? actor?.FindFirst(JwtRegisteredClaimNames.Sub)?.Value,
            actor?.FindFirst(JwtRegisteredClaimNames.UniqueName)?.Value
                ?? actor?.Identity?.Name);

        return WriteAsync(@event, message, resolved, targetType, targetId, targetName, level, meta, ct);
    }

    public async Task WriteAsync(
        string @event,
        string message,
        AuditActor actor,
        string? targetType = null,
        string? targetId = null,
        string? targetName = null,
        string level = AuditLevels.Info,
        Dictionary<string, string>? meta = null,
        CancellationToken ct = default)
    {
        var entry = new AuditEntry
        {
            Event       = @event,
            Message     = message,
            Level       = level,
            ActorUserId = actor.UserId,
            ActorName   = actor.Name,
            TargetType  = targetType,
            TargetId    = targetId,
            TargetName  = targetName,
            Meta        = meta
        };

        try
        {
            await _repo.AppendAsync(entry, ct);
        }
        catch (Exception ex)
        {
            // Операция уже выполнена — падать из-за журнала нельзя.
            _logger.LogError(ex, "Не удалось записать событие журнала {Event}", @event);
        }
    }
}

/// <summary>Коды событий журнала. Строкой в одном месте, чтобы не расходились.</summary>
public static class AuditEvents
{
    public const string ServerCreated        = "server.created";
    public const string ServerUpdated        = "server.updated";
    public const string ServerDeleted        = "server.deleted";
    public const string ServerCacheRefresh   = "server.cache_refreshed";
    public const string ServerInstallStarted = "server.install_started";

    public const string ProtocolAdded   = "protocol.added";
    public const string ProtocolRemoved = "protocol.removed";

    public const string KeyIssued       = "key.issued";
    public const string KeyIssueFailed  = "key.issue_failed";
    public const string KeyRevoked      = "key.revoked";
    public const string KeyRevokeFailed = "key.revoke_failed";

    public const string PassCodeCreated = "passcode.created";
    public const string PassCodeRevoked = "passcode.revoked";
    public const string PassCodeUsed    = "passcode.used";

    public const string UserLoggedIn = "user.logged_in";
    public const string UserCreated  = "user.created";
    public const string UserUpdated  = "user.updated";
    public const string UserBlocked  = "user.blocked";
    public const string UserUnblocked = "user.unblocked";
    public const string UserDeactivated = "user.deactivated";
    public const string UserPasswordReset = "user.password_reset";

    public const string SettingsUpdated = "settings.updated";

    // ── Фоновая эксплуатация (фаза 5) ─────────────────────────────────────────

    public const string ServerWentOffline = "server.went_offline";
    public const string ServerBackOnline  = "server.back_online";

    public const string KeyExpiringSoon = "key.expiring_soon";

    public const string PeersReconciled = "server.peers_reconciled";
}
