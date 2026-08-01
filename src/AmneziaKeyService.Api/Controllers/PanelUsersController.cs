using AmneziaKeyService.Core.DTOs;
using AmneziaKeyService.Core.DTOs.Panel;
using AmneziaKeyService.Core.Exceptions;
using AmneziaKeyService.Core.Interfaces;
using AmneziaKeyService.Core.Models;
using AmneziaKeyService.Infrastructure.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using MongoDB.Bson;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace AmneziaKeyService.Api.Controllers;

/// <summary>
/// Пользователи панели и VPN-клиенты. Физическое удаление намеренно не
/// поддерживается: записи могут быть владельцами ключей и целями аудита.
/// DELETE деактивирует учётную запись, устанавливая статус blocked.
/// </summary>
[ApiController]
[Route("api/users")]
[Authorize(Policy = AuthPolicies.PanelAdmin)]
public class PanelUsersController : ControllerBase
{
    private readonly IUserRepository _users;
    private readonly IVpnClientRepository _clients;
    private readonly IAuditService _audit;
    private readonly AuthService _auth;

    public PanelUsersController(IUserRepository users, IVpnClientRepository clients, IAuditService audit, AuthService auth)
    {
        _users   = users;
        _clients = clients;
        _audit   = audit;
        _auth    = auth;
    }

    [HttpGet]
    [ProducesResponseType(typeof(Paged<UserListItemDto>), StatusCodes.Status200OK)]
    public async Task<IActionResult> GetAll(
        [FromQuery] string? search,
        [FromQuery] string? status,
        [FromQuery] string? role,
        [FromQuery] int? page,
        [FromQuery] int? pageSize,
        CancellationToken ct)
    {
        var users    = await _users.SearchAsync(new UserQuery(search, status, role, page, pageSize), ct);
        var keyCount = await _clients.CountActiveByUserAsync(ct);

        return Ok(users.Map(u => UserListItemDto.From(u, keyCount.GetValueOrDefault(u.Id))));
    }

    [HttpGet("{id}")]
    [ProducesResponseType(typeof(UserListItemDto), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> GetById(string id, CancellationToken ct)
    {
        var user = await _users.FindByIdAsync(id, ct)
            ?? throw new NotFoundException("Пользователь не найден.");

        var keyCount = await _clients.CountActiveByUserAsync(ct);
        return Ok(UserListItemDto.From(user, keyCount.GetValueOrDefault(user.Id)));
    }

    /// <summary>Создаёт учётную запись для доступа к панели.</summary>
    [HttpPost]
    [ProducesResponseType(typeof(UserListItemDto), StatusCodes.Status201Created)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status409Conflict)]
    public async Task<IActionResult> Create([FromBody] CreatePanelUserRequest req, CancellationToken ct)
    {
        var actor = await RequireCurrentPanelAdminAsync(ct);
        var username = ValidateUsername(req.Username);
        ValidatePassword(req.Password);
        var role = ValidateAssignableRole(actor, req.Role);

        if (await _users.FindByUsernameAsync(username, ct) is not null)
            return Conflict(new { error = "Пользователь с таким логином уже существует." });

        var user = new User
        {
            Username = username,
            PasswordHash = BCrypt.Net.BCrypt.HashPassword(req.Password!),
            Role = role,
            Status = UserStatuses.Active,
            DisplayName = NormalizeOptional(req.DisplayName, "Отображаемое имя", 128),
            Contact = NormalizeOptional(req.Contact, "Контакт", 256)
        };

        if (!await _users.TryCreateAsync(user, ct))
            return Conflict(new { error = "Пользователь с таким логином уже существует." });

        var created = await _users.FindByUsernameAsync(username, ct)
            ?? throw new InvalidOperationException("Пользователь не найден после создания.");

        await WriteAuditAsync(AuditEvents.UserCreated, $"Создан пользователь {created.Username}", created, ct,
            new Dictionary<string, string> { ["role"] = created.Role });

        return CreatedAtAction(nameof(GetById), new { id = created.Id }, UserListItemDto.From(created, 0));
    }

    /// <summary>Редактирует профиль, роль и статус учётной записи.</summary>
    [HttpPut("{id}")]
    [ProducesResponseType(typeof(UserListItemDto), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    [ProducesResponseType(StatusCodes.Status403Forbidden)]
    public async Task<IActionResult> Update(string id, [FromBody] UpdatePanelUserRequest req, CancellationToken ct)
    {
        var actor = await RequireCurrentPanelAdminAsync(ct);
        var target = await FindTargetAsync(id, ct);
        EnsureCanManage(actor, target, changingPrivileges: req.Role != target.Role || req.Status != target.Status);

        var role = ValidateUpdatedRole(actor, target, req.Role);
        var status = ValidateStatus(req.Status);
        var promotedToPanel = !target.IsPanelUser && UserRoles.PanelRead.Contains(role);
        if (promotedToPanel)
            ValidatePassword(req.Password);

        var privilegesChanged = role != target.Role || status != target.Status;
        target.DisplayName = NormalizeOptional(req.DisplayName, "Отображаемое имя", 128);
        target.Contact = NormalizeOptional(req.Contact, "Контакт", 256);
        target.Role = role;
        target.Status = status;
        target.IsActive = status != UserStatuses.Blocked;
        if (promotedToPanel)
            target.PasswordHash = BCrypt.Net.BCrypt.HashPassword(req.Password!);
        await _users.UpdateAsync(target, ct);
        if (privilegesChanged)
            await _auth.RevokePanelSessionsAsync(target.Id, "privilege_or_status_changed", ct);

        await WriteAuditAsync(AuditEvents.UserUpdated, $"Изменён пользователь {target.Username}", target, ct,
            new Dictionary<string, string> { ["role"] = role, ["status"] = status });

        var keyCount = await _clients.CountActiveByUserAsync(ct);
        return Ok(UserListItemDto.From(target, keyCount.GetValueOrDefault(target.Id)));
    }

    [HttpPost("{id}/block")]
    [ProducesResponseType(typeof(UserListItemDto), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    [ProducesResponseType(StatusCodes.Status403Forbidden)]
    public Task<IActionResult> Block(string id, CancellationToken ct) =>
        SetStatusAsync(id, UserStatuses.Blocked, AuditEvents.UserBlocked, "Заблокирован пользователь", ct);

    [HttpPost("{id}/unblock")]
    [ProducesResponseType(typeof(UserListItemDto), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    [ProducesResponseType(StatusCodes.Status403Forbidden)]
    public Task<IActionResult> Unblock(string id, CancellationToken ct) =>
        SetStatusAsync(id, UserStatuses.Active, AuditEvents.UserUnblocked, "Разблокирован пользователь", ct);

    /// <summary>Задаёт новый пароль. Пароль и его хэш не попадают в ответ или аудит.</summary>
    [HttpPost("{id}/reset-password")]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    [ProducesResponseType(StatusCodes.Status403Forbidden)]
    public async Task<IActionResult> ResetPassword(string id, [FromBody] ResetUserPasswordRequest req, CancellationToken ct)
    {
        var actor = await RequireCurrentPanelAdminAsync(ct);
        var target = await FindTargetAsync(id, ct);
        EnsureCanManage(actor, target, changingPrivileges: false);
        ValidatePassword(req.Password);

        target.PasswordHash = BCrypt.Net.BCrypt.HashPassword(req.Password!);
        await _users.UpdateAsync(target, ct);
        await _auth.RevokePanelSessionsAsync(target.Id, "password_reset", ct);
        await WriteAuditAsync(AuditEvents.UserPasswordReset, $"Сброшен пароль пользователя {target.Username}", target, ct);
        return NoContent();
    }

    /// <summary>
    /// Безопасное удаление: сохраняет пользователя и связанные с ним ключи, но
    /// запрещает дальнейший вход. Для повторного доступа используйте /unblock.
    /// </summary>
    [HttpDelete("{id}")]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    [ProducesResponseType(StatusCodes.Status403Forbidden)]
    public async Task<IActionResult> Deactivate(string id, CancellationToken ct)
    {
        var actor = await RequireCurrentPanelAdminAsync(ct);
        var target = await FindTargetAsync(id, ct);
        EnsureCanManage(actor, target, changingPrivileges: true);

        if (target.Status != UserStatuses.Blocked)
        {
            target.Status = UserStatuses.Blocked;
            target.IsActive = false;
            await _users.UpdateAsync(target, ct);
            await _auth.RevokePanelSessionsAsync(target.Id, "deactivated", ct);
            await WriteAuditAsync(AuditEvents.UserDeactivated, $"Деактивирован пользователь {target.Username}", target, ct);
        }

        return NoContent();
    }

    private async Task<IActionResult> SetStatusAsync(string id, string status, string auditEvent, string message, CancellationToken ct)
    {
        var actor = await RequireCurrentPanelAdminAsync(ct);
        var target = await FindTargetAsync(id, ct);
        EnsureCanManage(actor, target, changingPrivileges: true);

        target.Status = ValidateStatus(status);
        target.IsActive = target.Status != UserStatuses.Blocked;
        await _users.UpdateAsync(target, ct);
        await _auth.RevokePanelSessionsAsync(target.Id, "status_changed", ct);
        await WriteAuditAsync(auditEvent, $"{message} {target.Username}", target, ct);

        var keyCount = await _clients.CountActiveByUserAsync(ct);
        return Ok(UserListItemDto.From(target, keyCount.GetValueOrDefault(target.Id)));
    }

    private async Task<User> RequireCurrentPanelAdminAsync(CancellationToken ct)
    {
        var actorId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value
            ?? User.FindFirst(JwtRegisteredClaimNames.Sub)?.Value;
        var actor = actorId is null ? null : await _users.FindByIdAsync(actorId, ct);

        if (actor is null || actor.Status == UserStatuses.Blocked)
            throw new UnauthorizedAccessException();
        if (!UserRoles.PanelAdmin.Contains(actor.Role))
            return ForbidActor();

        return actor;
    }

    private static User ForbidActor() => throw new ForbiddenException();

    private async Task<User> FindTargetAsync(string id, CancellationToken ct)
    {
        if (!ObjectId.TryParse(id, out _))
            throw new BadRequestException("Идентификатор пользователя имеет неверный формат.");

        return await _users.FindByIdAsync(id, ct)
            ?? throw new NotFoundException("Пользователь не найден.");
    }

    private static string ValidateUsername(string? value)
    {
        if (!PanelUserManagementRules.TryNormalizeUsername(value, out var username, out var error))
            throw new BadRequestException(error!);
        return username;
    }

    private static void ValidatePassword(string? password)
    {
        if (!PanelUserManagementRules.TryValidatePassword(password, out var error))
            throw new BadRequestException(error!);
    }

    private static string ValidateStatus(string? status)
    {
        var normalized = status?.Trim().ToLowerInvariant();
        if (!UserStatuses.IsKnown(normalized))
            throw new BadRequestException("Указан неизвестный статус пользователя.");
        return normalized!;
    }

    private static string ValidateAssignableRole(User actor, string? role)
    {
        var normalized = role?.Trim().ToLowerInvariant();
        if (!UserRoles.IsKnown(normalized) || !UserRoles.Assignable.Contains(normalized))
            throw new BadRequestException("Через этот API можно назначить только роли admin, operator или viewer.");
        if (!PanelUserManagementRules.CanAssignPanelRole(actor.Role, normalized!))
            throw new ForbiddenException();
        return normalized!;
    }

    private static string ValidateUpdatedRole(User actor, User target, string? role)
    {
        var normalized = role?.Trim().ToLowerInvariant();
        if (!UserRoles.IsKnown(normalized))
            throw new BadRequestException("Указана неизвестная роль пользователя.");

        // Роли owner и client не назначаются этим API. Но редактирование
        // существующего owner (только собственный безопасный профиль) или VPN-
        // клиента не должно требовать искусственно менять его роль.
        if (normalized == target.Role && normalized is UserRoles.Owner or UserRoles.Client)
            return normalized;

        return ValidateAssignableRole(actor, normalized);
    }

    private static string? NormalizeOptional(string? value, string field, int maxLength)
    {
        var normalized = string.IsNullOrWhiteSpace(value) ? null : value.Trim();
        if (normalized?.Length > maxLength)
            throw new BadRequestException($"{field} не может быть длиннее {maxLength} символов.");
        return normalized;
    }

    private static void EnsureCanManage(User actor, User target, bool changingPrivileges)
    {
        var isSelf = actor.Id == target.Id;
        if (!PanelUserManagementRules.CanManageTarget(actor.Role, target.Role, isSelf))
            throw new ForbiddenException();
        if (isSelf && changingPrivileges)
            throw new BadRequestException("Нельзя изменять собственную роль или статус через управление пользователями.");
        if (target.Role == UserRoles.Owner && changingPrivileges)
            throw new BadRequestException("Нельзя блокировать, деактивировать или понижать владельца панели.");
    }

    private Task WriteAuditAsync(string @event, string message, User target, CancellationToken ct, Dictionary<string, string>? meta = null) =>
        _audit.WriteAsync(@event, message, User, AuditTargets.User, target.Id, target.Username, meta: meta, ct: ct);
}


/// <summary>Журнал событий панели.</summary>
[ApiController]
[Route("api/logs")]
[Authorize(Policy = AuthPolicies.PanelRead)]
public class LogsController : ControllerBase
{
    private readonly IAuditLogRepository _audit;

    public LogsController(IAuditLogRepository audit) => _audit = audit;

    [HttpGet]
    [ProducesResponseType(typeof(Paged<AuditEntryDto>), StatusCodes.Status200OK)]
    public async Task<IActionResult> GetAll(
        [FromQuery] string? level,
        [FromQuery] string? targetType,
        [FromQuery] string? targetId,
        [FromQuery] DateTime? from,
        [FromQuery] DateTime? to,
        [FromQuery] int? page,
        [FromQuery] int? pageSize,
        CancellationToken ct)
    {
        var entries = await _audit.SearchAsync(
            new AuditQuery(level, targetType, targetId, from, to, page, pageSize), ct);

        return Ok(entries.Map(AuditEntryDto.From));
    }
}

/// <summary>Настройки панели.</summary>
[ApiController]
[Route("api/settings")]
[Authorize(Policy = AuthPolicies.PanelRead)]
public class SettingsController : ControllerBase
{
    private readonly IPanelSettingsRepository _settings;
    private readonly IAuditService _audit;

    public SettingsController(IPanelSettingsRepository settings, IAuditService audit)
    {
        _settings = settings;
        _audit = audit;
    }

    [HttpGet]
    [ProducesResponseType(typeof(PanelSettingsDto), StatusCodes.Status200OK)]
    public async Task<IActionResult> Get(CancellationToken ct)
        => Ok(PanelSettingsDto.From(await _settings.GetAsync(ct)));

    /// <summary>
    /// Меняет только фактически применяемые при выдаче ключей значения. Прочие
    /// поля модели пока не имеют обработчика runtime и намеренно не принимаются
    /// этим контрактом.
    /// </summary>
    [HttpPut]
    [Authorize(Policy = AuthPolicies.PanelAdmin)]
    [ProducesResponseType(typeof(PanelSettingsDto), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> Update([FromBody] UpdatePanelSettingsRequest req, CancellationToken ct)
    {
        if (!PanelSettingsRules.TryValidate(
                req.DefaultExpiryDays,
                req.DefaultTrafficLimitBytes,
                out var error))
            throw new BadRequestException(error!);

        var actorId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value
            ?? User.FindFirst(JwtRegisteredClaimNames.Sub)?.Value;
        if (string.IsNullOrWhiteSpace(actorId))
            throw new UnauthorizedAccessException();

        var settings = await _settings.UpdateAsync(
            req.DefaultExpiryDays,
            req.DefaultTrafficLimitBytes,
            actorId,
            ct);

        var changed = new List<string>();
        if (req.DefaultExpiryDays is not null) changed.Add("defaultExpiryDays");
        else changed.Add("defaultExpiryDays=unlimited");
        if (req.DefaultTrafficLimitBytes is not null) changed.Add("defaultTrafficLimitBytes");
        else changed.Add("defaultTrafficLimitBytes=unlimited");

        await _audit.WriteAsync(
            AuditEvents.SettingsUpdated,
            "Обновлены настройки выдачи ключей по умолчанию.",
            User,
            AuditTargets.System,
            PanelSettings.SingletonId,
            "Настройки панели",
            meta: new Dictionary<string, string> { ["changed"] = string.Join(",", changed) },
            ct: ct);

        return Ok(PanelSettingsDto.From(settings));
    }
}
