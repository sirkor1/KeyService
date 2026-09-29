using System.ComponentModel.DataAnnotations;
using System.Security.Claims;
using AmneziaKeyService.Core.Exceptions;
using AmneziaKeyService.Core.Interfaces;
using AmneziaKeyService.Core.Models;
using AmneziaKeyService.Infrastructure.Repositories;
using AmneziaKeyService.Infrastructure.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using MongoDB.Bson;

namespace AmneziaKeyService.Api.Controllers;

[ApiController, Route("api/routers"), Authorize(Policy = AuthPolicies.PanelRead)]
public sealed class RoutersController(
    RouterMonitorRepository routers, IUserRepository users, IVpnServerRepository servers,
    IVpnClientRepository clients, IVpnConfigReader configs, IAuditService audit) : ControllerBase
{
    [HttpGet]
    public async Task<IActionResult> List(CancellationToken ct)
    {
        var items = await routers.ListAsync(ct);
        var owners = (await users.GetByIdsAsync(items.Select(r => r.UserId), ct)).ToDictionary(u => u.Id);
        var nodes = (await servers.GetAllAsync(ct)).ToDictionary(s => s.Id);
        return Ok(items.Select(r => View(r, owners.GetValueOrDefault(r.UserId), nodes.GetValueOrDefault(r.ServerId))));
    }

    [HttpGet("options"), Authorize(Policy = AuthPolicies.PanelAdmin)]
    public async Task<IActionResult> Options(CancellationToken ct) => Ok(new
    {
        users = (await users.GetTelegramRecipientsAsync(ct)).Select(u => new { u.Id, name = u.DisplayName ?? u.Username, u.TelegramId }),
        servers = (await servers.GetAllAsync(ct)).Where(s => s.Status == ServerStatuses.Ok).Select(s => new
        {
            s.Id, s.Name, protocols = s.Protocols.Where(p => p.Kind == ProtocolKinds.WireGuard && s.CanIssue(p))
                .Select(p => new { p.Id, name = "WireGuard · " + p.Port })
        }).Where(s => s.protocols.Any())
    });

    [HttpGet("{id}")]
    public async Task<IActionResult> Get(string id, CancellationToken ct)
    {
        var r = await RequireAsync(id, ct);
        return Ok(View(r, await users.FindByIdAsync(r.UserId, ct), await servers.GetByIdAsync(r.ServerId, ct)));
    }

    [HttpGet("{id}/history")]
    public async Task<IActionResult> History(string id, CancellationToken ct)
    {
        _ = await RequireAsync(id, ct);
        return Ok((await routers.HistoryAsync(id, ct)).Select(h => new
        { h.Id, h.At, h.State, h.Detail, h.LastHandshakeAt, h.OutageSeconds, h.DeliveryStatus, h.DeliveryError, h.SentAt }));
    }

    [HttpPost, Authorize(Policy = AuthPolicies.PanelAdmin)]
    public async Task<IActionResult> Create(CreateRouterRequest req, CancellationToken ct)
    {
        await RequireRecipientAsync(req.UserId, ct);
        if (!ObjectId.TryParse(req.ServerId, out _)) throw new BadRequestException("Некорректный идентификатор сервера.");
        var server = await servers.GetByIdAsync(req.ServerId, ct) ?? throw new NotFoundException("Сервер не найден.");
        var protocol = server.IssuanceProtocol(req.ProtocolId);
        if (server.Status != ServerStatuses.Ok || protocol?.Kind != ProtocolKinds.WireGuard)
            throw new BadRequestException("Выберите установленный обычный WireGuard на доступном сервере.");
        var r = new RouterMonitor
        {
            Name = ValidName(req.Name), UserId = req.UserId, ServerId = server.Id, ProtocolId = protocol.Id,
            CreatedByUserId = User.FindFirstValue(ClaimTypes.NameIdentifier), LastCheckedAt = DateTime.UtcNow,
            Detail = "Готовится ключ подключения"
        };
        await routers.CreateAsync(r, ct);
        await AuditAsync("router.created", r, ct);
        // Worker durably relays provisioning, including after an API restart.
        return Accepted(new { r.Id });
    }

    [HttpPut("{id}"), Authorize(Policy = AuthPolicies.PanelAdmin)]
    public async Task<IActionResult> Update(string id, UpdateRouterRequest req, CancellationToken ct)
    {
        var r = await RequireAsync(id, ct);
        if (r.DeliveryGeneration != req.DeliveryGeneration) return Conflict(new { title = "Настройки уже изменены. Обновите страницу." });
        if (r.UserId != req.UserId) await RequireRecipientAsync(req.UserId, ct);
        var wasPaused = r.Paused;
        r.Name = ValidName(req.Name);
        r.UserId = req.UserId;
        r.NotificationsEnabled = req.NotificationsEnabled;
        r.Paused = req.Paused;
        r.OfflineAfterSeconds = req.OfflineAfterSeconds;
        r.DeliveryGeneration++;
        if (wasPaused != r.Paused)
        {
            RouterMonitorRules.Transition(r, r.Paused ? RouterStates.Paused : RouterStates.Unknown, null, DateTime.UtcNow);
            r.LastCheckedAt = DateTime.UtcNow;
        }
        if (!await routers.SaveAsync(r, ct)) return Conflict(new { title = "Состояние изменилось. Повторите сохранение." });
        await AuditAsync("router.updated", r, ct);
        return NoContent();
    }

    [HttpDelete("{id}"), Authorize(Policy = AuthPolicies.PanelAdmin)]
    public async Task<IActionResult> Archive(string id, CancellationToken ct)
    {
        var r = await RequireAsync(id, ct);
        r.Archived = true;
        r.Paused = true;
        r.DeliveryGeneration++;
        if (!await routers.SaveAsync(r, ct)) return Conflict(new { title = "Повторите удаление." });
        await AuditAsync("router.archived", r, ct);
        return NoContent();
    }

    [HttpPost("{id}/test"), Authorize(Policy = AuthPolicies.PanelAdmin)]
    public async Task<IActionResult> Test(string id, CancellationToken ct)
    {
        var r = await RequireAsync(id, ct);
        await RequireRecipientAsync(r.UserId, ct);
        var now = DateTime.UtcNow;
        var history = await routers.HistoryAsync(id, ct);
        if (r.PendingHistory.Concat(history).Any(h => h.State == "test" && now - h.At < TimeSpan.FromMinutes(1)))
            return StatusCode(429, new { title = "Тест можно отправлять раз в минуту." });
        r.PendingHistory.Add(new RouterTransition
        {
            RouterId = r.Id, RouterName = r.Name, UserId = r.UserId, DeliveryGeneration = r.DeliveryGeneration,
            At = now, AvailableAt = now, State = "test", DeliveryStatus = "pending"
        });
        if (!await routers.SaveAsync(r, ct)) return Conflict(new { title = "Повторите отправку теста." });
        await routers.FlushAsync(r, ct);
        return Accepted();
    }

    [HttpGet("{id}/config"), Authorize(Policy = AuthPolicies.PanelAdmin)]
    public async Task<IActionResult> Config(string id, CancellationToken ct)
    {
        var r = await RequireAsync(id, ct);
        var key = await clients.FindByIdAsync(r.KeyId, ct);
        if (key is not { IsActive: true, Status: KeyStatuses.Active })
            throw new BadRequestException("Ключ ещё не создан или уже отозван. Проверьте состояние и журнал выдачи.");
        var server = await servers.GetByIdAsync(r.ServerId, ct);
        var protocol = server?.FindProtocol(r.ProtocolId);
        if (protocol?.Kind != ProtocolKinds.WireGuard || protocol.Wg is null)
            throw new BadRequestException("Протокол WireGuard недоступен.");
        var file = await configs.BuildClientFileAsync(key, ct);
        Response.Headers.CacheControl = "no-store";
        return Ok(new { fileName = $"router-{r.Id}.conf", content = RouterConfigFile.Build(file.Content, protocol.Wg.SubnetAddress) });
    }

    private async Task<RouterMonitor> RequireAsync(string id, CancellationToken ct)
        => await routers.GetAsync(id, ct) is { Archived: false } r ? r : throw new NotFoundException("Роутер не найден.");
    private async Task RequireRecipientAsync(string id, CancellationToken ct)
    {
        if (!ObjectId.TryParse(id, out _)) throw new BadRequestException("Некорректный идентификатор пользователя.");
        if (!RouterMonitorRules.CanReceive(await users.FindByIdAsync(id, ct)))
            throw new BadRequestException("Выберите активного пользователя, зарегистрированного в Telegram-боте.");
    }
    private static string ValidName(string value)
        => string.IsNullOrWhiteSpace(value) ? throw new BadRequestException("Укажите название роутера.") : value.Trim();
    private Task AuditAsync(string action, RouterMonitor r, CancellationToken ct)
        => audit.WriteAsync(action, $"Роутер «{r.Name}»", new AuditActor(User.FindFirstValue(ClaimTypes.NameIdentifier), User.Identity?.Name),
            "router", r.Id, r.Name, ct: ct);
    private static object View(RouterMonitor r, User? user, VpnServer? server) => new
    {
        r.Id, r.Name, r.UserId, userName = user?.DisplayName ?? user?.Username, telegramId = user?.TelegramId,
        recipientAvailable = RouterMonitorRules.CanReceive(user), r.ServerId, serverName = server?.Name,
        r.ProtocolId, r.KeyId, r.ProvisionEventId, r.Paused, r.NotificationsEnabled, r.OfflineAfterSeconds,
        r.DeliveryGeneration, state = RouterStates.Effective(r, DateTime.UtcNow), r.StateSince,
        r.LastCheckedAt, r.LastHandshakeAt, r.OutageStartedAt, r.Detail, r.CreatedAt
    };
}

public record CreateRouterRequest(
    [Required, StringLength(100)] string Name, [Required] string UserId,
    [Required] string ServerId, [Required] string ProtocolId);
public record UpdateRouterRequest(
    [Required, StringLength(100)] string Name, [Required] string UserId, bool Paused,
    bool NotificationsEnabled, [Range(180, 3600)] int OfflineAfterSeconds, long DeliveryGeneration);
