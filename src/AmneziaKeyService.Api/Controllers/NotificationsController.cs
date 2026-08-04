using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using AmneziaKeyService.Core.DTOs;
using AmneziaKeyService.Core.DTOs.Panel;
using AmneziaKeyService.Core.Exceptions;
using AmneziaKeyService.Core.Interfaces;
using AmneziaKeyService.Core.Models;
using AmneziaKeyService.Infrastructure.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace AmneziaKeyService.Api.Controllers;

[ApiController]
[Route("api/notifications")]
[Authorize(Policy = AuthPolicies.PanelAdmin)]
public class NotificationsController : ControllerBase
{
    private const int TelegramTextMaxLength = 4096;
    private readonly INotificationRepository _notifications;
    private readonly IUserRepository _users;
    private readonly IAuditService _audit;

    public NotificationsController(
        INotificationRepository notifications,
        IUserRepository users,
        IAuditService audit)
    {
        _notifications = notifications;
        _users = users;
        _audit = audit;
    }

    [HttpGet]
    [ProducesResponseType(typeof(Paged<NotificationCampaignDto>), StatusCodes.Status200OK)]
    public async Task<IActionResult> GetAll(
        [FromQuery] string? status,
        [FromQuery] int? page,
        [FromQuery] int? pageSize,
        CancellationToken ct)
    {
        var campaigns = await _notifications.SearchCampaignsAsync(
            new NotificationCampaignQuery(status, page, pageSize), ct);
        return Ok(campaigns.Map(NotificationCampaignDto.From));
    }

    [HttpGet("audience")]
    [ProducesResponseType(typeof(NotificationAudienceDto), StatusCodes.Status200OK)]
    public async Task<IActionResult> GetAudience(CancellationToken ct)
        => Ok(new NotificationAudienceDto(await _users.CountTelegramRecipientsAsync(ct)));

    [HttpGet("{id}")]
    [ProducesResponseType(typeof(NotificationCampaignDto), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> GetById(string id, CancellationToken ct)
    {
        var campaign = await _notifications.GetCampaignAsync(id, ct)
            ?? throw new NotFoundException("Рассылка не найдена.");
        return Ok(NotificationCampaignDto.From(campaign));
    }

    [HttpPost]
    [ProducesResponseType(typeof(NotificationCampaignDto), StatusCodes.Status201Created)]
    public async Task<IActionResult> Create(
        [FromBody] CreateNotificationCampaignRequest request,
        CancellationToken ct)
    {
        var text = request.Text?.Trim() ?? string.Empty;
        if (text.Length is < 1 or > TelegramTextMaxLength)
            throw new BadRequestException($"Сообщение должно содержать от 1 до {TelegramTextMaxLength} символов.");

        var title = NormalizeTitle(request.Title, text);
        var recipients = await _users.GetTelegramRecipientsAsync(ct);
        var campaign = await _notifications.CreateAsync(new NotificationCampaign
        {
            Title = title,
            Text = text,
            DisableNotification = request.DisableNotification,
            CreatedByUserId = CurrentUserId()
        }, recipients, ct);

        await _audit.WriteAsync(
            AuditEvents.NotificationCreated,
            $"Создана рассылка «{campaign.Title}» для {campaign.TotalCount} получателей",
            User,
            AuditTargets.Notification,
            campaign.Id,
            campaign.Title,
            meta: new Dictionary<string, string> { ["recipients"] = campaign.TotalCount.ToString() },
            ct: ct);

        return CreatedAtAction(nameof(GetById), new { id = campaign.Id }, NotificationCampaignDto.From(campaign));
    }

    [HttpPost("{id}/cancel")]
    [ProducesResponseType(typeof(NotificationCampaignDto), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    [ProducesResponseType(StatusCodes.Status409Conflict)]
    public async Task<IActionResult> Cancel(string id, CancellationToken ct)
    {
        var existing = await _notifications.GetCampaignAsync(id, ct)
            ?? throw new NotFoundException("Рассылка не найдена.");

        if (!await _notifications.CancelAsync(id, ct))
            return Conflict(new { error = "Завершённую рассылку нельзя остановить." });

        var campaign = await _notifications.GetCampaignAsync(id, ct) ?? existing;
        await _audit.WriteAsync(
            AuditEvents.NotificationCanceled,
            $"Остановлена рассылка «{campaign.Title}»",
            User,
            AuditTargets.Notification,
            campaign.Id,
            campaign.Title,
            ct: ct);
        return Ok(NotificationCampaignDto.From(campaign));
    }

    private string? CurrentUserId()
        => User.FindFirst(ClaimTypes.NameIdentifier)?.Value
            ?? User.FindFirst(JwtRegisteredClaimNames.Sub)?.Value;

    private static string NormalizeTitle(string? value, string text)
    {
        var title = value?.Trim() ?? string.Empty;
        if (title.Length > 128)
            throw new BadRequestException("Название рассылки не должно превышать 128 символов.");
        if (title.Length > 0) return title;

        var firstLine = text.Split('\n', 2)[0].Trim();
        return firstLine.Length <= 80 ? firstLine : firstLine[..77] + "...";
    }
}
