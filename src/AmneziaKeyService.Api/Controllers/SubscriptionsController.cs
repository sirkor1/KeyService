using System.Security.Claims;
using AmneziaKeyService.Core.DTOs;
using AmneziaKeyService.Core.DTOs.Panel;
using AmneziaKeyService.Core.Exceptions;
using AmneziaKeyService.Core.Interfaces;
using AmneziaKeyService.Core.Models;
using AmneziaKeyService.Infrastructure.Subscriptions;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace AmneziaKeyService.Api.Controllers;

/// <summary>
/// Подписки в панели. Выдача, отзыв и перевыпуск — записи в базу и событие xcore.sync, SSH
/// здесь не нужен (<see cref="SubscriptionService"/>); применение на узлах видно в карточке узла.
/// Ни токен, ни UUID ни одним ответом, кроме <c>GET {id}/link</c>, не отдаются.
/// </summary>
[ApiController]
[Route("api/subscriptions")]
[Authorize(Policy = AuthPolicies.PanelRead)]
public class SubscriptionsController : ControllerBase
{
    /// <summary>Сколько пользователей подбирается под строку поиска по имени.</summary>
    private const int SearchUsersLimit = 100;

    private readonly ISubscriptionRepository _subscriptions;
    private readonly IUserRepository _users;
    private readonly SubscriptionService _service;

    public SubscriptionsController(
        ISubscriptionRepository subscriptions, IUserRepository users, SubscriptionService service)
    {
        _subscriptions = subscriptions;
        _users         = users;
        _service       = service;
    }

    [HttpGet]
    [ProducesResponseType(typeof(Paged<SubscriptionListItemDto>), StatusCodes.Status200OK)]
    public async Task<IActionResult> GetAll(
        [FromQuery] string? search,
        [FromQuery] string? status,
        [FromQuery] string? userId,
        [FromQuery] int? page,
        [FromQuery] int? pageSize,
        CancellationToken ct)
    {
        // Подписка не хранит имени владельца, поэтому поиск идёт через пользователей: строка
        // подбирает учётки по логину, имени и контакту, а подписки — по их идентификаторам.
        string? id = null;
        IReadOnlyCollection<string>? userIds = null;
        if (!string.IsNullOrWhiteSpace(userId))
        {
            userIds = [userId];
        }
        else if (!string.IsNullOrWhiteSpace(search))
        {
            var term = search.Trim();
            id = term;
            var matched = await _users.SearchAsync(new UserQuery(Search: term, PageSize: SearchUsersLimit), ct);
            userIds = [.. matched.Items.Select(u => u.Id)];
        }

        var found = await _subscriptions.SearchAsync(
            new SubscriptionQuery(id, userIds, status, page, pageSize), ct);

        var owners = await LoadOwnersAsync(found.Items, ct);
        return Ok(found.Map(s => SubscriptionListItemDto.From(s, owners.GetValueOrDefault(s.UserId))));
    }

    [HttpGet("{id}")]
    [ProducesResponseType(typeof(SubscriptionDetailDto), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> GetById(string id, CancellationToken ct)
        => Ok(await DetailAsync(await RequireAsync(id, ct), ct));

    /// <summary>
    /// Публичная ссылка подписки. Токен хранится зашифрованным, поэтому ссылку можно показать
    /// повторно, не перевыпуская её. Ответ — секрет и в кэш не попадает.
    /// </summary>
    [HttpGet("{id}/link")]
    [Authorize(Policy = AuthPolicies.PanelWrite)]
    [ProducesResponseType(typeof(SubscriptionLinkDto), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> GetLink(string id, CancellationToken ct)
    {
        var link = await _service.BuildLinkAsync(await RequireAsync(id, ct), ct);
        Response.Headers.CacheControl = "no-store";
        return Ok(new SubscriptionLinkDto(link));
    }

    [HttpPost]
    [Authorize(Policy = AuthPolicies.PanelWrite)]
    [ProducesResponseType(typeof(SubscriptionDetailDto), StatusCodes.Status201Created)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> Create([FromBody] CreateSubscriptionRequest req, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(req.UserId))
            throw new BadRequestException("Укажите пользователя, которому выдаётся подписка.");

        var created = await _service.CreateAsync(
            req.UserId,
            new SubscriptionCreateOptions(req.ExpiryDays, req.TrafficLimitBytes, KeySources.Panel, Actor),
            ct);

        var detail = await DetailAsync(created, ct);
        return Created($"/api/subscriptions/{created.Id}", detail);
    }

    [HttpPost("{id}/revoke")]
    [Authorize(Policy = AuthPolicies.PanelWrite)]
    [ProducesResponseType(typeof(SubscriptionDetailDto), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> Revoke(string id, CancellationToken ct)
        => Ok(await DetailAsync(await _service.RevokeAsync(id, RevokeReasons.Manual, Actor, ct), ct));

    [HttpPost("{id}/regenerate")]
    [Authorize(Policy = AuthPolicies.PanelWrite)]
    [ProducesResponseType(typeof(SubscriptionDetailDto), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> Regenerate(string id, CancellationToken ct)
        => Ok(await DetailAsync(await _service.RegenerateAsync(id, Actor, ct), ct));

    [HttpPut("{id}/limits")]
    [Authorize(Policy = AuthPolicies.PanelWrite)]
    [ProducesResponseType(typeof(SubscriptionDetailDto), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> UpdateLimits(
        string id, [FromBody] UpdateSubscriptionLimitsRequest req, CancellationToken ct)
        => Ok(await DetailAsync(
            await _service.UpdateLimitsAsync(id, req.ExpiresAt, req.TrafficLimitBytes, Actor, ct), ct));

    // ── Вспомогательное ───────────────────────────────────────────────────────

    /// <summary>Автор для журнала: логин из claim unique_name, как и в остальных контроллерах.</summary>
    private AuditActor Actor => new(
        User.FindFirstValue(ClaimTypes.NameIdentifier),
        User.FindFirstValue("unique_name") ?? User.Identity?.Name);

    private async Task<Subscription> RequireAsync(string id, CancellationToken ct) =>
        await _subscriptions.FindByIdAsync(id, ct) ?? throw new NotFoundException("Подписка не найдена.");

    private async Task<SubscriptionDetailDto> DetailAsync(Subscription subscription, CancellationToken ct)
    {
        var owner = await _users.FindByIdAsync(subscription.UserId, ct);
        return SubscriptionDetailDto.From(subscription, owner?.DisplayName ?? owner?.Username);
    }

    private async Task<Dictionary<string, string>> LoadOwnersAsync(
        IReadOnlyList<Subscription> subscriptions, CancellationToken ct)
    {
        var users = await _users.GetByIdsAsync(subscriptions.Select(s => s.UserId), ct);
        return users.ToDictionary(u => u.Id, u => u.DisplayName ?? u.Username);
    }
}
