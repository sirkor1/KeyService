using System.Security.Claims;
using AmneziaKeyService.Core.DTOs.Panel;
using AmneziaKeyService.Core.Exceptions;
using AmneziaKeyService.Core.Interfaces;
using AmneziaKeyService.Core.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace AmneziaKeyService.Api.Controllers;

/// <summary>
/// Статус доменного события: панель опрашивает его после выдачи и отзыва
/// ключа, клиентский /api/vpn/* — после публикации key.issue.
///
/// Политика мягче, чем у <c>JobsController</c> (там — PanelAdmin), потому что
/// этой ручкой пользуется и обычный клиент бота/панели, а не только оператор.
/// </summary>
[ApiController]
[Route("api/events")]
[Authorize]
public class EventsController : ControllerBase
{
    private readonly IDomainEventRepository _events;
    private readonly IAuthorizationService _authorization;

    public EventsController(IDomainEventRepository events, IAuthorizationService authorization)
    {
        _events        = events;
        _authorization = authorization;
    }

    [HttpGet("{id}")]
    [ProducesResponseType(typeof(DomainEventDto), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> GetById(string id, CancellationToken ct)
    {
        var evt = await _events.GetByIdAsync(id, ct)
            ?? throw new NotFoundException("Событие не найдено.");

        var panelAccess = await _authorization.AuthorizeAsync(User, AuthPolicies.PanelRead);

        // У кого панельного доступа нет, тот видит только событие, где он сам
        // указан заявителем. Чужое отдаём как 404, а не 403: иначе перебором
        // идентификаторов можно узнать, какие события вообще существуют.
        if (!panelAccess.Succeeded && evt.ActorUserId != CurrentUserId)
            throw new NotFoundException("Событие не найдено.");

        return Ok(DomainEventDto.From(evt));
    }

    private string? CurrentUserId => User.FindFirstValue(ClaimTypes.NameIdentifier);
}
