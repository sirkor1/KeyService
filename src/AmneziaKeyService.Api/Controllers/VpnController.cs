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
using MongoDB.Bson;

namespace AmneziaKeyService.Api.Controllers;

/// <summary>
/// Путь Telegram-бота и приложения AmneziaVPN. Выдача ключа идёт по SSH
/// в worker, а не здесь — эта точка входа только читает готовый конфиг
/// либо публикует заявку на выдачу.
/// </summary>
[ApiController]
[Route("api/vpn")]
[Authorize]
public class VpnController : ControllerBase
{
    private readonly IVpnClientRepository _clients;
    private readonly IVpnServerRepository _servers;
    private readonly IDomainEventPublisher _events;

    public VpnController(
        IVpnClientRepository clients,
        IVpnServerRepository servers,
        IDomainEventPublisher events)
    {
        _clients = clients;
        _servers = servers;
        _events  = events;
    }

    /// <summary>
    /// Возвращает VPN-конфиг в формате AmneziaVPN (vpn:// URI) для указанного сервера.
    ///
    /// Если у пользователя уже есть активный ключ с сохранённым конфигом —
    /// отдаёт его сразу (200), как и раньше: узел для этого не нужен, все
    /// данные уже лежат в документе ключа. Иначе публикует событие key.issue
    /// и отвечает 202 — саму выдачу (X25519 keypair, IP, peer на сервере)
    /// делает worker. Клиент опрашивает GET /api/events/{eventId}, а по
    /// статусу succeeded повторяет этот же запрос — тогда сработает быстрый
    /// путь выше.
    /// </summary>
    [HttpGet("config")]
    [ProducesResponseType(typeof(VpnConfigResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(EventAcceptedDto), StatusCodes.Status202Accepted)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> GetConfig([FromQuery] string serverId, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(serverId))
            return BadRequest(new { error = "Параметр serverId обязателен." });

        var userId = CurrentUserId;
        if (userId is null) return Unauthorized();

        var existing = await _clients.FindByUserIdAndServerAsync(userId, serverId, ct);

        // Готовый конфиг переиспользуем: публиковать событие и ждать worker
        // ради того, что уже есть, незачем — а при недоступном узле это
        // единственный рабочий путь, тем же поведением, что было в
        // VpnConfigService.GetOrCreateConfigAsync до переезда на события.
        if (existing?.VpnConfigJson is not null && existing.Status == KeyStatuses.Active)
        {
            return Ok(new VpnConfigResponse(
                AmneziaUriEncoder.Encode(existing.VpnConfigJson),
                existing.AssignedIp ?? string.Empty,
                existing.ClientPubKey ?? string.Empty));
        }

        return Accepted(await PublishIssueAsync(userId, serverId, ct));
    }

    /// <summary>
    /// Публикует заявку на новый VPN-ключ для указанного сервера.
    /// Один пользователь может иметь несколько ключей (для разных устройств),
    /// поэтому в отличие от /config здесь событие публикуется всегда.
    /// </summary>
    [HttpPost("new")]
    [ProducesResponseType(typeof(EventAcceptedDto), StatusCodes.Status202Accepted)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> CreateNew([FromQuery] string serverId, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(serverId))
            return BadRequest(new { error = "Параметр serverId обязателен." });

        var userId = CurrentUserId;
        if (userId is null) return Unauthorized();

        return Accepted(await PublishIssueAsync(userId, serverId, ct));
    }

    private async Task<EventAcceptedDto> PublishIssueAsync(
        string userId, string serverId, CancellationToken ct)
    {
        // Существование узла проверяем до публикации: до переезда на события
        // это давало 404 из IssueOnceAsync, и терять его нельзя — иначе опечатка
        // в serverId возвращала бы 202 и заведомо провальное событие, о котором
        // клиент узнал бы только опросом.
        _ = await _servers.GetByIdAsync(serverId, ct)
            ?? throw new NotFoundException($"Сервер '{serverId}' не найден.");

        // Идентификатор назначаем здесь же — тем же приёмом, что и панель:
        // OnFailedAsync обработчика отличает по нему «выдача не состоялась»
        // от «состоялась, но событие не закрылось».
        var keyId = ObjectId.GenerateNewId().ToString();

        var evt = await _events.PublishAsync(
            DomainEventTypes.KeyIssue,
            new KeyIssuePayload(
                KeyId: keyId,
                ServerId: serverId,
                OwnerUserId: userId,
                OwnerCreated: false,
                ProtocolId: null,
                OwnerName: null,
                DeviceName: null,
                Label: null,
                ExpiryDays: null,
                TrafficLimitBytes: null,
                // Именно Telegram, как сегодня проставляет CreateNewConfigAsync —
                // менять источник у ключей, выданных через /api/vpn/*, не задача
                // этого шага, это отдельное решение.
                Source: KeySources.Telegram,
                CreatedByUserId: null,
                Notify: null),
            partitionKey: serverId,
            correlationId: keyId,
            // Без этого пользователь не смог бы прочитать своё же событие —
            // EventsController отдаёт чужие события как 404.
            actorUserId: userId,
            ct);

        return new EventAcceptedDto(evt.Id, keyId);
    }

    private string? CurrentUserId =>
        User.FindFirstValue(ClaimTypes.NameIdentifier)
        ?? User.FindFirstValue(JwtRegisteredClaimNames.Sub);
}
