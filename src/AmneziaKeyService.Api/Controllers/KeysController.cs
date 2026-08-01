using System.Security.Claims;
using System.Text;
using System.Text.RegularExpressions;
using AmneziaKeyService.Core.DTOs;
using AmneziaKeyService.Core.DTOs.Panel;
using AmneziaKeyService.Core.Exceptions;
using AmneziaKeyService.Core.Interfaces;
using AmneziaKeyService.Core.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using MongoDB.Bson;

namespace AmneziaKeyService.Api.Controllers;

[ApiController]
[Route("api/keys")]
[Authorize(Policy = AuthPolicies.PanelRead)]
public partial class KeysController : ControllerBase
{
    private readonly IVpnClientRepository _clients;
    private readonly IVpnServerRepository _servers;
    private readonly IUserRepository _users;
    private readonly IVpnConfigReader _vpnConfigReader;
    private readonly IPanelSettingsRepository _settings;
    private readonly IDomainEventPublisher _events;

    public KeysController(
        IVpnClientRepository clients,
        IVpnServerRepository servers,
        IUserRepository users,
        IVpnConfigReader vpnConfigReader,
        IPanelSettingsRepository settings,
        IDomainEventPublisher events)
    {
        _clients         = clients;
        _servers         = servers;
        _users           = users;
        _vpnConfigReader = vpnConfigReader;
        _settings        = settings;
        _events          = events;
    }

    // ── Чтение ────────────────────────────────────────────────────────────────

    [HttpGet]
    [ProducesResponseType(typeof(Paged<KeyListItemDto>), StatusCodes.Status200OK)]
    public async Task<IActionResult> GetAll(
        [FromQuery] string? search,
        [FromQuery] string? status,
        [FromQuery] string? serverId,
        [FromQuery] string? protocol,
        [FromQuery] string? userId,
        [FromQuery] int? page,
        [FromQuery] int? pageSize,
        CancellationToken ct)
    {
        var keys = await _clients.SearchAsync(
            new KeyQuery(search, status, serverId, protocol, userId, page, pageSize), ct);

        var serverNames = await LoadServerNamesAsync(ct);
        var owners      = await LoadOwnersAsync(keys.Items, ct);

        return Ok(keys.Map(k => KeyListItemDto.From(
            k, serverNames.GetValueOrDefault(k.ServerId), owners.GetValueOrDefault(k.UserId))));
    }

    [HttpGet("{id}")]
    [ProducesResponseType(typeof(KeyDetailDto), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> GetById(string id, CancellationToken ct)
    {
        var key = await _clients.FindByIdAsync(id, ct)
            ?? throw new NotFoundException("Ключ не найден.");

        var server = await _servers.GetByIdAsync(key.ServerId, ct);
        var owner  = await _users.FindByIdAsync(key.UserId, ct);

        return Ok(KeyDetailDto.From(key, server?.Name, owner?.DisplayName ?? owner?.Username));
    }

    // ── Выдача ────────────────────────────────────────────────────────────────

    /// <summary>
    /// Принимает заявку на выдачу ключа и публикует событие key.issue —
    /// саму выдачу (SSH на узел, генерацию ключей) делает worker. Панель
    /// узнаёт результат через GET /api/events/{eventId}.
    ///
    /// Владелец создаётся здесь же: это не требует узла, и если заявка дальше
    /// не пройдёт валидацию — не остаётся мусорной учётки. Если же публикация
    /// состоялась, а выдача в worker сорвётся, за уборку созданного здесь
    /// владельца отвечает KeyIssueHandler.OnFailedAsync — ownerCreated едет
    /// в payload специально для этого.
    /// </summary>
    [HttpPost]
    [Authorize(Policy = AuthPolicies.PanelWrite)]
    [ProducesResponseType(typeof(EventAcceptedDto), StatusCodes.Status202Accepted)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> Issue([FromBody] IssueKeyRequest req, CancellationToken ct)
    {
        var server = await _servers.GetByIdAsync(req.ServerId, ct)
            ?? throw new NotFoundException("Сервер не найден.");

        // Протокол проверяем до создания владельца: иначе каждый запрос
        // с опечаткой в protocolId оставлял бы в базе мусорную учётку.
        if (req.ProtocolId is not null && server.FindProtocol(req.ProtocolId) is null)
            throw new NotFoundException($"Протокол '{req.ProtocolId}' на этом узле не найден.");

        if (server.DefaultProtocol is null)
            throw new BadRequestException($"На узле «{server.Name}» не настроен ни один протокол.");

        var (owner, ownerCreated) = await ResolveOwnerAsync(req, ct);
        var settings = await _settings.GetAsync(ct);

        // 0 означает «бессрочно», null — «взять из настроек панели».
        var expiryDays = req.ExpiryDays ?? settings.DefaultExpiryDays;
        if (expiryDays is <= 0) expiryDays = null;

        // Квота читается так же: 0 — без ограничения, null — из настроек.
        // Ноль нельзя пропускать как есть: квота в ноль байт исчерпана
        // первым же пакетом, и воркер отозвал бы ключ сразу после выдачи.
        var trafficLimit = req.TrafficLimitBytes ?? settings.DefaultTrafficLimitBytes;
        if (trafficLimit is <= 0) trafficLimit = null;

        // Идентификатор назначаем здесь, а не оставляем драйверу: OnFailedAsync
        // обработчика отличает по нему «выдача не состоялась» от «состоялась,
        // но событие не закрылось».
        var keyId = ObjectId.GenerateNewId().ToString();

        var evt = await _events.PublishAsync(
            DomainEventTypes.KeyIssue,
            new KeyIssuePayload(
                KeyId: keyId,
                ServerId: req.ServerId,
                OwnerUserId: owner.Id,
                OwnerCreated: ownerCreated,
                ProtocolId: req.ProtocolId,
                OwnerName: req.OwnerName ?? owner.DisplayName ?? owner.Username,
                DeviceName: req.DeviceName,
                Label: req.Label,
                ExpiryDays: expiryDays,
                TrafficLimitBytes: trafficLimit,
                Source: KeySources.Panel,
                CreatedByUserId: CurrentUserId,
                Notify: null),
            partitionKey: req.ServerId,
            correlationId: keyId,
            actorUserId: CurrentUserId,
            ct);

        return Accepted(new EventAcceptedDto(evt.Id, keyId));
    }

    // ── Отзыв ─────────────────────────────────────────────────────────────────

    /// <summary>
    /// Принимает заявку на отзыв и публикует событие key.revoke — удаление
    /// peer-а с узла делает worker. Запись в журнал и перевод в pendingRevoke
    /// при недоступном узле делает KeyRevokeHandler.
    /// </summary>
    [HttpPost("{id}/revoke")]
    [Authorize(Policy = AuthPolicies.PanelWrite)]
    [ProducesResponseType(typeof(EventAcceptedDto), StatusCodes.Status202Accepted)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> Revoke(
        string id, [FromBody] RevokeKeyRequest? req, CancellationToken ct)
    {
        var client = await _clients.FindByIdAsync(id, ct)
            ?? throw new NotFoundException("Ключ не найден.");

        var evt = await _events.PublishAsync(
            DomainEventTypes.KeyRevoke,
            new KeyRevokePayload(id, RevokeReasons.Manual, CurrentUserId, req?.Comment),
            partitionKey: client.ServerId,
            correlationId: id,
            actorUserId: CurrentUserId,
            ct);

        return Accepted(new EventAcceptedDto(evt.Id, id));
    }

    // ── Секрет ────────────────────────────────────────────────────────────────

    /// <summary>
    /// Ссылка vpn:// и клиентский файл для уже выданного ключа. В отличие
    /// от прежнего ответа на выдачу, доступна повторно, пока ключ активен:
    /// правило то же, что у /download — отозванный ключ отдаёт 404, потому
    /// что конфиг стёрт вместе с приватным ключом. Окна по времени нет.
    /// </summary>
    [HttpGet("{id}/secret")]
    [ProducesResponseType(typeof(KeySecretDto), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> GetSecret(string id, CancellationToken ct)
    {
        var client = await _clients.FindByIdAsync(id, ct)
            // Документа ключа ещё нет либо потому, что событие выдачи ещё
            // выполняется, либо потому, что id ошибочен — с панели различить
            // эти случаи нечем, а 500 от пустого документа хуже понятного 404.
            ?? throw new NotFoundException("Ключ ещё готовится или не существует.");

        if (client.Status is KeyStatuses.Revoked)
            throw new NotFoundException("Ключ отозван — его конфигурация больше не хранится.");

        var vpnUri = await _vpnConfigReader.BuildVpnUriAsync(client, ct);
        var file   = await _vpnConfigReader.BuildClientFileAsync(client, ct);

        return Ok(new KeySecretDto(vpnUri, file.FileName, file.Content));
    }

    // ── Скачивание ────────────────────────────────────────────────────────────

    /// <summary>
    /// Отдаёт конфиг файлом. Работает, пока ключ активен: после отзыва
    /// сохранённый конфиг стирается вместе с приватным ключом.
    /// </summary>
    [HttpGet("{id}/download")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> Download(
        string id, [FromQuery] string format = "conf", CancellationToken ct = default)
    {
        var client = await _clients.FindByIdAsync(id, ct)
            ?? throw new NotFoundException("Ключ не найден.");

        if (client.Status is KeyStatuses.Revoked)
            throw new NotFoundException("Ключ отозван — его конфигурация больше не хранится.");

        if (format.Equals("uri", StringComparison.OrdinalIgnoreCase))
        {
            var uri = await _vpnConfigReader.BuildVpnUriAsync(client, ct);
            return Ok(new { vpnUri = uri });
        }

        var file = await _vpnConfigReader.BuildClientFileAsync(client, ct);
        return File(Encoding.UTF8.GetBytes(file.Content), file.ContentType, file.FileName);
    }

    // ── Вспомогательное ───────────────────────────────────────────────────────

    private string? CurrentUserId => User.FindFirstValue(ClaimTypes.NameIdentifier);

    /// <summary>
    /// Находит владельца или заводит нового клиента.
    ///
    /// Форма выдачи в макете принимает произвольное имя, а не выбор из списка,
    /// поэтому запись пользователя создаётся здесь же. Роль всегда client:
    /// доступа к панели такая учётка не даёт.
    ///
    /// Второй элемент кортежа говорит, была ли учётка создана прямо сейчас —
    /// обработчик события удалит её, если выдача не состоится.
    /// </summary>
    private async Task<(User Owner, bool Created)> ResolveOwnerAsync(
        IssueKeyRequest req, CancellationToken ct)
    {
        if (!string.IsNullOrWhiteSpace(req.UserId))
        {
            var existing = await _users.FindByIdAsync(req.UserId, ct)
                ?? throw new NotFoundException("Пользователь не найден.");
            return (existing, false);
        }

        if (string.IsNullOrWhiteSpace(req.OwnerName))
            throw new BadRequestException("Укажите владельца ключа или выберите существующего клиента.");

        var username = await GenerateUsernameAsync(req.OwnerName, ct);

        var user = new User
        {
            Username     = username,
            DisplayName  = req.OwnerName.Trim(),
            Contact      = req.Contact,
            PasswordHash = string.Empty,
            Role         = UserRoles.Client,
            Status       = UserStatuses.Active,
        };

        await _users.CreateAsync(user, ct);

        var created = await _users.FindByUsernameAsync(username, ct)
            ?? throw new InvalidOperationException("Не удалось создать клиента.");

        return (created, true);
    }

    /// <summary>
    /// Логин из имени владельца, при коллизии — числовой суффикс.
    ///
    /// Буквы любых алфавитов, а не только латиница: иначе «Иван Петров»
    /// вырождался в пустую строку и все русскоязычные клиенты получали
    /// логины client, client-2, client-3. Эти учётки служебные — паролем
    /// в них не входят, — поэтому кириллица в логине безвредна.
    /// </summary>
    private async Task<string> GenerateUsernameAsync(string ownerName, CancellationToken ct)
    {
        var slug = NonSlugChars()
            .Replace(ownerName.Trim().ToLowerInvariant(), "-")
            .Trim('-');

        if (slug.Length > 32) slug = slug[..32].Trim('-');
        if (slug.Length == 0) slug = "client";

        var candidate = slug;
        for (var suffix = 2; await _users.FindByUsernameAsync(candidate, ct) is not null; suffix++)
            candidate = $"{slug}-{suffix}";

        return candidate;
    }

    [GeneratedRegex(@"[^\p{L}\p{N}]+")]
    private static partial Regex NonSlugChars();

    private async Task<Dictionary<string, string>> LoadServerNamesAsync(CancellationToken ct)
    {
        var servers = await _servers.GetAllAsync(ct);
        return servers.ToDictionary(s => s.Id, s => s.Name);
    }

    private async Task<Dictionary<string, string>> LoadOwnersAsync(
        IReadOnlyList<VpnClient> keys, CancellationToken ct)
    {
        var users = await _users.GetByIdsAsync(keys.Select(k => k.UserId), ct);
        return users.ToDictionary(u => u.Id, u => u.DisplayName ?? u.Username);
    }
}
