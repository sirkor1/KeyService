using AmneziaKeyService.Core.DTOs;
using AmneziaKeyService.Core.DTOs.Panel;
using AmneziaKeyService.Core.Exceptions;
using AmneziaKeyService.Core.Interfaces;
using AmneziaKeyService.Core.Models;
using AmneziaKeyService.Infrastructure.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace AmneziaKeyService.Api.Controllers;

/// <summary>
/// Узлы VPN. Заменяет прежний ServerConfigController: тот работал с плоской
/// одно-протокольной моделью и терял данные при обновлении.
/// </summary>
[ApiController]
[Route("api/servers")]
[Authorize(Policy = AuthPolicies.PanelAdmin)]
public class ServersController : ControllerBase
{
    /// <summary>Окно, за которое считаются трафик и аптайм в плитках KPI.</summary>
    private const int KpiWindowDays = 30;

    private readonly IVpnServerRepository _servers;
    private readonly IVpnClientRepository _clients;
    private readonly IUserRepository _users;
    private readonly IUsageRepository _usage;
    private readonly IServerParamsService _serverParams;
    private readonly IInstallService _install;
    private readonly ISecretProtector _secrets;
    private readonly IAuditService _audit;

    public ServersController(
        IVpnServerRepository servers,
        IVpnClientRepository clients,
        IUserRepository users,
        IUsageRepository usage,
        IServerParamsService serverParams,
        IInstallService install,
        ISecretProtector secrets,
        IAuditService audit)
    {
        _servers      = servers;
        _clients      = clients;
        _users        = users;
        _usage        = usage;
        _serverParams = serverParams;
        _install      = install;
        _secrets      = secrets;
        _audit        = audit;
    }

    /// <summary>Список узлов с фильтрами поиска, протокола и статуса.</summary>
    [HttpGet]
    [Authorize(Policy = AuthPolicies.PanelRead)]
    [ProducesResponseType(typeof(Paged<ServerListItemDto>), StatusCodes.Status200OK)]
    public async Task<IActionResult> GetAll(
        [FromQuery] string? search,
        [FromQuery] string? protocol,
        [FromQuery] string? status,
        [FromQuery] int? page,
        [FromQuery] int? pageSize,
        CancellationToken ct)
    {
        var result   = await _servers.SearchAsync(new ServerQuery(search, protocol, status, page, pageSize), ct);
        var keyCount = await _clients.CountActiveByServerAsync(ct);

        // Один запрос на всю страницу, а не по запросу на узел: суточных
        // срезов на 30 дней немного, и агрегация по ним дешевле N обращений.
        var (from, to) = KpiWindow();
        var traffic = await _usage.SumTrafficByServerAsync(from, to, ct);

        return Ok(result.Map(s => ServerListItemDto.From(
            s, keyCount.GetValueOrDefault(s.Id), traffic.GetValueOrDefault(s.Id))));
    }

    /// <summary>Детали узла: протоколы, SSH-доступ, здоровье, плитки KPI.</summary>
    [HttpGet("{id}")]
    [Authorize(Policy = AuthPolicies.PanelRead)]
    [ProducesResponseType(typeof(ServerDetailDto), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> GetById(string id, CancellationToken ct)
    {
        var server = await _servers.GetByIdAsync(id, ct)
            ?? throw new NotFoundException("Сервер не найден.");

        return Ok(ServerDetailDto.From(server, await BuildKpiAsync(server.Id, ct)));
    }

    /// <summary>Ключи, выданные на этом узле.</summary>
    [HttpGet("{id}/keys")]
    [Authorize(Policy = AuthPolicies.PanelRead)]
    [ProducesResponseType(typeof(Paged<KeyListItemDto>), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> GetKeys(
        string id,
        [FromQuery] int? page,
        [FromQuery] int? pageSize,
        CancellationToken ct)
    {
        var server = await _servers.GetByIdAsync(id, ct)
            ?? throw new NotFoundException("Сервер не найден.");

        var keys  = await _clients.SearchAsync(new KeyQuery(ServerId: id, Page: page, PageSize: pageSize), ct);
        var owners = await LoadOwnersAsync(keys.Items, ct);

        return Ok(keys.Map(k => KeyListItemDto.From(k, server.Name, owners.GetValueOrDefault(k.UserId))));
    }

    /// <summary>
    /// Добавляет узел и ставит установку в очередь.
    ///
    /// Отвечает 202: развёртывание занимает минуты, и держать запрос открытым
    /// всё это время нельзя. Ход установки панель смотрит через /api/jobs/{id}.
    /// </summary>
    [HttpPost("install")]
    [ProducesResponseType(typeof(JobAcceptedDto), StatusCodes.Status202Accepted)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> CreateAndInstall(
        [FromBody] CreateServerRequest req, CancellationToken ct)
    {
        var server = new VpnServer
        {
            Name     = req.Name,
            Host     = req.Host,
            Geo      = req.Geo,
            Provider = req.Provider,
            Note     = req.Note,
            KeyLimit = req.KeyLimit,
            Dns1     = req.Dns1,
            Dns2     = req.Dns2,
            // До окончания установки узел не готов выдавать ключи —
            // статус говорит об этом прямо, а не притворяется рабочим.
            Status   = ServerStatuses.Setup,
            Ssh = new SshCredentials
            {
                Port          = req.SshPort,
                User          = req.SshUser,
                AuthType      = string.IsNullOrEmpty(req.SshPrivateKey)
                    ? SshAuthTypes.Password
                    : SshAuthTypes.PrivateKey,
                Password      = _secrets.Protect(req.SshPassword),
                PrivateKey    = _secrets.Protect(req.SshPrivateKey),
                KeyPassphrase = _secrets.Protect(req.SshKeyPassphrase),
                KeyType       = DetectKeyType(req.SshPrivateKey),
            },
            CreatedByUserId = CurrentUserId,
        };

        if (server.Ssh.Password is null && server.Ssh.PrivateKey is null)
            throw new BadRequestException("Укажите пароль или приватный SSH-ключ.");

        EnsureDistinctSubnets(req);

        var created = await _servers.CreateAsync(server, ct);

        var job = await _install.EnqueueAsync(
            created.Id,
            InstallJobKinds.InstallServer,
            [.. req.Protocols.Select(p => p.ToSpec())],
            CurrentUserId,
            ct);

        await _audit.WriteAsync(AuditEvents.ServerInstallStarted,
            $"Запущена установка узла «{created.Name}» ({created.Host}): " +
            string.Join(", ", req.Protocols.Select(p => ProtocolKinds.DisplayName(p.Kind))),
            User, AuditTargets.Server, created.Id, created.Name, ct: ct);

        return Accepted(new JobAcceptedDto(created.Id, job.Id));
    }

    /// <summary>Проверяет доступность ещё не сохранённого узла.</summary>
    [HttpPost("test-connection")]
    [ProducesResponseType(typeof(ConnectionTestDto), StatusCodes.Status200OK)]
    public async Task<IActionResult> TestConnection(
        [FromBody] TestConnectionRequest req, CancellationToken ct)
    {
        var probe = new VpnServer
        {
            Host = req.Host,
            Ssh = new SshCredentials
            {
                Port          = req.SshPort,
                User          = req.SshUser,
                Password      = _secrets.Protect(req.SshPassword),
                PrivateKey    = _secrets.Protect(req.SshPrivateKey),
                KeyPassphrase = _secrets.Protect(req.SshKeyPassphrase),
            },
        };

        var result = await _install.TestConnectionAsync(probe, req.Ports, ct);
        return Ok(ConnectionTestDto.From(result));
    }

    /// <summary>Проверяет доступность уже сохранённого узла.</summary>
    [HttpPost("{id}/test-connection")]
    [ProducesResponseType(typeof(ConnectionTestDto), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> TestConnectionById(string id, CancellationToken ct)
    {
        var server = await _servers.GetByIdAsync(id, ct)
            ?? throw new NotFoundException("Сервер не найден.");

        var ports = server.Protocols.Select(p => p.Port).ToList();
        var result = await _install.TestConnectionAsync(server, ports, ct);

        return Ok(ConnectionTestDto.From(result));
    }

    // ── Протоколы ─────────────────────────────────────────────────────────────

    /// <summary>Добавляет протокол на существующий узел.</summary>
    [HttpPost("{id}/protocols")]
    [ProducesResponseType(typeof(JobAcceptedDto), StatusCodes.Status202Accepted)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> AddProtocol(
        string id, [FromBody] ProtocolSpecRequest req, CancellationToken ct)
    {
        var server = await _servers.GetByIdAsync(id, ct)
            ?? throw new NotFoundException("Сервер не найден.");

        var job = await _install.EnqueueAsync(
            id, InstallJobKinds.AddProtocol, [req.ToSpec()], CurrentUserId, ct);

        await _audit.WriteAsync(AuditEvents.ProtocolAdded,
            $"Добавление протокола {ProtocolKinds.DisplayName(req.Kind)} на узел «{server.Name}»",
            User, AuditTargets.Server, id, server.Name, ct: ct);

        return Accepted(new JobAcceptedDto(id, job.Id));
    }

    /// <summary>Удаляет протокол с узла вместе с контейнером.</summary>
    [HttpDelete("{id}/protocols/{protocolId}")]
    [ProducesResponseType(typeof(JobAcceptedDto), StatusCodes.Status202Accepted)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> RemoveProtocol(
        string id, string protocolId, CancellationToken ct)
    {
        var server = await _servers.GetByIdAsync(id, ct)
            ?? throw new NotFoundException("Сервер не найден.");

        var protocol = server.FindProtocol(protocolId)
            ?? throw new NotFoundException("Протокол на этом узле не найден.");

        var activeKeys = await _clients.SearchAsync(
            new KeyQuery(ServerId: id, Status: KeyStatuses.Active, PageSize: 1), ct);

        if (activeKeys.Total > 0)
        {
            throw new BadRequestException(
                $"На узле есть активные ключи ({activeKeys.Total}). " +
                "Отзовите их перед удалением протокола, иначе клиенты потеряют доступ без объяснения.");
        }

        var job = await _install.EnqueueAsync(
            id, InstallJobKinds.RemoveProtocol,
            [new ProtocolSpec { Kind = protocol.Kind, ProtocolId = protocolId }],
            CurrentUserId, ct);

        await _audit.WriteAsync(AuditEvents.ProtocolRemoved,
            $"Удаление протокола {protocol.DisplayNameOrKind()} с узла «{server.Name}»",
            User, AuditTargets.Server, id, server.Name, AuditLevels.Warn, ct: ct);

        return Accepted(new JobAcceptedDto(id, job.Id));
    }

    /// <summary>Добавить узел, уже настроенный вручную, без установки.</summary>
    [HttpPost]
    [ProducesResponseType(typeof(ServerDetailDto), StatusCodes.Status201Created)]
    public async Task<IActionResult> Create([FromBody] ServerConfigRequest req, CancellationToken ct)
    {
        var protocol = BuildWgProtocol(req);

        var server = new VpnServer
        {
            Name     = req.Description,
            Host     = req.Host,
            Geo      = req.Geo,
            Provider = req.Provider,
            Note     = req.Note,
            KeyLimit = req.KeyLimit,
            Ssh = new SshCredentials
            {
                Port           = req.SshPort,
                User           = req.SshUser,
                AuthType       = string.IsNullOrEmpty(req.SshPrivateKeyPath)
                    ? SshAuthTypes.Password
                    : SshAuthTypes.PrivateKey,
                Password       = _secrets.Protect(req.SshPassword),
                PrivateKeyPath = req.SshPrivateKeyPath
            },
            Protocols         = [protocol],
            DefaultProtocolId = protocol.Id,
            CreatedByUserId   = User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value
        };

        var created = await _servers.CreateAsync(server, ct);

        await _audit.WriteAsync(AuditEvents.ServerCreated,
            $"Добавлен узел «{created.Name}» ({created.Host})",
            User, AuditTargets.Server, created.Id, created.Name, ct: ct);

        return CreatedAtAction(nameof(GetById), new { id = created.Id },
            ServerDetailDto.From(created, new ServerKpiDto(null, 0, 0)));
    }

    /// <summary>
    /// Частичное обновление: применяются только переданные поля.
    /// Параметры протоколов правятся отдельными маршрутами (фаза 4).
    /// </summary>
    [HttpPut("{id}")]
    [ProducesResponseType(typeof(ServerDetailDto), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> Update(string id, [FromBody] ServerPatchRequest req, CancellationToken ct)
    {
        var server = await _servers.GetByIdAsync(id, ct)
            ?? throw new NotFoundException("Сервер не найден.");

        if (req.Host is not null)     server.Host     = req.Host;
        if (req.Name is not null)     server.Name     = req.Name;
        if (req.Geo is not null)      server.Geo      = req.Geo;
        if (req.Provider is not null) server.Provider = req.Provider;
        if (req.Note is not null)     server.Note     = req.Note;
        if (req.KeyLimit is not null) server.KeyLimit = req.KeyLimit;
        if (req.Dns1 is not null)     server.Dns1     = req.Dns1;
        if (req.Dns2 is not null)     server.Dns2     = req.Dns2;

        if (req.SshPort is not null) server.Ssh.Port = req.SshPort.Value;
        if (req.SshUser is not null) server.Ssh.User = req.SshUser;

        if (!string.IsNullOrEmpty(req.SshPassword))
        {
            server.Ssh.Password = _secrets.Protect(req.SshPassword);
            server.Ssh.AuthType = SshAuthTypes.Password;
        }

        if (req.SshPrivateKeyPath is not null)
        {
            server.Ssh.PrivateKeyPath = req.SshPrivateKeyPath;
            server.Ssh.AuthType       = SshAuthTypes.PrivateKey;
        }

        await _servers.UpdateAsync(server, ct);

        await _audit.WriteAsync(AuditEvents.ServerUpdated,
            $"Изменены параметры узла «{server.Name}»",
            User, AuditTargets.Server, server.Id, server.Name, ct: ct);

        return Ok(ServerDetailDto.From(server, await BuildKpiAsync(server.Id, ct)));
    }

    [HttpDelete("{id}")]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> Delete(string id, CancellationToken ct)
    {
        var server = await _servers.GetByIdAsync(id, ct)
            ?? throw new NotFoundException("Сервер не найден.");

        // DELETE only removes the panel record. Keep it limited to a failed
        // install until a teardown job can remove remote containers safely.
        if (server.Status != ServerStatuses.Error)
            throw new BadRequestException(
                "Удалить можно только запись узла с ошибкой установки. " +
                "Рабочие и устанавливаемые узлы остаются в панели.");

        var activeKeys = await _clients.SearchAsync(
            new KeyQuery(ServerId: id, Status: KeyStatuses.Active, PageSize: 1), ct);
        if (activeKeys.Total > 0)
            throw new BadRequestException(
                $"На узле есть активные ключи ({activeKeys.Total}). " +
                "Сначала отзовите их, затем повторите удаление.");

        await _servers.DeleteAsync(id, ct);

        // Удаление контейнеров и отзыв ключей появятся в фазе 4 — пока
        // предупреждаем оператора записью в журнал.
        await _audit.WriteAsync(AuditEvents.ServerDeleted,
            $"Удалён узел «{server.Name}» ({server.Host}). Контейнеры на самом узле не тронуты.",
            User, AuditTargets.Server, id, server.Name, AuditLevels.Warn, ct: ct);

        return NoContent();
    }

    /// <summary>Принудительно перечитать параметры протокола с узла по SSH.</summary>
    [HttpPost("{id}/refresh")]
    [HttpPost("{id}/refresh-cache")]
    [ProducesResponseType(typeof(ServerDetailDto), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    [ProducesResponseType(StatusCodes.Status502BadGateway)]
    public async Task<IActionResult> Refresh(string id, CancellationToken ct)
    {
        // Ошибки SSH превращает в ProblemDetails GlobalExceptionHandler:
        // текст команды содержит ключи и в ответ уходить не должен.
        // Кеш сбрасывается только после успешного чтения — см. ServerParamsService.
        var refreshed = await _serverParams.RefreshAsync(id, ct);

        await _audit.WriteAsync(AuditEvents.ServerCacheRefresh,
            $"Перечитаны параметры узла «{refreshed.Name}»",
            User, AuditTargets.Server, id, refreshed.Name, ct: ct);

        return Ok(ServerDetailDto.From(refreshed, await BuildKpiAsync(id, ct)));
    }

    // ── Вспомогательное ───────────────────────────────────────────────────────

    private string? CurrentUserId
        => User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;

    /// <summary>Плитки экрана узла: аптайм и трафик за окно KPI, активные ключи — на сейчас.</summary>
    private async Task<ServerKpiDto> BuildKpiAsync(string serverId, CancellationToken ct)
    {
        var (from, to) = KpiWindow();

        var keyCount = await _clients.CountActiveByServerAsync(ct);
        var uptime   = await _usage.GetUptimePercentAsync(serverId, from, to, ct);
        var traffic  = await _usage.SumServerTrafficAsync(serverId, from, to, ct);

        return new ServerKpiDto(uptime, keyCount.GetValueOrDefault(serverId), traffic);
    }

    private static (DateOnly From, DateOnly To) KpiWindow()
    {
        var today = DateOnly.FromDateTime(DateTime.UtcNow);
        return (today.AddDays(-(KpiWindowDays - 1)), today);
    }

    /// <summary>
    /// Два wg-контейнера на одном узле не могут делить подсеть: NAT и правила
    /// маршрутизации начнут конфликтовать, и оба протокола станут нерабочими.
    /// В upstream это не всплывает, потому что он ставит по одному протоколу.
    /// </summary>
    private static void EnsureDistinctSubnets(CreateServerRequest req)
    {
        var subnets = req.Protocols
            .Where(p => ProtocolKinds.IsWireGuardFamily(p.Kind))
            .Select(p => p.SubnetAddress ?? "10.8.1.0")
            .ToList();

        var duplicates = subnets.GroupBy(s => s).Where(g => g.Count() > 1).Select(g => g.Key).ToList();

        if (duplicates.Count > 0)
        {
            throw new BadRequestException(
                $"Несколько протоколов используют одну подсеть ({string.Join(", ", duplicates)}). " +
                "Задайте разные, например 10.8.1.0 и 10.8.2.0.");
        }
    }

    /// <summary>Тип ключа для строки «•••• ed25519» в панели.</summary>
    private static string? DetectKeyType(string? pem)
    {
        if (string.IsNullOrWhiteSpace(pem)) return null;

        if (pem.Contains("BEGIN OPENSSH PRIVATE KEY", StringComparison.Ordinal)) return "ed25519";
        if (pem.Contains("BEGIN RSA PRIVATE KEY", StringComparison.Ordinal)) return "rsa";
        if (pem.Contains("BEGIN EC PRIVATE KEY", StringComparison.Ordinal)) return "ecdsa";
        return "unknown";
    }

    private static ProtocolInstance BuildWgProtocol(ServerConfigRequest req) => new()
    {
        Kind           = string.Equals(req.WgBin, "awg", StringComparison.OrdinalIgnoreCase)
            ? ProtocolKinds.Awg2
            : ProtocolKinds.AwgLegacy,
        ContainerName  = req.ContainerName,
        Port           = req.AwgPort,
        TransportProto = "udp",
        State          = ProtocolStates.Installed,
        InstalledAt    = DateTime.UtcNow,
        Wg = new WgProtocolParams
        {
            InterfaceName    = req.AwgInterface,
            Binary           = req.WgBin,
            ServerConfigPath = req.AwgConfigPath,
            ServerPubKeyPath = req.ServerPublicKeyPath,
            PskKeyPath       = req.PskKeyPath,
            SubnetAddress    = req.SubnetAddress,
            SubnetCidr       = req.SubnetCidr
        }
    };

    /// <summary>Имена владельцев для колонки «Владелец», одним запросом на страницу.</summary>
    private async Task<Dictionary<string, string>> LoadOwnersAsync(
        IReadOnlyList<VpnClient> keys, CancellationToken ct)
    {
        var users = await _users.GetByIdsAsync(keys.Select(k => k.UserId), ct);
        return users.ToDictionary(u => u.Id, u => u.DisplayName ?? u.Username);
    }
}
