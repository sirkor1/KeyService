using System.Reflection;
using AmneziaKeyService.Core.DTOs.Panel;
using AmneziaKeyService.Core.Interfaces;
using AmneziaKeyService.Core.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace AmneziaKeyService.Api.Controllers;

[ApiController]
[Route("api/dashboard")]
[Authorize(Policy = AuthPolicies.PanelRead)]
public class DashboardController : ControllerBase
{
    private static readonly TimeSpan ExpiringWindow = TimeSpan.FromDays(7);

    private readonly IVpnServerRepository _servers;
    private readonly IVpnClientRepository _clients;
    private readonly IUserRepository _users;
    private readonly IAuditLogRepository _audit;
    private readonly IUsageRepository _usage;

    public DashboardController(
        IVpnServerRepository servers,
        IVpnClientRepository clients,
        IUserRepository users,
        IAuditLogRepository audit,
        IUsageRepository usage)
    {
        _servers = servers;
        _clients = clients;
        _users   = users;
        _audit   = audit;
        _usage   = usage;
    }

    /// <summary>Сводка для шапки, плиток KPI и бейджей меню.</summary>
    [HttpGet("summary")]
    [ProducesResponseType(typeof(DashboardSummaryDto), StatusCodes.Status200OK)]
    public async Task<IActionResult> GetSummary(CancellationToken ct)
    {
        var serversByStatus = await _servers.CountByStatusAsync(ct);
        var keysByStatus    = await _clients.CountByStatusAsync(ct);
        var usersTotal      = await _users.CountAsync(ct);
        var expiringSoon    = await _clients.CountExpiringSoonAsync(ExpiringWindow, ct);
        var errorsToday     = await _audit.CountByLevelAsync(AuditLevels.Error, TimeSpan.FromDays(1), ct);

        var serversTotal = (int)serversByStatus.Values.Sum();
        var serversOk    = (int)serversByStatus.GetValueOrDefault(ServerStatuses.Ok);
        var keysActive   = keysByStatus.GetValueOrDefault(KeyStatuses.Active);
        var keysTotal    = keysByStatus.Values.Sum();

        var allServers = await _servers.GetAllAsync(ct);

        // Именно календарный месяц, а не последние 30 дней: плитка называется
        // «Трафик за месяц», и оператор сверяет её с месячным лимитом провайдера.
        var today        = DateOnly.FromDateTime(DateTime.UtcNow);
        var monthStart   = new DateOnly(today.Year, today.Month, 1);
        var trafficMonth = await _usage.SumTotalTrafficAsync(monthStart, today, ct);

        var attention = BuildAttention(serversByStatus, allServers, expiringSoon);

        return Ok(new DashboardSummaryDto(
            ServersOk:   serversOk,
            ServersTotal: serversTotal,
            KeysActive:  keysActive,
            KeysTotal:   keysTotal,
            TrafficMonthBytes: trafficMonth,
            Attention:   attention,
            NavBadges:   new NavBadgesDto(serversTotal, keysActive, usersTotal, errorsToday),
            LastSyncAt:  allServers.Max(s => s.Health?.LastCheckAt ?? s.UpdatedAt),
            AppVersion:  Assembly.GetExecutingAssembly().GetName().Version?.ToString() ?? "dev"));
    }

    private static AttentionDto BuildAttention(
        Dictionary<string, long> serversByStatus,
        List<VpnServer> allServers,
        long expiringSoon)
    {
        var items = new List<AttentionItemDto>();

        var offline = serversByStatus.GetValueOrDefault(ServerStatuses.Offline);
        if (offline > 0)
            items.Add(new AttentionItemDto("server_offline", "Узлы недоступны", offline));

        var errored = serversByStatus.GetValueOrDefault(ServerStatuses.Error);
        if (errored > 0)
            items.Add(new AttentionItemDto("server_error", "Узлы с ошибкой", errored));

        // Узел без вычитанных параметров не может выдать ни одного ключа —
        // это отдельный повод для внимания, а не разновидность offline.
        var uncached = allServers.Count(s =>
            s.Protocols.Any(p => p.Wg is { IsCached: false } || p.Xray is { IsCached: false }));
        if (uncached > 0)
            items.Add(new AttentionItemDto("server_uncached", "Параметры узла не вычитаны", uncached));

        if (expiringSoon > 0)
            items.Add(new AttentionItemDto("keys_expiring", "Ключи истекают в ближайшую неделю", expiringSoon));

        // Считаем сами peer-ы, а не узлы с расхождением: оператору важно,
        // скольким доступам нет объяснения, а не на скольких машинах это нашлось.
        var orphans = allServers.Sum(s => s.OrphanPeerCount);
        if (orphans > 0)
            items.Add(new AttentionItemDto("peers_orphan", "Peer-ы без выданного ключа", orphans));

        return new AttentionDto((int)items.Sum(i => i.Count), items);
    }
}
