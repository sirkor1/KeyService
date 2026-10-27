using AmneziaKeyService.Core.DTOs.Panel;
using AmneziaKeyService.Core.Exceptions;
using AmneziaKeyService.Core.Interfaces;
using AmneziaKeyService.Core.Models;
using AmneziaKeyService.Infrastructure.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace AmneziaKeyService.Api.Controllers;

[ApiController]
[Route("api/servers")]
[Authorize(Policy = AuthPolicies.PanelAdmin)]
public class ServerImportController(ServerImportService imports, IAuditService audit) : ControllerBase
{
    [HttpPost("discover")]
    [ProducesResponseType(typeof(ServerDiscoveryDto), StatusCodes.Status200OK)]
    public Task<ServerDiscoveryDto> Discover(DiscoverServerRequest request, CancellationToken ct)
        => WithTimeout(token => imports.DiscoverAsync(request, token), ct);

    [HttpPost("import")]
    [ProducesResponseType(typeof(ServerDetailDto), StatusCodes.Status201Created)]
    public async Task<IActionResult> Import(ImportServerRequest request, CancellationToken ct)
    {
        var server = await WithTimeout(token => imports.ImportAsync(request,
            User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value, token), ct);
        await audit.WriteAsync("server.imported", $"Подключён настроенный узел «{server.Name}»: " +
            string.Join(", ", server.Protocols.Select(p => ProtocolKinds.DisplayName(p.Kind))),
            User, AuditTargets.Server, server.Id, server.Name, ct: ct);
        return Created($"/api/servers/{server.Id}", ServerDetailDto.From(server, new(null, 0, 0)));
    }

    private static async Task<T> WithTimeout<T>(Func<CancellationToken, Task<T>> action, CancellationToken ct)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(TimeSpan.FromSeconds(45));
        try { return await action(timeout.Token); }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        { throw new BadRequestException("Проверка узла заняла слишком много времени. Проверьте SSH-доступ и повторите поиск."); }
    }
}
