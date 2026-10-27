using System.ComponentModel.DataAnnotations;
using System.Security.Claims;
using AmneziaKeyService.Core.DTOs.Panel;
using AmneziaKeyService.Core.Models;
using AmneziaKeyService.Infrastructure.Install;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace AmneziaKeyService.Api.Controllers;

[ApiController]
[Route("api/servers")]
[Authorize(Policy = AuthPolicies.PanelAdmin)]
public class ServerMaintenanceController(ServerMaintenanceService maintenance) : ControllerBase
{
    [HttpPost("{id}/cleanup")]
    public Task<IActionResult> Cleanup(string id, ServerMaintenanceRequest request, CancellationToken ct)
        => Enqueue(id, InstallJobKinds.CleanupServer, request, ct);

    [HttpDelete("{id}")]
    public Task<IActionResult> Delete(string id, ServerMaintenanceRequest request, CancellationToken ct)
        => Enqueue(id, InstallJobKinds.DeleteServer, request, ct);

    private async Task<IActionResult> Enqueue(string id, string kind, ServerMaintenanceRequest request, CancellationToken ct)
    {
        var job = await maintenance.EnqueueAsync(id, kind, request.ConfirmationName,
            User.FindFirst(ClaimTypes.NameIdentifier)?.Value, ct);
        return Accepted(new JobAcceptedDto(id, job.Id));
    }
}

public record ServerMaintenanceRequest([Required] string ConfirmationName);
