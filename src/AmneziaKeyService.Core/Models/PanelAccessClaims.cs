using System.Security.Claims;

namespace AmneziaKeyService.Core.Models;

/// <summary>JWT claim extraction resilient to JwtBearer inbound-claim mapping.</summary>
public static class PanelAccessClaims
{
    public static string? FindUserId(ClaimsPrincipal principal) =>
        principal.FindFirst(ClaimTypes.NameIdentifier)?.Value
        ?? principal.FindFirst("sub")?.Value;

    public static string? FindRole(ClaimsPrincipal principal) =>
        principal.FindFirst(ClaimTypes.Role)?.Value
        ?? principal.FindFirst("role")?.Value;
}
