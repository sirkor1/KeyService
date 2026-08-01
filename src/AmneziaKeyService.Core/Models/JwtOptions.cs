namespace AmneziaKeyService.Core.Models;

public class JwtOptions
{
    public string Secret { get; set; } = default!;
    public string Issuer { get; set; } = "AmneziaKeyService";
    public string Audience { get; set; } = "AmneziaKeyService";
    // Bearer tokens used by existing VPN/API clients.
    public int ExpiryMinutes { get; set; } = 60;
    // Panel tokens are short-lived and always tied to a server-side session.
    public int PanelAccessExpiryMinutes { get; set; } = 15;
    public int RefreshTokenDays { get; set; } = 30;
}
