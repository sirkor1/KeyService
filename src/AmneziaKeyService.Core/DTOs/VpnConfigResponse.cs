namespace AmneziaKeyService.Core.DTOs;

/// <summary>
/// Ответ с готовым vpn://-URI для импорта в AmneziaVPN.
/// </summary>
public record VpnConfigResponse(
    /// <summary>vpn://&lt;base64url&gt; — вставляется в AmneziaVPN или сканируется QR.</summary>
    string VpnUri,

    /// <summary>Назначенный туннельный IP клиента.</summary>
    string ClientIp,

    /// <summary>Публичный ключ клиента (для справки).</summary>
    string ClientPubKey
);
