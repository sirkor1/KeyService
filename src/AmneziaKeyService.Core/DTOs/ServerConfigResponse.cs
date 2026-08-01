namespace AmneziaKeyService.Core.DTOs;

/// <summary>
/// Текущая конфигурация сервера (без паролей и приватных ключей).
/// </summary>
public class ServerConfigResponse
{
    public string Id { get; set; } = default!;
    public string Host { get; set; } = default!;
    public int SshPort { get; set; }
    public string SshUser { get; set; } = default!;
    public bool HasPassword { get; set; }
    public bool HasPrivateKey { get; set; }
    public string AwgPort { get; set; } = default!;
    public string ContainerName { get; set; } = default!;
    public string AwgInterface { get; set; } = default!;
    public string SubnetAddress { get; set; } = default!;
    public string SubnetCidr { get; set; } = default!;

    /// <summary>Закэшированы ли уже параметры сервера (serverPubKey, obfuscation).</summary>
    public bool IsCached { get; set; }
    public DateTime? CachedAt { get; set; }
}
