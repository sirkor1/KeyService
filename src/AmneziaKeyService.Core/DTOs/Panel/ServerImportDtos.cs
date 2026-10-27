using System.ComponentModel.DataAnnotations;

namespace AmneziaKeyService.Core.DTOs.Panel;

public class DiscoverServerRequest
{
    [Required, StringLength(253)] public string Host { get; set; } = "";
    [Range(1, 65535)] public int SshPort { get; set; } = 22;
    [Required, StringLength(64)] public string SshUser { get; set; } = "root";
    public string? SshPassword { get; set; }
    public string? SshPrivateKey { get; set; }
    public string? SshKeyPassphrase { get; set; }
}

public class ImportServerRequest : DiscoverServerRequest
{
    [Required, StringLength(128)] public string Name { get; set; } = "";
    [StringLength(256)] public string? Geo { get; set; }
    [StringLength(256)] public string? Provider { get; set; }
    [StringLength(2000)] public string? Note { get; set; }
    [Range(1, int.MaxValue)] public int? KeyLimit { get; set; }
    [Required, RegularExpression("^[A-F0-9]{64}$")] public string Revision { get; set; } = "";
    [Required, MinLength(1), MaxLength(4)] public List<string> Containers { get; set; } = [];
}

// Deliberately contains neither ProtocolInstance nor raw configuration/SSH secrets.
public record DiscoveredProtocolDto(string Kind, string DisplayName, string ContainerName,
    string? Port, string? Subnet, int PeerCount, bool CanImport, string? Error);

public record ServerDiscoveryDto(string Revision, IReadOnlyList<DiscoveredProtocolDto> Protocols,
    IReadOnlyList<string> Warnings);
