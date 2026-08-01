using AmneziaKeyService.Core.Models;

namespace AmneziaKeyService.Core.DTOs.Panel;

/// <summary>Строка таблицы «Активные серверы».</summary>
public record ServerListItemDto(
    string Id,
    string Name,
    string Host,
    string? Geo,
    string? Provider,
    int SshPort,
    string SshAuthType,
    IReadOnlyList<ProtocolSummaryDto> Protocols,
    long KeysCount,
    double? LoadPercent,
    long TrafficBytes,
    string Status)
{
    public static ServerListItemDto From(VpnServer server, long keysCount, long trafficBytes) => new(
        server.Id,
        server.Name,
        server.Host,
        server.Geo,
        server.Provider,
        server.Ssh.Port,
        server.Ssh.AuthType,
        [.. server.Protocols.Select(ProtocolSummaryDto.From)],
        keysCount,
        server.Health?.LoadPercent,
        trafficBytes,
        server.Status);
}

/// <summary>Протокол в свёрнутом виде — колонка «Протоколы».</summary>
public record ProtocolSummaryDto(string Id, string Kind, string DisplayName, string Port, string State)
{
    public static ProtocolSummaryDto From(ProtocolInstance p) => new(
        p.Id, p.Kind, ProtocolKinds.DisplayName(p.Kind), p.Port, p.State);
}

/// <summary>Экран деталей узла.</summary>
public record ServerDetailDto(
    string Id,
    string Name,
    string Host,
    string? Geo,
    string? Provider,
    string? Note,
    int? KeyLimit,
    string Status,
    string Dns1,
    string Dns2,
    SshInfoDto Ssh,
    IReadOnlyList<ProtocolDetailDto> Protocols,
    string? DefaultProtocolId,
    ServerHealthDto? Health,
    ServerKpiDto Kpi,
    int OrphanPeerCount,
    DateTime? ReconciledAt,
    DateTime CreatedAt,
    DateTime? UpdatedAt)
{
    public static ServerDetailDto From(VpnServer s, ServerKpiDto kpi) => new(
        s.Id, s.Name, s.Host, s.Geo, s.Provider, s.Note, s.KeyLimit, s.Status,
        s.Dns1, s.Dns2,
        SshInfoDto.From(s.Ssh),
        [.. s.Protocols.Select(ProtocolDetailDto.From)],
        s.DefaultProtocolId,
        s.Health is null ? null : ServerHealthDto.From(s.Health),
        kpi,
        s.OrphanPeerCount, s.ReconciledAt,
        s.CreatedAt, s.UpdatedAt);
}

/// <summary>
/// SSH-доступ для отображения. Пароль и приватный ключ наружу не отдаются
/// ни в каком виде — только признак их наличия.
/// </summary>
public record SshInfoDto(
    int Port,
    string User,
    string AuthType,
    bool HasPassword,
    bool HasPrivateKey,
    string? KeyType,
    string? HostFingerprint)
{
    public static SshInfoDto From(SshCredentials ssh) => new(
        ssh.Port,
        ssh.User,
        ssh.AuthType,
        ssh.Password is not null,
        ssh.PrivateKey is not null || !string.IsNullOrEmpty(ssh.PrivateKeyPath),
        ssh.KeyType,
        ssh.HostFingerprint);
}

/// <summary>Карточка протокола на экране узла.</summary>
public record ProtocolDetailDto(
    string Id,
    string Kind,
    string DisplayName,
    string ContainerName,
    string? ContainerVersion,
    bool Enabled,
    string State,
    string Port,
    string TransportProto,
    string? Mtu,
    bool IsCached,
    WgInfoDto? Wg,
    XrayInfoDto? Xray,
    DateTime? InstalledAt,
    DateTime? LastSyncedAt)
{
    public static ProtocolDetailDto From(ProtocolInstance p) => new(
        p.Id,
        p.Kind,
        ProtocolKinds.DisplayName(p.Kind),
        p.ContainerName,
        p.ContainerVersion,
        p.Enabled,
        p.State,
        p.Port,
        p.TransportProto,
        p.Mtu,
        p.Wg?.IsCached ?? p.Xray?.IsCached ?? false,
        p.Wg is null ? null : WgInfoDto.From(p.Wg),
        p.Xray is null ? null : XrayInfoDto.From(p.Xray),
        p.InstalledAt,
        p.LastSyncedAt);
}

/// <summary>Параметры WireGuard. Приватные ключи и PSK не отдаются.</summary>
public record WgInfoDto(
    string InterfaceName,
    string Binary,
    string SubnetAddress,
    string SubnetCidr,
    string? LastKnownPeerIp,
    ObfuscationDto? Obfuscation)
{
    public static WgInfoDto From(WgProtocolParams wg) => new(
        wg.InterfaceName, wg.Binary, wg.SubnetAddress, wg.SubnetCidr, wg.LastKnownPeerIp,
        wg.Obfuscation is null ? null : ObfuscationDto.From(wg.Obfuscation));
}

/// <summary>Параметры обфускации — строка «Jc 4, Jmin 40, Jmax 70» в карточке.</summary>
public record ObfuscationDto(string Jc, string Jmin, string Jmax, string Mtu)
{
    public static ObfuscationDto From(AwgObfuscationParams o) => new(o.Jc, o.Jmin, o.Jmax, o.Mtu);
}

/// <summary>Параметры Xray. Приватный ключ Reality сервер не покидает.</summary>
public record XrayInfoDto(string SiteName, string? PublicKey, string? ShortId)
{
    public static XrayInfoDto From(XrayProtocolParams x) => new(x.SiteName, x.PublicKey, x.ShortId);
}

public record ServerHealthDto(
    DateTime? LastCheckAt,
    bool Online,
    DateTime? UptimeSince,
    double? LoadPercent,
    double? MemPercent,
    double? DiskPercent,
    string? DockerVersion,
    string? Kernel)
{
    public static ServerHealthDto From(ServerHealth h) => new(
        h.LastCheckAt, h.Online, h.UptimeSince, h.LoadPercent, h.MemPercent, h.DiskPercent,
        h.DockerVersion, h.Kernel);
}

/// <summary>
/// Три плитки на экране узла. Трафик — за последние 30 дней по суточным срезам.
/// Uptime30dPercent равен null, пока по узлу не было ни одной проверки:
/// «нет данных» и «ноль процентов доступности» рисуются по-разному.
/// </summary>
public record ServerKpiDto(double? Uptime30dPercent, long KeysActive, long TrafficBytes);
