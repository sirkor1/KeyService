using AmneziaKeyService.Core.Exceptions;
using AmneziaKeyService.Core.Interfaces;
using AmneziaKeyService.Core.Models;

namespace AmneziaKeyService.Infrastructure.Services;

public class ServerParamsService : IServerParamsService
{
    private readonly IVpnServerRepository _servers;
    private readonly IProtocolRegistry _protocols;
    private readonly ISshSessionFactory _sshFactory;

    public ServerParamsService(
        IVpnServerRepository servers,
        IProtocolRegistry protocols,
        ISshSessionFactory sshFactory)
    {
        _servers    = servers;
        _protocols  = protocols;
        _sshFactory = sshFactory;
    }

    public Task<VpnServer> EnsureCachedAsync(string serverId, CancellationToken ct = default)
        => ReadAsync(serverId, force: false, ct);

    public Task<VpnServer> RefreshAsync(string serverId, CancellationToken ct = default)
        => ReadAsync(serverId, force: true, ct);

    private async Task<VpnServer> ReadAsync(string serverId, bool force, CancellationToken ct)
    {
        var server = await _servers.GetByIdAsync(serverId, ct)
            ?? throw new NotFoundException($"Сервер '{serverId}' не найден.");

        var pending = server.Protocols
            .Where(p => force || !IsCached(p))
            .Where(p => _protocols.IsSupported(p.Kind))
            .ToList();

        if (pending.Count == 0) return server;

        await using var ssh = await _sshFactory.ConnectAsync(server, ct);

        var changed = false;
        foreach (var protocol in pending)
        {
            if (force) ResetCache(protocol);

            var configurator = _protocols.GetConfigurator(protocol.Kind);
            changed |= await configurator.EnsureServerParamsAsync(ssh, server, protocol, ct);
        }

        if (changed)
        {
            server.Status = ServerStatuses.Ok;
            await _servers.UpdateAsync(server, ct);
        }

        return server;
    }

    private static bool IsCached(ProtocolInstance protocol)
        => protocol.Wg?.IsCached ?? protocol.Xray?.IsCached ?? false;

    /// <summary>
    /// Сбрасывает кеш в памяти, не трогая документ: если чтение с узла упадёт,
    /// сохранённые значения останутся нетронутыми и узел продолжит работать.
    /// </summary>
    private static void ResetCache(ProtocolInstance protocol)
    {
        if (protocol.Wg is { } wg)
        {
            wg.ServerPubKey = null;
            wg.PskKey       = null;
            wg.Obfuscation  = null;
        }

        if (protocol.Xray is { } xray)
        {
            xray.PublicKey = null;
            xray.ShortId   = null;
        }
    }
}
