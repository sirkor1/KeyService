using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using AmneziaKeyService.Core.DTOs.Panel;
using AmneziaKeyService.Core.Exceptions;
using AmneziaKeyService.Core.Interfaces;
using AmneziaKeyService.Core.Models;
using AmneziaKeyService.Infrastructure.Protocols;
using MongoDB.Driver;
using Org.BouncyCastle.Crypto.Parameters;

namespace AmneziaKeyService.Infrastructure.Services;

/// <summary>Adopts existing WG-family containers. Every remote operation is read-only.</summary>
public class ServerImportService(ISshSessionFactory sshFactory, ISecretProtector secrets,
    IVpnServerRepository servers)
{
    private static readonly WireGuardInstallProfile[] Profiles =
        [WireGuardInstallProfile.Awg3, WireGuardInstallProfile.Awg2,
         WireGuardInstallProfile.WireGuard, WireGuardInstallProfile.AwgLegacy];

    public async Task<ServerDiscoveryDto> DiscoverAsync(DiscoverServerRequest request, CancellationToken ct)
        => (await ProbeAsync(BuildServer(request), ct)).Preview;

    public async Task<VpnServer> ImportAsync(ImportServerRequest request, string? actor, CancellationToken ct)
    {
        var server = BuildServer(request);
        if (string.IsNullOrWhiteSpace(request.Name) || request.KeyLimit is <= 0)
            throw new BadRequestException("Укажите имя сервера и положительный лимит ключей.");
        if (request.Containers is null || request.Containers.Count == 0 ||
            request.Containers.Distinct(StringComparer.Ordinal).Count() != request.Containers.Count ||
            request.Containers.Any(c => !Profiles.Any(p => p.ContainerName == c)))
            throw new BadRequestException("Выберите найденные протоколы без повторов.");

        // Never trust client-supplied ports, paths, kinds or cached secrets. Re-read the node.
        var probe = await ProbeAsync(server, ct);
        if (request.Revision != probe.Preview.Revision)
            throw new BadRequestException("Конфигурация узла изменилась. Повторите поиск протоколов.");
        foreach (var container in request.Containers)
        {
            var found = probe.Protocols.SingleOrDefault(p => p.Protocol.ContainerName == container);
            if (found is null)
                throw new BadRequestException("Выбранный протокол недоступен для подключения. Повторите поиск.");
            server.Protocols.Add(found.Protocol);
            server.OrphanPeerCount += found.Peers;
        }
        server.Name = request.Name.Trim();
        server.Geo = request.Geo;
        server.Provider = request.Provider;
        server.Note = request.Note;
        server.KeyLimit = request.KeyLimit;
        server.DefaultProtocolId = server.Protocols[0].Id;
        server.CreatedByUserId = actor;
        server.ReconciledAt = DateTime.UtcNow;
        // The unique _id makes simultaneous imports of this endpoint atomic without a
        // new index on existing installations. Also check older, randomly assigned IDs.
        server.Id = Hash($"server-import\n{server.Host}\n{server.Ssh.Port}")[..24].ToLowerInvariant();
        await EnsureNotRegisteredAsync(server, ct);
        try { return await servers.CreateAsync(server, ct); }
        catch (MongoWriteException ex) when (ex.WriteError.Category == ServerErrorCategory.DuplicateKey)
        { throw new BadRequestException("Этот сервер уже добавлен в панель. Обновите список серверов."); }
    }

    private VpnServer BuildServer(DiscoverServerRequest request)
    {
        var host = NormalizeHost(request.Host);
        if (Uri.CheckHostName(host) == UriHostNameType.Unknown || request.SshPort is < 1 or > 65535 ||
            string.IsNullOrWhiteSpace(request.SshUser))
            throw new BadRequestException("Проверьте адрес сервера, SSH-порт и пользователя.");
        var hasPassword = !string.IsNullOrEmpty(request.SshPassword);
        var hasKey = !string.IsNullOrWhiteSpace(request.SshPrivateKey);
        if (hasPassword == hasKey)
            throw new BadRequestException("Укажите либо пароль SSH, либо приватный ключ.");
        return new VpnServer
        {
            Host = host,
            Ssh = new SshCredentials
            {
                Port = request.SshPort, User = request.SshUser.Trim(),
                AuthType = hasKey ? SshAuthTypes.PrivateKey : SshAuthTypes.Password,
                Password = secrets.Protect(request.SshPassword),
                PrivateKey = secrets.Protect(request.SshPrivateKey),
                KeyPassphrase = secrets.Protect(request.SshKeyPassphrase)
            }
        };
    }

    private async Task EnsureNotRegisteredAsync(VpnServer server, CancellationToken ct)
    {
        if ((await servers.GetAllAsync(ct)).Any(s => NormalizeHost(s.Host) == server.Host && s.Ssh.Port == server.Ssh.Port))
            throw new BadRequestException("Этот сервер уже добавлен в панель. Откройте его карточку.");
    }

    private async Task<Probe> ProbeAsync(VpnServer server, CancellationToken ct)
    {
        await EnsureNotRegisteredAsync(server, ct);
        await using var ssh = await sshFactory.ConnectAsync(server, ct);
        var listing = await ssh.RunCheckedAsync("docker ps -a --format '{{.Names}}'", "discover_containers", ct);
        var names = listing.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .ToHashSet(StringComparer.Ordinal);
        var discovered = new List<Found>();
        var rows = new List<DiscoveredProtocolDto>();
        var revision = new StringBuilder($"{server.Host}\n{server.Ssh.Port}\n");
        foreach (var profile in Profiles.Where(p => names.Contains(p.ContainerName)))
        {
            try
            {
                var found = await ReadProtocolAsync(ssh, profile, ct);
                discovered.Add(found);
                var p = found.Protocol;
                rows.Add(new(p.Kind, ProtocolKinds.DisplayName(p.Kind), p.ContainerName, p.Port,
                    $"{p.Wg!.SubnetAddress}/{p.Wg.SubnetCidr}", found.Peers, true, null));
                revision.Append(profile.ContainerName).Append(':').Append(found.Revision).Append('\n');
            }
            catch (Exception ex) when (ex is BadRequestException or SshCommandException or FormatException or JsonException)
            {
                // Remote text may contain secrets. Only our controlled validation messages escape.
                var error = ex is BadRequestException ? ex.Message : "Не удалось прочитать параметры контейнера. Проверьте его конфигурацию и SSH-доступ.";
                rows.Add(new(profile.Kind, ProtocolKinds.DisplayName(profile.Kind), profile.ContainerName,
                    null, null, 0, false, error));
                revision.Append(profile.ContainerName).Append(':').Append(error).Append('\n');
            }
        }
        var warnings = new List<string>();
        if (names.Any(n => n.StartsWith("amnezia-", StringComparison.Ordinal) && !Profiles.Any(p => p.ContainerName == n)))
            warnings.Add("На узле есть другие контейнеры Amnezia. Импорт поддерживает стандартные контейнеры WireGuard и AmneziaWG 1/2/3; остальные остаются без изменений.");
        return new(new(Hash(revision.ToString()), rows, warnings), discovered);
    }

    private static async Task<Found> ReadProtocolAsync(ISshSession ssh, WireGuardInstallProfile profile, CancellationToken ct)
    {
        // All shell arguments are compile-time allowlisted values, never request/remote strings.
        var name = profile.ContainerName;
        var inspect = await ssh.RunCheckedAsync("docker inspect --format " +
            "'{\"running\":{{json .State.Running}},\"network\":{{json .HostConfig.NetworkMode}},\"ports\":{{json .NetworkSettings.Ports}}}' " + name,
            "inspect_existing_protocol", ct);
        using var state = JsonDocument.Parse(inspect);
        if (!state.RootElement.GetProperty("running").GetBoolean())
            throw new BadRequestException("Контейнер остановлен. Запустите его на узле и повторите поиск.");
        var config = await ssh.ReadContainerFileAsync(name, profile.ServerConfigPath, ct);
        var parsed = ExistingWireGuardConfig.Parse(config, profile);
        var port = PublishedPort(state.RootElement, parsed.ListenPort);
        var directory = profile.ServerConfigPath[..profile.ServerConfigPath.LastIndexOf('/')];
        var publicPath = directory + "/wireguard_server_public_key.key";
        var pskPath = directory + "/wireguard_psk.key";
        var publicKey = (await ssh.ReadContainerFileAsync(name, publicPath, ct)).Trim();
        var psk = (await ssh.ReadContainerFileAsync(name, pskPath, ct)).Trim();
        ExistingWireGuardConfig.RequireKey(publicKey);
        ExistingWireGuardConfig.RequireKey(psk);
        var prefix = $"docker exec {name} {profile.Binary} show {profile.InterfaceName}";
        var livePublic = (await ssh.RunCheckedAsync(prefix + " public-key", "read_public_key", ct)).Trim();
        var livePort = (await ssh.RunCheckedAsync(prefix + " listen-port", "read_listen_port", ct)).Trim();
        var livePeers = await ssh.RunCheckedAsync(prefix + " allowed-ips", "read_existing_peers", ct);
        if (livePublic != publicKey || livePublic != parsed.PublicKey || livePort != parsed.ListenPort)
            throw new BadRequestException("Параметры работающего интерфейса расходятся с сохранёнными. Сначала согласуйте конфигурацию на узле.");
        parsed.CheckLivePeers(livePeers);
        var protocol = new ProtocolInstance
        {
            Kind = parsed.Kind, ContainerName = name, Port = port, Mtu = parsed.Mtu,
            State = ProtocolStates.Installed, LastSyncedAt = DateTime.UtcNow,
            Wg = new WgProtocolParams
            {
                Binary = profile.Binary, InterfaceName = profile.InterfaceName,
                ServerConfigPath = profile.ServerConfigPath, ServerPubKeyPath = publicPath, PskKeyPath = pskPath,
                SubnetAddress = parsed.Network, SubnetCidr = parsed.Cidr,
                ServerPubKey = publicKey, PskKey = psk,
                Obfuscation = profile.HasObfuscation ? WireGuardConfigurator.ParseObfuscation(
                    string.Join('\n', config.Split('\n').Select(line => line.TrimStart().StartsWith('#') ? line : line.Split('#', 2)[0])), null) : null
            }
        };
        return new(protocol, parsed.PeerCount, Hash(config + "\n" + publicKey + "\n" + psk + "\n" + port));
    }

    private static string PublishedPort(JsonElement state, string listenPort)
    {
        if (state.GetProperty("network").GetString() == "host") return listenPort;
        var ports = state.GetProperty("ports");
        if (ports.ValueKind != JsonValueKind.Object || !ports.TryGetProperty(listenPort + "/udp", out var bindings) ||
            bindings.ValueKind != JsonValueKind.Array)
            throw new BadRequestException("UDP-порт интерфейса не опубликован Docker.");
        var published = bindings.EnumerateArray()
            .Where(b => b.GetProperty("HostIp").GetString() is "0.0.0.0" or "::" or "")
            .Select(b => b.GetProperty("HostPort").GetString()).Distinct().ToArray();
        if (published.Length != 1 || !int.TryParse(published[0], out var port) || port is < 1 or > 65535)
            throw new BadRequestException("Нужен один публичный UDP-порт контейнера. Проверьте публикацию порта Docker.");
        return port.ToString();
    }

    private static string NormalizeHost(string host) => IPAddress.TryParse(host?.Trim(), out var ip)
        ? ip.ToString() : (host ?? "").Trim().TrimEnd('.').ToLowerInvariant();
    private static string Hash(string value) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value)));
    private record Found(ProtocolInstance Protocol, int Peers, string Revision);
    private record Probe(ServerDiscoveryDto Preview, List<Found> Protocols);
}

/// <summary>Strict parsing protects future syncconf and IP allocation from adopting a partial config.</summary>
public sealed class ExistingWireGuardConfig
{
    public required string Kind { get; init; }
    public required string ListenPort { get; init; }
    public required string Network { get; init; }
    public required string Cidr { get; init; }
    public required string PublicKey { get; init; }
    public string? Mtu { get; init; }
    private Dictionary<string, string> Peers { get; init; } = [];
    public int PeerCount => Peers.Count;

    public static ExistingWireGuardConfig Parse(string config, WireGuardInstallProfile profile)
    {
        var sections = new List<(string Name, Dictionary<string, string> Values)>();
        foreach (var raw in config.Split('\n'))
        {
            var line = raw.Split('#', 2)[0].Trim();
            if (line.Length == 0) continue;
            if (line.StartsWith('[') && line.EndsWith(']'))
            { sections.Add((line[1..^1], new(StringComparer.OrdinalIgnoreCase))); continue; }
            var pair = line.Split('=', 2, StringSplitOptions.TrimEntries);
            if (sections.Count == 0 || pair.Length != 2) throw InvalidConfig();
            // Hooks may repeat. Settings used by import must be unambiguous.
            var values = sections[^1].Values;
            if (!values.TryAdd(pair[0], pair[1]) && pair[0] is not ("PostUp" or "PostDown" or "PreUp" or "PreDown"))
                throw InvalidConfig();
        }
        if (sections.Count == 0 || sections[0].Name != "Interface" || sections.Skip(1).Any(s => s.Name != "Peer"))
            throw InvalidConfig();
        var fields = sections[0].Values;
        var privateKey = fields.GetValueOrDefault("PrivateKey", "");
        RequireKey(privateKey);
        var publicKey = Convert.ToBase64String(new X25519PrivateKeyParameters(Convert.FromBase64String(privateKey), 0)
            .GeneratePublicKey().GetEncoded());
        if (!int.TryParse(fields.GetValueOrDefault("ListenPort"), out var port) || port is < 1 or > 65535) throw InvalidConfig();
        // Existing allocator reserves network+1 for the server. Reject other layouts.
        var address = fields.GetValueOrDefault("Address", "").Split('/');
        if (address.Length != 2 || !IPAddress.TryParse(address[0], out var ip) || ip.GetAddressBytes().Length != 4 ||
            !int.TryParse(address[1], out var cidr) || cidr is < 8 or > 30)
            throw new BadRequestException("Поддерживается один IPv4-адрес интерфейса с маской /8–/30.");
        var value = System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(ip.GetAddressBytes());
        var network = value & (uint.MaxValue << (32 - cidr));
        if (value != network + 1)
            throw new BadRequestException("Адрес VPN-интерфейса должен быть первым адресом подсети (например, 10.8.1.1/24).");
        var bytes = new byte[4];
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(bytes, network);
        var kind = profile.Kind;
        if (profile.HasObfuscation)
        {
            foreach (var key in new[] { "Jc", "Jmin", "Jmax", "S1", "S2", "H1", "H2", "H3", "H4" })
                if (string.IsNullOrWhiteSpace(fields.GetValueOrDefault(key))) throw InvalidConfig();
            // New Amnezia clients can put AWG3 in a container named amnezia-awg2.
            if (!string.IsNullOrWhiteSpace(fields.GetValueOrDefault("HeaderProtectionKey"))) kind = ProtocolKinds.Awg3;
            if (kind == ProtocolKinds.Awg3 && string.IsNullOrWhiteSpace(fields.GetValueOrDefault("HeaderProtectionKey")))
                throw new BadRequestException("В конфигурации AWG3 отсутствует HeaderProtectionKey.");
        }
        var peers = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var (_, peer) in sections.Skip(1))
        {
            var key = peer.GetValueOrDefault("PublicKey", "");
            RequireKey(key);
            if (!peers.TryAdd(key, NormalizeAllowedIps(peer.GetValueOrDefault("AllowedIPs", "")))) throw InvalidConfig();
        }
        var mtu = fields.GetValueOrDefault("MTU");
        if (mtu is not null && (!int.TryParse(mtu, out var size) || size is < 576 or > 9000)) throw InvalidConfig();
        return new() { Kind = kind, ListenPort = port.ToString(), Network = new IPAddress(bytes).ToString(),
            Cidr = cidr.ToString(), PublicKey = publicKey, Mtu = mtu, Peers = peers };
    }

    public void CheckLivePeers(string output)
    {
        var live = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var line in output.Split('\n', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries))
        {
            var parts = Regex.Split(line, @"\s+", RegexOptions.None, TimeSpan.FromSeconds(1));
            if (parts.Length < 2 || !live.TryAdd(parts[0], NormalizeAllowedIps(string.Join(',', parts.Skip(1))))) throw InvalidConfig();
        }
        if (live.Count != Peers.Count || Peers.Any(p => !live.TryGetValue(p.Key, out var ips) || ips != p.Value))
            throw new BadRequestException("Список клиентов работающего интерфейса расходится с файлом конфигурации. Сохраните актуальную конфигурацию на узле перед импортом.");
    }

    private static string NormalizeAllowedIps(string text)
    {
        var result = new List<string>();
        foreach (var entry in text.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var parts = entry.Split('/');
            if (parts.Length != 2 || !IPAddress.TryParse(parts[0], out var ip) || !int.TryParse(parts[1], out var prefix) ||
                prefix < 0 || prefix > ip.GetAddressBytes().Length * 8) throw InvalidConfig();
            result.Add($"{ip}/{prefix}");
        }
        if (result.Count == 0) throw InvalidConfig();
        return string.Join(',', result.Distinct().Order(StringComparer.Ordinal));
    }

    public static void RequireKey(string key)
    {
        if (!Convert.TryFromBase64String(key, new byte[32], out var count) || count != 32) throw InvalidConfig();
    }
    private static BadRequestException InvalidConfig() => new("Неполная или неподдерживаемая конфигурация WireGuard/AmneziaWG.");
}
