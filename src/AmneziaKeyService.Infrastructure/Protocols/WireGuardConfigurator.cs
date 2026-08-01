using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using AmneziaKeyService.Core.Exceptions;
using AmneziaKeyService.Core.Interfaces;
using AmneziaKeyService.Core.Models;
using AmneziaKeyService.Infrastructure.Scripts;
using AmneziaKeyService.Infrastructure.Services;

namespace AmneziaKeyService.Infrastructure.Protocols;

/// <summary>
/// Конфигуратор семейства WireGuard: awg2, awg legacy и обычный WireGuard.
/// Отличия вынесены в <see cref="WireGuardProfile"/>.
/// </summary>
public partial class WireGuardConfigurator : IProtocolConfigurator
{
    /// <summary>
    /// Не экранировать &lt;, &gt;, + и &amp;. Параметр обфускации I1 — строка вида
    /// «&lt;r 2&gt;&lt;b 0x8580…&gt;», и стандартный энкодер превратил бы её в <.
    /// </summary>
    private static readonly JsonSerializerOptions RelaxedJson = new()
    {
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
        WriteIndented = false,
    };

    private readonly WireGuardProfile _profile;
    private readonly ScriptRegistry _scripts;
    private readonly KeyGenerationService _keyGen;
    private readonly IpAllocator _ipAllocator;

    public WireGuardConfigurator(
        WireGuardProfile profile,
        ScriptRegistry scripts,
        KeyGenerationService keyGen,
        IpAllocator ipAllocator)
    {
        _profile     = profile;
        _scripts     = scripts;
        _keyGen      = keyGen;
        _ipAllocator = ipAllocator;
    }

    public string Kind => _profile.Kind;

    // ── Параметры узла ────────────────────────────────────────────────────────

    public async Task<bool> EnsureServerParamsAsync(
        ISshSession ssh, VpnServer server, ProtocolInstance protocol, CancellationToken ct = default)
    {
        var wg = RequireWg(protocol);
        if (wg.ServerPubKey is not null && (!_profile.HasObfuscation || wg.Obfuscation is not null))
            return false;

        wg.ServerPubKey = (await ssh.ReadContainerFileAsync(
            protocol.ContainerName, wg.ServerPubKeyPath, ct)).Trim();

        wg.PskKey = (await ssh.ReadContainerFileAsync(
            protocol.ContainerName, wg.PskKeyPath, ct)).Trim();

        var rawConf = await ssh.ReadContainerFileAsync(
            protocol.ContainerName, wg.ServerConfigPath, ct);

        if (_profile.HasObfuscation)
            wg.Obfuscation = ParseObfuscation(rawConf, wg.Obfuscation);

        wg.LastKnownPeerIp = ParseMaxPeerIp(rawConf) ?? wg.LastKnownPeerIp;
        protocol.LastSyncedAt = DateTime.UtcNow;

        return true;
    }

    // ── Peer ──────────────────────────────────────────────────────────────────

    public async Task<IssuedPeer> AddPeerAsync(
        ISshSession ssh, PeerRequest request, CancellationToken ct = default)
    {
        var (server, protocol, _) = request;
        var wg = RequireWg(protocol);

        await EnsureServerParamsAsync(ssh, server, protocol, ct);

        var psk = wg.PskKey
            ?? throw new InvalidOperationException(
                "На узле не найден pre-shared key. Перечитайте параметры узла.");

        var (privateKey, publicKey) = _keyGen.GenerateX25519KeyPair();
        var clientIp = await _ipAllocator.AllocateAsync(server, protocol, ct);

        var peerBlock = new StringBuilder()
            .Append('\n').Append("[Peer]").Append('\n')
            .Append("PublicKey = ").Append(publicKey).Append('\n')
            .Append("PresharedKey = ").Append(psk).Append('\n')
            .Append("AllowedIPs = ").Append(clientIp).Append("/32").Append('\n')
            .ToString();

        await ssh.AppendContainerFileAsync(protocol.ContainerName, wg.ServerConfigPath, peerBlock, ct);
        await SyncConfigAsync(ssh, protocol, wg, ct);

        // Двигаем границу, чтобы следующий ключ не попал на тот же адрес,
        // даже если запись клиента ещё не сохранена.
        wg.LastKnownPeerIp = clientIp;

        return new IssuedPeer
        {
            AssignedIp    = clientIp,
            ClientPrivKey = privateKey,
            ClientPubKey  = publicKey,
            PskKey        = psk,
        };
    }

    public async Task RemovePeerAsync(
        ISshSession ssh, PeerRequest request, CancellationToken ct = default)
    {
        var (_, protocol, client) = request;
        var wg = RequireWg(protocol);

        if (string.IsNullOrEmpty(client.ClientPubKey))
            throw new InvalidOperationException("У ключа нет публичного ключа — нечего удалять с узла.");

        // grep -F: ключ трактуется как literal. Base64 не содержит $, `, \ и ",
        // поэтому двойные кавычки безопасны.
        // Блок peer-а — четыре строки: [Peer], PublicKey, PresharedKey, AllowedIPs.
        var script =
            $"n=$(grep -Fn \"{client.ClientPubKey}\" {wg.ServerConfigPath} | head -1 | cut -d: -f1); " +
            $"[ -n \"$n\" ] && sed -i \"$((n-1)),$((n+2))d\" {wg.ServerConfigPath} || true";

        await ssh.RunCheckedAsync(
            $"docker exec -i {protocol.ContainerName} sh -c '{script}'", "remove_peer", ct);

        await SyncConfigAsync(ssh, protocol, wg, ct);
    }

    /// <summary>
    /// Применяет изменённый конфиг без перезапуска контейнера.
    /// Подстановка процесса &lt;(...) требует именно bash.
    /// </summary>
    private static Task SyncConfigAsync(
        ISshSession ssh, ProtocolInstance protocol, WgProtocolParams wg, CancellationToken ct)
        => ssh.RunCheckedAsync(
            $"docker exec -i {protocol.ContainerName} bash -c " +
            $"'{wg.Binary} syncconf {wg.InterfaceName} <({wg.Binary}-quick strip {wg.ServerConfigPath})'",
            "sync_config", ct);

    // ── Конфиг клиента ────────────────────────────────────────────────────────

    public JsonObject BuildContainerEntry(
        VpnServer server, ProtocolInstance protocol, VpnClient client)
    {
        var wg  = RequireWg(protocol);
        var obf = wg.Obfuscation ?? new AwgObfuscationParams();
        var mtu = protocol.Mtu ?? obf.Mtu;

        var confText = BuildConfText(server, protocol, client);

        // last_config — это СТРОКА с JSON внутри, а не вложенный объект.
        // Так его пишет awg_configurator.cpp, и клиент разбирает именно строку.
        var lastConfig = new JsonObject
        {
            ["config"]                = confText,
            ["client_priv_key"]       = client.ClientPrivKey,
            ["client_pub_key"]        = client.ClientPubKey,
            ["server_pub_key"]        = wg.ServerPubKey,
            ["psk_key"]               = client.PskKey ?? wg.PskKey,
            ["client_ip"]             = client.AssignedIp,
            ["hostName"]              = server.Host,
            ["port"]                  = int.TryParse(protocol.Port, out var port) ? port : 55424,
            ["mtu"]                   = mtu,
            ["persistent_keep_alive"] = "25",
            ["allowed_ips"]           = new JsonArray("0.0.0.0/0", "::/0"),
            // clientId для WireGuard — это публичный ключ клиента.
            ["clientId"]              = client.ClientPubKey,
        };

        if (_profile.HasObfuscation)
        {
            // Заглавные ключи: Android читает их из last_config именно так
            // (Wireguard.kt, configExtensionParameters).
            lastConfig["Jc"]   = obf.Jc;
            lastConfig["Jmin"] = obf.Jmin;
            lastConfig["Jmax"] = obf.Jmax;
            lastConfig["S1"]   = obf.S1;
            lastConfig["S2"]   = obf.S2;

            if (_profile.HasExtendedJunk)
            {
                lastConfig["S3"] = obf.S3;
                lastConfig["S4"] = obf.S4;
            }

            lastConfig["H1"] = obf.H1;
            lastConfig["H2"] = obf.H2;
            lastConfig["H3"] = obf.H3;
            lastConfig["H4"] = obf.H4;
            lastConfig["I1"] = obf.I1;
            lastConfig["I2"] = obf.I2;
            lastConfig["I3"] = obf.I3;
            lastConfig["I4"] = obf.I4;
            lastConfig["I5"] = obf.I5;
        }

        var protocolObj = new JsonObject
        {
            ["port"]            = protocol.Port,
            ["transport_proto"] = protocol.TransportProto,
            ["subnet_address"]  = wg.SubnetAddress,
            ["mtu"]             = mtu,
            // Тот же нестрогий энкодер, что и на верхнем уровне. Клиент в любом
            // случае развернёт < обратно в <, но Qt-версия пишет символ как
            // есть, и байтовое совпадение упрощает сверку с эталоном.
            ["last_config"]     = lastConfig.ToJsonString(RelaxedJson),
        };

        if (_profile.HasObfuscation)
        {
            // Здесь — строчные: верхний уровень контейнера читает десктопный клиент.
            protocolObj["jc"]   = obf.Jc;
            protocolObj["jmin"] = obf.Jmin;
            protocolObj["jmax"] = obf.Jmax;
            protocolObj["s1"]   = obf.S1;
            protocolObj["s2"]   = obf.S2;

            if (_profile.HasExtendedJunk)
            {
                protocolObj["s3"] = obf.S3;
                protocolObj["s4"] = obf.S4;
            }

            protocolObj["h1"] = obf.H1;
            protocolObj["h2"] = obf.H2;
            protocolObj["h3"] = obf.H3;
            protocolObj["h4"] = obf.H4;
            protocolObj["i1"] = obf.I1;
            protocolObj["i2"] = obf.I2;
            protocolObj["i3"] = obf.I3;
            protocolObj["i4"] = obf.I4;
            protocolObj["i5"] = obf.I5;
        }

        if (_profile.ProtocolVersion is { } version)
            protocolObj["protocol_version"] = version;

        return new JsonObject
        {
            ["container"]        = protocol.ContainerName,
            [_profile.ConfigKey] = protocolObj,
        };
    }

    public ClientFile BuildClientFile(VpnServer server, ProtocolInstance protocol, VpnClient client)
        => new(
            FileName: $"{client.ShortId ?? "amnezia"}.conf",
            ContentType: "text/plain; charset=utf-8",
            Content: BuildConfText(server, protocol, client));

    /// <summary>
    /// Рендерит клиентский .conf по шаблону upstream. Именно по шаблону,
    /// а не сборкой строк в C#: клиент AmneziaVPN разбирает файл по этому
    /// же формату, и расхождение проявляется только несостоявшимся хэндшейком.
    /// </summary>
    private string BuildConfText(VpnServer server, ProtocolInstance protocol, VpnClient client)
    {
        var wg  = RequireWg(protocol);
        var obf = wg.Obfuscation ?? new AwgObfuscationParams();

        var vars = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["WIREGUARD_CLIENT_IP"]           = client.AssignedIp ?? string.Empty,
            ["PRIMARY_DNS"]                   = server.Dns1,
            ["SECONDARY_DNS"]                 = server.Dns2,
            ["WIREGUARD_CLIENT_PRIVATE_KEY"]  = client.ClientPrivKey ?? string.Empty,
            ["WIREGUARD_SERVER_PUBLIC_KEY"]   = wg.ServerPubKey ?? string.Empty,
            ["WIREGUARD_PSK"]                 = client.PskKey ?? wg.PskKey ?? string.Empty,
            ["SERVER_IP_ADDRESS"]             = server.Host,
            ["AWG_SERVER_PORT"]               = protocol.Port,
            ["WIREGUARD_SERVER_PORT"]         = protocol.Port,
        };

        if (_profile.HasObfuscation)
        {
            vars["JUNK_PACKET_COUNT"]              = obf.Jc;
            vars["JUNK_PACKET_MIN_SIZE"]           = obf.Jmin;
            vars["JUNK_PACKET_MAX_SIZE"]           = obf.Jmax;
            vars["INIT_PACKET_JUNK_SIZE"]          = obf.S1;
            vars["RESPONSE_PACKET_JUNK_SIZE"]      = obf.S2;
            vars["COOKIE_REPLY_PACKET_JUNK_SIZE"]  = obf.S3;
            vars["TRANSPORT_PACKET_JUNK_SIZE"]     = obf.S4;
            vars["INIT_PACKET_MAGIC_HEADER"]       = obf.H1;
            vars["RESPONSE_PACKET_MAGIC_HEADER"]   = obf.H2;
            vars["UNDERLOAD_PACKET_MAGIC_HEADER"]  = obf.H3;
            vars["TRANSPORT_PACKET_MAGIC_HEADER"]  = obf.H4;
            vars["SPECIAL_JUNK_1"]                 = obf.I1;
            vars["SPECIAL_JUNK_2"]                 = obf.I2;
            vars["SPECIAL_JUNK_3"]                 = obf.I3;
            vars["SPECIAL_JUNK_4"]                 = obf.I4;
            vars["SPECIAL_JUNK_5"]                 = obf.I5;
        }

        var template = _scripts.Read($"{_profile.TemplateFolder}/template.conf");
        var rendered = ScriptTemplateRenderer.Render(template, vars);

        // Пустые I1-I5 клиент воспринимает как ошибку разбора, а не как «нет значения».
        rendered = DropEmptyAssignments(rendered);

        return rendered;
    }

    /// <summary>Убирает строки вида «I3 = » с пустым значением.</summary>
    private static string DropEmptyAssignments(string conf)
        => string.Join('\n', conf
            .Split('\n')
            .Where(line => !EmptyAssignment().IsMatch(line)));

    [GeneratedRegex(@"^\s*[A-Za-z0-9_]+\s*=\s*$")]
    private static partial Regex EmptyAssignment();

    // ── Разбор конфига сервера ────────────────────────────────────────────────

    private static AwgObfuscationParams ParseObfuscation(string conf, AwgObfuscationParams? existing)
    {
        var p = existing ?? new AwgObfuscationParams();

        string? Get(string key)
        {
            var match = Regex.Match(
                conf, $@"^\s*{Regex.Escape(key)}\s*=\s*(.+)$",
                RegexOptions.Multiline | RegexOptions.IgnoreCase);
            return match.Success ? match.Groups[1].Value.Trim() : null;
        }

        p.Jc   = Get("Jc")   ?? p.Jc;
        p.Jmin = Get("Jmin") ?? p.Jmin;
        p.Jmax = Get("Jmax") ?? p.Jmax;
        p.S1   = Get("S1")   ?? p.S1;
        p.S2   = Get("S2")   ?? p.S2;
        // Отсутствие S3/S4 в конфиге означает 0, а не «оставить прежнее»:
        // клиент обязан передать ровно те же значения, иначе хэндшейк не пройдёт.
        p.S3   = Get("S3")   ?? "0";
        p.S4   = Get("S4")   ?? "0";
        p.H1   = Get("H1")   ?? p.H1;
        p.H2   = Get("H2")   ?? p.H2;
        p.H3   = Get("H3")   ?? p.H3;
        p.H4   = Get("H4")   ?? p.H4;
        p.I1   = Get("I1")   ?? "";
        p.I2   = Get("I2")   ?? "";
        p.I3   = Get("I3")   ?? "";
        p.I4   = Get("I4")   ?? "";
        p.I5   = Get("I5")   ?? "";

        return p;
    }

    /// <summary>Максимальный IP среди peer-ов — включая заведённые мимо сервиса.</summary>
    private static string? ParseMaxPeerIp(string conf)
    {
        uint max = 0;
        string? maxIp = null;

        foreach (Match m in Regex.Matches(
            conf, @"^\s*AllowedIPs\s*=\s*(\d+\.\d+\.\d+\.\d+)/32",
            RegexOptions.Multiline | RegexOptions.IgnoreCase))
        {
            var ip = m.Groups[1].Value;
            if (!System.Net.IPAddress.TryParse(ip, out var addr)) continue;

            var bytes = addr.GetAddressBytes();
            if (BitConverter.IsLittleEndian) Array.Reverse(bytes);
            var value = BitConverter.ToUInt32(bytes, 0);

            if (value > max) { max = value; maxIp = ip; }
        }

        return maxIp;
    }

    private static WgProtocolParams RequireWg(ProtocolInstance protocol)
        => protocol.Wg
           ?? throw new NotFoundException($"У протокола {protocol.Kind} нет параметров WireGuard.");
}
