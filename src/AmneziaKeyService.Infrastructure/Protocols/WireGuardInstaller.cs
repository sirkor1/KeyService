using AmneziaKeyService.Core.Models;
using AmneziaKeyService.Infrastructure.Scripts;

namespace AmneziaKeyService.Infrastructure.Protocols;

/// <summary>
/// Развёртывание контейнера семейства WireGuard.
///
/// Три варианта различаются папкой скриптов, именем контейнера, бинарём
/// и именем интерфейса — всё остальное совпадает, поэтому реализация одна.
/// </summary>
public class WireGuardInstaller : ProtocolInstallerBase
{
    private readonly WireGuardInstallProfile _profile;

    public WireGuardInstaller(WireGuardInstallProfile profile, ScriptRegistry scripts)
        : base(scripts) => _profile = profile;

    public override string Kind => _profile.Kind;
    public override string DefaultPort => _profile.DefaultPort;

    /// <summary>
    /// AmneziaWG второй версии требует ядро 4.14+: модуль amneziawg-go
    /// на более старых просто не поднимется.
    /// </summary>
    public override bool RequiresModernKernel => _profile.Kind is ProtocolKinds.Awg2 or ProtocolKinds.Awg3;

    protected override string ScriptFolder => _profile.ScriptFolder;
    protected override string ContainerName => _profile.ContainerName;
    protected override string? BaseImage => _profile.Kind == ProtocolKinds.Awg3
        ? "amneziavpn/amneziawg-go@sha256:cbafc02b8373a83f428272db6d8001b37bc02e6211cbd8c0cb4e2e3759b12b72"
        : null;

    protected override (ProtocolInstance, Dictionary<string, string>) Prepare(
        VpnServer server, ProtocolSpec spec)
    {
        var port = spec.Port ?? ScriptVars.RandomPort();
        // Upstream keeps the keys beside the server config. Plain WireGuard
        // uses /wireguard/, while all AWG variants use /awg/.
        var configDirectory = _profile.ServerConfigPath[.._profile.ServerConfigPath.LastIndexOf('/')];

        // Параметры обфускации генерируются на каждый узел заново: одинаковые
        // значения на всём флоте сами становятся сигнатурой для DPI.
        var obfuscation = _profile.Kind == ProtocolKinds.Awg3 ? ScriptVars.Awg3Obfuscation()
            : _profile.HasObfuscation ? ScriptVars.RandomObfuscation() : null;

        var wg = new WgProtocolParams
        {
            InterfaceName    = _profile.InterfaceName,
            Binary           = _profile.Binary,
            ServerConfigPath = _profile.ServerConfigPath,
            ServerPubKeyPath = configDirectory + "/wireguard_server_public_key.key",
            PskKeyPath       = configDirectory + "/wireguard_psk.key",
            SubnetAddress    = spec.SubnetAddress ?? "10.8.1.0",
            SubnetCidr       = spec.SubnetCidr ?? "24",
            Obfuscation      = obfuscation,
        };

        var protocol = new ProtocolInstance
        {
            Kind           = _profile.Kind,
            ContainerName  = _profile.ContainerName,
            Port           = port,
            TransportProto = "udp",
            Mtu            = spec.Mtu ?? obfuscation?.Mtu ?? "1376",
            State          = ProtocolStates.Installed,
            InstalledAt    = DateTime.UtcNow,
            Wg             = wg,
        };

        var vars = ScriptVars.Common(server, _profile.ContainerName);
        ScriptVars.AddWireGuard(vars, wg, port, obfuscation ?? new AwgObfuscationParams());

        if (_profile.Kind == ProtocolKinds.Awg3) ScriptVars.AddAwg3(vars, obfuscation!);
        return (protocol, vars);
    }
}

/// <summary>Различия трёх вариантов WireGuard на этапе установки.</summary>
public record WireGuardInstallProfile(
    string Kind,
    string ScriptFolder,
    string ContainerName,
    string Binary,
    string InterfaceName,
    string ServerConfigPath,
    string DefaultPort,
    bool HasObfuscation)
{
    public static readonly WireGuardInstallProfile Awg3 = new(
        ProtocolKinds.Awg3, "awg3", "amnezia-awg3",
        Binary: "awg", InterfaceName: "awg0",
        ServerConfigPath: "/opt/amnezia/awg/awg0.conf",
        DefaultPort: "55425", HasObfuscation: true);

    public static readonly WireGuardInstallProfile Awg2 = new(
        ProtocolKinds.Awg2, "awg", "amnezia-awg2",
        Binary: "awg", InterfaceName: "awg0",
        ServerConfigPath: "/opt/amnezia/awg/awg0.conf",
        DefaultPort: "55424", HasObfuscation: true);

    public static readonly WireGuardInstallProfile AwgLegacy = new(
        ProtocolKinds.AwgLegacy, "awg_legacy", "amnezia-awg",
        Binary: "wg", InterfaceName: "wg0",
        ServerConfigPath: "/opt/amnezia/awg/wg0.conf",
        DefaultPort: "55424", HasObfuscation: true);

    public static readonly WireGuardInstallProfile WireGuard = new(
        ProtocolKinds.WireGuard, "wireguard", "amnezia-wireguard",
        Binary: "wg", InterfaceName: "wg0",
        ServerConfigPath: "/opt/amnezia/wireguard/wg0.conf",
        DefaultPort: "51820", HasObfuscation: false);
}
