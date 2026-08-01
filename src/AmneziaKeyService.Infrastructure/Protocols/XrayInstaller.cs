using AmneziaKeyService.Core.Models;
using AmneziaKeyService.Infrastructure.Scripts;

namespace AmneziaKeyService.Infrastructure.Protocols;

/// <summary>Развёртывание контейнера VLESS Reality на Xray-core.</summary>
public class XrayInstaller : ProtocolInstallerBase
{
    /// <summary>
    /// Сайт, под который маскируется трафик. Должен поддерживать TLS 1.3
    /// и HTTP/2, иначе Reality не сработает.
    /// </summary>
    private const string DefaultSiteName = "www.googletagmanager.com";

    public XrayInstaller(ScriptRegistry scripts) : base(scripts) { }

    public override string Kind => ProtocolKinds.Xray;

    /// <summary>443: смысл Reality в том, чтобы выглядеть обычным HTTPS.</summary>
    public override string DefaultPort => "443";

    protected override string ScriptFolder => "xray";
    protected override string ContainerName => "amnezia-xray";

    protected override (ProtocolInstance, Dictionary<string, string>) Prepare(
        VpnServer server, ProtocolSpec spec)
    {
        var port = spec.Port ?? DefaultPort;
        var siteName = string.IsNullOrWhiteSpace(spec.SiteName) ? DefaultSiteName : spec.SiteName;

        var protocol = new ProtocolInstance
        {
            Kind           = ProtocolKinds.Xray,
            ContainerName  = ContainerName,
            Port           = port,
            TransportProto = "tcp",
            Mtu            = spec.Mtu,
            State          = ProtocolStates.Installed,
            InstalledAt    = DateTime.UtcNow,
            Xray = new XrayProtocolParams
            {
                SiteName         = siteName,
                ServerConfigPath = "/opt/amnezia/xray/server.json",
            },
        };

        var vars = ScriptVars.Common(server, ContainerName);
        ScriptVars.AddXray(vars, port, siteName);

        return (protocol, vars);
    }
}

/// <summary>Резолвит инсталлятор по виду протокола.</summary>
public class ProtocolInstallerRegistry : Core.Interfaces.IProtocolInstallerRegistry
{
    private readonly Dictionary<string, Core.Interfaces.IProtocolInstaller> _installers;

    public ProtocolInstallerRegistry(IEnumerable<Core.Interfaces.IProtocolInstaller> installers)
        => _installers = installers.ToDictionary(i => i.Kind, StringComparer.Ordinal);

    public bool IsSupported(string kind) => _installers.ContainsKey(kind);

    public Core.Interfaces.IProtocolInstaller Get(string kind)
        => _installers.TryGetValue(kind, out var installer)
            ? installer
            : throw new Core.Exceptions.NotFoundException(
                $"Установка протокола '{kind}' не поддерживается.");
}
