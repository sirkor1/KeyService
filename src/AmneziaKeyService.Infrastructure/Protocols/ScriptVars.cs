using System.Net;
using AmneziaKeyService.Core.Models;

namespace AmneziaKeyService.Infrastructure.Protocols;

/// <summary>
/// Таблица подстановок для скриптов установки.
///
/// Имена соответствуют ServerController::genVarsForScript из amnezia-client.
/// Отклоняться от них нельзя: скрипты скопированы дословно и ожидают
/// именно эти токены.
/// </summary>
public static class ScriptVars
{
    /// <summary>Переменные, общие для всех протоколов.</summary>
    public static Dictionary<string, string> Common(VpnServer server, string containerName) => new(StringComparer.Ordinal)
    {
        ["CONTAINER_NAME"]      = containerName,
        ["DOCKERFILE_FOLDER"]   = $"/opt/amnezia/{containerName}",
        ["REMOTE_HOST"]         = server.Host,
        // Для WireGuard и Xray upstream подставляет хост как есть, без
        // разрешения в IP: сертификаты и SNI завязаны на имя.
        ["SERVER_IP_ADDRESS"]   = server.Host,
        ["PRIMARY_SERVER_DNS"]  = server.Dns1,
        ["SECONDARY_SERVER_DNS"] = server.Dns2,
    };

    /// <summary>Переменные семейства WireGuard.</summary>
    public static void AddWireGuard(
        Dictionary<string, string> vars, WgProtocolParams wg, string port, AwgObfuscationParams obf)
    {
        // AWG_SUBNET_IP — адрес самого сервера в туннеле, то есть первый
        // адрес подсети. В скрипте он идёт в Address= секции [Interface].
        vars["AWG_SUBNET_IP"]           = ServerAddress(wg.SubnetAddress);
        vars["WIREGUARD_SUBNET_IP"]     = ServerAddress(wg.SubnetAddress);
        vars["WIREGUARD_SUBNET_CIDR"]   = wg.SubnetCidr;
        vars["WIREGUARD_SUBNET_MASK"]   = MaskFromCidr(wg.SubnetCidr);
        vars["AWG_SERVER_PORT"]         = port;
        vars["WIREGUARD_SERVER_PORT"]   = port;

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

    /// <summary>Переменные Xray.</summary>
    public static void AddXray(Dictionary<string, string> vars, string port, string siteName)
    {
        vars["XRAY_SERVER_PORT"] = port;
        vars["XRAY_SITE_NAME"]   = siteName;
    }

    /// <summary>Первый адрес подсети: 10.8.1.0 → 10.8.1.1.</summary>
    private static string ServerAddress(string subnetAddress)
    {
        var bytes = IPAddress.Parse(subnetAddress).GetAddressBytes();
        if (BitConverter.IsLittleEndian) Array.Reverse(bytes);

        var value = BitConverter.ToUInt32(bytes, 0) + 1;

        var result = BitConverter.GetBytes(value);
        if (BitConverter.IsLittleEndian) Array.Reverse(result);
        return new IPAddress(result).ToString();
    }

    private static string MaskFromCidr(string cidr)
    {
        if (!int.TryParse(cidr, out var bits) || bits is < 8 or > 30) bits = 24;

        var mask = bits == 0 ? 0u : uint.MaxValue << (32 - bits);
        var bytes = BitConverter.GetBytes(mask);
        if (BitConverter.IsLittleEndian) Array.Reverse(bytes);
        return new IPAddress(bytes).ToString();
    }

    /// <summary>
    /// Случайный порт в диапазоне upstream (getPortForInstall).
    /// Фиксированный порт по умолчанию — заметный признак Amnezia при сканировании.
    /// </summary>
    public static string RandomPort() => Random.Shared.Next(30000, 50000).ToString();

    /// <summary>
    /// Случайные параметры обфускации, как их генерирует InstallController
    /// для AmneziaWG второй версии. Одинаковые значения на всех узлах
    /// сами по себе становятся сигнатурой.
    /// </summary>
    public static AwgObfuscationParams RandomObfuscation() => new()
    {
        Jc   = Random.Shared.Next(3, 10).ToString(),
        Jmin = "50",
        Jmax = "1000",
        S1   = Random.Shared.Next(15, 150).ToString(),
        S2   = Random.Shared.Next(15, 150).ToString(),
        S3   = Random.Shared.Next(15, 150).ToString(),
        S4   = Random.Shared.Next(15, 150).ToString(),
        H1   = Random.Shared.Next(100_000, 500_000).ToString(),
        H2   = Random.Shared.Next(500_001, 1_000_000).ToString(),
        H3   = Random.Shared.Next(1_000_001, 1_500_000).ToString(),
        H4   = Random.Shared.Next(1_500_001, 2_000_000).ToString(),
        I1   = "", I2 = "", I3 = "", I4 = "", I5 = "",
        Mtu  = "1376",
    };
}
