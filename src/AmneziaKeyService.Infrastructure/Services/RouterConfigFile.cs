using System.Net;
using AmneziaKeyService.Core.Exceptions;

namespace AmneziaKeyService.Infrastructure.Services;

public static class RouterConfigFile
{
    // Keep upstream templates unchanged; constrain the exported monitoring profile.
    public static string Build(string original, string subnet)
    {
        if (!IPAddress.TryParse(subnet, out var address) || address.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
            throw new BadRequestException("Подсеть WireGuard должна быть IPv4.");
        var bytes = address.GetAddressBytes();
        for (var i = bytes.Length - 1; i >= 0; i--) { if (++bytes[i] != 0) break; }
        var target = new IPAddress(bytes) + "/32";
        var result = new List<string>();
        foreach (var line in original.Replace("\r", "").Split('\n'))
        {
            var name = line.Split('=', 2)[0].Trim();
            if (name.Equals("DNS", StringComparison.OrdinalIgnoreCase)) continue;
            if (name.Equals("AllowedIPs", StringComparison.OrdinalIgnoreCase)) { result.Add("AllowedIPs = " + target); continue; }
            if (name.Equals("PersistentKeepalive", StringComparison.OrdinalIgnoreCase)) continue;
            result.Add(line);
        }
        result.Add("PersistentKeepalive = 25");
        return string.Join('\n', result).Trim() + "\n";
    }
}
