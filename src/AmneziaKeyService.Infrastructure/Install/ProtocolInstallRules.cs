using System.Net;
using AmneziaKeyService.Core.Exceptions;
using AmneziaKeyService.Core.Models;
using AmneziaKeyService.Infrastructure.Protocols;

namespace AmneziaKeyService.Infrastructure.Install;

/// <summary>Validate both before queueing and under the worker's node lease.</summary>
public static class ProtocolInstallRules
{
    public static void Prepare(VpnServer server, IReadOnlyList<ProtocolSpec> specs)
    {
        var containers = server.Protocols.Select(p => p.ContainerName).ToHashSet(StringComparer.Ordinal);
        var ports = server.Protocols.Select(p => p.Port).ToHashSet(StringComparer.Ordinal);
        var ranges = server.Protocols.Where(p => p.Wg is not null)
            .Select(p => Range(p.Wg!.SubnetAddress, p.Wg.SubnetCidr)).ToList();
        foreach (var spec in specs)
        {
            if (!ProtocolKinds.All.Contains(spec.Kind)) throw new BadRequestException("Неизвестный протокол.");
            if (!containers.Add(ProtocolKinds.DefaultContainerName(spec.Kind)) || server.Protocols.Any(p => p.Kind == spec.Kind))
                throw new BadRequestException("Эта версия протокола уже установлена. Существующий контейнер и ключи сохраняются.");
            if (spec.Port is null)
            {
                do { spec.Port = ScriptVars.RandomPort(); } while (ports.Contains(spec.Port));
            }
            if (!int.TryParse(spec.Port, out var port) || port is < 1 or > 65535)
                throw new BadRequestException("Порт должен быть числом от 1 до 65535.");
            spec.Port = port.ToString();
            if (!ports.Add(spec.Port)) throw new BadRequestException("Порт уже используется другим протоколом этого сервера.");
            if (spec.Mtu is not null && (!int.TryParse(spec.Mtu, out var mtu) || mtu is < 576 or > 9000))
                throw new BadRequestException("MTU должен быть числом от 576 до 9000.");
            if (spec.SiteName is not null && Uri.CheckHostName(spec.SiteName) != UriHostNameType.Dns)
                throw new BadRequestException("SNI должен быть доменным именем.");
            if (!ProtocolKinds.IsWireGuardFamily(spec.Kind)) continue;
            spec.SubnetCidr ??= "24";
            if (spec.SubnetAddress is null)
            {
                spec.SubnetAddress = Enumerable.Range(1, 254).Select(n => $"10.8.{n}.0")
                    .FirstOrDefault(ip => !ranges.Any(r => Overlaps(r, Range(ip, spec.SubnetCidr))))
                    ?? throw new BadRequestException("Укажите свободную подсеть вручную.");
            }
            var candidate = Range(spec.SubnetAddress, spec.SubnetCidr);
            if (ranges.Any(r => Overlaps(r, candidate))) throw new BadRequestException("Подсеть пересекается с другим протоколом сервера.");
            ranges.Add(candidate);
        }
    }

    private static bool Overlaps((uint Start, uint End) a, (uint Start, uint End) b) => a.Start <= b.End && b.Start <= a.End;

    private static (uint Start, uint End) Range(string subnet, string cidr)
    {
        if (!IPAddress.TryParse(subnet, out var address) || address.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork
            || !int.TryParse(cidr, out var prefix) || prefix is < 8 or > 30)
            throw new BadRequestException("Нужна IPv4-подсеть с маской от /8 до /30.");
        var value = System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(address.GetAddressBytes());
        var mask = uint.MaxValue << (32 - prefix);
        if ((value & mask) != value) throw new BadRequestException("Укажите адрес сети, например 10.8.3.0/24.");
        return (value, value | ~mask);
    }
}
