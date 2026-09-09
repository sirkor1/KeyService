using System.Net;
using AmneziaKeyService.Core.Interfaces;
using AmneziaKeyService.Core.Models;

namespace AmneziaKeyService.Infrastructure.Services;

/// <summary>
/// Выдаёт туннельные адреса внутри подсети протокола.
///
/// Берётся наименьший свободный адрес, а не «максимум + 1», как было раньше:
/// при прежнем подходе отозванные ключи не освобождали адрес, и подсеть /24
/// исчерпывалась навсегда после ~250 выдач, даже если активных ключей оставалось
/// двое.
///
/// Занятыми считаются адреса неотозванных ключей плюс адреса из актуальных
/// AllowedIPs peer-ов на узле. Серверный конфиг читается перед каждой выдачей:
/// это защищает от пересечений с peer-ами, заведёнными мимо сервиса, но не
/// мешает переиспользовать адреса действительно удалённых peer-ов.
///
/// Аллокатор не гарантирует уникальность сам по себе — гонку закрывает
/// частичный уникальный индекс из миграции 006, а вызывающий повторяет
/// операцию при duplicate key.
/// </summary>
public class IpAllocator
{
    private readonly IVpnClientRepository _clients;

    public IpAllocator(IVpnClientRepository clients) => _clients = clients;

    public async Task<string> AllocateAsync(
        VpnServer server,
        ProtocolInstance protocol,
        IEnumerable<string> serverAllowedIps,
        CancellationToken ct = default)
    {
        var wg = protocol.Wg
            ?? throw new InvalidOperationException(
                $"Протокол {protocol.Kind} не использует туннельные адреса.");

        var assigned = await _clients.GetAssignedIpsAsync(server.Id, protocol.Id, ct);
        return SelectAvailableIp(wg, assigned, serverAllowedIps);
    }

    internal static string SelectAvailableIp(
        WgProtocolParams wg,
        IEnumerable<string> assignedIps,
        IEnumerable<string> serverAllowedIps)
    {
        var taken = new HashSet<uint>(assignedIps.Select(ToUInt32));
        var serverRanges = serverAllowedIps
            .Select(ParseRange)
            .OfType<IpRange>()
            .ToArray();
        var (network, broadcast) = SubnetRange(wg);

        // network + 1 — сам сервер, клиентам достаётся со второго адреса.
        for (var candidate = network + 2; candidate < broadcast; candidate++)
        {
            // .0 и .255 внутри диапазона пропускаем: часть клиентов и роутеров
            // трактует их как адрес сети и широковещательный.
            var lastOctet = candidate & 0xFF;
            if (lastOctet is 0 or 255) continue;

            if (!taken.Contains(candidate) && !serverRanges.Any(x => x.Contains(candidate)))
                return ToIp(candidate);
        }

        throw new InvalidOperationException(
            $"В подсети {wg.SubnetAddress}/{wg.SubnetCidr} не осталось свободных адресов. " +
            "Отзовите неиспользуемые ключи или расширьте подсеть.");
    }

    private static IpRange? ParseRange(string allowedIp)
    {
        var parts = allowedIp.Trim().Split('/', 2);
        if (!IPAddress.TryParse(parts[0], out var address) ||
            address.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
            return null;

        var prefix = 32;
        if (parts.Length == 2 &&
            (!int.TryParse(parts[1], out prefix) || prefix is < 0 or > 32))
            return null;

        var value = ToUInt32(address.ToString());
        var mask = prefix == 0 ? 0u : uint.MaxValue << (32 - prefix);
        var network = value & mask;
        return new IpRange(network, network | ~mask);
    }

    private static (uint Network, uint Broadcast) SubnetRange(WgProtocolParams wg)
    {
        var network = ToUInt32(wg.SubnetAddress);

        if (!int.TryParse(wg.SubnetCidr, out var cidr) || cidr is < 8 or > 30)
            cidr = 24;

        var hostBits = 32 - cidr;
        var size = (1u << hostBits) - 1;

        // Нормализуем: в конфиге вместо адреса сети может стоять адрес хоста.
        network &= ~size;

        return (network, network + size);
    }

    private static uint ToUInt32(string ip)
    {
        var bytes = IPAddress.Parse(ip).GetAddressBytes();
        if (BitConverter.IsLittleEndian) Array.Reverse(bytes);
        return BitConverter.ToUInt32(bytes, 0);
    }

    private static string ToIp(uint value)
    {
        var bytes = BitConverter.GetBytes(value);
        if (BitConverter.IsLittleEndian) Array.Reverse(bytes);
        return new IPAddress(bytes).ToString();
    }

    private readonly record struct IpRange(uint First, uint Last)
    {
        public bool Contains(uint address) => address >= First && address <= Last;
    }
}
