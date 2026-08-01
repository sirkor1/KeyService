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
/// Занятыми считаются адреса неотозванных ключей плюс весь диапазон до
/// lastKnownPeerIp: на узле есть peer-ы, заведённые мимо сервиса (у боевого
/// узла их 13), и пересечение с ними ломает обе стороны.
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
        VpnServer server, ProtocolInstance protocol, CancellationToken ct = default)
    {
        var wg = protocol.Wg
            ?? throw new InvalidOperationException(
                $"Протокол {protocol.Kind} не использует туннельные адреса.");

        var taken = await LoadTakenAsync(server.Id, protocol.Id, wg, ct);
        var (network, broadcast) = SubnetRange(wg);

        // network + 1 — сам сервер, клиентам достаётся со второго адреса.
        for (var candidate = network + 2; candidate < broadcast; candidate++)
        {
            // .0 и .255 внутри диапазона пропускаем: часть клиентов и роутеров
            // трактует их как адрес сети и широковещательный.
            var lastOctet = candidate & 0xFF;
            if (lastOctet is 0 or 255) continue;

            if (!taken.Contains(candidate)) return ToIp(candidate);
        }

        throw new InvalidOperationException(
            $"В подсети {wg.SubnetAddress}/{wg.SubnetCidr} не осталось свободных адресов. " +
            "Отзовите неиспользуемые ключи или расширьте подсеть.");
    }

    private async Task<HashSet<uint>> LoadTakenAsync(
        string serverId, string protocolId, WgProtocolParams wg, CancellationToken ct)
    {
        var assigned = await _clients.GetAssignedIpsAsync(serverId, protocolId, ct);
        var taken = new HashSet<uint>(assigned.Select(ToUInt32));

        if (wg.LastKnownPeerIp is { } last && IPAddress.TryParse(last, out _))
        {
            var boundary = ToUInt32(last);
            var (network, _) = SubnetRange(wg);

            for (var addr = network + 1; addr <= boundary; addr++)
                taken.Add(addr);
        }

        return taken;
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
}
