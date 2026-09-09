using AmneziaKeyService.Core.Models;
using AmneziaKeyService.Infrastructure.Protocols;
using AmneziaKeyService.Infrastructure.Services;

var failures = new List<string>();

void Check(string name, string expected, string actual)
{
    var ok = expected == actual;
    Console.WriteLine($"[{(ok ? "OK" : "FAIL")}] {name}: {actual}");
    if (!ok) failures.Add($"{name}: ожидался {expected}, получен {actual}");
}

var wg = new WgProtocolParams
{
    SubnetAddress = "10.8.1.0",
    SubnetCidr = "24",
    LastKnownPeerIp = "10.8.1.200",
};

var withoutRevokedFour = new[]
{
    "10.8.1.2", "10.8.1.3", "10.8.1.5", "10.8.1.6", "10.8.1.7", "10.8.1.8",
};

Check(
    "отозванный .4 переиспользуется, старый lastKnownPeerIp не мешает",
    "10.8.1.4",
    IpAllocator.SelectAvailableIp(wg, withoutRevokedFour, withoutRevokedFour.Select(x => $"{x}/32")));

Check(
    "после повторной выдачи .4 следующим становится .9",
    "10.8.1.9",
    IpAllocator.SelectAvailableIp(
        wg,
        [.. withoutRevokedFour, "10.8.1.4"],
        [.. withoutRevokedFour.Select(x => $"{x}/32"), "10.8.1.4/32"]));

Check(
    "peer, оставшийся на сервере после сбоя отзыва, сохраняет .4 занятым",
    "10.8.1.9",
    IpAllocator.SelectAvailableIp(
        wg,
        withoutRevokedFour,
        [.. withoutRevokedFour.Select(x => $"{x}/32"), "10.8.1.4/32"]));

var rawConfig = """
    [Interface]
    Address = 10.8.1.1/24

    [Peer]
    PublicKey = first
    AllowedIPs = 10.8.1.2/32

    [Peer]
    PublicKey = external
    AllowedIPs = 10.8.1.8/29, fd00::8/128
    """;

var parsed = WireGuardConfigurator.ParsePeerAllowedIps(rawConfig);
Check(
    "парсер читает несколько AllowedIPs, широкий маршрут защищает диапазон",
    "10.8.1.16",
    IpAllocator.SelectAvailableIp(
        wg,
        ["10.8.1.2", "10.8.1.3", "10.8.1.4", "10.8.1.5", "10.8.1.6", "10.8.1.7"],
        parsed));

if (failures.Count > 0)
{
    Console.Error.WriteLine(string.Join(Environment.NewLine, failures));
    return 1;
}

Console.WriteLine("Все сценарии распределения IP пройдены.");
return 0;
