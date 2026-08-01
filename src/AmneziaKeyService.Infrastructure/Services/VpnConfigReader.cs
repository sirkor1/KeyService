using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Nodes;
using AmneziaKeyService.Core.Exceptions;
using AmneziaKeyService.Core.Interfaces;
using AmneziaKeyService.Core.Models;

namespace AmneziaKeyService.Infrastructure.Services;

/// <summary>
/// Сборка ссылки vpn:// и клиентского файла без обращения к узлу.
///
/// Все данные для конфига уже лежат в документах сервера и ключа, поэтому
/// здесь нет <see cref="ISshSessionFactory"/> — им api и бот могут пользоваться
/// без доступа к узлам. <see cref="VpnConfigService"/> переиспользует эту же
/// сборку для новых ключей, а не дублирует её.
/// </summary>
public class VpnConfigReader : IVpnConfigReader
{
    private readonly IVpnServerRepository _servers;
    private readonly IProtocolRegistry _protocols;

    public VpnConfigReader(IVpnServerRepository servers, IProtocolRegistry protocols)
    {
        _servers   = servers;
        _protocols = protocols;
    }

    public async Task<string> BuildVpnUriAsync(VpnClient client, CancellationToken ct = default)
    {
        if (client.VpnConfigJson is { } cached) return AmneziaUriEncoder.Encode(cached);

        var (server, protocol, configurator) = await ResolveAsync(client, ct);
        return AmneziaUriEncoder.Encode(BuildConfigJson(server, protocol, client, configurator));
    }

    public async Task<ClientFile> BuildClientFileAsync(VpnClient client, CancellationToken ct = default)
    {
        var (server, protocol, configurator) = await ResolveAsync(client, ct);
        return configurator.BuildClientFile(server, protocol, client);
    }

    /// <summary>
    /// Собирает JSON, который экспортирует exportController.cpp:
    /// { hostName, description, dns1, dns2, defaultContainer, containers: [...] }.
    /// </summary>
    internal static string BuildConfigJson(
        VpnServer server, ProtocolInstance protocol, VpnClient client,
        IProtocolConfigurator configurator)
    {
        var root = new JsonObject
        {
            ["hostName"]         = server.Host,
            ["description"]      = server.Name,
            ["dns1"]             = server.Dns1,
            ["dns2"]             = server.Dns2,
            ["defaultContainer"] = protocol.ContainerName,
            ["containers"]       = new JsonArray(
                configurator.BuildContainerEntry(server, protocol, client)),
        };

        // UnsafeRelaxedJsonEscaping обязателен: параметр обфускации I1 — строка
        // вида «<r 2><b 0x8580…>», и после экранирования < в &lt; конфиг
        // перестаёт работать.
        return root.ToJsonString(new JsonSerializerOptions
        {
            Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
            WriteIndented = false,
        });
    }

    // ── Вспомогательное ───────────────────────────────────────────────────────

    internal async Task<(VpnServer, ProtocolInstance, IProtocolConfigurator)> ResolveAsync(
        VpnClient client, CancellationToken ct)
    {
        var server = await _servers.GetByIdAsync(client.ServerId, ct)
            ?? throw new NotFoundException("Сервер этого ключа не найден.");

        var protocol = ResolveProtocol(server, client.ProtocolId);
        return (server, protocol, _protocols.GetConfigurator(protocol.Kind));
    }

    internal static ProtocolInstance ResolveProtocol(VpnServer server, string? protocolId)
    {
        if (protocolId is not null)
        {
            return server.FindProtocol(protocolId)
                ?? throw new NotFoundException($"Протокол '{protocolId}' на узле не найден.");
        }

        return server.DefaultProtocol
            ?? throw new NotFoundException($"На узле «{server.Name}» не настроен ни один протокол.");
    }
}
