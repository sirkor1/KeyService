using System.Text.Json;
using System.Text.Json.Nodes;
using AmneziaKeyService.Core.Exceptions;
using AmneziaKeyService.Core.Interfaces;
using AmneziaKeyService.Core.Models;
using AmneziaKeyService.Infrastructure.Scripts;
using Microsoft.Extensions.Logging;

namespace AmneziaKeyService.Infrastructure.Protocols;

/// <summary>
/// VLESS Reality на Xray-core.
///
/// Отличается от WireGuard принципиально: список клиентов лежит в server.json
/// внутри контейнера, и после каждой правки контейнер нужно перезапустить.
/// Это роняет все активные соединения на несколько секунд — так же ведёт себя
/// оригинальный клиент Amnezia, но при массовой выдаче это заметно.
/// </summary>
public class XrayConfigurator : IProtocolConfigurator
{
    private const string Flow = "xtls-rprx-vision";

    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    private readonly ScriptRegistry _scripts;
    private readonly ILogger<XrayConfigurator> _logger;

    public XrayConfigurator(ScriptRegistry scripts, ILogger<XrayConfigurator> logger)
    {
        _scripts = scripts;
        _logger  = logger;
    }

    public string Kind => ProtocolKinds.Xray;

    public async Task<bool> EnsureServerParamsAsync(
        ISshSession ssh, VpnServer server, ProtocolInstance protocol, CancellationToken ct = default)
    {
        var xray = RequireXray(protocol);
        if (xray.PublicKey is not null && xray.ShortId is not null) return false;

        // Приватный ключ Reality остаётся на сервере: клиенту он не нужен,
        // а его утечка позволила бы выдавать себя за узел.
        xray.PublicKey = (await ssh.ReadContainerFileAsync(
            protocol.ContainerName, "/opt/amnezia/xray/xray_public.key", ct)).Trim();

        xray.ShortId = (await ssh.ReadContainerFileAsync(
            protocol.ContainerName, "/opt/amnezia/xray/xray_short_id.key", ct)).Trim();

        protocol.LastSyncedAt = DateTime.UtcNow;
        return true;
    }

    public async Task<IssuedPeer> AddPeerAsync(
        ISshSession ssh, PeerRequest request, CancellationToken ct = default)
    {
        var (server, protocol, _) = request;
        var xray = RequireXray(protocol);

        await EnsureServerParamsAsync(ssh, server, protocol, ct);

        // uuid генерируется здесь, а не на узле: так же делает xray_configurator.cpp.
        var clientId = Guid.NewGuid().ToString();

        var config = await LoadServerConfigAsync(ssh, protocol, xray, ct);
        var clients = GetClientsArray(config);

        clients.Add(new JsonObject { ["id"] = clientId, ["flow"] = Flow });

        await SaveServerConfigAsync(ssh, protocol, xray, config, ct);
        await RestartAsync(ssh, protocol, ct);

        return new IssuedPeer { XrayClientId = clientId };
    }

    public async Task RemovePeerAsync(
        ISshSession ssh, PeerRequest request, CancellationToken ct = default)
    {
        var (_, protocol, client) = request;
        var xray = RequireXray(protocol);

        if (string.IsNullOrEmpty(client.XrayClientId))
            throw new InvalidOperationException("У ключа нет идентификатора Xray — нечего удалять.");

        var config = await LoadServerConfigAsync(ssh, protocol, xray, ct);
        var clients = GetClientsArray(config);

        var removed = false;
        for (var i = clients.Count - 1; i >= 0; i--)
        {
            if (clients[i] is JsonObject entry &&
                entry["id"]?.GetValue<string>() == client.XrayClientId)
            {
                clients.RemoveAt(i);
                removed = true;
            }
        }

        if (!removed)
        {
            // Идемпотентность: peer уже удалён — перезапускать контейнер незачем.
            _logger.LogInformation(
                "Клиент {ClientId} отсутствует в конфиге Xray на узле — отзыв считаем выполненным.",
                client.XrayClientId);
            return;
        }

        await SaveServerConfigAsync(ssh, protocol, xray, config, ct);
        await RestartAsync(ssh, protocol, ct);
    }

    public JsonObject BuildContainerEntry(
        VpnServer server, ProtocolInstance protocol, VpnClient client)
    {
        var xray = RequireXray(protocol);

        var vars = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["SERVER_IP_ADDRESS"] = server.Host,
            ["XRAY_SERVER_PORT"]  = protocol.Port,
            ["XRAY_CLIENT_ID"]    = client.XrayClientId ?? string.Empty,
            ["XRAY_SITE_NAME"]    = xray.SiteName,
            ["XRAY_PUBLIC_KEY"]   = xray.PublicKey ?? string.Empty,
            ["XRAY_SHORT_ID"]     = xray.ShortId ?? string.Empty,
        };

        var template = _scripts.Read("xray/template.json");
        var rendered = ScriptTemplateRenderer.Render(template, vars);

        // Незамещённый плейсхолдер даёт внешне валидный конфиг, который молча
        // не подключается. Оригинальный конфигуратор проверяет то же самое.
        ScriptTemplateRenderer.EnsureNoPlaceholdersLeft(
            rendered, "XRAY_CLIENT_ID", "XRAY_PUBLIC_KEY", "XRAY_SHORT_ID");

        return new JsonObject
        {
            ["container"] = protocol.ContainerName,
            ["xray"] = new JsonObject
            {
                ["port"]            = protocol.Port,
                ["transport_proto"] = protocol.TransportProto,
                ["last_config"]     = rendered,
            },
        };
    }

    public ClientFile BuildClientFile(VpnServer server, ProtocolInstance protocol, VpnClient client)
    {
        var entry = BuildContainerEntry(server, protocol, client);
        var lastConfig = entry["xray"]?["last_config"]?.GetValue<string>() ?? "{}";

        return new ClientFile(
            FileName: $"{client.ShortId ?? "amnezia"}-xray.json",
            ContentType: "application/json; charset=utf-8",
            Content: lastConfig);
    }

    // ── Работа с server.json ──────────────────────────────────────────────────

    private static async Task<JsonObject> LoadServerConfigAsync(
        ISshSession ssh, ProtocolInstance protocol, XrayProtocolParams xray, CancellationToken ct)
    {
        var raw = await ssh.ReadContainerFileAsync(protocol.ContainerName, xray.ServerConfigPath, ct);

        return JsonNode.Parse(raw) as JsonObject
            ?? throw new InvalidOperationException(
                "server.json на узле повреждён: ожидался объект JSON.");
    }

    private static Task SaveServerConfigAsync(
        ISshSession ssh, ProtocolInstance protocol, XrayProtocolParams xray,
        JsonObject config, CancellationToken ct)
        => ssh.WriteContainerFileAsync(
            protocol.ContainerName, xray.ServerConfigPath, config.ToJsonString(JsonOptions), ct);

    /// <summary>
    /// Достаёт inbounds[0].settings.clients, создавая недостающие узлы.
    /// Структуру задаёт configure_container.sh из upstream.
    /// </summary>
    private static JsonArray GetClientsArray(JsonObject config)
    {
        if (config["inbounds"] is not JsonArray { Count: > 0 } inbounds ||
            inbounds[0] is not JsonObject inbound)
        {
            throw new InvalidOperationException(
                "В server.json на узле нет секции inbounds — контейнер настроен не по схеме Amnezia.");
        }

        if (inbound["settings"] is not JsonObject settings)
        {
            settings = new JsonObject();
            inbound["settings"] = settings;
        }

        if (settings["clients"] is not JsonArray clients)
        {
            clients = new JsonArray();
            settings["clients"] = clients;
        }

        return clients;
    }

    private static Task RestartAsync(ISshSession ssh, ProtocolInstance protocol, CancellationToken ct)
        => ssh.RunCheckedAsync($"docker restart {protocol.ContainerName}", "restart_xray", ct);

    private static XrayProtocolParams RequireXray(ProtocolInstance protocol)
        => protocol.Xray
           ?? throw new NotFoundException($"У протокола {protocol.Kind} нет параметров Xray.");
}
