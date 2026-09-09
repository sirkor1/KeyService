using System.Text.Json.Nodes;
using AmneziaKeyService.Core.DTOs;
using AmneziaKeyService.Core.Exceptions;
using AmneziaKeyService.Core.Interfaces;
using AmneziaKeyService.Core.Models;
using Microsoft.Extensions.Logging;
using MongoDB.Driver;

namespace AmneziaKeyService.Infrastructure.Services;

/// <summary>
/// Выдача и отзыв ключей поверх абстракции протоколов.
///
/// Сам не знает ни про WireGuard, ни про Xray: конкретика живёт
/// в <see cref="IProtocolConfigurator"/>. Здесь остаётся общее — открытие
/// SSH-сессии, работа с документами и сборка конфига vpn://.
/// </summary>
public class VpnConfigService : IVpnConfigService
{
    /// <summary>
    /// Сколько раз повторить выдачу при конфликте адресов. Конфликт означает,
    /// что параллельный запрос успел занять тот же IP; на следующей попытке
    /// аллокатор увидит его занятым и возьмёт другой.
    /// </summary>
    private const int AllocationRetries = 3;

    private readonly IVpnClientRepository _clients;
    private readonly IVpnServerRepository _servers;
    private readonly IProtocolRegistry _protocols;
    private readonly ISshSessionFactory _sshFactory;
    private readonly IVpnConfigReader _reader;
    private readonly ILogger<VpnConfigService> _logger;

    public VpnConfigService(
        IVpnClientRepository clients,
        IVpnServerRepository servers,
        IProtocolRegistry protocols,
        ISshSessionFactory sshFactory,
        IVpnConfigReader reader,
        ILogger<VpnConfigService> logger)
    {
        _clients    = clients;
        _servers    = servers;
        _protocols  = protocols;
        _sshFactory = sshFactory;
        _reader     = reader;
        _logger     = logger;
    }

    // ── Совместимость: Telegram-бот и /api/vpn/* ─────────────────────────────

    public async Task<VpnConfigResponse> GetOrCreateConfigAsync(
        string userId, string serverId, CancellationToken ct = default)
    {
        var existing = await _clients.FindByUserIdAndServerAsync(userId, serverId, ct);

        // Готовый конфиг переиспользуем: ходить на узел ради того, что уже есть,
        // незачем — а при недоступном узле это единственный рабочий путь.
        if (existing?.VpnConfigJson is not null && existing.Status == KeyStatuses.Active)
        {
            return new VpnConfigResponse(
                AmneziaUriEncoder.Encode(existing.VpnConfigJson),
                existing.AssignedIp ?? string.Empty,
                existing.ClientPubKey ?? string.Empty);
        }

        var client = await IssueAsync(
            userId, serverId, new IssueKeyOptions { Source = KeySources.Telegram }, ct);

        return ToResponse(client);
    }

    public async Task<VpnConfigResponse> CreateNewConfigAsync(
        string userId, string serverId, CancellationToken ct = default)
    {
        var client = await IssueAsync(
            userId, serverId, new IssueKeyOptions { Source = KeySources.Telegram }, ct);

        return ToResponse(client);
    }

    private static VpnConfigResponse ToResponse(VpnClient client) => new(
        AmneziaUriEncoder.Encode(client.VpnConfigJson ?? "{}"),
        client.AssignedIp ?? string.Empty,
        client.ClientPubKey ?? string.Empty);

    // ── Выдача ────────────────────────────────────────────────────────────────

    public async Task<VpnClient> IssueAsync(
        string userId, string serverId, IssueKeyOptions options, CancellationToken ct = default)
    {
        for (var attempt = 1; ; attempt++)
        {
            try
            {
                return await IssueOnceAsync(userId, serverId, options, ct);
            }
            catch (MongoWriteException ex)
                when (attempt < AllocationRetries && IsAddressAllocationConflict(ex))
            {
                _logger.LogWarning(
                    "Конфликт адресов при выдаче ключа (попытка {Attempt}). Повторяю.", attempt);
            }
        }
    }

    /// <summary>
    /// Различает две причины DuplicateKey у одного и того же write-исключения.
    ///
    /// Конфликт по уникальному индексу назначенных IP — гонка аллокатора: два
    /// параллельных запроса выбрали один адрес, и повтор со следующим свободным
    /// его решает. Конфликт по _id — совсем другое: с шага D его проставляет
    /// продюсер события, и дубликат означает, что это событие уже обработали
    /// (например, обработчик выполнил работу, но не успел закрыть событие
    /// до перезапуска). Повторять в этом случае нельзя — три лишних SSH-захода
    /// заведут и тут же откатят второй peer на уже выданном ключе. MongoDB
    /// не различает эти случаи в ServerErrorCategory, только в тексте ошибки:
    /// оба — DuplicateKey, и разница видна лишь по имени сработавшего индекса.
    /// </summary>
    private static bool IsAddressAllocationConflict(MongoWriteException ex)
        => ex.WriteError?.Category == ServerErrorCategory.DuplicateKey
           && !(ex.WriteError.Message?.Contains("index: _id_", StringComparison.Ordinal) ?? false);

    private async Task<VpnClient> IssueOnceAsync(
        string userId, string serverId, IssueKeyOptions options, CancellationToken ct)
    {
        var server = await _servers.GetByIdAsync(serverId, ct)
            ?? throw new NotFoundException($"Сервер '{serverId}' не найден.");

        var protocol = server.IssuanceProtocol(options.ProtocolId)
            ?? throw new BadRequestException("Протокол недоступен для выдачи новых ключей.");
        var configurator = _protocols.GetConfigurator(protocol.Kind);

        var client = new VpnClient
        {
            UserId            = userId,
            ServerId          = serverId,
            ProtocolId        = protocol.Id,
            ProtocolKind      = protocol.Kind,
            ShortId           = GenerateShortId(),
            OwnerName         = options.OwnerName,
            DeviceName        = options.DeviceName,
            Label             = options.Label,
            ExpiresAt         = options.ExpiryDays is { } days ? DateTime.UtcNow.AddDays(days) : null,
            TrafficLimitBytes = options.TrafficLimitBytes,
            CreatedByUserId   = options.CreatedByUserId,
            Source            = options.Source,
        };
        client.SetStatus(KeyStatuses.Active);

        // Продюсер события мог назначить идентификатор заранее — тогда его
        // 24-символьная hex-строка уходит в _id как есть. Драйвер MongoDB
        // подставляет свой ObjectId только в пустое поле, так что при KeyId
        // == null поведение не меняется: идентификатор сгенерирует драйвер.
        if (options.KeyId is not null) client.Id = options.KeyId;

        await using var ssh = await _sshFactory.ConnectAsync(server, ct);

        var peer = await configurator.AddPeerAsync(ssh, new PeerRequest(server, protocol, client), ct);

        client.AssignedIp    = peer.AssignedIp;
        client.ClientPrivKey = peer.ClientPrivKey;
        client.ClientPubKey  = peer.ClientPubKey;
        client.PskKey        = peer.PskKey;
        client.XrayClientId  = peer.XrayClientId;
        client.VpnConfigJson = VpnConfigReader.BuildConfigJson(server, protocol, client, configurator);

        try
        {
            await _clients.CreateAsync(client, ct);
        }
        catch
        {
            // Peer на узле уже заведён. Если запись не сохранилась, его надо
            // убрать, иначе он останется бесхозным и займёт адрес навсегда.
            await TryRollbackPeerAsync(ssh, server, protocol, client, configurator, ct);
            throw;
        }

        // Могли вычитаться параметры узла и сдвинуться граница адресов.
        await _servers.UpdateProtocolParamsAsync(server.Id, protocol, ct);

        await TryUpdateClientsTableAsync(ssh, server, protocol, client, add: true, ct);

        return client;
    }

    private async Task TryRollbackPeerAsync(
        ISshSession ssh, VpnServer server, ProtocolInstance protocol,
        VpnClient client, IProtocolConfigurator configurator, CancellationToken ct)
    {
        try
        {
            await configurator.RemovePeerAsync(ssh, new PeerRequest(server, protocol, client), ct);
        }
        catch (Exception ex)
        {
            // Ошибку отката не поднимаем: важнее показать исходную причину сбоя.
            _logger.LogError(ex,
                "Не удалось откатить peer на узле {Host} после неудачной записи ключа. " +
                "Peer остался на сервере и всплывёт при сверке как «сирота».", server.Host);
        }
    }

    // ── Отзыв ─────────────────────────────────────────────────────────────────

    public async Task<VpnClient> RevokeAsync(
        string clientId, string reason, string? revokedByUserId, CancellationToken ct = default)
    {
        var client = await _clients.FindByIdAsync(clientId, ct)
            ?? throw new NotFoundException("Ключ не найден.");

        if (client.Status == KeyStatuses.Revoked) return client;

        var server = await _servers.GetByIdAsync(client.ServerId, ct)
            ?? throw new NotFoundException("Сервер этого ключа не найден.");

        var protocol = VpnConfigReader.ResolveProtocol(server, client.ProtocolId);
        var configurator = _protocols.GetConfigurator(protocol.Kind);

        try
        {
            await using var ssh = await _sshFactory.ConnectAsync(server, ct);
            await configurator.RemovePeerAsync(ssh, new PeerRequest(server, protocol, client), ct);
            await TryUpdateClientsTableAsync(ssh, server, protocol, client, add: false, ct);

            client.SetStatus(KeyStatuses.Revoked);
            client.RevokedAt = DateTime.UtcNow;
        }
        catch (Exception ex) when (ex is SshConnectionException or SshCommandException)
        {
            // Узел недоступен — peer жив, доступ у клиента остался.
            // Помечать ключ отозванным было бы неправдой.
            _logger.LogError(ex,
                "Не удалось удалить peer ключа {ShortId} с узла {Host}. Помечаю как pendingRevoke.",
                client.ShortId, server.Host);

            client.SetStatus(KeyStatuses.PendingRevoke);
        }

        client.RevokedByUserId = revokedByUserId;
        client.RevokeReason    = reason;

        // Секреты после отзыва не нужны, а хранить их — лишний риск.
        client.ClientPrivKey = null;
        client.VpnConfigJson = null;

        await _clients.UpdateAsync(client, ct);
        return client;
    }

    // ── Конфиг ────────────────────────────────────────────────────────────────

    // Сборка ссылки vpn:// и клиентского файла узла не требует — этим
    // занимается VpnConfigReader, здесь только делегирование.
    public Task<string> BuildVpnUriAsync(VpnClient client, CancellationToken ct = default)
        => _reader.BuildVpnUriAsync(client, ct);

    public Task<ClientFile> BuildClientFileAsync(VpnClient client, CancellationToken ct = default)
        => _reader.BuildClientFileAsync(client, ct);

    // ── Вспомогательное ───────────────────────────────────────────────────────

    /// <summary>Короткий идентификатор в формате макета: KEY-7F3A2B.</summary>
    private static string GenerateShortId()
        => $"KEY-{Guid.NewGuid().ToString("N")[..6].ToUpperInvariant()}";

    /// <summary>
    /// Поддерживает clientsTable внутри контейнера — файл, по которому
    /// десктопный клиент Amnezia показывает список выданных клиентов.
    /// Сбой здесь не должен ронять выдачу: файл справочный.
    /// </summary>
    private async Task TryUpdateClientsTableAsync(
        ISshSession ssh, VpnServer server, ProtocolInstance protocol,
        VpnClient client, bool add, CancellationToken ct)
    {
        var clientId = client.ClientPubKey ?? client.XrayClientId;
        if (clientId is null) return;

        var path = $"/opt/amnezia/{ContainerTypeFolder(protocol.Kind)}/clientsTable";

        try
        {
            var raw = await ssh.RunAsync(
                $"docker exec -i {protocol.ContainerName} sh -c \"cat '{path}' 2>/dev/null || echo '[]'\"",
                ct);

            var table = JsonNode.Parse(
                string.IsNullOrWhiteSpace(raw.StdOut) ? "[]" : raw.StdOut) as JsonArray ?? [];

            for (var i = table.Count - 1; i >= 0; i--)
                if (table[i]?["clientId"]?.GetValue<string>() == clientId)
                    table.RemoveAt(i);

            if (add)
            {
                table.Add(new JsonObject
                {
                    ["clientId"] = clientId,
                    ["userData"] = new JsonObject
                    {
                        ["clientName"]   = client.DeviceName ?? client.OwnerName ?? client.ShortId,
                        ["creationDate"] = client.CreatedAt.ToString("yyyy-MM-ddTHH:mm:ss"),
                    },
                });
            }

            await ssh.WriteContainerFileAsync(protocol.ContainerName, path, table.ToJsonString(), ct);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex,
                "Не удалось обновить clientsTable на узле {Host}. Ключ выдан, но в списке " +
                "клиентов приложения Amnezia он не появится.", server.Host);
        }
    }

    /// <summary>Каталог протокола на узле — как в ContainerProps::containerTypeToString.</summary>
    private static string ContainerTypeFolder(string kind) => kind switch
    {
        ProtocolKinds.Awg3 or ProtocolKinds.Awg2 or ProtocolKinds.AwgLegacy => "awg",
        ProtocolKinds.WireGuard                       => "wireguard",
        ProtocolKinds.Xray                            => "xray",
        _                                             => kind,
    };
}
