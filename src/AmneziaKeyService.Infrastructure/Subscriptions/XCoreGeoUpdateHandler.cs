using AmneziaKeyService.Core.Interfaces;
using AmneziaKeyService.Core.Models;
using AmneziaKeyService.Infrastructure.Events;
using AmneziaKeyService.Infrastructure.Protocols.XCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using MongoDB.Bson;

namespace AmneziaKeyService.Infrastructure.Subscriptions;

/// <summary>
/// Кладёт на вход новый релиз российских списков (<see cref="XCoreGeoService"/>) и просит синхронизацию
/// применить его в конфиге. Событие делит партицию с <c>xcore.sync</c>: подмена файлов и рестарт не идут
/// параллельно с синхронизацией узла.
///
/// Тег в базу пишется после подмены файлов, а не до: по нему рендерер решает, ссылаться ли конфигу на
/// <c>ext:rf-…</c>, и тег без файла сломал бы запуск контейнера.
/// </summary>
public class XCoreGeoUpdateHandler : IDomainEventHandler
{
    private const string FailureFallback = "Не удалось обновить российские списки.";

    private readonly IVpnServerRepository _servers;
    private readonly ISshSessionFactory _sshFactory;
    private readonly XCoreGeoService _geo;
    private readonly IXCoreReleaseSource _releases;
    private readonly XCoreSyncPublisher _publisher;
    private readonly XCoreOptions _options;
    private readonly ILogger<XCoreGeoUpdateHandler> _logger;

    public XCoreGeoUpdateHandler(
        IVpnServerRepository servers,
        ISshSessionFactory sshFactory,
        XCoreGeoService geo,
        IXCoreReleaseSource releases,
        XCoreSyncPublisher publisher,
        IOptions<XCoreOptions> options,
        ILogger<XCoreGeoUpdateHandler> logger)
    {
        _servers    = servers;
        _sshFactory = sshFactory;
        _geo        = geo;
        _releases   = releases;
        _publisher  = publisher;
        _options    = options.Value;
        _logger     = logger;
    }

    public string EventType => DomainEventTypes.XCoreGeoUpdate;

    /// <summary>
    /// Идемпотентна: тот же тег — ничего не делается, прерванное скачивание стартует заново с чистого каталога
    /// кандидатов, а рабочие файлы меняются только после проверки. Повторы нужны недоступному узлу; ожидаемые
    /// отказы (сумма не совпала, Xray отклонил список) повторять бессмысленно, и они записываются сразу.
    /// </summary>
    public DomainEventPolicy Policy => DomainEventPolicy.Retrying(3, TimeSpan.FromMinutes(2));

    public async Task<BsonDocument?> HandleAsync(DomainEvent evt, CancellationToken ct)
    {
        var payload = evt.PayloadAs<XCoreGeoUpdatePayload>();

        var server = await _servers.GetByIdAsync(payload.ServerId, ct);
        var protocol = server?.FindProtocol(payload.ProtocolId);
        if (server is null || protocol is not { Kind: ProtocolKinds.XCore, XCore.Role: XCoreRoles.Entry }
            || protocol.State != ProtocolStates.Installed)
            return Skipped(payload.ServerId, "not_applicable");
        if (!_options.RfListsEnabled)
            return Skipped(server.Id, "disabled");

        var node = protocol.XCore!;
        string tag;
        try
        {
            tag = payload.Tag ?? await _releases.GetLatestTagAsync(_options.RfListsRepo, ct);
        }
        catch (XCoreGeoException ex)
        {
            await _servers.SetXCoreGeoErrorAsync(server.Id, protocol.Id, XCoreSyncHandler.SafeError(ex.Message, FailureFallback), ct);
            return Failed(server.Id, ex.Message);
        }

        if (tag == node.RfListsTag)
        {
            // Тот же релиз: узел не трогаем, но проверка состоялась — оператор видит свежую дату.
            await _servers.SetXCoreRfListsCheckedAsync(server.Id, protocol.Id, DateTime.UtcNow, ct);
            return Skipped(server.Id, "same_tag");
        }

        var exits = XCoreTopology.ExitTargets(await _servers.GetAllAsync(ct));
        await using var ssh = await _sshFactory.ConnectAsync(server, ct);
        try
        {
            await _geo.UpdateAsync(ssh, protocol, tag, exits, ct);
        }
        catch (XCoreGeoException ex)
        {
            _logger.LogWarning("Узел xcore {ServerName}: списки РФ релиза {Tag} не применены: {Reason}", server.Name, tag, ex.Message);
            await _servers.SetXCoreGeoErrorAsync(server.Id, protocol.Id, XCoreSyncHandler.SafeError(ex.Message, FailureFallback), ct);
            return Failed(server.Id, ex.Message);
        }

        await _servers.MarkXCoreRfListsAppliedAsync(server.Id, protocol.Id, tag, DateTime.UtcNow, ct);
        _logger.LogInformation("Узел xcore {ServerName}: российские списки релиза {Tag} положены на узел.", server.Name, tag);

        // Конфиг с ext-правилами и перезапуск Xray применяет синхронизация: она читает тег из базы. Сбой
        // публикации не бросается — узел догонит периодическая сверка.
        await _publisher.PublishForNodeAsync(server.Id, protocol.Id, evt.ActorUserId, ct);

        return new BsonDocument { ["serverId"] = server.Id, ["tag"] = tag };
    }

    /// <summary>
    /// Недоступный узел или иной сбой, исчерпавший повторы: оператор видит причину рядом со списками, а не в
    /// логах worker.
    /// </summary>
    public async Task OnFailedAsync(DomainEvent evt, string error, CancellationToken ct)
    {
        var payload = evt.PayloadAs<XCoreGeoUpdatePayload>();
        await _servers.SetXCoreGeoErrorAsync(
            payload.ServerId, payload.ProtocolId, XCoreSyncHandler.SafeError(error, FailureFallback), ct);
    }

    private static BsonDocument Skipped(string serverId, string reason) =>
        new() { ["serverId"] = serverId, ["skipped"] = reason };

    private static BsonDocument Failed(string serverId, string reason) =>
        new() { ["serverId"] = serverId, ["error"] = XCoreSyncHandler.SafeError(reason, FailureFallback) };
}
