using AmneziaKeyService.Core.Interfaces;
using AmneziaKeyService.Core.Models;
using AmneziaKeyService.Infrastructure.Protocols.XCore;
using AmneziaKeyService.Infrastructure.Subscriptions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace AmneziaKeyService.Infrastructure.Monitoring;

/// <summary>
/// Раз в сутки (<c>Polling:XCoreGeoIntervalHours</c>) смотрит на GitHub, не вышел ли новый релиз российских
/// списков, и для каждого входа, которому он положен, публикует <c>xcore.geo_update</c>. Сам воркер на узлы не
/// ходит: скачивание, проверка и подмена файлов идут событием на партиции узла и не пересекаются с синхронизацией.
///
/// Релиз вносится не чаще чем раз в <c>XCore:RfListsMinAgeDays</c>: релизы выходят ежедневно, а каждое
/// применение — перезапуск Xray и обрыв соединений. Исключение — первая загрузка: у входа без списков срок
/// отсчитывать не от чего.
/// </summary>
public class XCoreGeoUpdateService : PeriodicWorker
{
    public XCoreGeoUpdateService(
        IServiceScopeFactory scopeFactory,
        IOptions<PollingOptions> options,
        ILogger<XCoreGeoUpdateService> logger)
        : base(scopeFactory,
               options.Value.For(TimeSpan.FromHours(options.Value.XCoreGeoIntervalHours)),
               logger)
    {
    }

    protected override string Name => "xcore-geo";

    protected override async Task TickAsync(IServiceProvider services, CancellationToken ct)
    {
        var published = await CheckAsync(services, DateTime.UtcNow, ct);
        if (published > 0)
            Logger.LogInformation("Списки РФ: опубликовано обновлений входов — {Count}.", published);
    }

    /// <summary>Один проход; возвращает число опубликованных обновлений.</summary>
    public async Task<int> CheckAsync(IServiceProvider services, DateTime now, CancellationToken ct)
    {
        var options = services.GetRequiredService<IOptions<XCoreOptions>>().Value;
        if (!options.RfListsEnabled) return 0;

        var servers = services.GetRequiredService<IVpnServerRepository>();
        var entries = XCoreSyncPublisher.GeoTargets(await servers.GetAllAsync(ct)).ToList();
        if (entries.Count == 0) return 0;

        string latest;
        try
        {
            latest = await services.GetRequiredService<IXCoreReleaseSource>().GetLatestTagAsync(options.RfListsRepo, ct);
        }
        catch (XCoreGeoException ex)
        {
            // Не трогаем ни теги, ни ошибки входов: недоступный GitHub — не проблема узла. Следующий проход повторит.
            Logger.LogWarning("Списки РФ: последний релиз не определён: {Reason}", ex.Message);
            return 0;
        }

        var publisher = services.GetRequiredService<XCoreSyncPublisher>();
        var published = 0;
        foreach (var (server, protocol) in entries)
        {
            var node = protocol.XCore!;
            var newer = XCoreRfLists.IsNewer(latest, node.RfListsTag);
            var due = string.IsNullOrEmpty(node.RfListsTag)
                || (newer && (node.RfListsAppliedAt is not { } appliedAt
                    || now - appliedAt >= TimeSpan.FromDays(Math.Max(0, options.RfListsMinAgeDays))));

            if (due)
            {
                if (await publisher.PublishGeoUpdateAsync(server.Id, protocol.Id, latest, null, ct)) published++;
                continue;
            }

            await servers.SetXCoreRfListsCheckedAsync(server.Id, protocol.Id, now, ct);
        }

        return published;
    }
}
