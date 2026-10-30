using AmneziaKeyService.Core.Models;
using AmneziaKeyService.Infrastructure.Subscriptions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace AmneziaKeyService.Infrastructure.Monitoring;

/// <summary>
/// Страховка для xcore.sync: раз в несколько минут просит синхронизировать каждый подходящий
/// узел. Событие могло не опубликоваться (сбой базы в момент отзыва), контейнер мог
/// перезапуститься с устаревшим файлом, оператор мог поправить узел руками.
///
/// Дёшево, потому что обработчик при совпадении ревизии и живого списка ничего не пишет на узел,
/// а <c>PublishIfNoPendingAsync</c> не копит события за недоступным узлом.
/// </summary>
public class XCoreReconcileService : PeriodicWorker
{
    public XCoreReconcileService(
        IServiceScopeFactory scopeFactory,
        IOptions<PollingOptions> options,
        ILogger<XCoreReconcileService> logger)
        : base(scopeFactory,
               options.Value.For(TimeSpan.FromMinutes(options.Value.XCoreReconcileIntervalMinutes)),
               logger)
    {
    }

    protected override string Name => "xcore-reconcile";

    protected override async Task TickAsync(IServiceProvider services, CancellationToken ct)
    {
        var published = await services.GetRequiredService<XCoreSyncPublisher>().PublishForAllAsync(null, ct);
        if (published > 0)
            Logger.LogInformation("Сверка xcore: опубликовано синхронизаций узлов — {Count}.", published);
    }
}
