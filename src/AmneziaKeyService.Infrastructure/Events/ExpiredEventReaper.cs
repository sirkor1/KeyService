using AmneziaKeyService.Core.Interfaces;
using AmneziaKeyService.Core.Models;
using AmneziaKeyService.Infrastructure.Monitoring;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace AmneziaKeyService.Infrastructure.Events;

/// <summary>
/// Разбирает события, чью аренду перестали продлевать: процесс умер посреди
/// работы, и без вмешательства такое событие осталось бы в статусе «взято»
/// навсегда.
///
/// Решение принимает политика типа, и разница здесь принципиальная. Вернуть
/// в очередь установку, оборвавшуюся на середине, — значит запустить её поверх
/// наполовину настроенного узла. Не вернуть отзыв ключа — значит оставить
/// доступ работающим у того, кому его отозвали. Поэтому «повторять или нет»
/// объявляет обработчик, а не общий механизм.
///
/// Каждый процесс разбирает только те типы, которые сам умеет обрабатывать:
/// о чужой идемпотентности он ничего не знает.
/// </summary>
public class ExpiredEventReaper : PeriodicWorker
{
    /// <summary>Сколько событий разбирать за тик. Их не бывает много.</summary>
    private const int BatchSize = 50;

    private readonly DomainEventCatalog _catalog;

    public ExpiredEventReaper(
        IServiceScopeFactory scopeFactory,
        IOptions<EventBusOptions> options,
        DomainEventCatalog catalog,
        ILogger<ExpiredEventReaper> logger)
        : base(scopeFactory, options.Value.ReaperSchedule, logger)
        => _catalog = catalog;

    protected override string Name => "events-reaper";

    protected override async Task TickAsync(IServiceProvider services, CancellationToken ct)
    {
        var types = _catalog.HandledTypes;
        if (types.Count == 0) return;

        var events = services.GetRequiredService<IDomainEventRepository>();

        var expired = await events.FindExpiredAsync(types, BatchSize, ct);
        if (expired.Count == 0) return;

        foreach (var evt in expired)
        {
            var policy = _catalog.PolicyFor(evt.Type);

            if (policy.RetryOnLeaseExpiry && evt.Attempt < policy.MaxAttempts)
            {
                Logger.LogWarning(
                    "Событие {EventType} ({EventId}) осталось без исполнителя, возвращаю в очередь.",
                    evt.Type, evt.Id);

                await events.RequeueAsync(evt.Id, DateTime.UtcNow, countsAsAttempt: true, ct);
                continue;
            }

            var reason = policy.RetryOnLeaseExpiry
                ? "Исполнитель исчез, а попытки исчерпаны."
                : "Исполнитель исчез посреди работы, а операция не допускает повтора.";

            Logger.LogError(
                "Событие {EventType} ({EventId}) провалено: {Reason}", evt.Type, evt.Id, reason);

            await events.FailAsync(evt.Id, reason, ct);
            await NotifyFailedAsync(evt, reason, ct);
        }
    }

    /// <summary>
    /// Даёт обработчику прибрать за собой. Ровно этот путь и важен: исполнитель
    /// уже мёртв, сам он задачу установки не пометит, и без уборки панель
    /// показывала бы вечный прогресс.
    /// </summary>
    private async Task NotifyFailedAsync(DomainEvent evt, string reason, CancellationToken ct)
    {
        try
        {
            // Свой scope: обработчики scoped, а тик жнеца может задеть несколько
            // событий разных типов подряд.
            using var scope = ScopeFactory.CreateScope();

            var handler = scope.ServiceProvider.GetServices<IDomainEventHandler>()
                .FirstOrDefault(h => h.EventType == evt.Type);

            if (handler is null) return;

            await handler.OnFailedAsync(evt, reason, ct);
        }
        catch (Exception ex)
        {
            Logger.LogError(ex,
                "Обработчик {EventType} не смог прибрать за брошенным событием.", evt.Type);
        }
    }
}
