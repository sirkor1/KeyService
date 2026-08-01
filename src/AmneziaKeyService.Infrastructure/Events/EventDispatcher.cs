using AmneziaKeyService.Core.Interfaces;
using AmneziaKeyService.Core.Models;
using AmneziaKeyService.Infrastructure.Monitoring;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using MongoDB.Bson;

namespace AmneziaKeyService.Infrastructure.Events;

/// <summary>
/// Забирает события из очереди и отдаёт их обработчикам.
///
/// Конкурирующие потребители: несколько экземпляров процесса могут работать
/// одновременно, потому что захват атомарен. Ограничение только одно —
/// события с общим ключом партиции исполняются строго по одному:
/// две правки конфига WireGuard на одном узле теряют peer-ов.
/// </summary>
public class EventDispatcher : PeriodicWorker
{
    private readonly EventBusOptions _options;
    private readonly DomainEventCatalog _catalog;

    /// <summary>
    /// Кто мы для аренд. Идентификатор процесса плюс случайный хвост:
    /// в логах видно машину, а хвост различает перезапуски — иначе поднявшийся
    /// процесс унаследовал бы аренды своего предшественника.
    /// </summary>
    private readonly string _owner =
        $"{Environment.MachineName}/{Environment.ProcessId}/{Guid.NewGuid().ToString("N")[..6]}";

    public EventDispatcher(
        IServiceScopeFactory scopeFactory,
        IOptions<EventBusOptions> options,
        DomainEventCatalog catalog,
        ILogger<EventDispatcher> logger)
        : base(scopeFactory, options.Value.DispatcherSchedule, logger)
    {
        _options = options.Value;
        _catalog = catalog;
    }

    protected override string Name => "events";

    private TimeSpan LeaseTtl => TimeSpan.FromSeconds(_options.LeaseTtlSeconds);

    protected override async Task TickAsync(IServiceProvider services, CancellationToken ct)
    {
        var types = _catalog.HandledTypes;
        if (types.Count == 0) return;

        var events = services.GetRequiredService<IDomainEventRepository>();

        // Берём пачкой, пока есть что брать: при всплеске нагрузки ждать
        // секунду между событиями незачем.
        for (var taken = 0; taken < _options.BatchSize && !ct.IsCancellationRequested; taken++)
        {
            var evt = await events.ClaimAsync(types, _owner, LeaseTtl, ct);
            if (evt is null) return;

            await ExecuteAsync(evt, ct);
        }
    }

    private async Task ExecuteAsync(DomainEvent evt, CancellationToken ct)
    {
        using var logScope = Logger.BeginScope(new Dictionary<string, object>
        {
            ["EventId"]       = evt.Id,
            ["EventType"]     = evt.Type,
            ["CorrelationId"] = evt.CorrelationId ?? string.Empty,
            ["Attempt"]       = evt.Attempt,
        });

        // Scope на событие, а не на тик: обработчики scoped, и делить их
        // между двумя событиями подряд означало бы делить их состояние.
        using var scope = ScopeFactory.CreateScope();
        var services = scope.ServiceProvider;

        var events = services.GetRequiredService<IDomainEventRepository>();
        var leases = services.GetRequiredService<ILeaseRepository>();

        var partition = evt.PartitionKey is null ? null : LeaseKeys.Partition(evt.PartitionKey);

        if (partition is not null &&
            !await leases.TryAcquireAsync(partition, _owner, LeaseTtl, ct))
        {
            // Узел занят другой операцией. Возвращаем событие, не сжигая
            // попытку: работа так и не начиналась.
            Logger.LogDebug("Партиция {PartitionKey} занята, откладываю.", evt.PartitionKey);

            await events.RequeueAsync(
                evt.Id,
                DateTime.UtcNow.AddSeconds(_options.PartitionBusyDelaySeconds),
                countsAsAttempt: false,
                ct);

            return;
        }

        try
        {
            var handler = services.GetServices<IDomainEventHandler>()
                .FirstOrDefault(h => h.EventType == evt.Type);

            if (handler is null)
            {
                // Каталог собран по тем же обработчикам, поэтому сюда можно
                // попасть только при рассогласовании регистрации. Молчать
                // нельзя: событие иначе крутилось бы в очереди вечно.
                await events.FailAsync(evt.Id, $"Нет обработчика для события «{evt.Type}».", ct);
                Logger.LogError("Нет обработчика для события {EventType}.", evt.Type);
                return;
            }

            await RunAsync(handler, evt, events, leases, partition, ct);

        }
        finally
        {
            if (partition is not null)
                await leases.ReleaseAsync(partition, _owner, CancellationToken.None);
        }
    }

    private async Task RunAsync(
        IDomainEventHandler handler,
        DomainEvent evt,
        IDomainEventRepository events,
        ILeaseRepository leases,
        string? partition,
        CancellationToken ct)
    {
        // Отдельный источник отмены: его дёргает пульс, если аренду отобрали.
        // Продолжать работу, которую уже забрал другой процесс, нельзя —
        // получилось бы два исполнителя одной операции.
        using var work = CancellationTokenSource.CreateLinkedTokenSource(ct);
        using var heartbeatStop = new CancellationTokenSource();

        var heartbeat = HeartbeatAsync(events, leases, evt.Id, partition, work, heartbeatStop.Token);

        try
        {
            var result = await handler.HandleAsync(evt, work.Token);

            await events.CompleteAsync(evt.Id, result, CancellationToken.None);
            Logger.LogInformation("Событие {EventType} выполнено.", evt.Type);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            // Останов процесса. Аренду не снимаем и статус не трогаем: она
            // истечёт сама, а жнец поступит по политике типа. Для установки
            // это провал, для отзыва — повтор, и решать здесь мы не вправе.
            Logger.LogWarning("Событие {EventType} прервано остановом процесса.", evt.Type);
        }
        catch (OperationCanceledException)
        {
            Logger.LogWarning("Событие {EventType} прервано: аренда потеряна.", evt.Type);
        }
        catch (Exception ex)
        {
            await FailOrRetryAsync(events, handler, evt, ex);
        }
        finally
        {
            await heartbeatStop.CancelAsync();
            await heartbeat;
        }
    }

    private async Task FailOrRetryAsync(
        IDomainEventRepository events, IDomainEventHandler handler, DomainEvent evt, Exception ex)
    {
        // Наружу уходит только безопасный текст: сообщения SSH-исключений
        // не содержат ни команды, ни stderr — см. SshCommandException.
        var message = ex.Message;
        var policy = handler.Policy;

        if (evt.Attempt < policy.MaxAttempts)
        {
            Logger.LogWarning(ex,
                "Событие {EventType} не удалось (попытка {Attempt} из {MaxAttempts}), повторю.",
                evt.Type, evt.Attempt, policy.MaxAttempts);

            await events.RequeueAsync(
                evt.Id, DateTime.UtcNow + policy.RetryBackoff, countsAsAttempt: true,
                CancellationToken.None);

            return;
        }

        Logger.LogError(ex, "Событие {EventType} провалено окончательно.", evt.Type);
        await events.FailAsync(evt.Id, message, CancellationToken.None);

        await NotifyFailedAsync(handler, evt, message);
    }

    /// <summary>
    /// Даёт обработчику прибрать за собой видимое оператору состояние.
    /// Ошибку уборки глотаем: событие уже провалено, и второй сбой поверх
    /// первого только запутает картину в логе.
    /// </summary>
    private async Task NotifyFailedAsync(IDomainEventHandler handler, DomainEvent evt, string error)
    {
        try
        {
            await handler.OnFailedAsync(evt, error, CancellationToken.None);
        }
        catch (Exception ex)
        {
            Logger.LogError(ex,
                "Обработчик {EventType} не смог прибрать за проваленным событием.", evt.Type);
        }
    }

    /// <summary>
    /// Продлевает аренду события и партиции, пока идёт работа. Потеря любой
    /// из них означает, что нас вытеснили, — и тогда работу надо прервать.
    /// </summary>
    private async Task HeartbeatAsync(
        IDomainEventRepository events,
        ILeaseRepository leases,
        string eventId,
        string? partition,
        CancellationTokenSource work,
        CancellationToken stop)
    {
        var period = TimeSpan.FromSeconds(Math.Max(1, _options.HeartbeatSeconds));
        using var timer = new PeriodicTimer(period);

        try
        {
            while (await timer.WaitForNextTickAsync(stop))
            {
                var held = await events.RenewLeaseAsync(eventId, _owner, LeaseTtl, stop);

                if (held && partition is not null)
                    held = await leases.RenewAsync(partition, _owner, LeaseTtl, stop);

                if (held) continue;

                Logger.LogWarning("Аренда события {EventId} потеряна, прерываю работу.", eventId);
                await work.CancelAsync();
                return;
            }
        }
        catch (OperationCanceledException)
        {
            // Штатное завершение пульса вместе с работой.
        }
    }
}
