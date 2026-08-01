using AmneziaKeyService.Core.Models;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace AmneziaKeyService.Infrastructure.Monitoring;

/// <summary>
/// Основа для воркеров, которые делают одно и то же через равные промежутки.
///
/// Берёт на себя то, в чём легко ошибиться четырежды подряд: scope на тик
/// (репозитории синглтоны, но SSH-сессии и конфигураторы — scoped), проглатывание
/// ошибки одного тика без остановки цикла и корректное завершение по стоп-токену.
///
/// Наследник получает готовый <see cref="IServiceProvider"/> тика и не думает
/// ни о времени, ни о жизненном цикле.
/// </summary>
public abstract class PeriodicWorker : BackgroundService
{
    private readonly IServiceScopeFactory _scopeFactory;
    private readonly WorkerSchedule _schedule;

    protected PeriodicWorker(
        IServiceScopeFactory scopeFactory, WorkerSchedule schedule, ILogger logger)
    {
        _scopeFactory = scopeFactory;
        _schedule     = schedule;
        Logger        = logger;
    }

    protected ILogger Logger { get; }

    /// <summary>
    /// Для наследников, которым нужен собственный scope внутри тика —
    /// например, отдельный на каждое обработанное событие.
    /// </summary>
    protected IServiceScopeFactory ScopeFactory => _scopeFactory;

    /// <summary>Имя для логов — по нему воркер ищется в Seq.</summary>
    protected abstract string Name { get; }

    /// <summary>Один проход. Исключения ловит база.</summary>
    protected abstract Task TickAsync(IServiceProvider services, CancellationToken ct);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!_schedule.Enabled)
        {
            Logger.LogInformation("Воркер {Worker} выключен настройкой.", Name);
            return;
        }

        var interval = _schedule.Interval;
        if (interval <= TimeSpan.Zero)
        {
            Logger.LogWarning(
                "Воркер {Worker} не запущен: интервал {Interval} не положителен.", Name, interval);
            return;
        }

        try
        {
            await Task.Delay(_schedule.StartupDelay, stoppingToken);
        }
        catch (OperationCanceledException)
        {
            return;
        }

        Logger.LogInformation(
            "Воркер {Worker} запущен с интервалом {IntervalSeconds} с.", Name, interval.TotalSeconds);

        // PeriodicTimer не накапливает задолженность: если тик занял больше
        // интервала, следующий просто пойдёт сразу, а не пачкой пропущенных.
        using var timer = new PeriodicTimer(interval);

        do
        {
            try
            {
                using var scope = _scopeFactory.CreateScope();
                await TickAsync(scope.ServiceProvider, stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                return;
            }
            catch (Exception ex)
            {
                // Цикл не прерываем: сбой одного тика — норма, узел мог просто
                // уйти в перезагрузку. Остановка воркера означала бы, что после
                // единственной сетевой ошибки статистика молча перестала собираться.
                Logger.LogError(ex, "Тик воркера {Worker} завершился ошибкой.", Name);
            }
        }
        while (await SafeWaitAsync(timer, stoppingToken));
    }

    private static async Task<bool> SafeWaitAsync(PeriodicTimer timer, CancellationToken ct)
    {
        try
        {
            return await timer.WaitForNextTickAsync(ct);
        }
        catch (OperationCanceledException)
        {
            return false;
        }
    }

    /// <summary>
    /// Обходит узлы с ограничением параллелизма. Ошибка одного узла не отменяет
    /// остальных — иначе один недоступный сервер лишал бы статистики весь парк.
    ///
    /// Каждый узел получает собственный scope: узлы обрабатываются параллельно,
    /// а scoped-сервисы на то и scoped, что не рассчитаны на одновременное
    /// использование из нескольких задач.
    /// </summary>
    protected async Task ForEachServerAsync(
        IEnumerable<VpnServer> servers,
        Func<IServiceProvider, VpnServer, CancellationToken, Task> action,
        CancellationToken ct)
    {
        using var slots = new SemaphoreSlim(Math.Max(1, _schedule.MaxParallel));

        var tasks = servers.Select(async server =>
        {
            await slots.WaitAsync(ct);

            // Скоуп логирования, а не подстановка в каждое сообщение: все
            // события узла получают ServerId и ServerName свойствами, и в Seq
            // история одного узла собирается запросом, а не чтением глазами.
            using var logScope = Logger.BeginScope(new Dictionary<string, object>
            {
                ["Worker"]     = Name,
                ["ServerId"]   = server.Id,
                ["ServerName"] = server.Name,
            });

            try
            {
                using var scope = _scopeFactory.CreateScope();
                await action(scope.ServiceProvider, server, ct);
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                // Остановка сервиса — не ошибка узла.
            }
            catch (Exception ex)
            {
                Logger.LogWarning(ex,
                    "Воркер {Worker}: узел {ServerName} ({ServerId}) обработать не удалось.",
                    Name, server.Name, server.Id);
            }
            finally
            {
                slots.Release();
            }
        });

        await Task.WhenAll(tasks);
    }
}
