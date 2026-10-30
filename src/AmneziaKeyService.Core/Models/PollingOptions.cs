namespace AmneziaKeyService.Core.Models;

/// <summary>
/// Интервалы фоновых воркеров. Вынесены в конфиг, чтобы на машине разработчика
/// их можно было приглушить или выключить целиком, не пересобирая образ:
/// четыре воркера, ходящие по SSH на боевые узлы с локального dotnet run, —
/// не то, что нужно при отладке контроллера.
/// </summary>
public class PollingOptions
{
    /// <summary>Общий выключатель: false — ни один воркер не стартует.</summary>
    public bool Enabled { get; set; } = true;

    /// <summary>Опрос счётчиков трафика.</summary>
    public int StatsIntervalSeconds { get; set; } = 60;

    /// <summary>Проверка доступности и нагрузки узлов.</summary>
    public int HealthIntervalSeconds { get; set; } = 300;

    /// <summary>Проверка сроков и квот.</summary>
    public int EnforcementIntervalSeconds { get; set; } = 60;

    /// <summary>Сверка peer-ов на узлах с выданными ключами.</summary>
    public int ReconcileIntervalHours { get; set; } = 24;

    /// <summary>
    /// Страховочная сверка подписчиков на узлах xcore: переиздаёт xcore.sync, если событие
    /// потерялось или узел разошёлся с базой.
    /// </summary>
    public int XCoreReconcileIntervalMinutes { get; set; } = 15;

    /// <summary>
    /// Как часто worker смотрит на GitHub, не вышел ли новый релиз российских списков для входов xcore.
    /// Сам релиз применяется не чаще <c>XCore:RfListsMinAgeDays</c>.
    /// </summary>
    public int XCoreGeoIntervalHours { get; set; } = 24;

    /// <summary>
    /// Сколько узлов опрашивается одновременно. Каждый узел — отдельная
    /// SSH-сессия, и на парке в сотню узлов без потолка это сотня
    /// одновременных подключений.
    /// </summary>
    public int MaxParallelServers { get; set; } = 4;

    /// <summary>
    /// Задержка перед первым тиком. Даёт миграциям отработать и не грузит
    /// старт сервиса SSH-подключениями ко всему парку разом.
    /// </summary>
    public int StartupDelaySeconds { get; set; } = 30;

    /// <summary>Расписание одного из воркеров эксплуатации.</summary>
    public WorkerSchedule For(TimeSpan interval) => new(
        Enabled,
        interval,
        TimeSpan.FromSeconds(StartupDelaySeconds),
        MaxParallelServers);
}

/// <summary>
/// Расписание фонового воркера.
///
/// Отдельная запись, а не ссылка на секцию конфига: у воркеров эксплуатации
/// и у шины событий разные выключатели. Локально <c>Polling:Enabled=false</c>
/// глушит опрос узлов — и не должен при этом останавливать обработку событий,
/// иначе панель молча перестала бы выдавать ключи.
/// </summary>
public record WorkerSchedule(
    bool Enabled,
    TimeSpan Interval,
    TimeSpan StartupDelay,
    int MaxParallel = 1);
