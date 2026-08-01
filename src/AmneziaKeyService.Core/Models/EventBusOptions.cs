namespace AmneziaKeyService.Core.Models;

/// <summary>
/// Настройки шины доменных событий.
///
/// Свой выключатель, отдельный от <see cref="PollingOptions"/>: остановка
/// опроса узлов на машине разработчика не должна останавливать обработку
/// событий, иначе панель молча перестала бы выдавать ключи.
/// </summary>
public class EventBusOptions
{
    public bool Enabled { get; set; } = true;

    /// <summary>
    /// Как часто диспетчер заглядывает в очередь. Секунда — это потолок
    /// задержки любой операции; на фоне выдачи ключа по SSH она незаметна.
    /// </summary>
    public int PollIntervalSeconds { get; set; } = 1;

    public int StartupDelaySeconds { get; set; } = 5;

    /// <summary>Сколько событий забирать за один тик, прежде чем уснуть.</summary>
    public int BatchSize { get; set; } = 10;

    /// <summary>
    /// Насколько событие закрепляется за процессом при захвате. Дальше срок
    /// продлевается пульсом, поэтому начальное значение важно только тем,
    /// что оно должно быть заметно больше периода пульса.
    /// </summary>
    public int LeaseTtlSeconds { get; set; } = 60;

    /// <summary>Период продления аренды на время работы обработчика.</summary>
    public int HeartbeatSeconds { get; set; } = 20;

    /// <summary>Через сколько повторить событие, чья партиция занята.</summary>
    public int PartitionBusyDelaySeconds { get; set; } = 2;

    /// <summary>Как часто разбирать события с истёкшей арендой.</summary>
    public int ReaperIntervalSeconds { get; set; } = 30;

    public WorkerSchedule DispatcherSchedule => new(
        Enabled,
        TimeSpan.FromSeconds(PollIntervalSeconds),
        TimeSpan.FromSeconds(StartupDelaySeconds));

    public WorkerSchedule ReaperSchedule => new(
        Enabled,
        TimeSpan.FromSeconds(ReaperIntervalSeconds),
        TimeSpan.FromSeconds(StartupDelaySeconds));
}
