namespace AmneziaKeyService.Core.Interfaces;

/// <summary>Приращение трафика по одному ключу за интервал опроса.</summary>
public record UsageDelta(string KeyId, string ServerId, long RxBytes, long TxBytes)
{
    public bool IsEmpty => RxBytes == 0 && TxBytes == 0;
}

/// <summary>
/// Суточные срезы трафика и доступности.
///
/// Все методы записи идемпотентны по документу, но не по вызову: повторный
/// вызов с теми же приращениями сложится дважды. Это осознанно — воркер
/// считает приращения от сохранённых сырых счётчиков, поэтому «те же»
/// приращения второй раз не возникают.
/// </summary>
public interface IUsageRepository
{
    /// <summary>Одним bulk-запросом добавляет приращения по ключам за указанные сутки.</summary>
    Task IncrementKeysAsync(
        IReadOnlyCollection<UsageDelta> deltas, DateOnly day, CancellationToken ct = default);

    /// <summary>Добавляет приращение по узлу — сумму за тот же тик.</summary>
    Task IncrementServerAsync(
        string serverId, DateOnly day, long rxBytes, long txBytes, CancellationToken ct = default);

    /// <summary>Учитывает результат одной проверки доступности узла.</summary>
    Task RecordHealthCheckAsync(
        string serverId, DateOnly day, bool ok, CancellationToken ct = default);

    /// <summary>Суммарный трафик узла за период, включая обе границы.</summary>
    Task<long> SumServerTrafficAsync(
        string serverId, DateOnly from, DateOnly to, CancellationToken ct = default);

    /// <summary>Трафик по всем узлам за период — один запрос на список узлов.</summary>
    Task<Dictionary<string, long>> SumTrafficByServerAsync(
        DateOnly from, DateOnly to, CancellationToken ct = default);

    /// <summary>Суммарный трафик по всему парку за период — плитка дашборда.</summary>
    Task<long> SumTotalTrafficAsync(DateOnly from, DateOnly to, CancellationToken ct = default);

    /// <summary>
    /// Доля удачных проверок за период, 0–100. Null, если проверок не было
    /// вовсе: ноль процентов и «нет данных» — разные вещи, и рисуются по-разному.
    /// </summary>
    Task<double?> GetUptimePercentAsync(
        string serverId, DateOnly from, DateOnly to, CancellationToken ct = default);
}
