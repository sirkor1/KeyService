namespace AmneziaKeyService.Infrastructure.Monitoring;

/// <summary>Строка peer-а из вывода <c>wg show &lt;iface&gt; dump</c>.</summary>
/// <param name="PublicKey">Публичный ключ клиента — по нему peer сопоставляется с выданным ключом.</param>
/// <param name="Endpoint">Адрес клиента или null, если соединения ещё не было.</param>
/// <param name="AllowedIps">Туннельный адрес peer-а, обычно один /32.</param>
/// <param name="LatestHandshake">Момент последнего хэндшейка; null, если его не было.</param>
/// <param name="RxBytes">Сырой счётчик приёма с момента старта контейнера.</param>
/// <param name="TxBytes">Сырой счётчик передачи с момента старта контейнера.</param>
public record WgPeer(
    string PublicKey,
    string? Endpoint,
    string? AllowedIps,
    DateTime? LatestHandshake,
    long RxBytes,
    long TxBytes);

/// <summary>
/// Разбор машиночитаемого вывода <c>wg show &lt;iface&gt; dump</c>.
///
/// Именно dump, а не <c>wg show</c>: последний рассчитан на чтение человеком,
/// его раскладка менялась между версиями инструмента и зависит от ширины
/// терминала. Формат dump — TSV и стабилен: первая строка описывает сам
/// интерфейс (4 поля), каждая следующая — peer (8 полей).
///
/// Строка интерфейса содержит приватный ключ сервера. Парсер её отбрасывает
/// и наружу не отдаёт: в модели <see cref="WgPeer"/> для неё просто нет места.
/// </summary>
public static class WgDumpParser
{
    private const int PeerFieldCount = 8;

    /// <summary>Значение, которым wg обозначает отсутствие поля.</summary>
    private const string None = "(none)";

    public static List<WgPeer> Parse(string? dump)
    {
        var peers = new List<WgPeer>();
        if (string.IsNullOrWhiteSpace(dump)) return peers;

        foreach (var line in dump.Split('\n'))
        {
            var fields = line.TrimEnd('\r').Split('\t');

            // Отбор по числу полей, а не «пропустить первую строку»: если
            // команда что-то допишет в stdout, разбор не съедет на peer-ы.
            if (fields.Length != PeerFieldCount) continue;

            var publicKey = fields[0].Trim();
            if (publicKey.Length == 0 || publicKey == None) continue;

            peers.Add(new WgPeer(
                PublicKey:       publicKey,
                Endpoint:        Nullable(fields[2]),
                AllowedIps:      Nullable(fields[3]),
                LatestHandshake: ParseHandshake(fields[4]),
                RxBytes:         ParseCounter(fields[5]),
                TxBytes:         ParseCounter(fields[6])));
        }

        return peers;
    }

    private static string? Nullable(string field)
    {
        var value = field.Trim();
        return value.Length == 0 || value == None ? null : value;
    }

    /// <summary>Unix-время последнего хэндшейка. Ноль означает «хэндшейка не было».</summary>
    private static DateTime? ParseHandshake(string field)
        => long.TryParse(field.Trim(), out var seconds) && seconds > 0
            ? DateTimeOffset.FromUnixTimeSeconds(seconds).UtcDateTime
            : null;

    private static long ParseCounter(string field)
        => long.TryParse(field.Trim(), out var value) && value > 0 ? value : 0;
}
