using System.Text.RegularExpressions;

namespace AmneziaKeyService.Infrastructure.Protocols.XCore;

/// <summary>
/// Российские geo-списки на входе (релизы runetfreedom/russia-v2ray-rules-dat): имена файлов, теги, на которые
/// ссылается рендерер, адреса скачивания и разбор файла контрольных сумм. Всё, что попадает в команду для
/// shell, проверяется здесь же — репозиторий и тег приходят из настроек и с GitHub.
///
/// Теги рендерера и теги пробного конфига берутся из одних констант: если рендерер начнёт ссылаться на новый
/// тег, пробная проверка нового релиза начнёт проверять и его, и забыть добавить его в пробу нельзя.
/// </summary>
public static partial class XCoreRfLists
{
    /// <summary>Файлы релиза и имена, под которыми они лежат на узле рядом со встроенными списками образа.</summary>
    public static readonly IReadOnlyList<(string Remote, string Local)> Files =
    [
        ("geosite.dat", "rf-geosite.dat"),
        ("geoip.dat", "rf-geoip.dat"),
    ];

    public const string GeositeFile = "rf-geosite.dat";
    public const string GeoipFile = "rf-geoip.dat";

    /// <summary>Домены, заблокированные в РФ: идут через выход, даже если домен в российской зоне.</summary>
    public const string BlockedDomains = "ext:" + GeositeFile + ":ru-blocked";

    /// <summary>Адреса ресурсов, заблокированных в РФ (тег есть и в geoip.dat — проверено `run -test`).</summary>
    public const string BlockedIps = "ext:" + GeoipFile + ":ru-blocked";

    /// <summary>Ресурсы, доступные только изнутри РФ: идут со входа напрямую вместе с российскими списками.</summary>
    public const string AvailableOnlyInside = "ext:" + GeositeFile + ":ru-available-only-inside";

    /// <summary>
    /// Минимальный конфиг, ссылающийся на все теги, которые может выдать рендерер. Проверка нового релиза
    /// прогоняет его всегда: даже у входа без выходов (в его настоящем конфиге <c>ext:</c>-правил нет) релиз
    /// без нужного тега был бы отклонён сейчас, а не при добавлении первого выхода, когда он уже блокирует
    /// синхронизацию подписчиков.
    /// </summary>
    public static string ProbeConfig() =>
        "{\"log\":{\"loglevel\":\"warning\"}," +
        "\"inbounds\":[{\"tag\":\"probe\",\"listen\":\"127.0.0.1\",\"port\":10999,\"protocol\":\"dokodemo-door\"," +
        "\"settings\":{\"address\":\"127.0.0.1\",\"port\":80,\"network\":\"tcp\"}}]," +
        "\"outbounds\":[{\"tag\":\"direct\",\"protocol\":\"freedom\"}]," +
        "\"routing\":{\"rules\":[" +
        $"{{\"type\":\"field\",\"domain\":[\"{BlockedDomains}\",\"{AvailableOnlyInside}\"],\"outboundTag\":\"direct\"}}," +
        $"{{\"type\":\"field\",\"ip\":[\"{BlockedIps}\"],\"outboundTag\":\"direct\"}}]}}}}";

    [GeneratedRegex(@"\A[A-Za-z0-9][A-Za-z0-9._-]{0,63}\z")]
    private static partial Regex TagPattern();

    [GeneratedRegex(@"\A[A-Za-z0-9][A-Za-z0-9._-]{0,99}/[A-Za-z0-9._-]{1,100}\z")]
    private static partial Regex RepoPattern();

    [GeneratedRegex(@"\A[0-9a-fA-F]{64}\z")]
    private static partial Regex HexPattern();

    public static bool IsSafeTag(string? tag) => tag is not null && TagPattern().IsMatch(tag);

    public static bool IsSafeRepo(string? repo) => repo is not null && RepoPattern().IsMatch(repo.Trim());

    /// <summary>Адрес файла релиза. Тег и репозиторий должны пройти проверку: адрес подставляется в команду.</summary>
    public static string DownloadUrl(string repo, string tag, string file) =>
        $"https://github.com/{repo.Trim()}/releases/download/{tag}/{file}";

    public static string LatestReleaseApiUrl(string repo) =>
        $"https://api.github.com/repos/{repo.Trim()}/releases/latest";

    /// <summary>
    /// Новее ли <paramref name="latest"/> применённого тега. Теги runetfreedom — время релиза
    /// (<c>202610291019</c>), поэтому сравниваются как числа; тег другого вида считается новым, если просто отличается.
    /// Откат на более старый релиз ни при каком сравнении не происходит.
    /// </summary>
    public static bool IsNewer(string latest, string? applied)
    {
        if (string.IsNullOrEmpty(applied)) return true;
        if (long.TryParse(latest, out var l) && long.TryParse(applied, out var a)) return l > a;
        return !string.Equals(latest, applied, StringComparison.Ordinal);
    }

    /// <summary>
    /// Ищет в выводе <c>sha256sum</c> сумму файла <paramref name="fileName"/>. Формат строки —
    /// <c>&lt;hex&gt;␠␠имя</c> (текстовый режим) или <c>&lt;hex&gt;␠*имя</c> (двоичный): релизы runetfreedom
    /// используют второй, и разбор, ожидающий два пробела, отверг бы каждый релиз. Имя сверяется, чтобы чужая
    /// сумма из того же файла не была принята за искомую. Null — подходящей строки нет.
    /// </summary>
    public static string? ParseSha256Sum(string? text, string fileName)
    {
        if (string.IsNullOrWhiteSpace(text)) return null;

        foreach (var raw in text.Split('\n'))
        {
            var line = raw.Trim();
            if (line.Length <= 65 || !HexPattern().IsMatch(line[..64])) continue;

            var rest = line[64..];
            if (rest[0] != ' ') continue;
            // Два пробела либо пробел и «*»: после хеша обязательно ровно один разделитель режима.
            var name = rest.Length > 1 && rest[1] is ' ' or '*' ? rest[2..] : rest[1..];
            name = name.Trim();
            // sha256sum может напечатать путь: берём имя файла.
            if (name.Contains('/')) name = name[(name.LastIndexOf('/') + 1)..];
            if (string.Equals(name, fileName, StringComparison.Ordinal))
                return line[..64].ToLowerInvariant();
        }

        return null;
    }

    /// <summary>Сумма из вывода <c>sha256sum &lt;файл&gt;</c> — первое слово, 64 hex-символа.</summary>
    public static string? ParseSha256Output(string? text)
    {
        var first = text?.Trim().Split([' ', '\t', '\n', '\r'], 2, StringSplitOptions.RemoveEmptyEntries).FirstOrDefault();
        return first is not null && HexPattern().IsMatch(first) ? first.ToLowerInvariant() : null;
    }
}
