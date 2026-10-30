using System.Text.Json;
using System.Text.RegularExpressions;
using AmneziaKeyService.Infrastructure.Services;

namespace AmneziaKeyService.Infrastructure.Protocols.XCore;

/// <summary>Вывод xray не удалось разобрать. Текст вывода в сообщение не попадает: в нём бывают ключи и UUID.</summary>
public sealed class XrayOutputException(string message) : Exception(message);

/// <param name="Added">Сколько пользователей добавлено.</param>
/// <param name="AlreadyExisted">Email-ы, которые уже были на узле, — не ошибка для идемпотентной синхронизации.</param>
/// <param name="Errors">Всё остальное, уже пропущенное через <see cref="SecretRedactor"/>.</param>
public sealed record XrayAddUsersResult(int Added, IReadOnlyList<string> AlreadyExisted, IReadOnlyList<string> Errors)
{
    public bool IsSuccess => Errors.Count == 0;
}

/// <param name="Removed">Сколько пользователей удалено.</param>
/// <param name="NotFound">Email-ы, которых и не было, — для удаления это не ошибка.</param>
public sealed record XrayRemoveUsersResult(int Removed, IReadOnlyList<string> NotFound, IReadOnlyList<string> Errors)
{
    public bool IsSuccess => Errors.Count == 0;
}

public sealed record XrayUserTraffic(long Uplink, long Downlink);

public sealed record XrayKeyPair(string PrivateKey, string PublicKey);

/// <summary>Пара строк из <c>xray vlessenc</c>. <paramref name="Decryption"/> содержит приватный ключ.</summary>
public sealed record XrayVlessEncryption(string Decryption, string Encryption);

public sealed record XrayConfigTestResult(bool Ok, string? Error);

/// <summary>
/// Разбор вывода команд <c>xray</c>. Все <c>xray api …</c> завершаются с кодом 0 даже при
/// ошибке, поэтому успех определяется только по тексту — и ошибается здесь молча.
/// Образцы вывода зафиксированы в tools/VerifyXCore на xray-core 26.10.21; при смене
/// версии образа их нужно сверять заново.
/// </summary>
public static partial class XrayApiOutput
{
    private const int MaxErrorLength = 300;

    [GeneratedRegex(@"^Added (\d+) user\(s\) in total\.$")]
    private static partial Regex AddedSummary();

    [GeneratedRegex(@"^Removed (\d+) user\(s\) in total\.$")]
    private static partial Regex RemovedSummary();

    [GeneratedRegex(@"^user>>>(.+)>>>traffic>>>(uplink|downlink)$")]
    private static partial Regex UserTrafficName();

    [GeneratedRegex(@"^(?:PrivateKey):\s*(\S+)$")]
    private static partial Regex PrivateKeyLine();

    // «Password (PublicKey)» — форма новых версий, «PublicKey» — прежняя.
    [GeneratedRegex(@"^(?:Password \(PublicKey\)|PublicKey):\s*(\S+)$")]
    private static partial Regex PublicKeyLine();

    [GeneratedRegex(@"^[A-Za-z0-9_-]{43}$")]
    private static partial Regex RealityKey();

    // Строка значения: «"decryption": "…"» или «"encryption": "…"», запятая после неё допустима.
    [GeneratedRegex(@"^""(decryption|encryption)""\s*:\s*""([^""]*)"",?$")]
    private static partial Regex VlessEncLine();

    // Серверная строка варианта X25519: режим native, срок билета «600s», затем 32 байта приватного ключа base64url.
    [GeneratedRegex(@"^mlkem768x25519plus\.native\.[0-9]+s\.[A-Za-z0-9_-]{43}$")]
    private static partial Regex VlessDecryptionValue();

    // Клиентская строка: тот же режим, «0rtt» и публичный ключ.
    [GeneratedRegex(@"^mlkem768x25519plus\.native\.0rtt\.[A-Za-z0-9_-]{43}$")]
    private static partial Regex VlessEncryptionValue();

    public static XrayAddUsersResult ParseAddUsers(string? output)
    {
        var added = new List<string>();
        var existed = new List<string>();
        var errors = new List<string>();
        string? current = null;
        int? summary = null;

        foreach (var line in Lines(output))
        {
            if (line.StartsWith("processing inbound:", StringComparison.Ordinal)) continue;

            if (line.StartsWith("add user:", StringComparison.Ordinal))
            {
                FlushUnconfirmed(ref current, errors, "без ответа");
                current = line["add user:".Length..].Trim();
            }
            else if (line == "result: ok" && current is not null)
            {
                added.Add(current);
                current = null;
            }
            else if (line.StartsWith("rpc error:", StringComparison.Ordinal) && current is not null)
            {
                if (line.Contains("already exists", StringComparison.Ordinal)) existed.Add(current);
                else errors.Add($"{current}: {Clip(line)}");
                current = null;
            }
            else if (AddedSummary().Match(line) is { Success: true } m)
            {
                summary = int.Parse(m.Groups[1].Value);
            }
            else
            {
                // «failed to build config: …» и любая строка, которой нет в образцах.
                errors.Add(Clip(line));
            }
        }

        FlushUnconfirmed(ref current, errors, "без ответа");

        if (summary is null)
            throw new XrayOutputException("В выводе xray api adu нет итоговой строки «Added N user(s) in total.».");
        if (summary != added.Count)
            throw new XrayOutputException(
                $"Вывод xray api adu противоречит себе: итог {summary}, подтверждено {added.Count}.");

        return new XrayAddUsersResult(added.Count, existed, errors);
    }

    public static XrayRemoveUsersResult ParseRemoveUsers(string? output)
    {
        var removed = new List<string>();
        var notFound = new List<string>();
        var errors = new List<string>();
        string? current = null;
        int? summary = null;

        // У успешного удаления нет собственной строки: оно подтверждается тем, что
        // после «remove user:» не пришло ошибки. Поэтому ожидающий пользователь
        // засчитывается удалённым, когда начинается следующий или приходит итог.
        void Settle()
        {
            if (current is not null) removed.Add(current);
            current = null;
        }

        foreach (var line in Lines(output))
        {
            if (line.StartsWith("processing inbound:", StringComparison.Ordinal)) continue;

            if (line.StartsWith("remove user:", StringComparison.Ordinal))
            {
                Settle();
                current = line["remove user:".Length..].Trim();
            }
            else if (line.StartsWith("rpc error:", StringComparison.Ordinal) && current is not null)
            {
                if (line.Contains("not found", StringComparison.Ordinal)) notFound.Add(current);
                else errors.Add($"{current}: {Clip(line)}");
                current = null;
            }
            else if (RemovedSummary().Match(line) is { Success: true } m)
            {
                Settle();
                summary = int.Parse(m.Groups[1].Value);
            }
            else
            {
                errors.Add(Clip(line));
            }
        }

        Settle();

        if (summary is null)
            throw new XrayOutputException("В выводе xray api rmu нет итоговой строки «Removed N user(s) in total.».");
        if (summary != removed.Count)
            throw new XrayOutputException(
                $"Вывод xray api rmu противоречит себе: итог {summary}, подтверждено {removed.Count}.");

        return new XrayRemoveUsersResult(removed.Count, notFound, errors);
    }

    /// <summary>Пользователи inbound-а. Пустой список xray печатает как <c>{}</c>.</summary>
    public static IReadOnlyList<XCoreUser> ParseInboundUsers(string? output)
    {
        var root = ParseJson(output, "inbounduser");
        if (!root.TryGetProperty("users", out var users)) return [];
        if (users.ValueKind != JsonValueKind.Array)
            throw new XrayOutputException("В выводе xray api inbounduser «users» — не массив.");

        var result = new List<XCoreUser>();
        foreach (var user in users.EnumerateArray())
        {
            var email = user.ValueKind == JsonValueKind.Object && user.TryGetProperty("email", out var e)
                ? e.GetString() : null;
            string? id = null;
            if (user.ValueKind == JsonValueKind.Object && user.TryGetProperty("account", out var account)
                && account.ValueKind == JsonValueKind.Object && account.TryGetProperty("id", out var i))
                id = i.GetString();

            if (string.IsNullOrEmpty(email) || string.IsNullOrEmpty(id))
                throw new XrayOutputException("В выводе xray api inbounduser у пользователя нет email или account.id.");
            result.Add(new XCoreUser(email, id));
        }
        return result;
    }

    /// <summary>
    /// Число пользователей inbound-а: <c>{"count": N}</c>, а при нуле — <c>{}</c>
    /// (proto3 не печатает нулевое поле). Если разбирать только «count», пустой inbound
    /// выглядел бы как неисправный API.
    /// </summary>
    public static int ParseInboundUserCount(string? output)
    {
        var root = ParseJson(output, "inboundusercount");
        if (!root.TryGetProperty("count", out var count)) return 0;
        if (count.ValueKind == JsonValueKind.Number && count.TryGetInt32(out var n) && n >= 0) return n;
        if (count.ValueKind == JsonValueKind.String && int.TryParse(count.GetString(), out var s) && s >= 0) return s;
        throw new XrayOutputException("В выводе xray api inboundusercount «count» — не число.");
    }

    /// <summary>
    /// Счётчики по пользователям, email → (uplink, downlink). Поле value у нулевого
    /// счётчика отсутствует — это 0. Вызывать без <c>-reset</c>: сброс со сбоем записи
    /// потерял бы трафик, а обнуление при рестарте <c>UsageMath.Delta</c> уже переживает.
    /// </summary>
    public static IReadOnlyDictionary<string, XrayUserTraffic> ParseUserTraffic(string? output)
    {
        var root = ParseJson(output, "statsquery");
        var result = new Dictionary<string, XrayUserTraffic>(StringComparer.Ordinal);
        if (!root.TryGetProperty("stat", out var stats)) return result;
        if (stats.ValueKind != JsonValueKind.Array)
            throw new XrayOutputException("В выводе xray api statsquery «stat» — не массив.");

        foreach (var stat in stats.EnumerateArray())
        {
            if (stat.ValueKind != JsonValueKind.Object || !stat.TryGetProperty("name", out var nameProp)
                || nameProp.GetString() is not { } name)
                throw new XrayOutputException("В выводе xray api statsquery счётчик без имени.");

            // Счётчики inbound-ов и outbound-ов в выборку по «user>>>» не попадают,
            // но чужое имя не повод ронять разбор.
            if (UserTrafficName().Match(name) is not { Success: true } m) continue;

            var value = ReadCounter(stat);
            var email = m.Groups[1].Value;
            var current = result.GetValueOrDefault(email) ?? new XrayUserTraffic(0, 0);
            result[email] = m.Groups[2].Value == "uplink"
                ? current with { Uplink = value }
                : current with { Downlink = value };
        }
        return result;
    }

    /// <summary>Пара ключей из <c>xray x25519</c>. Сообщения об ошибках не содержат вывода: в нём приватный ключ.</summary>
    public static XrayKeyPair ParseX25519(string? output)
    {
        string? priv = null, pub = null;
        foreach (var line in Lines(output))
        {
            if (PrivateKeyLine().Match(line) is { Success: true } p) priv = p.Groups[1].Value;
            else if (PublicKeyLine().Match(line) is { Success: true } q) pub = q.Groups[1].Value;
        }

        if (priv is null || pub is null)
            throw new XrayOutputException("В выводе xray x25519 нет приватного или публичного ключа.");
        if (!RealityKey().IsMatch(priv) || !RealityKey().IsMatch(pub))
            throw new XrayOutputException("Ключ в выводе xray x25519 не похож на base64url из 43 символов.");
        return new XrayKeyPair(priv, pub);
    }

    /// <summary>
    /// Строки <c>decryption</c> и <c>encryption</c> варианта «Authentication: X25519» из <c>xray vlessenc</c>.
    /// Команда печатает два варианта подряд (X25519 и ML-KEM-768); берётся X25519: клиентская строка у него
    /// около 75 символов против 1,6 КБ у ML-KEM-768, а ссылка с такой строкой не помещается в QR и неудобна для
    /// вставки. Обмен ключами в обоих случаях постквантовый (ML-KEM-768 в рукопожатии) — отличается только
    /// аутентификация сервера. Разбор строгий: ровно один раздел X25519, в нём ровно по одной строке каждого
    /// вида, значения целиком совпадают с ожидаемым форматом. Любое отклонение (новая версия Xray поменяла
    /// вывод) — отказ, а не догадка: строка с неверным ключом выглядела бы рабочей и не подключалась.
    /// Сообщения об ошибках не содержат вывода: в нём приватный ключ.
    /// </summary>
    public static XrayVlessEncryption ParseVlessEnc(string? output)
    {
        const string Header = "Authentication:";
        var sections = new List<(string Title, List<string> Lines)>();
        foreach (var line in Lines(output))
        {
            if (line.StartsWith(Header, StringComparison.Ordinal)) sections.Add((line[Header.Length..].Trim(), []));
            else if (sections.Count > 0) sections[^1].Lines.Add(line);
        }

        var x25519 = sections.Where(s => s.Title.StartsWith("X25519", StringComparison.Ordinal)).ToList();
        if (x25519.Count != 1)
            throw new XrayOutputException("В выводе xray vlessenc нет ровно одного раздела «Authentication: X25519».");

        var decryption = new List<string>();
        var encryption = new List<string>();
        foreach (var line in x25519[0].Lines)
        {
            if (VlessEncLine().Match(line) is not { Success: true } m) continue;
            (m.Groups[1].Value == "decryption" ? decryption : encryption).Add(m.Groups[2].Value);
        }

        if (decryption.Count != 1 || encryption.Count != 1)
            throw new XrayOutputException("В разделе X25519 вывода xray vlessenc нет ровно по одной строке decryption и encryption.");
        if (!VlessDecryptionValue().IsMatch(decryption[0]) || !VlessEncryptionValue().IsMatch(encryption[0]))
            throw new XrayOutputException("Строки decryption и encryption в выводе xray vlessenc не в ожидаемом формате.");
        return new XrayVlessEncryption(decryption[0], encryption[0]);
    }

    /// <summary>Серверная строка в формате, который выдаёт <see cref="ParseVlessEnc"/>; в конфиг не попадёт ничего иного.</summary>
    public static bool IsVlessDecryption(string? value) => value is not null && VlessDecryptionValue().IsMatch(value);

    /// <summary>Клиентская строка в формате, который выдаёт <see cref="ParseVlessEnc"/>.</summary>
    public static bool IsVlessEncryption(string? value) => value is not null && VlessEncryptionValue().IsMatch(value);

    /// <summary>Успех — только строка <c>Configuration OK.</c> и ни одной строки <c>Failed</c>.</summary>
    public static XrayConfigTestResult ParseConfigTest(string? output)
    {
        var lines = Lines(output).ToList();
        var failure = lines.FirstOrDefault(l => l.StartsWith("Failed", StringComparison.Ordinal));
        if (failure is not null) return new XrayConfigTestResult(false, Clip(failure));
        if (lines.Contains("Configuration OK.")) return new XrayConfigTestResult(true, null);
        return new XrayConfigTestResult(false, "xray run -test не подтвердил конфиг: нет строки «Configuration OK.»");
    }

    private static long ReadCounter(JsonElement stat)
    {
        if (!stat.TryGetProperty("value", out var value)) return 0;
        // int64 в protobuf-JSON бывает числом или строкой.
        if (value.ValueKind == JsonValueKind.Number && value.TryGetInt64(out var n)) return n;
        if (value.ValueKind == JsonValueKind.String && long.TryParse(value.GetString(), out var s)) return s;
        throw new XrayOutputException("В выводе xray api statsquery значение счётчика — не число.");
    }

    private static JsonElement ParseJson(string? output, string command)
    {
        if (string.IsNullOrWhiteSpace(output))
            throw new XrayOutputException($"Пустой вывод xray api {command}.");
        try
        {
            using var doc = JsonDocument.Parse(output);
            var root = doc.RootElement.Clone();
            if (root.ValueKind != JsonValueKind.Object)
                throw new XrayOutputException($"Вывод xray api {command} — не JSON-объект.");
            return root;
        }
        catch (JsonException)
        {
            // Сообщение JsonException несёт позицию, но не текст; сам вывод не цитируем.
            throw new XrayOutputException($"Вывод xray api {command} — не JSON.");
        }
    }

    private static void FlushUnconfirmed(ref string? current, List<string> errors, string reason)
    {
        if (current is not null) errors.Add($"{current}: {reason}");
        current = null;
    }

    private static IEnumerable<string> Lines(string? output) =>
        (output ?? string.Empty).Split('\n').Select(l => l.Trim()).Where(l => l.Length > 0);

    private static string Clip(string line)
    {
        var redacted = SecretRedactor.Redact(line);
        return redacted.Length <= MaxErrorLength ? redacted : redacted[..MaxErrorLength] + "…";
    }
}
