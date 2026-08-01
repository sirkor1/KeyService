using System.Text.RegularExpressions;

namespace AmneziaKeyService.Infrastructure.Services;

/// <summary>
/// Вырезает секреты из строк перед записью в лог.
///
/// Прогоняется по каждой строке вывода SSH и по каждой строке лога задачи установки:
/// скрипты Amnezia печатают сгенерированные ключи в stdout, а команды docker exec
/// содержат PSK и приватные ключи прямо в аргументах.
/// </summary>
public static partial class SecretRedactor
{
    private const string Mask = "***";

    /// <summary>PEM-блок целиком, включая заголовок и тело.</summary>
    [GeneratedRegex(@"-----BEGIN [^-]+-----.*?-----END [^-]+-----",
        RegexOptions.Singleline | RegexOptions.IgnoreCase)]
    private static partial Regex PemBlock();

    /// <summary>Присваивания ключей в конфигах WireGuard/AWG: PrivateKey = ..., PresharedKey = ...</summary>
    [GeneratedRegex(@"\b(PrivateKey|PresharedKey|PublicKey|Password|passwd)\b\s*[=:]\s*\S+",
        RegexOptions.IgnoreCase)]
    private static partial Regex KeyAssignment();

    /// <summary>Голый base64 X25519-ключ: ровно 43 символа и '='.</summary>
    [GeneratedRegex(@"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{43}=(?![A-Za-z0-9+/=])")]
    private static partial Regex Base64Key();

    /// <summary>Reality-ключи и uuid из скриптов xray.</summary>
    [GeneratedRegex(@"\b(XRAY_PRIVATE_KEY|XRAY_PUBLIC_KEY|XRAY_CLIENT_ID|XRAY_SHORT_ID|WIREGUARD_SERVER_PRIVATE_KEY|WIREGUARD_PSK)\b\s*[=:]\s*\S+",
        RegexOptions.IgnoreCase)]
    private static partial Regex NamedSecret();

    /// <summary>Аргументы вида -p secret / --password secret в командах.</summary>
    [GeneratedRegex(@"(--password|--token|-p)\s+\S+", RegexOptions.IgnoreCase)]
    private static partial Regex PasswordArg();

    public static string Redact(string? text)
    {
        if (string.IsNullOrEmpty(text)) return string.Empty;

        var result = PemBlock().Replace(text, Mask);
        result = NamedSecret().Replace(result, m => $"{m.Groups[1].Value}={Mask}");
        result = KeyAssignment().Replace(result, m => $"{m.Groups[1].Value} = {Mask}");
        result = PasswordArg().Replace(result, m => $"{m.Groups[1].Value} {Mask}");
        result = Base64Key().Replace(result, Mask);

        return result;
    }

    /// <summary>Обрезает длинный вывод до хвоста заданной длины — stderr от docker build бывает огромным.</summary>
    public static string Tail(string? text, int maxChars = 2000)
    {
        var redacted = Redact(text);
        return redacted.Length <= maxChars
            ? redacted
            : string.Concat("…", redacted.AsSpan(redacted.Length - maxChars));
    }
}
