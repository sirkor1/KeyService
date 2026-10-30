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
    [GeneratedRegex(@"\b(HeaderProtectionKey|PrivateKey|PresharedKey|PublicKey|Password|passwd)\b\s*[=:]\s*\S+",
        RegexOptions.IgnoreCase)]
    private static partial Regex KeyAssignment();

    /// <summary>Голый base64 X25519-ключ: ровно 43 символа и '='.</summary>
    [GeneratedRegex(@"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{43}=(?![A-Za-z0-9+/=])")]
    private static partial Regex Base64Key();

    /// <summary>
    /// Base64url без padding ровно из 43 символов: приватный ключ Reality, токен подписки.
    /// Требуются и строчная, и заглавная буква: у случайных 32 байт шанс обойтись без
    /// одного из регистров порядка 1e-10, зато так не задеваются длинные kebab-case и
    /// snake_case имена (контейнеры, файлы), у которых заглавных нет. Цифра не требуется:
    /// её отсутствие у настоящего ключа — около 0,07%, а это утечка. Окружение не
    /// допускает соседних символов base64, чтобы не вырезать кусок из более длинной
    /// строки (тот же vpn://), и '=' после — этот случай ведёт Base64Key.
    /// Ложные срабатывания: sha256 в base64url и 43-символьные смешанно-регистровые
    /// идентификаторы без пробелов — маскируются зря, но безвредно.
    /// </summary>
    [GeneratedRegex(@"(?<![A-Za-z0-9_+/\-])(?=[A-Za-z0-9_-]{0,42}[a-z])(?=[A-Za-z0-9_-]{0,42}[A-Z])[A-Za-z0-9_-]{43}(?![A-Za-z0-9_+/=\-])")]
    private static partial Regex Base64UrlKey();

    /// <summary>
    /// UUID Xray только в контексте: <c>"id": "…"</c> (файл для adu, вывод inbounduser,
    /// в том числе внутри экранированной строки) и <c>vless://…@</c>. Голые UUID не трогаем:
    /// в логах их несёт и jti токена, и клиентский id, который не секрет.
    /// </summary>
    [GeneratedRegex(@"(?<p>\\?""id\\?""\s*:\s*\\?"")[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}(?=\\?"")")]
    private static partial Regex JsonIdUuid();

    [GeneratedRegex(@"(?<p>vless://)[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}(?=@)",
        RegexOptions.IgnoreCase)]
    private static partial Regex VlessUuid();

    /// <summary>
    /// Строка VLESS Encryption целиком, как бы она ни была записана: <c>mlkem768x25519plus.native.600s.&lt;ключ&gt;</c>
    /// (серверная — с приватным ключом) и <c>…0rtt.&lt;ключ&gt;</c> (клиентская), с необязательным набором заполнения
    /// между режимом и ключом. Общее правило для 43-символьных ключей её не ловит: в варианте ML-KEM-768 ключ
    /// в десятки раз длиннее, а у X25519 он ловится лишь пока в нём есть и строчные, и заглавные буквы. Клиентская
    /// строка не секретна, но отделять её от серверной по виду нельзя, и маскируются обе.
    /// </summary>
    [GeneratedRegex(@"(?<p>mlkem768x25519plus\.)[A-Za-z0-9_.\-]+")]
    private static partial Regex VlessEncryptionString();

    /// <summary>Токен подписки в пути: <c>/sub/&lt;token&gt;</c>. Ссылка и есть учётные данные.</summary>
    [GeneratedRegex(@"(?<p>/sub/)[A-Za-z0-9_-]{16,}")]
    private static partial Regex SubscriptionPath();

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
        result = VlessEncryptionString().Replace(result, m => m.Groups["p"].Value + Mask);
        result = NamedSecret().Replace(result, m => $"{m.Groups[1].Value}={Mask}");
        result = KeyAssignment().Replace(result, m => $"{m.Groups[1].Value} = {Mask}");
        result = PasswordArg().Replace(result, m => $"{m.Groups[1].Value} {Mask}");
        result = Base64Key().Replace(result, Mask);
        result = Base64UrlKey().Replace(result, Mask);
        result = JsonIdUuid().Replace(result, m => m.Groups["p"].Value + Mask);
        result = VlessUuid().Replace(result, m => m.Groups["p"].Value + Mask);
        result = SubscriptionPath().Replace(result, m => m.Groups["p"].Value + Mask);

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
