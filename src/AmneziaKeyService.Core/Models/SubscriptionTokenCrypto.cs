using System.Security.Cryptography;
using System.Text;

namespace AmneziaKeyService.Core.Models;

/// <summary>
/// Токен ссылки подписки: 256 бит случайности в base64url без padding (43 символа).
/// Хеш и сравнение устроены так же, как в <see cref="RefreshTokenCrypto"/>.
/// </summary>
public static class SubscriptionTokenCrypto
{
    public const int TokenLength = 43;

    public static string Create() => Convert.ToBase64String(RandomNumberGenerator.GetBytes(32))
        .Replace('+', '-').Replace('/', '_').TrimEnd('=');

    public static string Hash(string token) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(token)));

    /// <summary>
    /// Годится ли строка на роль токена. Отсекает мусор до обращения к базе: в путь
    /// <c>/sub/{token}</c> приходит что угодно, а поиск по хешу стоит запроса.
    /// </summary>
    public static bool IsWellFormed(string? token) =>
        token is { Length: TokenLength } && token.All(c => c is (>= 'A' and <= 'Z') or (>= 'a' and <= 'z') or (>= '0' and <= '9') or '-' or '_');

    public static bool Matches(string token, string persistedHash)
    {
        try
        {
            return CryptographicOperations.FixedTimeEquals(
                Convert.FromHexString(Hash(token)), Convert.FromHexString(persistedHash));
        }
        catch (FormatException)
        {
            return false;
        }
    }
}
