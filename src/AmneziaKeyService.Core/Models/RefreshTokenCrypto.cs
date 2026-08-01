using System.Security.Cryptography;
using System.Text;

namespace AmneziaKeyService.Core.Models;

/// <summary>Opaque 256-bit refresh-token generation and non-reversible persistence representation.</summary>
public static class RefreshTokenCrypto
{
    public static string Create() => Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));

    public static string Hash(string token) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(token)));

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
