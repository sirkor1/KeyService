using System.Security.Cryptography;
using System.Text;
using AmneziaKeyService.Core.Interfaces;
using AmneziaKeyService.Core.Models;
using Microsoft.Extensions.Options;

namespace AmneziaKeyService.Infrastructure.Services;

/// <summary>
/// AES-256-GCM поверх System.Security.Cryptography — без внешних зависимостей.
///
/// Намеренно не ASP.NET DataProtection: его key-ring живёт файлами в volume,
/// и при пересоздании контейнера все ранее зашифрованные значения становятся
/// нечитаемыми. Здесь ключ приходит из конфига и переживает любой передеплой.
///
/// Границы защиты: это защита от дампа базы, но не от компрометации хоста —
/// ключ лежит в том же .env на той же машине, что и MongoDB.
/// </summary>
public class AesGcmSecretProtector : ISecretProtector
{
    private const int NonceSize = 12;   // рекомендованный размер для GCM
    private const int TagSize   = 16;
    private const int KeySize   = 32;   // AES-256

    private readonly Dictionary<string, byte[]> _keys;
    private readonly string _activeKeyId;

    public AesGcmSecretProtector(IOptions<SecurityOptions> options)
    {
        var opts = options.Value;
        _keys = BuildKeyRing(opts);

        _activeKeyId = opts.ActiveKeyId;
        if (!_keys.ContainsKey(_activeKeyId))
            throw new InvalidOperationException(
                $"Security:ActiveKeyId = '{_activeKeyId}', но ключ с таким Id не задан в Security:Keys.");
    }

    private static Dictionary<string, byte[]> BuildKeyRing(SecurityOptions opts)
    {
        var ring = new Dictionary<string, byte[]>(StringComparer.Ordinal);

        foreach (var entry in opts.Keys)
            ring[entry.Id] = DecodeKey(entry.Base64Key, $"Security:Keys[{entry.Id}]");

        // Упрощённый режим с одним ключом
        if (ring.Count == 0 && !string.IsNullOrWhiteSpace(opts.DataProtectionKey))
            ring["default"] = DecodeKey(opts.DataProtectionKey, "Security:DataProtectionKey");

        if (ring.Count == 0)
            throw new InvalidOperationException(
                "Не задан ключ шифрования секретов. Укажите Security:DataProtectionKey " +
                "(32 байта в base64) или заполните Security:Keys.");

        return ring;
    }

    private static byte[] DecodeKey(string base64, string configPath)
    {
        byte[] key;
        try
        {
            key = Convert.FromBase64String(base64);
        }
        catch (FormatException)
        {
            throw new InvalidOperationException($"{configPath}: значение не является корректным base64.");
        }

        if (key.Length != KeySize)
            throw new InvalidOperationException(
                $"{configPath}: ожидается ключ длиной {KeySize} байт (AES-256), получено {key.Length}.");

        return key;
    }

    public EncryptedValue? Protect(string? plainText)
    {
        if (string.IsNullOrEmpty(plainText)) return null;

        var key       = _keys[_activeKeyId];
        var plain     = Encoding.UTF8.GetBytes(plainText);
        var nonce     = RandomNumberGenerator.GetBytes(NonceSize);
        var cipher    = new byte[plain.Length];
        var tag       = new byte[TagSize];

        using var aes = new AesGcm(key, TagSize);
        aes.Encrypt(nonce, plain, cipher, tag);

        return new EncryptedValue
        {
            KeyId      = _activeKeyId,
            Nonce      = Convert.ToBase64String(nonce),
            CipherText = Convert.ToBase64String(cipher),
            Tag        = Convert.ToBase64String(tag)
        };
    }

    public string? Unprotect(EncryptedValue? value)
    {
        if (value is null) return null;

        if (!_keys.TryGetValue(value.KeyId, out var key))
            throw new InvalidOperationException(
                $"Секрет зашифрован ключом '{value.KeyId}', которого нет в конфигурации. " +
                "Верните ключ в Security:Keys, иначе значение не восстановить.");

        var nonce  = Convert.FromBase64String(value.Nonce);
        var cipher = Convert.FromBase64String(value.CipherText);
        var tag    = Convert.FromBase64String(value.Tag);
        var plain  = new byte[cipher.Length];

        using var aes = new AesGcm(key, tag.Length);
        aes.Decrypt(nonce, cipher, tag, plain);

        return Encoding.UTF8.GetString(plain);
    }

    public bool NeedsRotation(EncryptedValue? value)
        => value is not null && !string.Equals(value.KeyId, _activeKeyId, StringComparison.Ordinal);
}
