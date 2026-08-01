using System.IO.Compression;
using System.Text;

namespace AmneziaKeyService.Infrastructure.Services;

/// <summary>
/// Кодирует JSON конфига в формат vpn://&lt;base64url&gt; для AmneziaVPN.
///
/// Формат воспроизводит exportController.cpp из amnezia-client-dev:
///   1. JSON → UTF-8 bytes
///   2. qCompress: 4 байта big-endian (размер оригинала) + zlib (RFC 1950)
///   3. Base64 URL-safe без padding (Qt::Base64UrlEncoding | OmitTrailingEquals)
///   4. Префикс "vpn://"
///
/// Qt использует уровень сжатия 8; .NET ZLibStream с Optimal (~6) тоже
/// производит валидный zlib-поток — AmneziaVPN декомпрессирует его qUncompress().
/// </summary>
public static class AmneziaUriEncoder
{
    public static string Encode(string json)
    {
        var jsonBytes = Encoding.UTF8.GetBytes(json);

        using var output = new MemoryStream();

        // qCompress header: uncompressed size в big-endian uint32
        var len = (uint)jsonBytes.Length;
        output.WriteByte((byte)(len >> 24));
        output.WriteByte((byte)(len >> 16));
        output.WriteByte((byte)(len >> 8));
        output.WriteByte((byte) len);

        // Стандартный zlib (RFC 1950) — совместим с Qt zlib/qUncompress
        using (var zlib = new ZLibStream(output, CompressionLevel.Optimal, leaveOpen: true))
            zlib.Write(jsonBytes);

        var compressed = output.ToArray();

        var base64Url = Convert.ToBase64String(compressed)
            .Replace('+', '-')
            .Replace('/', '_')
            .TrimEnd('=');

        return $"vpn://{base64Url}";
    }

    public static string Decode(string vpnUri)
    {
        var base64Url = vpnUri.StartsWith("vpn://", StringComparison.OrdinalIgnoreCase)
            ? vpnUri[6..]
            : vpnUri;

        var base64 = base64Url
            .Replace('-', '+')
            .Replace('_', '/');

        // Восстанавливаем padding
        base64 = (base64.Length % 4) switch
        {
            2 => base64 + "==",
            3 => base64 + "=",
            _ => base64
        };

        var compressed = Convert.FromBase64String(base64);

        // Пропускаем 4-байтовый qCompress-заголовок
        using var input  = new MemoryStream(compressed, 4, compressed.Length - 4);
        using var zlib   = new ZLibStream(input, CompressionMode.Decompress);
        using var reader = new StreamReader(zlib, Encoding.UTF8);

        return reader.ReadToEnd();
    }
}
