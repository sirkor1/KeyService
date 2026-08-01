using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace AmneziaKeyService.Infrastructure.Services;

/// <summary>
/// Генерация X25519 keypair для WireGuard/AmneziaWG.
///
/// Аналог WireguardConfigurator::genClientKeys() из amnezia-client-dev:
///   - там используется OpenSSL EVP_PKEY_X25519 + RAND_priv_bytes
///   - здесь — BouncyCastle X25519KeyPairGenerator с SecureRandom
/// Оба подхода дают RFC 7748 совместимые Curve25519 ключи в формате raw 32 bytes → Base64.
/// </summary>
public class KeyGenerationService
{
    public (string PrivateKeyBase64, string PublicKeyBase64) GenerateX25519KeyPair()
    {
        var gen = new X25519KeyPairGenerator();
        gen.Init(new X25519KeyGenerationParameters(new SecureRandom()));
        var keyPair = gen.GenerateKeyPair();

        var privateKey = ((X25519PrivateKeyParameters)keyPair.Private).GetEncoded();
        var publicKey  = ((X25519PublicKeyParameters)keyPair.Public).GetEncoded();

        return (Convert.ToBase64String(privateKey), Convert.ToBase64String(publicKey));
    }
}
