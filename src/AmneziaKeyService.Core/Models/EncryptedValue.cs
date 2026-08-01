using MongoDB.Bson.Serialization.Attributes;

namespace AmneziaKeyService.Core.Models;

/// <summary>
/// Секрет, зашифрованный AES-GCM. Хранится в MongoDB вместо открытого текста.
///
/// keyId позволяет ротировать ключ: старые документы читаются прежним ключом,
/// новые пишутся активным.
/// </summary>
public class EncryptedValue
{
    /// <summary>Версия формата — на случай смены алгоритма.</summary>
    [BsonElement("v")]
    public int Version { get; set; } = 1;

    [BsonElement("alg")]
    public string Algorithm { get; set; } = "AESGCM";

    /// <summary>Идентификатор ключа шифрования из Security:Keys.</summary>
    [BsonElement("keyId")]
    public string KeyId { get; set; } = default!;

    /// <summary>Nonce, 12 байт, base64.</summary>
    [BsonElement("nonce")]
    public string Nonce { get; set; } = default!;

    /// <summary>Шифротекст, base64.</summary>
    [BsonElement("ct")]
    public string CipherText { get; set; } = default!;

    /// <summary>Тег аутентификации, 16 байт, base64.</summary>
    [BsonElement("tag")]
    public string Tag { get; set; } = default!;
}

/// <summary>Ключи шифрования секретов. Секция "Security" в конфиге.</summary>
public class SecurityOptions
{
    /// <summary>Идентификатор ключа, которым шифруются новые значения.</summary>
    public string ActiveKeyId { get; set; } = "default";

    public List<SecurityKeyEntry> Keys { get; set; } = [];

    /// <summary>
    /// Упрощённый вариант для одного ключа: SECURITY__DATAPROTECTIONKEY=&lt;base64 32 байта&gt;.
    /// Если задан и Keys пуст — используется как ключ с идентификатором "default".
    /// </summary>
    public string? DataProtectionKey { get; set; }
}

public class SecurityKeyEntry
{
    public string Id { get; set; } = default!;

    /// <summary>32 байта в base64.</summary>
    public string Base64Key { get; set; } = default!;
}
