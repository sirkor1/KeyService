using AmneziaKeyService.Core.Models;

namespace AmneziaKeyService.Core.Interfaces;

/// <summary>Шифрование секретов, хранимых в MongoDB (SSH-пароли, приватные ключи).</summary>
public interface ISecretProtector
{
    /// <summary>Шифрует активным ключом. Для null и пустой строки возвращает null.</summary>
    EncryptedValue? Protect(string? plainText);

    /// <summary>Расшифровывает. Для null возвращает null.</summary>
    string? Unprotect(EncryptedValue? value);

    /// <summary>Нужна ли перешифровка: значение зашифровано неактивным ключом.</summary>
    bool NeedsRotation(EncryptedValue? value);
}
