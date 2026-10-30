using AmneziaKeyService.Core.Models;

namespace AmneziaKeyService.Core.DTOs.Panel;

/// <summary>
/// Настройки xcore из панели (<c>PUT /api/servers/{id}/protocols/{protocolId}/xcore</c>). Роль, домен
/// узла и ключи этим запросом не меняются. Поля входа (<c>RuDirect</c>, списки доменов,
/// <c>SubscriptionHost</c>) выходу передавать нельзя: сервер ответит отказом, а не промолчит.
/// </summary>
public class XCoreSettingsRequest
{
    /// <summary>Название подключения в приложении, до 30 символов; пусто — имя узла.</summary>
    public string? Title { get; set; }

    public int SortOrder { get; set; }

    /// <summary>
    /// Не передано — без изменений. Не bool: по умолчанию false, и запрос, забывший поле,
    /// молча убрал бы узел из подписок у всех пользователей.
    /// </summary>
    public bool? SubscriptionEnabled { get; set; }

    /// <summary>Только вход. Не передано — без изменений.</summary>
    public bool? RuDirect { get; set; }

    /// <summary>Только вход, «всегда напрямую». Не передано — без изменений.</summary>
    public List<string>? DirectDomains { get; set; }

    /// <summary>Только вход, «всегда через VPN». Не передано — без изменений.</summary>
    public List<string>? ProxyDomains { get; set; }

    /// <summary>Только вход. Не передано или пусто — домен подписки снимается.</summary>
    public string? SubscriptionHost { get; set; }

    /// <summary>
    /// VLESS Encryption на узле. Не передано — без изменений; true генерирует ключи на узле (если их ещё нет),
    /// false выключает шифрование и стирает ключи. Меняет структуру конфига: узел перезапускается, а у выхода
    /// ещё и перерисовываются конфиги всех входов.
    /// </summary>
    public bool? VlessEncryption { get; set; }
}

/// <summary>
/// Проверенные и нормализованные настройки, готовые к записи в узел. <see cref="Entry"/> заполнен
/// для входа и пуст для выхода: репозиторий не должен записать выходу поля маршрутизации.
/// </summary>
/// <param name="VlessEncryption">Null — шифрование не меняется. Ключи генерирует контроллер: правила чистые, без SSH.</param>
public sealed record XCoreSettingsUpdate(
    string? Title, int SortOrder, bool SubscriptionEnabled, XCoreEntrySettings? Entry,
    XCoreVlessEncryptionChange? VlessEncryption = null);

/// <summary>
/// Новое состояние VLESS Encryption узла. Включение несёт обе строки из <c>xray vlessenc</c>, выключение — только
/// <c>Enabled = false</c>: репозиторий стирает ключи, неиспользуемый секрет в базе не нужен.
/// </summary>
/// <param name="Decryption">Серверная строка, уже зашифрованная; содержит приватный ключ.</param>
/// <param name="Client">Клиентская строка (публичная).</param>
public sealed record XCoreVlessEncryptionChange(bool Enabled, EncryptedValue? Decryption, string? Client);

/// <param name="RuDirect">Null — не менять.</param>
/// <param name="DirectDomains">Null — не менять.</param>
/// <param name="ProxyDomains">Null — не менять.</param>
/// <param name="SubscriptionHost">Всегда задаётся целиком: null снимает домен подписки.</param>
public sealed record XCoreEntrySettings(
    bool? RuDirect, IReadOnlyList<string>? DirectDomains, IReadOnlyList<string>? ProxyDomains, string? SubscriptionHost);
