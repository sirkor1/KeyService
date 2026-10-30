namespace AmneziaKeyService.Core.Models;

/// <summary>Настройки xcore. Секция "XCore" в конфиге.</summary>
public class XCoreOptions
{
    /// <summary>
    /// Адрес для регистрации в Let's Encrypt (уведомления об истечении сертификата).
    /// Без него установка xcore отклоняется: Caddy выпустил бы сертификат без
    /// контакта, и предупреждение о сбое продления некому было бы получить.
    /// </summary>
    public string? AcmeEmail { get; set; }

    /// <summary>
    /// Куда Caddy входа проксирует <c>/sub/</c>, например https://sub-origin.example.com: публичный адрес
    /// API панели за рубежом. Без него домен подписки входу задать нельзя — проксировать было бы некуда.
    /// </summary>
    public string? SubscriptionUpstream { get; set; }

    /// <summary>
    /// Российские geo-списки на входе (ru-blocked, ru-available-only-inside). false — вход работает
    /// на встроенных списках образа, обновление не публикуется и не выполняется.
    /// </summary>
    public bool RfListsEnabled { get; set; } = true;

    /// <summary>
    /// Репозиторий GitHub с релизами geosite.dat и geoip.dat. Попадает в адрес для curl на узле, поэтому
    /// проверяется на формат <c>владелец/имя</c>.
    /// </summary>
    public string RfListsRepo { get; set; } = "runetfreedom/russia-v2ray-rules-dat";

    /// <summary>
    /// Не чаще чем раз в столько дней вход получает новый релиз списков: релизы ежедневные, а каждое обновление —
    /// перезапуск Xray и обрыв соединений. Первая загрузка и ручное обновление из панели этот срок не ждут.
    /// </summary>
    public int RfListsMinAgeDays { get; set; } = 7;

    /// <summary>
    /// Сколько минут после неудачного выпуска сертификата домена подписки Caddy не перезапускается с тем же
    /// Caddyfile: Let's Encrypt после серии неудач блокирует выпуск для домена. 0 — без паузы.
    /// </summary>
    public int CaddyRetryMinutes { get; set; } = 60;
}
