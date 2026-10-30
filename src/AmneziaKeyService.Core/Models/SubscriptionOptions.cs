namespace AmneziaKeyService.Core.Models;

/// <summary>Настройки подписок. Секция "Subscription" в конфиге.</summary>
public class SubscriptionOptions
{
    /// <summary>
    /// Публичный адрес, с которого клиенты забирают подписку, например https://sub.example.com.
    /// Без него подписку создать можно, но ссылку построить нельзя — если только у какого-то входа не задан
    /// домен подписки: тогда ссылка строится на него, а этот адрес остаётся запасным.
    /// </summary>
    public string? PublicBaseUrl { get; set; }

    /// <summary>Название профиля в приложении; до 25 символов.</summary>
    public string ProfileTitle { get; set; } = "VPN";

    public string? SupportUrl { get; set; }

    /// <summary>
    /// Как часто приложение перезапрашивает подписку. По умолчанию 12, а не 1: при переезде
    /// DNS частое обновление выбивает подписки у тех, кто в этот момент без связи.
    /// </summary>
    public int UpdateIntervalHours { get; set; } = 12;

    /// <summary>
    /// Профиль маршрутизации Happ в заголовке <c>routing</c>: российские сайты идут напрямую с устройства
    /// пользователя, а не через вход. По умолчанию выключен — решение об этом принимает оператор.
    /// </summary>
    public bool HappRoutingEnabled { get; set; }

    /// <summary>Название профиля в Happ; по нему профиль обновляется, а не дублируется.</summary>
    public string HappRoutingName { get; set; } = "RU direct";

    /// <summary>
    /// Provider ID Happ (happ-proxy.com); пусто — выключено. Когда задан, ответ <c>/sub/</c> получает заголовок
    /// <c>providerid</c> и открываются расширенные заголовки Happ (из них отправляется <c>fallback-url</c>).
    /// Цена включения: Happ раз в день отправляет на check.happ-proxy.com идентификатор устройства (HWID),
    /// хеш домена подписки и версию ОС — то есть третья сторона узнаёт о числе и составе устройств подписки.
    /// </summary>
    public string? HappProviderId { get; set; }

    /// <summary>Публичная ссылка подписки <c>{PublicBaseUrl}/sub/{token}</c>; false — адрес не настроен.</summary>
    public bool TryBuildUrl(string token, out string url)
    {
        url = string.Empty;
        if (!Uri.TryCreate(PublicBaseUrl?.Trim(), UriKind.Absolute, out var baseUri)
            || baseUri.Scheme is not ("https" or "http")
            || !string.IsNullOrEmpty(baseUri.Query) || !string.IsNullOrEmpty(baseUri.Fragment))
            return false;

        url = $"{baseUri.GetLeftPart(UriPartial.Path).TrimEnd('/')}/sub/{token}";
        return true;
    }
}
