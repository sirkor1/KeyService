using System.Globalization;
using AmneziaKeyService.Core.Interfaces;
using AmneziaKeyService.Core.Models;

namespace AmneziaKeyService.Bot.Services;

/// <summary>
/// Тексты кнопки «Подписка Happ». Вынесены из бота, чтобы их можно было проверить без Telegram:
/// ошибка здесь не падает, а молча выдаёт пользователю ссылку без предупреждения «не пересылайте».
/// </summary>
public static class SubscriptionBotMessages
{
    public const string MenuCallback = "cmd:sub";

    public const string Unavailable = "Подписки временно недоступны. Попробуйте позже.";

    /// <summary>Подпись к QR-коду: без ссылки, она уже есть текстом выше.</summary>
    public const string QrCaption = "QR-код подписки — отсканируйте в Happ";

    /// <summary>Лимит Telegram на текст кнопки копирования (см. <c>WithCopyText</c>).</summary>
    public const int CopyTextMaxLength = 256;

    private const string Instruction =
        "1. Установите приложение Happ (https://www.happ.su).\n" +
        "2. Скопируйте ссылку.\n" +
        "3. В Happ нажмите «+» → «Вставить из буфера».\n\n" +
        "Ссылку не пересылайте: по ней подключается любой.";

    public static string Granted(Subscription subscription, string link) =>
        $"📲 Подписка Happ\n\n{link}\n\n" +
        $"Действует: {Expiry(subscription)}\n" +
        $"Трафик: {Traffic(subscription)}\n\n" +
        Instruction;

    /// <summary>Отказ по правилу повторной выдачи: ссылки в тексте нет.</summary>
    public static string Denied(string reason) =>
        $"Подписка отключена ({DeniedReason(reason)}). Обратитесь к администратору.";

    public static string DeniedReason(string reason) => reason switch
    {
        RevokeReasons.Expired => "истёк срок действия",
        RevokeReasons.Quota   => "исчерпана квота трафика",
        _                     => "отключена администратором",
    };

    private static string Expiry(Subscription subscription) => subscription.ExpiresAt is { } expires
        ? $"до {expires.ToUniversalTime():dd.MM.yyyy HH:mm} UTC"
        : "бессрочно";

    private static string Traffic(Subscription subscription)
    {
        var used = FormatBytes(subscription.Usage.TotalBytes);
        return subscription.TrafficLimitBytes is { } limit
            ? $"{used} из {FormatBytes(limit)}"
            : $"{used}, без ограничения";
    }

    public static string FormatBytes(long bytes)
    {
        string[] units = ["Б", "КиБ", "МиБ", "ГиБ", "ТиБ"];
        var value = (double)Math.Max(bytes, 0);
        var unit = 0;
        while (value >= 1024 && unit < units.Length - 1)
        {
            value /= 1024;
            unit++;
        }

        return unit == 0
            ? $"{value.ToString("0", CultureInfo.InvariantCulture)} {units[unit]}"
            : $"{value.ToString("0.#", CultureInfo.InvariantCulture)} {units[unit]}";
    }
}
