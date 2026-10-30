using QRCoder;

namespace AmneziaKeyService.Bot.Services;

/// <summary>
/// QR-код ссылки подписки для сканирования в Happ с другого устройства. Вынесен из бота,
/// чтобы проверяться без Telegram. Картинка содержит ссылку целиком, то есть те же учётные
/// данные, что и текст сообщения: ни её, ни байты PNG не логируют.
/// </summary>
public static class SubscriptionQr
{
    /// <summary>
    /// 10 пикселей на модуль: при телеграмной перекодировке фото края модулей остаются чёткими,
    /// а сканер телефона уверенно читает QR и с экрана монитора.
    /// </summary>
    private const int PixelsPerModule = 10;

    private static readonly byte[] Dark = [0, 0, 0];
    private static readonly byte[] Light = [255, 255, 255];

    /// <summary>
    /// PNG без System.Drawing — тот работает только на Windows, а бот живёт в Linux-контейнере.
    /// Уровень коррекции M: ссылка подписки — 70–100 символов, запас на потёртость экрана нужен,
    /// а более высокий уровень раздувает код и делает его хуже читаемым с малого экрана.
    /// Тихая зона обязательна: без неё сканеры часто не находят код на тёмном фоне чата.
    /// </summary>
    public static byte[] RenderPng(string link)
    {
        using var generator = new QRCodeGenerator();
        using var data = generator.CreateQrCode(link, QRCodeGenerator.ECCLevel.M);
        return new PngByteQRCode(data).GetGraphic(PixelsPerModule, Dark, Light, drawQuietZones: true);
    }
}
