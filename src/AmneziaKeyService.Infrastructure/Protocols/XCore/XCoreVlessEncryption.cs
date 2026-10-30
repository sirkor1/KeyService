using AmneziaKeyService.Core.DTOs.Panel;
using AmneziaKeyService.Core.Exceptions;
using AmneziaKeyService.Core.Interfaces;

namespace AmneziaKeyService.Infrastructure.Protocols.XCore;

/// <summary>
/// Генерация ключей VLESS Encryption на узле. Отдельно от рендерера и синхронизации: ключи создаются один раз,
/// при включении флага из панели, а не при установке и не при каждой синхронизации — новые ключи инвалидировали бы
/// все выданные ссылки.
/// </summary>
public static class XCoreVlessEncryption
{
    /// <summary>
    /// Запускает <c>xray vlessenc</c> одноразовым контейнером образа узла и разбирает вывод. Серверная строка
    /// шифруется сразу: дальше по коду она идёт только в репозиторий. Тексты ошибок не содержат вывода команды.
    /// </summary>
    public static async Task<XCoreVlessEncryptionChange> GenerateAsync(
        ISshSession ssh, string imageRef, ISecretProtector secrets, CancellationToken ct = default)
    {
        if (!XCoreNode.IsSafeImageRef(imageRef))
            throw new BadRequestException("Ссылка на образ Xray в параметрах узла некорректна.");

        var output = await ssh.RunCheckedAsync(XCoreNode.VlessEncCommand(imageRef), "xcore_vlessenc", ct);

        XrayVlessEncryption pair;
        try
        {
            pair = XrayApiOutput.ParseVlessEnc(output);
        }
        catch (XrayOutputException ex)
        {
            // Сообщение разборщика не содержит вывода, а значит и ключей.
            throw new BadRequestException($"Не удалось получить ключи шифрования VLESS: {ex.Message}");
        }

        return new XCoreVlessEncryptionChange(
            Enabled: true, secrets.Protect(pair.Decryption), pair.Encryption);
    }
}
