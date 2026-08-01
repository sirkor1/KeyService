using AmneziaKeyService.Core.Models;

namespace AmneziaKeyService.Core.Interfaces;

/// <summary>
/// Сборка ссылки vpn:// и клиентского файла по уже выданному ключу.
///
/// Узел для этого не нужен: все данные для конфига (адрес, ключи, параметры
/// обфускации) уже лежат в <see cref="VpnClient"/> и <see cref="VpnServer"/>.
/// Поэтому это всё, что требуется api и боту — им незачем открывать SSH
/// ради того, что уже посчитано при выдаче.
/// </summary>
public interface IVpnConfigReader
{
    /// <summary>Собирает vpn://-ссылку для существующего ключа.</summary>
    Task<string> BuildVpnUriAsync(VpnClient client, CancellationToken ct = default);

    /// <summary>Файл клиентского конфига для скачивания.</summary>
    Task<ClientFile> BuildClientFileAsync(VpnClient client, CancellationToken ct = default);
}
