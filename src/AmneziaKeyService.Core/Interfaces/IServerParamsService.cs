using AmneziaKeyService.Core.Models;

namespace AmneziaKeyService.Core.Interfaces;

/// <summary>Чтение параметров протоколов с узла по SSH.</summary>
public interface IServerParamsService
{
    /// <summary>
    /// Вычитывает недостающие параметры всех протоколов узла и сохраняет их.
    /// Уже закешированные не перечитывает.
    /// </summary>
    Task<VpnServer> EnsureCachedAsync(string serverId, CancellationToken ct = default);

    /// <summary>
    /// Принудительно перечитывает параметры: сбрасывает кеш и идёт на узел.
    ///
    /// Кеш сбрасывается только после успешного чтения — иначе неудачный
    /// refresh оставлял бы узел без ключа сервера и PSK, и выдача ключей
    /// ломалась бы сильнее, чем до попытки.
    /// </summary>
    Task<VpnServer> RefreshAsync(string serverId, CancellationToken ct = default);
}
