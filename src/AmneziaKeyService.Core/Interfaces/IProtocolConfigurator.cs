using System.Text.Json.Nodes;
using AmneziaKeyService.Core.Models;

namespace AmneziaKeyService.Core.Interfaces;

/// <summary>Запрос на создание peer-а для клиента.</summary>
public record PeerRequest(VpnServer Server, ProtocolInstance Protocol, VpnClient Client);

/// <summary>
/// Данные выданного peer-а, которые нужно сохранить в документе ключа.
/// Набор полей зависит от протокола: у WireGuard это ключи и туннельный IP,
/// у Xray — только uuid.
/// </summary>
public record IssuedPeer
{
    public string? AssignedIp { get; init; }
    public string? ClientPrivKey { get; init; }
    public string? ClientPubKey { get; init; }
    public string? PskKey { get; init; }
    public string? XrayClientId { get; init; }
}

/// <summary>
/// Операции над клиентами конкретного протокола: создание и удаление peer-а
/// на узле и сборка клиентского конфига.
/// </summary>
public interface IProtocolConfigurator
{
    string Kind { get; }

    /// <summary>
    /// Заводит peer на узле. Вызывается уже внутри открытой сессии, чтобы
    /// выдача нескольких ключей подряд не открывала подключение на каждый.
    /// </summary>
    Task<IssuedPeer> AddPeerAsync(ISshSession ssh, PeerRequest request, CancellationToken ct = default);

    /// <summary>Удаляет peer с узла. Идемпотентна: отсутствующий peer — не ошибка.</summary>
    Task RemovePeerAsync(ISshSession ssh, PeerRequest request, CancellationToken ct = default);

    /// <summary>
    /// Убеждается, что параметры протокола вычитаны с узла (ключ сервера, PSK,
    /// обфускация — либо публичный ключ Reality и shortId). Возвращает true,
    /// если что-то было обновлено и документ узла надо сохранить.
    /// </summary>
    Task<bool> EnsureServerParamsAsync(
        ISshSession ssh, VpnServer server, ProtocolInstance protocol, CancellationToken ct = default);

    /// <summary>Элемент массива containers[] в конфиге vpn://.</summary>
    JsonObject BuildContainerEntry(VpnServer server, ProtocolInstance protocol, VpnClient client);

    /// <summary>
    /// Файл, который скачивает пользователь: .conf для WireGuard,
    /// .json для Xray.
    /// </summary>
    ClientFile BuildClientFile(VpnServer server, ProtocolInstance protocol, VpnClient client);
}

/// <summary>Скачиваемый клиентский конфиг.</summary>
public record ClientFile(string FileName, string ContentType, string Content);

/// <summary>Резолвит конфигуратор по виду протокола.</summary>
public interface IProtocolRegistry
{
    IProtocolConfigurator GetConfigurator(string kind);

    bool IsSupported(string kind);
}
