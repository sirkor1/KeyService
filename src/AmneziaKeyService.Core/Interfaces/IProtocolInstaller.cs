using AmneziaKeyService.Core.Models;

namespace AmneziaKeyService.Core.Interfaces;

/// <summary>Куда инсталлятор пишет ход работы.</summary>
public interface IInstallProgress
{
    /// <summary>Уточняет, что происходит внутри текущего шага.</summary>
    Task DetailAsync(string detail, CancellationToken ct = default);

    /// <summary>Строка в лог задачи. Секреты вырезаются реализацией.</summary>
    Task LogAsync(string text, string level = AuditLevels.Info, CancellationToken ct = default);
}

/// <summary>
/// Развёртывание контейнера протокола на узле.
///
/// Отделён от <see cref="IProtocolConfigurator"/> намеренно: выдача ключей
/// нужна постоянно, а установка — один раз, и тянуть скрипты развёртывания
/// в горячий путь незачем.
/// </summary>
public interface IProtocolInstaller
{
    string Kind { get; }

    /// <summary>
    /// Разворачивает контейнер и возвращает описание установленного протокола.
    /// Вызывается внутри уже открытой сессии.
    /// </summary>
    Task<ProtocolInstance> InstallAsync(
        ISshSession ssh,
        VpnServer server,
        ProtocolSpec spec,
        IInstallProgress progress,
        CancellationToken ct = default);

    /// <summary>Останавливает и удаляет контейнер. Идемпотентна.</summary>
    Task RemoveAsync(
        ISshSession ssh,
        VpnServer server,
        ProtocolInstance protocol,
        IInstallProgress progress,
        CancellationToken ct = default);

    /// <summary>Перезапускает контейнер.</summary>
    Task RestartAsync(
        ISshSession ssh, VpnServer server, ProtocolInstance protocol, CancellationToken ct = default);

    /// <summary>Порт по умолчанию, если он не задан явно.</summary>
    string DefaultPort { get; }

    /// <summary>Требуется ли ядро Linux 4.14+ (нужно AmneziaWG второй версии).</summary>
    bool RequiresModernKernel { get; }
}

/// <summary>Резолвит инсталлятор по виду протокола.</summary>
public interface IProtocolInstallerRegistry
{
    IProtocolInstaller Get(string kind);

    bool IsSupported(string kind);
}
