using AmneziaKeyService.Core.Models;

namespace AmneziaKeyService.Core.Interfaces;

/// <summary>Результат проверки доступности узла перед установкой.</summary>
public record ConnectionTestResult(
    bool Ok,
    string? Kernel,
    string? DockerVersion,
    bool SudoAvailable,
    string? HostFingerprint,
    IReadOnlyList<string> BusyPorts,
    string? Error);

/// <summary>Создание и сопровождение задач установки.</summary>
public interface IInstallService
{
    /// <summary>Ставит задачу в очередь. Один активный job на узел.</summary>
    Task<InstallJob> EnqueueAsync(
        string serverId, string kind, IReadOnlyList<ProtocolSpec> spec,
        string? createdByUserId, CancellationToken ct = default);

    /// <summary>
    /// Проверяет доступность узла: SSH, sudo, версия ядра, Docker, занятость
    /// портов. Ничего не меняет — используется мастером до установки.
    /// </summary>
    Task<ConnectionTestResult> TestConnectionAsync(
        VpnServer server, IReadOnlyList<string> portsToCheck, CancellationToken ct = default);
}
