using AmneziaKeyService.Core.Interfaces;
using AmneziaKeyService.Core.Models;
using AmneziaKeyService.Infrastructure.Scripts;

namespace AmneziaKeyService.Infrastructure.Protocols;

/// <summary>
/// Общая последовательность развёртывания контейнера, одинаковая для всех
/// протоколов. Повторяет ServerController::setupContainer из amnezia-client:
///
///   prepare_host → remove_container → SCP Dockerfile → build → run →
///   configure_container → setup_host_firewall → start.sh
///
/// Различия протоколов сводятся к папке скриптов и набору переменных.
/// </summary>
public abstract class ProtocolInstallerBase : IProtocolInstaller
{
    protected readonly ScriptRegistry Scripts;

    protected ProtocolInstallerBase(ScriptRegistry scripts) => Scripts = scripts;

    public abstract string Kind { get; }
    public abstract string DefaultPort { get; }
    public virtual bool RequiresModernKernel => false;

    /// <summary>Папка скриптов протокола в ServerScripts.</summary>
    protected abstract string ScriptFolder { get; }

    /// <summary>Имя docker-контейнера.</summary>
    protected abstract string ContainerName { get; }

    /// <summary>Готовит описание протокола и таблицу подстановок.</summary>
    protected abstract (ProtocolInstance Protocol, Dictionary<string, string> Vars) Prepare(
        VpnServer server, ProtocolSpec spec);

    public async Task<ProtocolInstance> InstallAsync(
        ISshSession ssh,
        VpnServer server,
        ProtocolSpec spec,
        IInstallProgress progress,
        CancellationToken ct = default)
    {
        var (protocol, vars) = Prepare(server, spec);

        await progress.DetailAsync($"Подготовка узла для {protocol.ContainerName}", ct);
        await RunSharedAsync(ssh, "prepare_host.sh", vars, "prepare_host", progress, ct);

        // Прошлый контейнер с тем же именем убираем: скрипт upstream делает
        // то же самое, и его падение при отсутствии контейнера ожидаемо.
        await progress.DetailAsync("Удаление прежнего контейнера, если он был", ct);
        await TryRunSharedAsync(ssh, "remove_container.sh", vars, progress, ct);

        await progress.DetailAsync($"Сборка образа {protocol.ContainerName} — это занимает минуты", ct);
        await UploadDockerfileAsync(ssh, vars, progress, ct);
        await RunSharedAsync(ssh, "build_container.sh", vars, "build_container", progress, ct);

        await progress.DetailAsync($"Запуск контейнера {protocol.ContainerName}", ct);
        await RunScriptAsync(ssh, $"{ScriptFolder}/run_container.sh", vars, "run_container", progress, ct);

        await progress.DetailAsync("Генерация ключей внутри контейнера", ct);
        await ConfigureAsync(ssh, protocol, vars, progress, ct);

        return protocol;
    }

    public async Task RemoveAsync(
        ISshSession ssh,
        VpnServer server,
        ProtocolInstance protocol,
        IInstallProgress progress,
        CancellationToken ct = default)
    {
        var vars = ScriptVars.Common(server, protocol.ContainerName);
        await TryRunSharedAsync(ssh, "remove_container.sh", vars, progress, ct);
    }

    public Task RestartAsync(
        ISshSession ssh, VpnServer server, ProtocolInstance protocol, CancellationToken ct = default)
        => ssh.RunCheckedAsync($"sudo docker restart {protocol.ContainerName}", "restart_container", ct);

    // ── Шаги ──────────────────────────────────────────────────────────────────

    /// <summary>
    /// Заливает Dockerfile в каталог сборки на хосте. Прежний удаляем явно:
    /// upstream делает так же, чтобы не собрать образ по устаревшему файлу.
    /// </summary>
    private async Task UploadDockerfileAsync(
        ISshSession ssh, Dictionary<string, string> vars, IInstallProgress progress, CancellationToken ct)
    {
        var folder = vars["DOCKERFILE_FOLDER"];
        await ssh.RunAsync($"sudo rm -f {folder}/Dockerfile", ct);

        var dockerfile = ScriptTemplateRenderer.Render(
            Scripts.Read($"{ScriptFolder}/Dockerfile"), vars);

        await progress.LogAsync($"Загружаю Dockerfile в {folder}", ct: ct);
        await ssh.WriteHostFileAsync($"{folder}/Dockerfile", dockerfile, ct);
    }

    /// <summary>
    /// Выполняет configure_container.sh внутри контейнера и загружает start.sh,
    /// который контейнер запускает при каждом старте.
    /// </summary>
    private async Task ConfigureAsync(
        ISshSession ssh, ProtocolInstance protocol, Dictionary<string, string> vars,
        IInstallProgress progress, CancellationToken ct)
    {
        var configure = ScriptTemplateRenderer.Render(
            Scripts.Read($"{ScriptFolder}/configure_container.sh"), vars);

        var output = await ssh.RunInContainerScriptAsync(
            protocol.ContainerName, configure, "configure_container", ct);

        if (!string.IsNullOrWhiteSpace(output))
            await progress.LogAsync(output, ct: ct);

        var startup = ScriptTemplateRenderer.Render(
            Scripts.Read($"{ScriptFolder}/start.sh"), vars);

        await ssh.WriteContainerFileAsync(
            protocol.ContainerName, "/opt/amnezia/start.sh", startup, ct);

        await ssh.RunCheckedAsync(
            $"sudo docker exec -d {protocol.ContainerName} " +
            "sh -c \"chmod a+x /opt/amnezia/start.sh && /opt/amnezia/start.sh\"",
            "start_container", ct);
    }

    // ── Запуск скриптов ───────────────────────────────────────────────────────

    protected Task<string> RunSharedAsync(
        ISshSession ssh, string name, Dictionary<string, string> vars,
        string operation, IInstallProgress progress, CancellationToken ct)
        => RunScriptAsync(ssh, $"shared/{name}", vars, operation, progress, ct);

    /// <summary>
    /// Выполняет скрипт на хосте.
    ///
    /// set -e намеренно не добавляется: upstream выполняет каждую логическую
    /// строку отдельным exec-ом, и его скрипты рассчитывают, что падение одной
    /// команды не прерывает остальные. install_docker.sh на этом построен.
    /// </summary>
    protected async Task<string> RunScriptAsync(
        ISshSession ssh, string path, Dictionary<string, string> vars,
        string operation, IInstallProgress progress, CancellationToken ct)
    {
        var script = ScriptTemplateRenderer.Render(Scripts.Read(path), vars);
        var output = await ssh.RunHostScriptAsync(script, operation, ct);

        if (!string.IsNullOrWhiteSpace(output))
            await progress.LogAsync(output, ct: ct);

        return output;
    }

    /// <summary>Скрипт, падение которого ожидаемо и не должно прерывать установку.</summary>
    protected async Task TryRunSharedAsync(
        ISshSession ssh, string name, Dictionary<string, string> vars,
        IInstallProgress progress, CancellationToken ct)
    {
        var script = ScriptTemplateRenderer.Render(Scripts.Read($"shared/{name}"), vars);
        var result = await ssh.RunHostScriptRawAsync(script, ct);

        if (!string.IsNullOrWhiteSpace(result.StdOut))
            await progress.LogAsync(result.StdOut, ct: ct);
    }
}
