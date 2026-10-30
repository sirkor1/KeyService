using System.Text.RegularExpressions;
using AmneziaKeyService.Core.Exceptions;
using AmneziaKeyService.Core.Interfaces;
using AmneziaKeyService.Core.Models;
using AmneziaKeyService.Infrastructure.Protocols.XCore;
using AmneziaKeyService.Infrastructure.Subscriptions;
using Microsoft.Extensions.Logging;

namespace AmneziaKeyService.Infrastructure.Install;

/// <summary>
/// Выполняет задачу установки по шагам.
///
/// Последовательность повторяет ServerController::setupContainer
/// из amnezia-client, а коды шагов совпадают с чеклистом в панели.
/// </summary>
public partial class InstallOrchestrator
{
    /// <summary>Минимальная версия ядра для AmneziaWG второй версии.</summary>
    private static readonly Version MinKernelForAwg2 = new(4, 14);

    /// <summary>Сколько ждать освобождения пакетного менеджера.</summary>
    private const int DpkgBusyRetries = 30;
    private static readonly TimeSpan DpkgBusyDelay = TimeSpan.FromSeconds(10);

    private readonly IVpnServerRepository _servers;
    private readonly IInstallJobRepository _jobs;
    private readonly ISshSessionFactory _sshFactory;
    private readonly IProtocolInstallerRegistry _installers;
    private readonly IProtocolRegistry _configurators;
    private readonly Scripts.ScriptRegistry _scripts;
    private readonly ILogger<InstallOrchestrator> _logger;
    private readonly XCoreSyncPublisher _xcoreSync;

    public InstallOrchestrator(
        IVpnServerRepository servers,
        IInstallJobRepository jobs,
        ISshSessionFactory sshFactory,
        IProtocolInstallerRegistry installers,
        IProtocolRegistry configurators,
        Scripts.ScriptRegistry scripts,
        ILogger<InstallOrchestrator> logger,
        XCoreSyncPublisher xcoreSync)
    {
        _servers       = servers;
        _jobs          = jobs;
        _sshFactory    = sshFactory;
        _installers    = installers;
        _configurators = configurators;
        _scripts       = scripts;
        _logger        = logger;
        _xcoreSync     = xcoreSync;
    }

    public async Task ExecuteAsync(InstallJob job, CancellationToken ct)
    {
        var progress = new InstallProgressReporter(_jobs, job);

        job.Status    = InstallJobStatuses.Running;
        job.StartedAt = DateTime.UtcNow;
        await _jobs.UpdateAsync(job, ct);

        var server = await _servers.GetByIdAsync(job.ServerId, ct);
        if (server is null)
        {
            await FailAsync(job, "Узел не найден — возможно, он был удалён.", ct);
            return;
        }

        var previousStatus = server.Status;
        try
        {
            if (job.Kind != InstallJobKinds.RemoveProtocol) ProtocolInstallRules.Prepare(server, job.Spec);
            await using var ssh = await StepAsync(job, InstallStepCodes.Ssh, progress, ct,
                () => ConnectAsync(server, progress, ct));

            await StepAsync(job, InstallStepCodes.Fingerprint, progress, ct,
                () => VerifyFingerprintAsync(ssh, server, progress, ct));

            await StepAsync(job, InstallStepCodes.Docker, progress, ct,
                () => PrepareDockerAsync(ssh, server, job, progress, ct));

            var installed = await StepAsync(job, InstallStepCodes.Containers, progress, ct,
                () => InstallContainersAsync(ssh, server, job, progress, ct));

            await StepAsync(job, InstallStepCodes.KeysAndFw, progress, ct,
                () => FinalizeAsync(ssh, server, installed, progress, ct));

            await StepAsync(job, InstallStepCodes.Verify, progress, ct,
                () => VerifyAsync(ssh, server, installed, progress, ct));

            server.Status = ServerStatuses.Ok;
            await _servers.UpdateInstallationAsync(server, ct);

            job.Status          = InstallJobStatuses.Succeeded;
            job.ProgressPercent = 100;
            job.CurrentStepCode = null;
            job.FinishedAt      = DateTime.UtcNow;
            await _jobs.UpdateAsync(job, ct);

            await progress.LogAsync("Установка завершена.", ct: ct);

            // Установка кладёт на узел конфиг без пользователей, и сам он подписчиков не получит. А
            // новый выход меняет конфиги входов, новый вход — список служебных пользователей на
            // выходах, поэтому синхронизируются все узлы xcore, а не только этот. Задача уже успешна,
            // поэтому токен отмены не передаём: отмена здесь пометила бы её отменённой. Сбой
            // публикации не бросается — узлы подхватит периодическая сверка.
            if (installed.Any(p => p.Kind == ProtocolKinds.XCore))
            {
                await _xcoreSync.PublishForAllAsync(job.CreatedByUserId, CancellationToken.None);

                // Первичная загрузка российских списков для нового входа — отдельным событием после
                // установки: её сбой (узел не дотянулся до GitHub) установку не проваливает, вход работает
                // на встроенных списках образа, а причина видна оператору в GeoError.
                foreach (var entry in installed.Where(p => p.Kind == ProtocolKinds.XCore && p.XCore?.Role == XCoreRoles.Entry))
                    await _xcoreSync.PublishGeoUpdateAsync(
                        server.Id, entry.Id, null, job.CreatedByUserId, CancellationToken.None);
            }
        }
        catch (OperationCanceledException)
        {
            await CancelAsync(job, server, progress, ct);
        }
        catch (Exception ex)
        {
            // Наружу уходит только безопасный текст: SshCommandException
            // содержит метку операции, но не команду.
            var message = ex is SshCommandException or SshConnectionException or NotFoundException or BadRequestException
                ? ex.Message
                : "Внутренняя ошибка установки. Подробности в логе сервиса.";

            _logger.LogError(ex, "Задача установки {JobId} провалилась.", job.Id);

            await progress.LogAsync(message, AuditLevels.Error, CancellationToken.None);
            await MarkCurrentStepFailedAsync(job, message);
            await FailAsync(job, message, CancellationToken.None);

            server.Status = job.Kind == InstallJobKinds.AddProtocol ? previousStatus : ServerStatuses.Error;
            foreach (var p in server.Protocols.Where(p => p.State == ProtocolStates.Installing)) p.State = ProtocolStates.Failed;
            await _servers.UpdateInstallationAsync(server, CancellationToken.None);
        }
    }

    // ── Шаги ──────────────────────────────────────────────────────────────────

    /// <summary>Подключение по SSH и проверка прав.</summary>
    private async Task<ISshSession> ConnectAsync(
        VpnServer server, InstallProgressReporter progress, CancellationToken ct)
    {
        await progress.DetailAsync($"Подключение к {server.Ssh.User}@{server.Host}:{server.Ssh.Port}", ct);

        var ssh = await _sshFactory.ConnectAsync(server, ct);

        var uname = await ssh.RunAsync("uname -a", ct);
        await progress.LogAsync(uname.StdOut, ct: ct);

        // check_user_in_sudo.sh завершается ненулевым кодом, если sudo
        // недоступен без пароля. Установка без него невозможна.
        var sudo = await ssh.RunHostScriptRawAsync(_scripts.Read("shared/check_user_in_sudo.sh"), ct);
        if (!sudo.Ok)
        {
            await ssh.DisposeAsync();
            throw new BadRequestException(
                $"Пользователь {server.Ssh.User} не может выполнять sudo без пароля. " +
                "Установка требует привилегий root.");
        }

        return ssh;
    }

    /// <summary>
    /// Фиксирует отпечаток хоста при первой установке и сверяет при повторной.
    ///
    /// Модель доверия при первом подключении: сохранённый отпечаток защищает
    /// от подмены узла в дальнейшем, но саму первую установку — нет.
    /// </summary>
    private async Task VerifyFingerprintAsync(
        ISshSession ssh, VpnServer server, InstallProgressReporter progress, CancellationToken ct)
    {
        var result = await ssh.RunAsync(
            "ssh-keyscan -t ed25519 localhost 2>/dev/null | ssh-keygen -lf - 2>/dev/null | awk '{print $2}'", ct);

        var fingerprint = result.StdOut.Trim();
        if (string.IsNullOrEmpty(fingerprint))
        {
            await progress.LogAsync(
                "Отпечаток хоста получить не удалось — проверка пропущена.", AuditLevels.Warn, ct);
            return;
        }

        if (string.IsNullOrEmpty(server.Ssh.HostFingerprint))
        {
            server.Ssh.HostFingerprint = fingerprint;
            await _servers.UpdateInstallationAsync(server, ct);
            await progress.DetailAsync($"Отпечаток зафиксирован: {fingerprint}", ct);
            return;
        }

        if (server.Ssh.HostFingerprint != fingerprint)
        {
            throw new BadRequestException(
                "Отпечаток хоста не совпадает с сохранённым. Узел мог быть переустановлен " +
                "или подменён. Проверьте вручную и обновите отпечаток в настройках узла.");
        }

        await progress.DetailAsync("Отпечаток совпадает с сохранённым", ct);
    }

    /// <summary>Docker, зависимости и проверка занятости портов.</summary>
    private async Task PrepareDockerAsync(
        ISshSession ssh, VpnServer server, InstallJob job,
        InstallProgressReporter progress, CancellationToken ct)
    {
        await WaitForPackageManagerAsync(ssh, progress, ct);

        await progress.DetailAsync("Установка Docker и зависимостей", ct);
        var docker = await ssh.RunAsync("sudo docker info >/dev/null 2>&1", ct);
        var output = docker.Ok
            ? (await ssh.RunAsync("uname -sr", ct)).StdOut
            : await ssh.RunHostScriptAsync(_scripts.Read("shared/install_docker.sh"), "install_docker", ct);
        await progress.LogAsync(output, ct: ct);

        // Ядро проверяем по выводу install_docker.sh — он заканчивается uname -sr.
        if (job.Spec.Any(s => _installers.Get(s.Kind).RequiresModernKernel))
            EnsureKernelSupported(output);

        await EnsurePortsFreeAsync(ssh, job, progress, ct);
    }

    /// <summary>
    /// Ждёт освобождения apt/dpkg: на свежем VPS часто идёт автообновление,
    /// и установка Docker упала бы на заблокированном менеджере пакетов.
    /// </summary>
    private async Task WaitForPackageManagerAsync(
        ISshSession ssh, InstallProgressReporter progress, CancellationToken ct)
    {
        var script = _scripts.Read("shared/check_server_is_busy.sh");

        for (var attempt = 1; attempt <= DpkgBusyRetries; attempt++)
        {
            var result = await ssh.RunHostScriptRawAsync(script, ct);
            var probeState = PackageManagerProbe.FromExitStatus(result.ExitStatus);
            if (probeState == PackageManagerProbeState.Ready) return;

            if (probeState == PackageManagerProbeState.Error)
            {
                _logger.LogWarning(
                    "Package-manager lock probe finished with exit status {ExitStatus}.",
                    result.ExitStatus);
                throw new BadRequestException(
                    "Не удалось безопасно проверить занятость пакетного менеджера на узле. " +
                    "Проверьте пакетный менеджер и его служебные файлы на сервере, затем повторите установку.");
            }

            await progress.DetailAsync(
                $"Пакетный менеджер занят, ожидание ({attempt}/{DpkgBusyRetries})", ct);

            await Task.Delay(DpkgBusyDelay, ct);
        }

        throw new BadRequestException(
            "Пакетный менеджер на узле занят дольше пяти минут. " +
            "Дождитесь окончания обновлений и повторите установку.");
    }

    private static void EnsureKernelSupported(string unameOutput)
    {
        var match = KernelVersion().Match(unameOutput);
        if (!match.Success) return;

        var version = new Version(int.Parse(match.Groups[1].Value), int.Parse(match.Groups[2].Value));
        if (version >= MinKernelForAwg2) return;

        throw new BadRequestException(
            $"Ядро Linux {version} слишком старое для AmneziaWG: требуется {MinKernelForAwg2} или новее. " +
            "Обновите систему или выберите другой протокол.");
    }

    [GeneratedRegex(@"Linux\s+(\d+)\.(\d+)")]
    private static partial Regex KernelVersion();

    private static async Task EnsurePortsFreeAsync(
        ISshSession ssh, InstallJob job, InstallProgressReporter progress, CancellationToken ct)
    {
        foreach (var spec in job.Spec.Where(s => s.Port is not null))
        {
            // xcore занимает два порта и только по TCP: Xray на 443 и Caddy на 80 для ACME.
            // Выбрать другой порт нельзя, поэтому и подсказка в отказе другая.
            var isXCore = spec.Kind == ProtocolKinds.XCore;
            string[] ports = isXCore ? [XCoreNode.HttpsPort, XCoreNode.AcmePort] : [spec.Port!];
            var sockets = isXCore ? "-lnt" : "-lntu";

            foreach (var port in ports)
            {
                var result = await ssh.RunAsync($"sudo ss -H {sockets} 'sport = :{port}'", ct);

                if (!result.Ok) throw new BadRequestException("Не удалось проверить занятость порта на узле.");

                // grep без совпадений возвращает 1 — это и есть «порт свободен».
                if (result.Ok && !string.IsNullOrWhiteSpace(result.StdOut))
                {
                    throw new BadRequestException(isXCore
                        ? $"Порт {port} на узле уже занят другим процессом (веб-сервер, прокси). " +
                          "xcore нужны порты 443 и 80: освободите их."
                        : $"Порт {port} на узле уже занят другим процессом. " +
                          "Освободите его или выберите другой порт.");
                }

                await progress.LogAsync($"Порт {port} свободен.", ct: ct);
            }
        }
    }

    /// <summary>Сборка и запуск контейнеров всех протоколов задачи.</summary>
    private async Task<List<ProtocolInstance>> InstallContainersAsync(
        ISshSession ssh, VpnServer server, InstallJob job,
        InstallProgressReporter progress, CancellationToken ct)
    {
        var installed = new List<ProtocolInstance>();

        foreach (var spec in job.Spec)
        {
            ct.ThrowIfCancellationRequested();

            var installer = _installers.Get(spec.Kind);
            var protocol = await installer.InstallAsync(ssh, server, spec, progress, ct);

            // Номер маршрута нужен выходу с первой же минуты, но выбирается по всем узлам, а
            // установщик их не видит. Читаем как можно позже — перед самой записью: два выхода,
            // ставящихся одновременно на разные узлы, разойдутся только если окажутся здесь в одну
            // и ту же долю секунды.
            // Уникальный индекс номера (M017) отсекает проигравшего гонку именно на записи ниже: тогда
            // берётся следующий свободный номер по свежему снимку, и запись повторяется.
            protocol.State = ProtocolStates.Installing;
            server.DefaultProtocolId ??= protocol.Id;
            for (var attempt = 1; ; attempt++)
            {
                if (protocol.XCore is { Role: XCoreRoles.Exit } exit)
                    exit.RouteId = XCoreRoute.NextFree(
                        XCoreTopology.UsedRouteIds([.. await _servers.GetAllAsync(ct), server]));

                // Сохраняем сразу после каждого протокола: если следующий упадёт,
                // уже развёрнутый не потеряется и не станет «сиротой» на узле.
                server.Protocols.Add(protocol);
                try
                {
                    await _servers.UpdateInstallationAsync(server, ct);
                    break;
                }
                catch (RouteIdTakenException) when (attempt < XCoreRoute.AssignAttempts)
                {
                    server.Protocols.Remove(protocol);
                }
            }

            installed.Add(protocol);
        }

        return installed;
    }

    /// <summary>Файрвол хоста и вычитывание сгенерированных параметров.</summary>
    private async Task FinalizeAsync(
        ISshSession ssh, VpnServer server, List<ProtocolInstance> installed,
        InstallProgressReporter progress, CancellationToken ct)
    {
        await progress.DetailAsync("Настройка файрвола узла", ct);
        var firewall = await ssh.RunHostScriptRawAsync(
            _scripts.Read("shared/setup_host_firewall.sh"), ct);

        if (!firewall.Ok)
        {
            // Часть правил не применяется на VPS с урезанным netfilter.
            // Это не повод считать установку провальной.
            await progress.LogAsync(
                "Не все правила файрвола применились — проверьте настройки узла вручную.",
                AuditLevels.Warn, ct);
        }

        await progress.DetailAsync("Чтение сгенерированных ключей", ct);
        foreach (var protocol in installed)
        {
            // У xcore конфигуратора нет: ключи Reality установщик получил и сохранил сам,
            // а читать у контейнера без shell нечего.
            if (!_configurators.IsSupported(protocol.Kind)) continue;

            var configurator = _configurators.GetConfigurator(protocol.Kind);
            await configurator.EnsureServerParamsAsync(ssh, server, protocol, ct);
        }

        await _servers.UpdateInstallationAsync(server, ct);
    }

    /// <summary>Проверка, что контейнеры действительно работают.</summary>
    private async Task VerifyAsync(
        ISshSession ssh, VpnServer server, List<ProtocolInstance> installed,
        InstallProgressReporter progress, CancellationToken ct)
    {
        var running = await ssh.RunAsync("sudo docker ps --format '{{.Names}}'", ct);
        await progress.LogAsync(running.StdOut, ct: ct);

        var names = running.StdOut
            .Split('\n', StringSplitOptions.RemoveEmptyEntries)
            .Select(n => n.Trim())
            .ToHashSet(StringComparer.Ordinal);

        foreach (var protocol in installed)
        {
            if (!names.Contains(protocol.ContainerName))
            {
                throw new BadRequestException(
                    $"Контейнер {protocol.ContainerName} не запустился. " +
                    "Посмотрите его логи на узле: docker logs " + protocol.ContainerName);
            }

            if (protocol.Wg is { } wg)
            {
                // start.sh is launched with docker exec -d; wait for the actual interface.
                var ready = false;
                for (var attempt = 0; attempt < 10; attempt++)
                {
                    var probe = await ssh.RunAsync($"sudo docker exec {protocol.ContainerName} {wg.Binary} show {wg.InterfaceName}", ct);
                    if (probe.Ok) { ready = true; break; }
                    await Task.Delay(TimeSpan.FromSeconds(1), ct);
                }
                if (!ready) throw new BadRequestException("Интерфейс VPN не запустился. Проверьте поддержку параметров протокола и журнал контейнера.");
            }

            if (protocol.XCore is { } xcore)
                await EnsureXCoreApiRespondsAsync(ssh, xcore, ct);
            protocol.State = ProtocolStates.Installed;
            var version = await ReadContainerVersionAsync(ssh, protocol, ct);
            if (version is not null)
            {
                protocol.ContainerVersion = version;
                await progress.LogAsync($"{protocol.ContainerName}: {version}", ct: ct);
            }
        }

        await _servers.UpdateInstallationAsync(server, ct);
    }

    /// <summary>
    /// «Контейнер запущен» для xcore мало: Xray мог упасть сразу после старта на конфиге,
    /// который прошёл <c>run -test</c>. Ответ API статистики подтверждает, что процесс жив
    /// и inbound поднят. API стартует не мгновенно, поэтому несколько попыток.
    /// </summary>
    private static async Task EnsureXCoreApiRespondsAsync(
        ISshSession ssh, XCoreProtocolParams xcore, CancellationToken ct)
    {
        for (var attempt = 0; attempt < 10; attempt++)
        {
            var probe = await ssh.RunAsync(XCoreNode.InboundUserCountCommand(xcore.ApiPort), ct);
            if (probe.Ok)
            {
                try
                {
                    XrayApiOutput.ParseInboundUserCount(probe.StdOut);
                    return;
                }
                catch (XrayOutputException)
                {
                    // Не JSON: сервер ответил, но не тот. Повторяем, как и при отказе.
                }
            }
            await Task.Delay(TimeSpan.FromSeconds(1), ct);
        }

        throw new BadRequestException(
            "API Xray не отвечает. Посмотрите журнал контейнера на узле: docker logs " + XCoreNode.XrayContainer);
    }

    private static async Task<string?> ReadContainerVersionAsync(
        ISshSession ssh, ProtocolInstance protocol, CancellationToken ct)
    {
        var command = protocol.Kind switch
        {
            ProtocolKinds.XCore => XCoreNode.VersionCommand,
            ProtocolKinds.Xray => $"sudo docker exec -i {protocol.ContainerName} xray version",
            _ => $"sudo docker exec -i {protocol.ContainerName} {protocol.Wg?.Binary ?? "wg"} --version",
        };

        var result = await ssh.RunAsync(command, ct);
        if (!result.Ok) return null;

        return result.StdOut.Split('\n').FirstOrDefault()?.Trim();
    }

    // ── Механика шагов ────────────────────────────────────────────────────────

    private Task StepAsync(
        InstallJob job, string code, InstallProgressReporter progress,
        CancellationToken ct, Func<Task> action)
        => StepAsync<object?>(job, code, progress, ct, async () => { await action(); return null; });

    /// <summary>
    /// Обрамляет шаг: отметка о начале, проверка отмены, пересчёт прогресса.
    ///
    /// Отмена проверяется только на границах: прервать идущую сборку образа
    /// без риска оставить узел в промежуточном состоянии нельзя.
    /// </summary>
    private async Task<T> StepAsync<T>(
        InstallJob job, string code, InstallProgressReporter progress,
        CancellationToken ct, Func<Task<T>> action)
    {
        var fresh = await _jobs.GetByIdAsync(job.Id, ct);
        if (fresh?.CancelRequested == true) throw new OperationCanceledException();

        var step = job.Step(code)
            ?? throw new InvalidOperationException($"Шаг '{code}' не объявлен в задаче.");

        job.CurrentStepCode = code;
        step.Status    = InstallStepStatuses.Running;
        step.StartedAt = DateTime.UtcNow;
        await _jobs.UpdateAsync(job, ct);

        var result = await action();

        step.Status     = InstallStepStatuses.Done;
        step.FinishedAt = DateTime.UtcNow;
        step.Detail     = null;

        job.ProgressPercent = CalculateProgress(job);
        await _jobs.UpdateAsync(job, ct);

        return result;
    }

    /// <summary>
    /// Прогресс по весам шагов, а не по их количеству: сборка образов
    /// занимает больше половины времени, и равномерная шкала застревала бы
    /// на одном значении минутами.
    /// </summary>
    private static int CalculateProgress(InstallJob job)
    {
        var done = InstallStepCodes.All
            .Where(s => job.Step(s.Code)?.Status == InstallStepStatuses.Done)
            .Sum(s => s.Weight);

        return Math.Clamp(done, 0, 100);
    }

    private async Task MarkCurrentStepFailedAsync(InstallJob job, string message)
    {
        var step = job.Step(job.CurrentStepCode ?? string.Empty);
        if (step is null) return;

        step.Status     = InstallStepStatuses.Failed;
        step.Message    = message;
        step.Detail     = null;
        step.FinishedAt = DateTime.UtcNow;

        await _jobs.UpdateAsync(job, CancellationToken.None);
    }

    private async Task FailAsync(InstallJob job, string error, CancellationToken ct)
    {
        job.Status     = InstallJobStatuses.Failed;
        job.Error      = error;
        job.FinishedAt = DateTime.UtcNow;
        await _jobs.UpdateAsync(job, ct);
    }

    private async Task CancelAsync(
        InstallJob job, VpnServer server, InstallProgressReporter progress, CancellationToken ct)
    {
        job.Status     = InstallJobStatuses.Canceled;
        job.FinishedAt = DateTime.UtcNow;
        await _jobs.UpdateAsync(job, CancellationToken.None);

        await progress.LogAsync(
            "Установка отменена оператором.", AuditLevels.Warn, CancellationToken.None);

        if (job.Kind != InstallJobKinds.AddProtocol) server.Status = ServerStatuses.Error;
        foreach (var p in server.Protocols.Where(p => p.State == ProtocolStates.Installing)) p.State = ProtocolStates.Failed;
        await _servers.UpdateInstallationAsync(server, CancellationToken.None);
    }
}
