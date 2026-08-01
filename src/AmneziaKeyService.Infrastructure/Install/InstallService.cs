using System.Text.RegularExpressions;
using AmneziaKeyService.Core.Exceptions;
using AmneziaKeyService.Core.Interfaces;
using AmneziaKeyService.Core.Models;
using AmneziaKeyService.Infrastructure.Scripts;

namespace AmneziaKeyService.Infrastructure.Install;

public partial class InstallService : IInstallService
{
    private readonly IInstallJobRepository _jobs;
    private readonly IDomainEventPublisher _events;
    private readonly IProtocolInstallerRegistry _installers;
    private readonly ISshSessionFactory _sshFactory;
    private readonly ScriptRegistry _scripts;

    public InstallService(
        IInstallJobRepository jobs,
        IDomainEventPublisher events,
        IProtocolInstallerRegistry installers,
        ISshSessionFactory sshFactory,
        ScriptRegistry scripts)
    {
        _jobs       = jobs;
        _events     = events;
        _installers = installers;
        _sshFactory = sshFactory;
        _scripts    = scripts;
    }

    public async Task<InstallJob> EnqueueAsync(
        string serverId, string kind, IReadOnlyList<ProtocolSpec> spec,
        string? createdByUserId, CancellationToken ct = default)
    {
        if (spec.Count == 0)
            throw new BadRequestException("Не выбран ни один протокол для установки.");

        foreach (var item in spec)
        {
            if (!_installers.IsSupported(item.Kind))
                throw new BadRequestException($"Установка протокола '{item.Kind}' не поддерживается.");
        }

        // Одновременно на узле может идти только одна установка: параллельные
        // docker build с одним именем контейнера затрут друг друга.
        var active = await _jobs.FindActiveByServerAsync(serverId, ct);
        if (active is not null)
        {
            throw new BadRequestException(
                "На этом узле уже выполняется установка. Дождитесь её завершения или отмените.");
        }

        var job = new InstallJob
        {
            ServerId        = serverId,
            Kind            = kind,
            Spec            = [.. spec],
            Status          = InstallJobStatuses.Queued,
            CreatedByUserId = createdByUserId,
            Steps =
            [
                .. InstallStepCodes.All.Select(s => new InstallStep
                {
                    Code   = s.Code,
                    Title  = s.Title,
                    Status = InstallStepStatuses.Pending,
                }),
            ],
        };

        await _jobs.CreateAsync(job, ct);

        // Задача создана — событие только просит её исполнить. Порядок важен:
        // событие ссылается на задачу по идентификатору, и обработчик,
        // подхвативший его мгновенно, обязан её застать.
        //
        // partitionKey — узел: две установки на один сервер одновременно
        // затрут друг друга по docker build с одним именем контейнера.
        await _events.PublishAsync(
            DomainEventTypes.ServerInstall,
            new ServerInstallPayload(job.Id),
            partitionKey: serverId,
            correlationId: job.Id,
            actorUserId: createdByUserId,
            ct);

        return job;
    }

    public async Task<ConnectionTestResult> TestConnectionAsync(
        VpnServer server, IReadOnlyList<string> portsToCheck, CancellationToken ct = default)
    {
        try
        {
            await using var ssh = await _sshFactory.ConnectAsync(server, ct);

            var uname = await ssh.RunAsync("uname -sr", ct);
            var docker = await ssh.RunAsync("docker --version", ct);
            var sudo = await ssh.RunHostScriptRawAsync(
                _scripts.Read("shared/check_user_in_sudo.sh"), ct);

            var fingerprint = await ReadFingerprintAsync(ssh, ct);
            var busy = await FindBusyPortsAsync(ssh, portsToCheck, ct);

            return new ConnectionTestResult(
                Ok: true,
                Kernel: uname.StdOut.Trim(),
                // docker --version падает, если Docker ещё не установлен —
                // это нормально, установка его и поставит.
                DockerVersion: docker.Ok ? docker.StdOut.Trim() : null,
                SudoAvailable: sudo.Ok,
                HostFingerprint: fingerprint,
                BusyPorts: busy,
                Error: null);
        }
        catch (Exception ex) when (ex is SshConnectionException or SshCommandException)
        {
            // Проверка связи — диагностика, а не операция: сообщение о неудаче
            // здесь полезнее исключения.
            return new ConnectionTestResult(
                false, null, null, false, null, [], ex.Message);
        }
    }

    private static async Task<string?> ReadFingerprintAsync(ISshSession ssh, CancellationToken ct)
    {
        var result = await ssh.RunAsync(
            "ssh-keyscan -t ed25519 localhost 2>/dev/null | ssh-keygen -lf - 2>/dev/null | awk '{print $2}'",
            ct);

        var value = result.StdOut.Trim();
        return string.IsNullOrEmpty(value) ? null : value;
    }

    private static async Task<List<string>> FindBusyPortsAsync(
        ISshSession ssh, IReadOnlyList<string> ports, CancellationToken ct)
    {
        var busy = new List<string>();

        foreach (var port in ports.Where(p => PortPattern().IsMatch(p)))
        {
            var result = await ssh.RunAsync(
                $"sudo lsof -i -P -n | grep -E ':{port}\\b' | grep -i LISTEN", ct);

            if (result.Ok && !string.IsNullOrWhiteSpace(result.StdOut)) busy.Add(port);
        }

        return busy;
    }

    /// <summary>Порт подставляется в shell-команду, поэтому только цифры.</summary>
    [GeneratedRegex(@"^\d{1,5}$")]
    private static partial Regex PortPattern();
}
