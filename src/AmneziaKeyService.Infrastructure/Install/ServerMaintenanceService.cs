using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using AmneziaKeyService.Core.Exceptions;
using AmneziaKeyService.Core.Interfaces;
using AmneziaKeyService.Core.Models;

namespace AmneziaKeyService.Infrastructure.Install;

/// <summary>Executed by the event dispatcher under the same node lease as installation and key issuance.</summary>
public class ServerMaintenanceService(IVpnServerRepository servers, IVpnClientRepository clients,
    IInstallJobRepository jobs, IDomainEventPublisher events, ISshSessionFactory sshFactory, IAuditService audit)
{
    public async Task<InstallJob> EnqueueAsync(string id, string kind, string confirmation,
        string? actor, CancellationToken ct, bool forgetKeys = false)
    {
        if (!InstallJobKinds.IsMaintenance(kind)) throw new BadRequestException("Неизвестная операция.");
        var server = await servers.GetByIdAsync(id, ct) ?? throw new NotFoundException("Сервер не найден.");
        if (confirmation != server.Name) throw new BadRequestException("Для подтверждения введите точное имя узла.");
        if (await jobs.FindActiveByServerAsync(id, ct) is not null)
            throw new BadRequestException("Дождитесь завершения текущей операции над узлом.");
        if (kind == InstallJobKinds.DeleteServer)
        {
            if (!forgetKeys) await EnsureNoLiveKeysAsync(id, ct);
        }
        else
        {
            if (forgetKeys) throw new BadRequestException("Удаление без отзыва ключей доступно только при удалении записи узла.");
            ValidateContainers(server);
        }
        var job = new InstallJob
        {
            ServerId = id, Kind = kind, CreatedByUserId = actor, MaintenanceRevision = Revision(server),
            ForgetKeys = forgetKeys,
            Steps = [new() { Code = "maintenance", Title = kind == InstallJobKinds.CleanupServer
                ? "Удаление VPN-контейнеров и отзыв ключей"
                : forgetKeys ? "Удаление записи узла без отзыва доступа на сервере" : "Удаление записи узла" }]
        };
        await jobs.CreateAsync(job, ct);
        try
        {
            await events.PublishAsync(DomainEventTypes.ServerInstall, new ServerInstallPayload(job.Id),
                partitionKey: id, correlationId: job.Id, actorUserId: actor, ct: ct);
        }
        catch
        {
            job.Status = InstallJobStatuses.Failed;
            job.Error = "Не удалось поставить операцию в очередь. Повторите запрос.";
            job.FinishedAt = DateTime.UtcNow;
            await jobs.UpdateAsync(job, CancellationToken.None);
            throw;
        }
        await AuditAsync(job, server, "requested", "Запрошена операция: " + job.Steps[0].Title, ct);
        return job;
    }

    public async Task ExecuteAsync(InstallJob job, CancellationToken ct)
    {
        var progress = new InstallProgressReporter(jobs, job);
        VpnServer? server = null;
        var step = job.Steps.Single();
        try
        {
            await CheckCancellationAsync(job, ct);
            job.Status = InstallJobStatuses.Running;
            job.StartedAt = DateTime.UtcNow;
            job.CurrentStepCode = step.Code;
            step.Status = InstallStepStatuses.Running;
            step.StartedAt = DateTime.UtcNow;
            await jobs.UpdateAsync(job, ct);
            server = await servers.GetByIdAsync(job.ServerId, ct) ?? throw new NotFoundException("Сервер не найден.");
            if (job.MaintenanceRevision != Revision(server))
                throw new BadRequestException("Параметры узла изменились после подтверждения. Откройте карточку и повторите операцию.");

            if (job.Kind == InstallJobKinds.DeleteServer)
            {
                if (job.ForgetKeys)
                {
                    // If detaching or deleting fails, keep the node closed to new issuance.
                    // The node partition lease serializes this with queued key issuance.
                    var legacyProtocolId = server.DefaultProtocol?.Id;
                    foreach (var p in server.Protocols) { p.Enabled = false; p.State = ProtocolStates.Failed; }
                    server.DefaultProtocolId = legacyProtocolId;
                    server.Status = ServerStatuses.Error;
                    await servers.UpdateInstallationAsync(server, ct);
                    await clients.DetachServerKeysAsync(server.Id, job.CreatedByUserId, ct);
                }
                await EnsureNoLiveKeysAsync(server.Id, ct);
                // Purge keys first so a failed purge retains the node for an explicit retry.
                // Includes revoked keys and legacy keys without a protocol ID.
                await clients.DeleteByServerAsync(server.Id, ct);
                await servers.DeleteAsync(server.Id, ct);
            }
            else if (job.Kind == InstallJobKinds.CleanupServer)
            {
                ValidateContainers(server);
                await CleanupAsync(server, job, progress, ct);
            }
            else throw new BadRequestException("Неизвестная операция.");

            job.Status = InstallJobStatuses.Succeeded;
            job.ProgressPercent = 100;
            step.Status = InstallStepStatuses.Done;
            await progress.LogAsync(job.Kind == InstallJobKinds.DeleteServer
                ? "Запись узла и все выданные им ключи удалены из базы. Контейнеры на сервере не изменялись; доступ на сервере не отзывался."
                : "VPN-контейнеры удалены, ключи отозваны. Узел сохранён для новой установки.", ct: ct);
            await AuditAsync(job, server, "completed", job.Steps[0].Title + ": завершено", ct);
        }
        catch (Exception ex)
        {
            job.Status = ex is OperationCanceledException ? InstallJobStatuses.Canceled : InstallJobStatuses.Failed;
            job.Error = ex is BadRequestException or NotFoundException or SshConnectionException or SshCommandException
                ? ex.Message : job.Kind == InstallJobKinds.DeleteServer
                    ? "Удаление записи прервано. Обновите список узлов и повторите операцию, если узел остался. Часть или все ключи узла могли быть удалены из базы."
                    : "Операция прервана. Проверьте состояние узла и повторите её; часть контейнеров могла быть удалена.";
            step.Status = InstallStepStatuses.Failed;
            step.Message = job.Error;
            await progress.LogAsync(job.Error, AuditLevels.Error, CancellationToken.None);
            if (server is not null) await AuditAsync(job, server, "failed", job.Error, CancellationToken.None);
        }
        finally
        {
            job.CurrentStepCode = null;
            job.FinishedAt = step.FinishedAt = DateTime.UtcNow;
            await jobs.UpdateAsync(job, CancellationToken.None);
        }
    }

    private async Task CleanupAsync(VpnServer server, InstallJob job, InstallProgressReporter progress, CancellationToken ct)
    {
        var legacyProtocolId = server.DefaultProtocol?.Id;
        var liveKeys = await clients.GetLiveByServerAsync(server.Id, ct);
        if (liveKeys.Any(k => k.ProtocolId is { } id ? server.FindProtocol(id) is null : legacyProtocolId is null))
            throw new BadRequestException("У некоторых ключей отсутствует протокол в карточке узла. Сначала восстановите сведения о протоколах.");
        // Preflight the complete scope before deleting anything. Docker's own immutable IDs
        // prevent deleting a replacement container if an external operator races this task.
        await using var ssh = await sshFactory.ConnectAsync(server, ct);
        var present = await ListAsync(ssh, ct);
        var ids = new Dictionary<string, string>();
        foreach (var protocol in server.Protocols.Where(p => present.Contains(p.ContainerName)))
        {
            var raw = await ssh.RunCheckedAsync($"sudo docker inspect {protocol.ContainerName}", "cleanup_inspect", ct);
            using var json = JsonDocument.Parse(raw);
            var item = json.RootElement[0];
            var id = item.GetProperty("Id").GetString() ?? "";
            if (!Regex.IsMatch(id, "\\A[0-9a-f]{64}\\z") || item.GetProperty("Name").GetString() != "/" + protocol.ContainerName)
                throw new BadRequestException("Не удалось проверить контейнер перед удалением.");
            // Upstream WG containers bind /lib/modules read-write. It is system data,
            // not VPN storage, and docker rm leaves it intact. Reject other mounts,
            // including read-only config mounts, because their keys would survive.
            if (item.GetProperty("Mounts").EnumerateArray().Any(m =>
                m.GetProperty("Type").GetString() != "bind" ||
                m.GetProperty("Destination").GetString() != "/lib/modules" ||
                m.GetProperty("Source").GetString() is not ("/lib/modules" or "/usr/lib/modules")))
                throw new BadRequestException("В контейнере есть внешние каталоги или тома с данными. Автоматическая очистка такой конфигурации не поддерживается.");
            ids.Add(protocol.ContainerName, id);
        }

        // Keep the full protocol list until completion: after a crash, a new explicit
        // cleanup can reconcile already removed containers and finish revoking their keys.
        foreach (var p in server.Protocols) { p.Enabled = false; p.State = ProtocolStates.Failed; }
        server.DefaultProtocolId = legacyProtocolId;
        server.Status = ServerStatuses.Error;
        await servers.UpdateInstallationAsync(server, ct);
        foreach (var p in server.Protocols)
        {
            await CheckCancellationAsync(job, ct);
            await progress.DetailAsync($"Удаление {p.ContainerName}", ct);
            if (ids.TryGetValue(p.ContainerName, out var id))
                await ssh.RunCheckedAsync($"sudo docker rm -f -v {id}", "cleanup_remove_container", ct);
            if ((await ListAsync(ssh, ct)).Contains(p.ContainerName))
                throw new BadRequestException("Контейнер остался на узле или был создан заново. Очистка остановлена.");
            await clients.RevokeRemovedProtocolAsync(server.Id, p.Id, p.Id == legacyProtocolId,
                job.CreatedByUserId, ct);
        }
        await EnsureNoLiveKeysAsync(server.Id, ct);
        server.Protocols.Clear();
        server.DefaultProtocolId = null;
        server.Status = ServerStatuses.Empty;
        await servers.UpdateInstallationAsync(server, ct);
        server.OrphanPeerCount = 0;
        server.ReconciledAt = DateTime.UtcNow;
        await servers.UpdateReconciliationAsync(server, ct);
    }

    private static async Task<HashSet<string>> ListAsync(ISshSession ssh, CancellationToken ct)
        => (await ssh.RunCheckedAsync("sudo docker ps -a --format '{{.Names}}'", "cleanup_list", ct))
            .Split('\n', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries).ToHashSet(StringComparer.Ordinal);

    private async Task CheckCancellationAsync(InstallJob job, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        if ((await jobs.GetByIdAsync(job.Id, ct))?.CancelRequested == true) throw new OperationCanceledException();
    }

    private async Task EnsureNoLiveKeysAsync(string id, CancellationToken ct)
    {
        if ((await clients.GetLiveByServerAsync(id, ct)).Count > 0)
            throw new BadRequestException("На узле остались неотозванные ключи. Выполните очистку, завершите отзыв или подтвердите удаление записи без отзыва ключей.");
    }

    public static void ValidateContainers(VpnServer server)
    {
        var allowed = ProtocolKinds.All.Select(ProtocolKinds.DefaultContainerName).ToHashSet(StringComparer.Ordinal);
        if (server.Protocols.Any(p => !allowed.Contains(p.ContainerName)) ||
            server.Protocols.Select(p => p.ContainerName).Distinct().Count() != server.Protocols.Count)
            throw new BadRequestException("Очистка поддерживает только стандартные контейнеры Amnezia без повторов.");
    }

    public static string Revision(VpnServer server) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(
        JsonSerializer.Serialize(new { server.Id, server.Name, server.Host, server.Ssh.Port, server.DefaultProtocolId,
            LegacyProtocolId = server.DefaultProtocol?.Id,
            Protocols = server.Protocols.OrderBy(p => p.Id).Select(p => new { p.Id, p.Kind, p.ContainerName }) }))));

    private Task AuditAsync(InstallJob job, VpnServer server, string stage, string message, CancellationToken ct)
        => audit.WriteAsync($"server.{job.Kind}.{stage}", message, new AuditActor(job.CreatedByUserId, null),
            AuditTargets.Server, server.Id, server.Name, AuditLevels.Warn, ct: ct);
}
