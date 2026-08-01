using System.Globalization;
using AmneziaKeyService.Core.Interfaces;
using AmneziaKeyService.Core.Models;
using AmneziaKeyService.Infrastructure.Services;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace AmneziaKeyService.Infrastructure.Monitoring;

/// <summary>
/// Проверяет доступность и нагрузку узлов.
///
/// Все показатели снимаются одной командой: семь отдельных exec-ов по SSH
/// стоят семи round-trip-ов на узел, а нужны они одновременно и раз в пять минут.
/// </summary>
public class HealthPollerService : PeriodicWorker
{
    /// <summary>
    /// Каждая величина берётся в подстановке с подавленным stderr: отсутствие
    /// docker или урезанный df не должны обрывать сбор остальных.
    ///
    /// Аптайм считается от /proc/uptime, а не от «uptime -s»: второй печатает
    /// время в часовом поясе узла, и на сервере не в UTC момент загрузки
    /// уезжал бы на несколько часов.
    /// </summary>
    private const string ProbeScript = """
        echo "boot_seconds=$(cut -d' ' -f1 /proc/uptime 2>/dev/null)"
        echo "cpus=$(nproc 2>/dev/null)"
        echo "load1=$(cut -d' ' -f1 /proc/loadavg 2>/dev/null)"
        echo "mem_percent=$(free 2>/dev/null | awk '/^Mem:/{printf "%.1f", $3/$2*100}')"
        echo "disk_percent=$(df -P / 2>/dev/null | awk 'NR==2{gsub(/%/,"",$5); print $5}')"
        echo "docker=$(docker --version 2>/dev/null | head -1)"
        echo "kernel=$(uname -r 2>/dev/null)"
        """;

    public HealthPollerService(
        IServiceScopeFactory scopeFactory,
        IOptions<PollingOptions> options,
        ILogger<HealthPollerService> logger)
        : base(scopeFactory,
               options.Value.For(TimeSpan.FromSeconds(options.Value.HealthIntervalSeconds)),
               logger)
    {
    }

    protected override string Name => "health";

    protected override async Task TickAsync(IServiceProvider services, CancellationToken ct)
    {
        var servers = await services.GetRequiredService<IVpnServerRepository>().GetAllAsync(ct);

        // Узлы в setup проверять нечего: контейнеров ещё нет, а статус
        // ими управляет оркестратор установки.
        var checkable = servers
            .Where(s => s.Status is ServerStatuses.Ok or ServerStatuses.Offline or ServerStatuses.Error)
            .ToList();

        if (checkable.Count == 0) return;

        await ForEachServerAsync(checkable, CheckAsync, ct);
    }

    private async Task CheckAsync(IServiceProvider services, VpnServer server, CancellationToken ct)
    {
        var probe = await ProbeAsync(services, server, ct);

        server.Health = probe ?? new ServerHealth
        {
            LastCheckAt = DateTime.UtcNow,
            Online      = false,
            // Прежние значения нагрузки не переносим: показывать загрузку 12%
            // у узла, до которого нет доступа, — вводить в заблуждение.
        };

        await ApplyStatusAsync(services, server, probe is not null, ct);

        await services.GetRequiredService<IVpnServerRepository>().UpdateAsync(server, ct);

        await services.GetRequiredService<IUsageRepository>().RecordHealthCheckAsync(
            server.Id, DateOnly.FromDateTime(DateTime.UtcNow), probe is not null, ct);
    }

    /// <summary>Снимает показатели с узла. Null — узел не ответил.</summary>
    private async Task<ServerHealth?> ProbeAsync(
        IServiceProvider services, VpnServer server, CancellationToken ct)
    {
        try
        {
            await using var ssh = await services
                .GetRequiredService<ISshSessionFactory>()
                .ConnectAsync(server, ct);

            var result = await ssh.RunAsync(ProbeScript, ct);

            if (!result.Ok)
            {
                Logger.LogWarning(
                    "Узел {ServerName}: проверка вернула код {ExitStatus}. {Error}",
                    server.Name, result.ExitStatus, SecretRedactor.Tail(result.StdErr, 500));

                return null;
            }

            return Parse(result.StdOut);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            // Недоступный узел — рядовой результат проверки, а не сбой воркера.
            Logger.LogInformation(
                "Узел {ServerName} ({ServerHost}) недоступен: {Reason}",
                server.Name, server.Host, ex.Message);

            return null;
        }
    }

    /// <summary>
    /// Переводит узел между ok и offline. Статусы setup и error не трогает:
    /// error означает неудачную установку и говорит больше, чем «недоступен»,
    /// а setup означает идущую установку, статусом которой владеет оркестратор.
    /// </summary>
    private async Task ApplyStatusAsync(
        IServiceProvider services, VpnServer server, bool online, CancellationToken ct)
    {
        var audit = services.GetRequiredService<IAuditService>();

        if (!online && server.Status == ServerStatuses.Ok)
        {
            server.Status = ServerStatuses.Offline;

            Logger.LogWarning("Узел {ServerName} ({ServerId}) ушёл в offline.",
                server.Name, server.Id);

            await audit.WriteAsync(AuditEvents.ServerWentOffline,
                $"Узел «{server.Name}» перестал отвечать",
                targetType: AuditTargets.Server, targetId: server.Id, targetName: server.Name,
                level: AuditLevels.Warn, ct: ct);

            return;
        }

        if (online && server.Status == ServerStatuses.Offline)
        {
            server.Status = ServerStatuses.Ok;

            Logger.LogInformation("Узел {ServerName} ({ServerId}) снова доступен.",
                server.Name, server.Id);

            await audit.WriteAsync(AuditEvents.ServerBackOnline,
                $"Узел «{server.Name}» снова доступен",
                targetType: AuditTargets.Server, targetId: server.Id, targetName: server.Name,
                ct: ct);
        }

        // Повторные проверки в том же состоянии молчат: иначе журнал
        // недоступного узла пополнялся бы записью каждые пять минут.
    }

    private static ServerHealth Parse(string output)
    {
        var values = new Dictionary<string, string>(StringComparer.Ordinal);

        foreach (var line in output.Split('\n'))
        {
            var separator = line.IndexOf('=');
            if (separator <= 0) continue;

            var key   = line[..separator].Trim();
            var value = line[(separator + 1)..].Trim();

            if (value.Length > 0) values[key] = value;
        }

        var now = DateTime.UtcNow;

        return new ServerHealth
        {
            LastCheckAt   = now,
            Online        = true,
            UptimeSince   = Number(values, "boot_seconds") is { } seconds
                                ? now.AddSeconds(-seconds)
                                : null,
            CpuCount      = Number(values, "cpus") is { } cpus ? (int)cpus : null,
            Load1         = Number(values, "load1"),
            MemPercent    = Number(values, "mem_percent"),
            DiskPercent   = Number(values, "disk_percent"),
            DockerVersion = values.GetValueOrDefault("docker"),
            Kernel        = values.GetValueOrDefault("kernel"),
        };
    }

    /// <summary>
    /// Разбор числа строго в инвариантной культуре: на узле с локалью,
    /// где разделитель дробной части — запятая, awk печатает «12,5»,
    /// и разбор по текущей культуре сервиса дал бы то 12.5, то 125.
    /// </summary>
    private static double? Number(Dictionary<string, string> values, string key)
        => values.TryGetValue(key, out var raw)
           && double.TryParse(raw.Replace(',', '.'), NumberStyles.Float, CultureInfo.InvariantCulture, out var value)
            ? value
            : null;
}
