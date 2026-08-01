using System.ComponentModel.DataAnnotations;
using AmneziaKeyService.Core.Models;

namespace AmneziaKeyService.Core.DTOs.Panel;

public record InstallStepDto(
    string Code,
    string Title,
    string Status,
    string? Detail,
    string? Message,
    DateTime? StartedAt,
    DateTime? FinishedAt)
{
    public static InstallStepDto From(InstallStep s) => new(
        s.Code, s.Title, s.Status, s.Detail, s.Message, s.StartedAt, s.FinishedAt);
}

public record JobDto(
    string Id,
    string ServerId,
    string Kind,
    string Status,
    string? CurrentStepCode,
    int ProgressPercent,
    IReadOnlyList<InstallStepDto> Steps,
    long LogSeq,
    bool CancelRequested,
    string? Error,
    DateTime CreatedAt,
    DateTime? StartedAt,
    DateTime? FinishedAt)
{
    public static JobDto From(InstallJob job) => new(
        job.Id, job.ServerId, job.Kind, job.Status, job.CurrentStepCode, job.ProgressPercent,
        [.. job.Steps.Select(InstallStepDto.From)],
        job.LogSeq, job.CancelRequested, job.Error,
        job.CreatedAt, job.StartedAt, job.FinishedAt);
}

public record JobLogEntryDto(long Seq, DateTime At, string? StepCode, string Level, string Text)
{
    public static JobLogEntryDto From(InstallJobLog e) => new(e.Seq, e.At, e.StepCode, e.Level, e.Text);
}

/// <summary>Хвост лога. NextSeq передаётся в следующий запрос.</summary>
public record JobLogDto(IReadOnlyList<JobLogEntryDto> Entries, long NextSeq, bool Done);

/// <summary>Ответ на постановку задачи в очередь.</summary>
public record JobAcceptedDto(string ServerId, string JobId);

// ── Запросы ──────────────────────────────────────────────────────────────────

/// <summary>Протокол, который нужно развернуть.</summary>
public class ProtocolSpecRequest
{
    [Required]
    public string Kind { get; set; } = default!;

    public string? Port { get; set; }
    public string? Mtu { get; set; }
    public string? SubnetAddress { get; set; }
    public string? SubnetCidr { get; set; }

    /// <summary>SNI для VLESS Reality.</summary>
    public string? SiteName { get; set; }

    public ProtocolSpec ToSpec() => new()
    {
        Kind          = Kind,
        Port          = Port,
        Mtu           = Mtu,
        SubnetAddress = SubnetAddress,
        SubnetCidr    = SubnetCidr,
        SiteName      = SiteName,
    };
}

/// <summary>
/// Создание узла с последующей установкой.
///
/// Отличается от прежнего ServerConfigRequest тем, что не описывает уже
/// настроенный узел, а задаёт, что на нём развернуть.
/// </summary>
public class CreateServerRequest
{
    [Required]
    public string Host { get; set; } = default!;

    [Required]
    public string Name { get; set; } = default!;

    public string? Geo { get; set; }
    public string? Provider { get; set; }
    public string? Note { get; set; }
    public int? KeyLimit { get; set; }

    public int SshPort { get; set; } = 22;

    [Required]
    public string SshUser { get; set; } = "root";

    public string? SshPassword { get; set; }

    /// <summary>Приватный ключ в PEM. Хранится зашифрованным.</summary>
    public string? SshPrivateKey { get; set; }

    public string? SshKeyPassphrase { get; set; }

    public string Dns1 { get; set; } = "1.1.1.1";
    public string Dns2 { get; set; } = "8.8.8.8";

    [Required]
    [MinLength(1, ErrorMessage = "Выберите хотя бы один протокол.")]
    public List<ProtocolSpecRequest> Protocols { get; set; } = [];
}

/// <summary>Проверка доступности узла до его сохранения.</summary>
public class TestConnectionRequest
{
    [Required]
    public string Host { get; set; } = default!;

    public int SshPort { get; set; } = 22;

    [Required]
    public string SshUser { get; set; } = "root";

    public string? SshPassword { get; set; }
    public string? SshPrivateKey { get; set; }
    public string? SshKeyPassphrase { get; set; }

    /// <summary>Порты, занятость которых надо проверить.</summary>
    public List<string> Ports { get; set; } = [];
}

public record ConnectionTestDto(
    bool Ok,
    string? Kernel,
    string? DockerVersion,
    bool SudoAvailable,
    string? HostFingerprint,
    IReadOnlyList<string> BusyPorts,
    string? Error)
{
    public static ConnectionTestDto From(Interfaces.ConnectionTestResult r) => new(
        r.Ok, r.Kernel, r.DockerVersion, r.SudoAvailable, r.HostFingerprint, r.BusyPorts, r.Error);
}
