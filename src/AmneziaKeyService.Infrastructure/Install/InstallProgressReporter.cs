using AmneziaKeyService.Core.Interfaces;
using AmneziaKeyService.Core.Models;
using AmneziaKeyService.Infrastructure.Services;

namespace AmneziaKeyService.Infrastructure.Install;

/// <summary>
/// Пишет ход установки в документ задачи и в её лог.
///
/// Каждая строка проходит через <see cref="SecretRedactor"/>: скрипты Amnezia
/// печатают сгенерированные ключи в stdout, а лог задачи выгружается из панели.
/// </summary>
public class InstallProgressReporter : IInstallProgress
{
    /// <summary>
    /// Ограничение на строку. docker build выдаёт очень длинные строки
    /// прогресса, а панель их всё равно не покажет целиком.
    /// </summary>
    private const int MaxLineLength = 2000;

    private readonly IInstallJobRepository _jobs;
    private readonly InstallJob _job;

    public InstallProgressReporter(IInstallJobRepository jobs, InstallJob job)
    {
        _jobs = jobs;
        _job  = job;
    }

    public async Task DetailAsync(string detail, CancellationToken ct = default)
    {
        var step = _job.Step(_job.CurrentStepCode ?? string.Empty);
        if (step is not null) step.Detail = detail;

        await _jobs.UpdateAsync(_job, ct);
        await LogAsync(detail, ct: ct);
    }

    public async Task LogAsync(
        string text, string level = AuditLevels.Info, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(text)) return;

        foreach (var line in SplitLines(text))
        {
            _job.LogSeq++;

            await _jobs.AppendLogAsync(new InstallJobLog
            {
                JobId    = _job.Id,
                Seq      = _job.LogSeq,
                StepCode = _job.CurrentStepCode,
                Level    = level,
                Text     = SecretRedactor.Redact(line),
            }, ct);
        }

        await _jobs.UpdateAsync(_job, ct);
    }

    private static IEnumerable<string> SplitLines(string text)
        => text.Split('\n')
            .Select(line => line.TrimEnd('\r'))
            .Where(line => !string.IsNullOrWhiteSpace(line))
            .Select(line => line.Length > MaxLineLength ? line[..MaxLineLength] + "…" : line);
}
