using AmneziaKeyService.Core.DTOs;
using AmneziaKeyService.Core.Models;

namespace AmneziaKeyService.Core.Interfaces;

public interface IInstallJobRepository
{
    Task<InstallJob> CreateAsync(InstallJob job, CancellationToken ct = default);

    Task<InstallJob?> GetByIdAsync(string id, CancellationToken ct = default);

    Task UpdateAsync(InstallJob job, CancellationToken ct = default);

    Task<Paged<InstallJob>> SearchAsync(JobQuery query, CancellationToken ct = default);

    /// <summary>Активная задача узла. Одновременно их может быть не больше одной.</summary>
    Task<InstallJob?> FindActiveByServerAsync(string serverId, CancellationToken ct = default);

    /// <summary>
    /// Помечает задачи, оставшиеся в running после перезапуска сервиса.
    /// Установка не идемпотентна на середине, поэтому возобновлять нельзя —
    /// только честно сообщить, что она прервана.
    /// </summary>
    Task<long> FailInterruptedAsync(string reason, CancellationToken ct = default);

    /// <summary>Помечает запрос отмены. Воркер проверит его на границе шага.</summary>
    Task<bool> RequestCancelAsync(string id, CancellationToken ct = default);

    // ── Лог ───────────────────────────────────────────────────────────────────

    Task AppendLogAsync(InstallJobLog entry, CancellationToken ct = default);

    /// <summary>Строки лога после указанного seq — панель дочитывает хвост.</summary>
    Task<List<InstallJobLog>> GetLogAsync(
        string jobId, long afterSeq, int limit, CancellationToken ct = default);
}

public record JobQuery(
    string? ServerId = null,
    string? Status = null,
    int? Page = null,
    int? PageSize = null)
{
    public PageRequest Paging => new(Page, PageSize);
}
