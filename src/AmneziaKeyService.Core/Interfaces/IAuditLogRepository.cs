using AmneziaKeyService.Core.DTOs;
using AmneziaKeyService.Core.Models;

namespace AmneziaKeyService.Core.Interfaces;

/// <summary>Журнал событий панели (коллекция audit_log).</summary>
public interface IAuditLogRepository
{
    Task AppendAsync(AuditEntry entry, CancellationToken ct = default);

    Task<Paged<AuditEntry>> SearchAsync(AuditQuery query, CancellationToken ct = default);

    /// <summary>Число записей уровня error за период — плитка «Требуют внимания».</summary>
    Task<long> CountByLevelAsync(string level, TimeSpan within, CancellationToken ct = default);
}

public record AuditQuery(
    string? Level = null,
    string? TargetType = null,
    string? TargetId = null,
    DateTime? From = null,
    DateTime? To = null,
    int? Page = null,
    int? PageSize = null)
{
    public PageRequest Paging => new(Page, PageSize);
}

/// <summary>Настройки панели (коллекция panel_settings, один документ).</summary>
public interface IPanelSettingsRepository
{
    /// <summary>Возвращает сохранённые настройки или значения по умолчанию.</summary>
    Task<PanelSettings> GetAsync(CancellationToken ct = default);

    /// <summary>
    /// Точечно обновляет только применяемые параметры выдачи и метаданные.
    /// Так параллельное сохранение не стирает неизвестные или пока не
    /// редактируемые поля единственного документа.
    /// </summary>
    Task<PanelSettings> UpdateAsync(
        int? defaultExpiryDays,
        long? defaultTrafficLimitBytes,
        string updatedByUserId,
        CancellationToken ct = default);
}
