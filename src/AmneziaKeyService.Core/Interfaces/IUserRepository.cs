using AmneziaKeyService.Core.DTOs;
using AmneziaKeyService.Core.Models;

namespace AmneziaKeyService.Core.Interfaces;

public interface IUserRepository
{
    Task<User?> FindByUsernameAsync(string username, CancellationToken ct = default);
    Task<User?> FindByIdAsync(string id, CancellationToken ct = default);
    Task<User?> FindByTelegramIdAsync(long telegramId, CancellationToken ct = default);

    /// <summary>Первый пользователь с указанной ролью. Используется для поиска владельца панели.</summary>
    Task<User?> FindByRoleAsync(string role, CancellationToken ct = default);

    Task CreateAsync(User user, CancellationToken ct = default);

    /// <summary>
    /// Создаёт пользователя только если уникальный индекс username это допускает.
    /// False покрывает гонку между предварительной проверкой и вставкой.
    /// </summary>
    Task<bool> TryCreateAsync(User user, CancellationToken ct = default);
    Task UpdateAsync(User user, CancellationToken ct = default);
    Task<bool> DeleteAsync(string id, CancellationToken ct = default);

    // ── Для панели ────────────────────────────────────────────────────────────

    Task<Paged<User>> SearchAsync(UserQuery query, CancellationToken ct = default);

    /// <summary>Пользователи по списку id — для подстановки владельцев в список ключей.</summary>
    Task<List<User>> GetByIdsAsync(IEnumerable<string> ids, CancellationToken ct = default);

    Task<long> CountAsync(CancellationToken ct = default);
}

/// <summary>
/// Фильтры списка пользователей. Search сопоставляется с логином,
/// отображаемым именем и контактом.
/// </summary>
public record UserQuery(
    string? Search = null,
    string? Status = null,
    string? Role = null,
    int? Page = null,
    int? PageSize = null)
{
    public PageRequest Paging => new(Page, PageSize);
}
