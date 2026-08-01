using AmneziaKeyService.Core.Models;

namespace AmneziaKeyService.Core.Interfaces;

public interface IPassCodeRepository
{
    Task<PassCode?> FindByCodeAsync(string code, CancellationToken ct = default);
    Task<PassCode?> FindByIdAsync(string id, CancellationToken ct = default);
    Task<List<PassCode>> GetAllAsync(CancellationToken ct = default);
    /// <summary>Создаёт код, возвращая false при конфликте уникального индекса code.</summary>
    Task<bool> TryCreateAsync(PassCode passCode, CancellationToken ct = default);
    /// <summary>Атомарно резервирует активный неиспользованный код.</summary>
    Task<bool> TryClaimAsync(string id, string claimToken, string username, string passwordHash, long? telegramId, CancellationToken ct = default);
    /// <summary>Привязывает уже зарезервированный код к созданному пользователю.</summary>
    Task<bool> CompleteClaimAsync(string id, string claimToken, string userId, CancellationToken ct = default);
    /// <summary>Освобождает резерв, если создание пользователя завершилось ошибкой.</summary>
    Task ReleaseClaimAsync(string id, string claimToken, CancellationToken ct = default);
    /// <summary>Отзывает только неиспользованный код. Возвращает false при гонке или уже использованном коде.</summary>
    Task<bool> TryRevokeUnusedAsync(string id, CancellationToken ct = default);
}
