using AmneziaKeyService.Core.Models;

namespace AmneziaKeyService.Core.Interfaces;

public interface IRefreshSessionRepository
{
    Task CreateAsync(RefreshSession session, CancellationToken ct = default);
    Task<RefreshSession?> FindByTokenHashAsync(string tokenHash, CancellationToken ct = default);
    Task<RefreshRotationResult> RotateAsync(string tokenHash, RefreshSession replacement, DateTime now, CancellationToken ct = default);
    Task<bool> IsActiveAsync(string sessionId, string userId, DateTime now, CancellationToken ct = default);
    Task RevokeAsync(string sessionId, DateTime now, string reason, CancellationToken ct = default);
    Task RevokeFamilyAsync(string familyId, DateTime now, string reason, CancellationToken ct = default);
    Task RevokeAllForUserAsync(string userId, DateTime now, string reason, CancellationToken ct = default);
}
