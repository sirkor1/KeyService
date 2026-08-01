using AmneziaKeyService.Core.Interfaces;
using AmneziaKeyService.Core.Models;
using Microsoft.Extensions.Options;
using MongoDB.Driver;

namespace AmneziaKeyService.Infrastructure.Repositories;

public class RefreshSessionRepository : IRefreshSessionRepository
{
    private readonly IMongoCollection<RefreshSession> _sessions;

    public RefreshSessionRepository(IMongoClient mongo, IOptions<MongoDbOptions> opts) =>
        _sessions = mongo.GetDatabase(opts.Value.DatabaseName)
            .GetCollection<RefreshSession>(opts.Value.RefreshSessionsCollection);

    public Task CreateAsync(RefreshSession session, CancellationToken ct = default) =>
        _sessions.InsertOneAsync(session, cancellationToken: ct);

    public Task<RefreshSession?> FindByTokenHashAsync(string tokenHash, CancellationToken ct = default) =>
        _sessions.Find(x => x.TokenHash == tokenHash).FirstOrDefaultAsync(ct)!;

    public async Task<RefreshRotationResult> RotateAsync(string tokenHash, RefreshSession replacement, DateTime now, CancellationToken ct = default)
    {
        // Standalone MongoDB does not provide multi-document transactions. Persist an inert child first;
        // it becomes usable only after the parent CAS and only if replay has not revoked the family.
        await _sessions.InsertOneAsync(replacement, cancellationToken: ct);
        var b = Builders<RefreshSession>.Filter;
        var active = b.Eq(x => x.TokenHash, tokenHash)
            & b.Eq(x => x.RevokedAt, null)
            & b.Eq(x => x.RotatedAt, null)
            & b.Gt(x => x.ExpiresAt, now);
        var update = Builders<RefreshSession>.Update
            .Set(x => x.RotatedAt, now)
            .Set(x => x.ReplacedById, replacement.Id);
        var consumed = await _sessions.FindOneAndUpdateAsync(active, update,
            new FindOneAndUpdateOptions<RefreshSession> { ReturnDocument = ReturnDocument.Before }, ct);
        if (consumed is not null)
        {
            var activated = await _sessions.UpdateOneAsync(
                x => x.Id == replacement.Id && x.RevokedAt == null && x.ActivatedAt == null,
                Builders<RefreshSession>.Update.Set(x => x.ActivatedAt, now), cancellationToken: ct);
            return activated.ModifiedCount == 1 ? RefreshRotationResult.Rotated : RefreshRotationResult.ReuseDetected;
        }

        // A rotated token is evidence of replay. Revoke the entire chain, including its newest child.
        var presented = await _sessions.Find(b.Eq(x => x.TokenHash, tokenHash)).FirstOrDefaultAsync(ct);
        if (presented?.RotatedAt is not null)
        {
            await RevokeFamilyAsync(presented.FamilyId, now, "refresh_token_reuse", ct);
            return RefreshRotationResult.ReuseDetected;
        }
        return RefreshRotationResult.Invalid;
    }

    public Task<bool> IsActiveAsync(string sessionId, string userId, DateTime now, CancellationToken ct = default) =>
        _sessions.Find(x => x.Id == sessionId && x.UserId == userId && x.RevokedAt == null
                            && x.RotatedAt == null && x.ActivatedAt != null && x.ExpiresAt > now)
            .AnyAsync(ct);

    public Task RevokeAsync(string sessionId, DateTime now, string reason, CancellationToken ct = default) =>
        _sessions.UpdateOneAsync(x => x.Id == sessionId && x.RevokedAt == null,
            Builders<RefreshSession>.Update.Set(x => x.RevokedAt, now).Set(x => x.RevocationReason, reason), cancellationToken: ct);

    public Task RevokeFamilyAsync(string familyId, DateTime now, string reason, CancellationToken ct = default) =>
        _sessions.UpdateManyAsync(x => x.FamilyId == familyId && x.RevokedAt == null,
            Builders<RefreshSession>.Update.Set(x => x.RevokedAt, now).Set(x => x.RevocationReason, reason), cancellationToken: ct);

    public Task RevokeAllForUserAsync(string userId, DateTime now, string reason, CancellationToken ct = default) =>
        _sessions.UpdateManyAsync(x => x.UserId == userId && x.RevokedAt == null,
            Builders<RefreshSession>.Update.Set(x => x.RevokedAt, now).Set(x => x.RevocationReason, reason), cancellationToken: ct);
}
