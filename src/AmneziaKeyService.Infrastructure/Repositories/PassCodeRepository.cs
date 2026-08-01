using AmneziaKeyService.Core.Interfaces;
using AmneziaKeyService.Core.Models;
using Microsoft.Extensions.Options;
using MongoDB.Driver;

namespace AmneziaKeyService.Infrastructure.Repositories;

public class PassCodeRepository : IPassCodeRepository
{
    private readonly IMongoCollection<PassCode> _collection;

    public PassCodeRepository(IMongoClient mongo, IOptions<MongoDbOptions> opts)
    {
        var db = mongo.GetDatabase(opts.Value.DatabaseName);
        _collection = db.GetCollection<PassCode>(opts.Value.PassCodesCollection);
        // Индексы создаёт миграция 005.
    }

    public Task<PassCode?> FindByCodeAsync(string code, CancellationToken ct = default)
        => _collection.Find(x => x.Code == code).FirstOrDefaultAsync(ct)!;

    public Task<PassCode?> FindByIdAsync(string id, CancellationToken ct = default)
        => _collection.Find(x => x.Id == id).FirstOrDefaultAsync(ct)!;

    public Task<List<PassCode>> GetAllAsync(CancellationToken ct = default)
        => _collection.Find(_ => true).SortByDescending(x => x.CreatedAt).ToListAsync(ct);

    public async Task<bool> TryCreateAsync(PassCode passCode, CancellationToken ct = default)
    {
        try
        {
            await _collection.InsertOneAsync(passCode, cancellationToken: ct);
            return true;
        }
        catch (MongoWriteException ex) when (ex.WriteError?.Category == ServerErrorCategory.DuplicateKey)
        {
            return false;
        }
    }

    public async Task<bool> TryClaimAsync(string id, string claimToken, string username, string passwordHash, long? telegramId, CancellationToken ct = default)
    {
        var now = DateTime.UtcNow;
        // Резерв намеренно не переуступается: один код навсегда связан с одним
        // кандидатом, поэтому зависший первый запрос не может создать второго
        // пользователя после того, как другой запрос забрал бы его код.
        var filter = Builders<PassCode>.Filter.Eq(x => x.Id, id)
            // $ne вне partialFilterExpression корректно включает legacy BSON,
            // где isRevoked ещё отсутствует (такие коды активны).
            & Builders<PassCode>.Filter.Ne(x => x.IsRevoked, true)
            & Builders<PassCode>.Filter.Eq(x => x.IsUsed, false);
        var update = Builders<PassCode>.Update
            .Set(x => x.IsUsed, true)
            .Set(x => x.UsedAt, now)
            .Set(x => x.ClaimToken, claimToken)
            .Set(x => x.ClaimedAt, now)
            .Set(x => x.ClaimUsername, username)
            .Set(x => x.ClaimPasswordHash, passwordHash)
            .Set(x => x.ClaimTelegramId, telegramId);
        var result = await _collection.UpdateOneAsync(filter, update, cancellationToken: ct);
        return result.ModifiedCount == 1;
    }

    public async Task<bool> CompleteClaimAsync(string id, string claimToken, string userId, CancellationToken ct = default)
    {
        var filter = Builders<PassCode>.Filter.Eq(x => x.Id, id)
            & Builders<PassCode>.Filter.Eq(x => x.IsUsed, true)
            & Builders<PassCode>.Filter.Eq(x => x.UsedByUserId, null)
            & Builders<PassCode>.Filter.Eq(x => x.ClaimToken, claimToken);
        var result = await _collection.UpdateOneAsync(filter,
            Builders<PassCode>.Update
                .Set(x => x.UsedByUserId, userId)
                .Set(x => x.ClaimToken, null)
                .Set(x => x.ClaimedAt, null)
                .Set(x => x.ClaimUsername, null)
                .Set(x => x.ClaimPasswordHash, null)
                .Set(x => x.ClaimTelegramId, null), cancellationToken: ct);
        if (result.ModifiedCount == 1) return true;

        // Второй одинаковый retry может прийти после завершения первого. Он уже
        // не увидит claimToken (поле очищено), но тот же userId означает, что
        // операция фактически выполнена и должна считаться успешной.
        return await _collection.Find(
                Builders<PassCode>.Filter.Eq(x => x.Id, id)
                & Builders<PassCode>.Filter.Eq(x => x.IsUsed, true)
                & Builders<PassCode>.Filter.Eq(x => x.UsedByUserId, userId))
            .AnyAsync(ct);
    }

    public Task ReleaseClaimAsync(string id, string claimToken, CancellationToken ct = default)
    {
        var filter = Builders<PassCode>.Filter.Eq(x => x.Id, id)
            & Builders<PassCode>.Filter.Eq(x => x.IsUsed, true)
            & Builders<PassCode>.Filter.Ne(x => x.IsRevoked, true)
            & Builders<PassCode>.Filter.Eq(x => x.UsedByUserId, null)
            & Builders<PassCode>.Filter.Eq(x => x.ClaimToken, claimToken);
        var update = Builders<PassCode>.Update
            .Set(x => x.IsUsed, false)
            .Set(x => x.UsedAt, null)
            .Set(x => x.ClaimToken, null)
            .Set(x => x.ClaimedAt, null)
            .Set(x => x.ClaimUsername, null)
            .Set(x => x.ClaimPasswordHash, null)
            .Set(x => x.ClaimTelegramId, null);
        return _collection.UpdateOneAsync(filter, update, cancellationToken: ct);
    }

    public async Task<bool> TryRevokeUnusedAsync(string id, CancellationToken ct = default)
    {
        var filter = Builders<PassCode>.Filter.Eq(x => x.Id, id)
            & Builders<PassCode>.Filter.Eq(x => x.IsUsed, false)
            & Builders<PassCode>.Filter.Ne(x => x.IsRevoked, true);
        var update = Builders<PassCode>.Update
            .Set(x => x.IsRevoked, true)
            .Set(x => x.RevokedAt, DateTime.UtcNow);
        var result = await _collection.UpdateOneAsync(filter, update, cancellationToken: ct);
        return result.ModifiedCount == 1;
    }
}
