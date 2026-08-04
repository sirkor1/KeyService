using System.Text.RegularExpressions;
using AmneziaKeyService.Core.DTOs;
using AmneziaKeyService.Core.Interfaces;
using AmneziaKeyService.Core.Models;
using Microsoft.Extensions.Options;
using MongoDB.Bson;
using MongoDB.Driver;

namespace AmneziaKeyService.Infrastructure.Repositories;

public class UserRepository : IUserRepository
{
    private readonly IMongoCollection<User> _collection;

    public UserRepository(IMongoClient mongo, IOptions<MongoDbOptions> opts)
    {
        var db = mongo.GetDatabase(opts.Value.DatabaseName);
        _collection = db.GetCollection<User>(opts.Value.UsersCollection);
        // Индексы создаёт миграция 005.
    }

    public Task<User?> FindByUsernameAsync(string username, CancellationToken ct = default)
        => _collection.Find(x => x.Username == username).FirstOrDefaultAsync(ct)!;

    public Task<User?> FindByIdAsync(string id, CancellationToken ct = default)
        => _collection.Find(x => x.Id == id).FirstOrDefaultAsync(ct)!;

    public Task<User?> FindByTelegramIdAsync(long telegramId, CancellationToken ct = default)
        => _collection.Find(x => x.TelegramId == telegramId).FirstOrDefaultAsync(ct)!;

    public Task<User?> FindByRoleAsync(string role, CancellationToken ct = default)
        => _collection.Find(x => x.Role == role)
            .SortBy(x => x.CreatedAt)
            .FirstOrDefaultAsync(ct)!;

    public Task CreateAsync(User user, CancellationToken ct = default)
        => _collection.InsertOneAsync(user, cancellationToken: ct);

    public async Task<bool> TryCreateAsync(User user, CancellationToken ct = default)
    {
        try
        {
            await _collection.InsertOneAsync(user, cancellationToken: ct);
            return true;
        }
        catch (MongoWriteException ex) when (ex.WriteError?.Category == ServerErrorCategory.DuplicateKey)
        {
            return false;
        }
    }

    public Task UpdateAsync(User user, CancellationToken ct = default)
    {
        var filter = Builders<User>.Filter.Eq(x => x.Id, user.Id);
        return _collection.ReplaceOneAsync(filter, user, cancellationToken: ct);
    }

    public async Task<bool> DeleteAsync(string id, CancellationToken ct = default)
    {
        if (!ObjectId.TryParse(id, out _)) return false;
        var result = await _collection.DeleteOneAsync(x => x.Id == id, ct);
        return result.DeletedCount > 0;
    }

    // ── Запросы панели ────────────────────────────────────────────────────────

    public async Task<Paged<User>> SearchAsync(UserQuery query, CancellationToken ct = default)
    {
        var b = Builders<User>.Filter;
        var filters = new List<FilterDefinition<User>>();

        if (!string.IsNullOrWhiteSpace(query.Search))
        {
            // Regex.Escape: строка приходит от пользователя, спецсимволы
            // регулярного выражения должны трактоваться буквально.
            var pattern = new BsonRegularExpression(Regex.Escape(query.Search), "i");
            filters.Add(b.Or(
                b.Regex(x => x.Username,    pattern),
                b.Regex(x => x.DisplayName, pattern),
                b.Regex(x => x.Contact,     pattern)));
        }

        if (!string.IsNullOrWhiteSpace(query.Status)) filters.Add(b.Eq(x => x.Status, query.Status));
        if (!string.IsNullOrWhiteSpace(query.Role))   filters.Add(b.Eq(x => x.Role, query.Role));

        var filter = filters.Count == 0 ? FilterDefinition<User>.Empty : b.And(filters);
        var paging = query.Paging;

        var total = await _collection.CountDocumentsAsync(filter, cancellationToken: ct);

        var items = await _collection.Find(filter)
            .SortByDescending(x => x.CreatedAt)
            .Skip(paging.Skip)
            .Limit(paging.PageSize)
            .ToListAsync(ct);

        return new Paged<User>(items, total, paging.Page, paging.PageSize);
    }

    public async Task<List<User>> GetByIdsAsync(IEnumerable<string> ids, CancellationToken ct = default)
    {
        // Невалидные ObjectId отсекаем: драйвер бросит на конвертации фильтра.
        var valid = ids.Where(id => ObjectId.TryParse(id, out _)).Distinct().ToList();
        if (valid.Count == 0) return [];

        return await _collection.Find(Builders<User>.Filter.In(x => x.Id, valid)).ToListAsync(ct);
    }

    public Task<long> CountAsync(CancellationToken ct = default)
        => _collection.CountDocumentsAsync(FilterDefinition<User>.Empty, cancellationToken: ct);

    public Task<List<User>> GetTelegramRecipientsAsync(CancellationToken ct = default)
        => _collection.Find(TelegramRecipientsFilter()).SortBy(x => x.Id).ToListAsync(ct);

    public Task<long> CountTelegramRecipientsAsync(CancellationToken ct = default)
        => _collection.CountDocumentsAsync(TelegramRecipientsFilter(), cancellationToken: ct);

    private static FilterDefinition<User> TelegramRecipientsFilter()
    {
        var b = Builders<User>.Filter;
        return b.And(
            b.Eq(x => x.IsActive, true),
            b.Eq(x => x.Status, UserStatuses.Active),
            b.Ne(x => x.TelegramId, null));
    }
}
