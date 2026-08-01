using AmneziaKeyService.Core.Models;
using Microsoft.Extensions.Options;
using MongoDB.Bson;
using MongoDB.Driver;

namespace AmneziaKeyService.Infrastructure.Migrations;

/// <summary>
/// Убирает явные telegramId: null у существующих пользователей.
///
/// Индекс telegramId уникальный и sparse, но sparse исключает из индекса только
/// отсутствующее поле — явный null в него попадает. Поэтому любые два пользователя
/// без Telegram (например, владелец панели и любой зарегистрированный через HTTP)
/// конфликтовали с E11000. Модель теперь помечена BsonIgnoreIfNull; эта миграция
/// приводит в порядок уже записанные документы.
/// </summary>
public class M002_UnsetNullTelegramId : IMongoMigration
{
    private readonly MongoDbOptions _opts;

    public M002_UnsetNullTelegramId(IOptions<MongoDbOptions> opts) => _opts = opts.Value;

    public string Id => "002_unset_null_telegram_id";

    public Task ApplyAsync(IMongoDatabase db, CancellationToken ct)
        => db.GetCollection<BsonDocument>(_opts.UsersCollection).UpdateManyAsync(
            Builders<BsonDocument>.Filter.Eq("telegramId", BsonNull.Value),
            Builders<BsonDocument>.Update.Unset("telegramId"),
            cancellationToken: ct);
}
