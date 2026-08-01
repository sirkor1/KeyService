using AmneziaKeyService.Core.Models;
using Microsoft.Extensions.Options;
using MongoDB.Bson;
using MongoDB.Driver;

namespace AmneziaKeyService.Infrastructure.Migrations;

/// <summary>
/// Проставляет role и status существующим пользователям.
///
/// Все, кто есть в базе на момент миграции, — конечные VPN-пользователи
/// (зарегистрированные ботом или через открытый /api/auth/register),
/// поэтому получают role=client. Владелец панели создаётся отдельно в M002.
/// </summary>
public class M001_UsersRoles : IMongoMigration
{
    private readonly MongoDbOptions _opts;

    public M001_UsersRoles(IOptions<MongoDbOptions> opts) => _opts = opts.Value;

    public string Id => "001_users_roles";

    public async Task ApplyAsync(IMongoDatabase db, CancellationToken ct)
    {
        var users = db.GetCollection<BsonDocument>(_opts.UsersCollection);

        await users.UpdateManyAsync(
            Builders<BsonDocument>.Filter.Exists("role", false),
            Builders<BsonDocument>.Update.Set("role", UserRoles.Client),
            cancellationToken: ct);

        // status выводим из существующего isActive, чтобы не потерять отключённые учётки
        await users.UpdateManyAsync(
            Builders<BsonDocument>.Filter.And(
                Builders<BsonDocument>.Filter.Exists("status", false),
                Builders<BsonDocument>.Filter.Eq("isActive", false)),
            Builders<BsonDocument>.Update.Set("status", UserStatuses.Blocked),
            cancellationToken: ct);

        await users.UpdateManyAsync(
            Builders<BsonDocument>.Filter.Exists("status", false),
            Builders<BsonDocument>.Update.Set("status", UserStatuses.Active),
            cancellationToken: ct);
    }
}
