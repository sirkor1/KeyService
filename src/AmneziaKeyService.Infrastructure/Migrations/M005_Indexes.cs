using AmneziaKeyService.Core.Models;
using Microsoft.Extensions.Options;
using MongoDB.Driver;

namespace AmneziaKeyService.Infrastructure.Migrations;

/// <summary>
/// Единая точка создания индексов.
///
/// Раньше индексы создавались в конструкторах репозиториев — DDL выполнялся
/// при каждом старте каждого инстанса, а VpnClientRepository вдобавок дропал
/// и пересоздавал индекс. Здесь это делается один раз.
///
/// Имена индексов намеренно не задаются: в базе уже есть индексы, созданные
/// прежним кодом с автогенерированными именами (username_1, code_1). Создание
/// того же набора ключей под другим именем MongoDB отвергает с
/// IndexOptionsConflict, а с автоименем повторный вызов — безобидный no-op.
/// </summary>
public class M005_Indexes : IMongoMigration
{
    private readonly MongoDbOptions _opts;

    public M005_Indexes(IOptions<MongoDbOptions> opts) => _opts = opts.Value;

    public string Id => "005_indexes";

    public async Task ApplyAsync(IMongoDatabase db, CancellationToken ct)
    {
        await CreateUserIndexesAsync(db, ct);
        await CreateClientIndexesAsync(db, ct);
        await CreatePassCodeIndexesAsync(db, ct);
        await CreateAuditIndexesAsync(db, ct);
    }

    private async Task CreateUserIndexesAsync(IMongoDatabase db, CancellationToken ct)
    {
        var users = db.GetCollection<User>(_opts.UsersCollection);
        var keys  = Builders<User>.IndexKeys;

        await users.Indexes.CreateManyAsync(
        [
            new CreateIndexModel<User>(keys.Ascending(x => x.Username),
                new CreateIndexOptions { Unique = true }),

            // Sparse: у пользователей панели поля telegramId нет вовсе.
            new CreateIndexModel<User>(keys.Ascending(x => x.TelegramId),
                new CreateIndexOptions { Unique = true, Sparse = true }),

            new CreateIndexModel<User>(keys.Ascending(x => x.Role))
        ], ct);
    }

    private async Task CreateClientIndexesAsync(IMongoDatabase db, CancellationToken ct)
    {
        var clients = db.GetCollection<VpnClient>(_opts.ClientsCollection);
        var keys    = Builders<VpnClient>.IndexKeys;

        await clients.Indexes.CreateManyAsync(
        [
            new CreateIndexModel<VpnClient>(
                keys.Ascending(x => x.UserId).Ascending(x => x.ServerId)),

            new CreateIndexModel<VpnClient>(keys.Ascending(x => x.ShortId),
                new CreateIndexOptions { Unique = true, Sparse = true }),

            new CreateIndexModel<VpnClient>(
                keys.Ascending(x => x.ServerId).Ascending(x => x.Status)),

            new CreateIndexModel<VpnClient>(keys.Ascending(x => x.ClientPubKey),
                new CreateIndexOptions { Sparse = true })
        ], ct);

        // Уникальный индекс по назначенным IP создаёт миграция 006.
    }

    private async Task CreatePassCodeIndexesAsync(IMongoDatabase db, CancellationToken ct)
    {
        var passCodes = db.GetCollection<PassCode>(_opts.PassCodesCollection);

        await passCodes.Indexes.CreateOneAsync(
            new CreateIndexModel<PassCode>(
                Builders<PassCode>.IndexKeys.Ascending(x => x.Code),
                new CreateIndexOptions { Unique = true }),
            cancellationToken: ct);
    }

    private async Task CreateAuditIndexesAsync(IMongoDatabase db, CancellationToken ct)
    {
        var audit = db.GetCollection<AuditEntry>(_opts.AuditLogCollection);
        var keys  = Builders<AuditEntry>.IndexKeys;

        await audit.Indexes.CreateManyAsync(
        [
            new CreateIndexModel<AuditEntry>(keys.Descending(x => x.At)),

            new CreateIndexModel<AuditEntry>(
                keys.Ascending(x => x.TargetId).Descending(x => x.At)),

            // TTL 180 дней: журнал растёт бесконечно, а панель показывает недавнее.
            // Отдельное имя обязательно — ключ At уже занят индексом at_desc.
            new CreateIndexModel<AuditEntry>(keys.Ascending(x => x.At),
                new CreateIndexOptions
                {
                    Name        = "at_ttl",
                    ExpireAfter = TimeSpan.FromDays(180)
                })
        ], ct);
    }
}
