using AmneziaKeyService.Core.Models;
using Microsoft.Extensions.Options;
using MongoDB.Bson;
using MongoDB.Driver;

namespace AmneziaKeyService.Infrastructure.Migrations;

/// <summary>
/// Индексы подписок и суточных срезов их трафика.
///
/// Уникальность «одна активная подписка на пользователя» держит индекс, а не проверка в
/// коде: проверка и вставка не атомарны, и два запроса бота подряд завели бы две подписки.
/// Фильтр перечисляет статусы через $in, а не исключает отозванные через $ne: MongoDB не
/// принимает $ne в partialFilterExpression (требуется MongoDB 6.0+). Отозванные подписки
/// остаются в коллекции историей и в индекс не входят.
/// </summary>
public class M016_Subscriptions : IMongoMigration
{
    /// <summary>Статусы, при которых подписка занимает «место» пользователя.</summary>
    private static readonly string[] OccupyingStatuses = [SubscriptionStatuses.Active];

    private readonly MongoDbOptions _opts;

    public M016_Subscriptions(IOptions<MongoDbOptions> opts) => _opts = opts.Value;

    public string Id => "016_subscriptions";

    public async Task ApplyAsync(IMongoDatabase db, CancellationToken ct)
    {
        var subscriptions = db.GetCollection<Subscription>(_opts.SubscriptionsCollection);
        var keys = Builders<Subscription>.IndexKeys;

        await subscriptions.Indexes.CreateManyAsync(
        [
            // Поиск при запросе /sub/{token}.
            new CreateIndexModel<Subscription>(
                keys.Ascending(x => x.TokenHash), new CreateIndexOptions { Unique = true }),

            // UUID есть в каждой ссылке на узел и служит учётными данными в Xray.
            new CreateIndexModel<Subscription>(
                keys.Ascending(x => x.XrayUuid), new CreateIndexOptions { Unique = true }),

            new CreateIndexModel<Subscription>(
                keys.Ascending(x => x.UserId),
                new CreateIndexOptions<Subscription>
                {
                    Unique = true,
                    PartialFilterExpression = new BsonDocumentFilterDefinition<Subscription>(
                        new BsonDocument("status", new BsonDocument("$in", new BsonArray(OccupyingStatuses)))),
                }),

            // Отбор кандидатов на отзыв по сроку и список желаемых пользователей узла.
            new CreateIndexModel<Subscription>(keys.Ascending(x => x.Status).Ascending(x => x.ExpiresAt)),

            // Последняя подписка пользователя в любом статусе — по ней бот решает, можно ли выдать
            // новую. Частичный уникальный индекс выше видит только активные и тут не помогает.
            new CreateIndexModel<Subscription>(
                keys.Ascending(x => x.UserId).Descending(x => x.CreatedAt).Descending(x => x.Id)),
        ], ct);

        var usage = db.GetCollection<SubscriptionUsageDaily>(_opts.SubscriptionUsageDailyCollection);
        var usageKeys = Builders<SubscriptionUsageDaily>.IndexKeys;

        await usage.Indexes.CreateManyAsync(
        [
            new CreateIndexModel<SubscriptionUsageDaily>(
                usageKeys.Ascending(x => x.SubscriptionId).Ascending(x => x.Date)),

            // 400 дней, как у остальных срезов: момент удаления записан в самом документе.
            new CreateIndexModel<SubscriptionUsageDaily>(usageKeys.Ascending(x => x.ExpireAt),
                new CreateIndexOptions { ExpireAfter = TimeSpan.Zero }),
        ], ct);
    }
}
