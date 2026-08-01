using AmneziaKeyService.Core.Models;
using Microsoft.Extensions.Options;
using MongoDB.Driver;

namespace AmneziaKeyService.Infrastructure.Migrations;

/// <summary>Индексы шины доменных событий и коллекции аренд.</summary>
public class M010_DomainEvents : IMongoMigration
{
    private readonly MongoDbOptions _opts;

    public M010_DomainEvents(IOptions<MongoDbOptions> opts) => _opts = opts.Value;

    public string Id => "010_domain_events";

    public async Task ApplyAsync(IMongoDatabase db, CancellationToken ct)
    {
        var events = db.GetCollection<DomainEvent>(_opts.DomainEventsCollection);
        var keys   = Builders<DomainEvent>.IndexKeys;

        await events.Indexes.CreateManyAsync(
        [
            // Запрос захвата: тип, статус и готовность по времени. Порядок полей
            // повторяет фильтр, сортировка по availableAt закрывается тем же
            // индексом — иначе каждый тик диспетчера сортировал бы в памяти.
            new CreateIndexModel<DomainEvent>(
                keys.Ascending(x => x.Type)
                    .Ascending(x => x.Status)
                    .Ascending(x => x.AvailableAt)),

            // Жнец ищет по статусу и сроку аренды.
            new CreateIndexModel<DomainEvent>(
                keys.Ascending(x => x.Status).Ascending("lease.until")),

            // По ключу или узлу собирается вся история операций над ним.
            new CreateIndexModel<DomainEvent>(keys.Ascending(x => x.CorrelationId),
                new CreateIndexOptions { Sparse = true }),

            // Завершённые события живут 30 дней: дальше они интересны разве что
            // как история, а история операторского уровня лежит в audit_log.
            new CreateIndexModel<DomainEvent>(keys.Ascending(x => x.FinishedAt),
                new CreateIndexOptions
                {
                    ExpireAfter = TimeSpan.FromDays(30),
                    Sparse      = true,
                }),
        ], ct);

        var leases = db.GetCollection<Lease>(_opts.LeasesCollection);

        // Только уборка мусора, и с запасом в час. Корректность держится
        // на условии until < now в фильтре взятия аренды: TTL-монитор ходит
        // раз в минуту и полагаться на него как на механизм освобождения
        // означало бы минуту простоя после каждого падения держателя.
        await leases.Indexes.CreateOneAsync(
            new CreateIndexModel<Lease>(
                Builders<Lease>.IndexKeys.Ascending(x => x.Until),
                new CreateIndexOptions { ExpireAfter = TimeSpan.FromHours(1) }),
            cancellationToken: ct);
    }
}
