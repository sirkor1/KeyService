using AmneziaKeyService.Core.Models;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using MongoDB.Driver;

namespace AmneziaKeyService.Infrastructure.Migrations;

/// <summary>
/// Уникальный частичный индекс на (serverId, protocolId, assignedIp).
///
/// Закрывает гонку: два одновременных запроса на выдачу выбирали один и тот же
/// свободный адрес и оба его записывали. С индексом второй получает duplicate key,
/// который аллокатор ловит и повторяет со следующим адресом.
///
/// Фильтр перечисляет «занимающие» статусы через $in, а не исключает revoked
/// через $ne: MongoDB не принимает $ne в partialFilterExpression. Требуется
/// MongoDB 6.0+ ($in в частичных индексах). Отозванные ключи в индекс не входят —
/// их peer удалён с узла, адрес свободен.
/// </summary>
public class M006_UniqueAssignedIpIndex : IMongoMigration
{
    /// <summary>Статусы, при которых ключ продолжает занимать адрес.</summary>
    private static readonly string[] OccupyingStatuses =
    [
        KeyStatuses.Active,
        KeyStatuses.Expired,
        KeyStatuses.Suspended,
        KeyStatuses.PendingRevoke
    ];

    private readonly MongoDbOptions _opts;
    private readonly ILogger<M006_UniqueAssignedIpIndex> _logger;

    public M006_UniqueAssignedIpIndex(
        IOptions<MongoDbOptions> opts, ILogger<M006_UniqueAssignedIpIndex> logger)
    {
        _opts   = opts.Value;
        _logger = logger;
    }

    public string Id => "006_unique_assigned_ip_index";

    public async Task ApplyAsync(IMongoDatabase db, CancellationToken ct)
    {
        var clients = db.GetCollection<VpnClient>(_opts.ClientsCollection);
        var b = Builders<VpnClient>.Filter;

        var model = new CreateIndexModel<VpnClient>(
            Builders<VpnClient>.IndexKeys
                .Ascending(x => x.ServerId)
                .Ascending(x => x.ProtocolId)
                .Ascending(x => x.AssignedIp),
            new CreateIndexOptions<VpnClient>
            {
                Unique = true,
                PartialFilterExpression = b.And(
                    b.In(x => x.Status, OccupyingStatuses),
                    b.Exists(x => x.AssignedIp))
            });

        try
        {
            await clients.Indexes.CreateOneAsync(model, cancellationToken: ct);
        }
        catch (MongoCommandException ex) when (IsDuplicateData(ex))
        {
            // Только конфликт ДАННЫХ терпим: дубликаты мог создать прежний
            // аллокатор с гонкой. Ошибку в самой спецификации индекса
            // проглатывать нельзя — она означает баг, и старт должен упасть.
            var duplicates = await FindDuplicateIpsAsync(clients, ct);

            _logger.LogError(
                "Уникальный индекс по назначенным IP не создан: в базе уже есть дубликаты ({Duplicates}). " +
                "Выдача ключей работает, но без защиты от гонки при одновременной выдаче. " +
                "Устраните дубликаты и перезапустите сервис.",
                duplicates.Count == 0 ? "список получить не удалось" : string.Join("; ", duplicates));
        }
    }

    private static bool IsDuplicateData(MongoCommandException ex)
        => ex.Code == 11000 || ex.Message.Contains("E11000", StringComparison.Ordinal);

    private static async Task<List<string>> FindDuplicateIpsAsync(
        IMongoCollection<VpnClient> clients, CancellationToken ct)
    {
        var groups = await clients.Aggregate()
            .Match(Builders<VpnClient>.Filter.And(
                Builders<VpnClient>.Filter.In(x => x.Status, OccupyingStatuses),
                Builders<VpnClient>.Filter.Ne(x => x.AssignedIp, null)))
            .Group(x => new { x.ServerId, x.ProtocolId, x.AssignedIp },
                   g => new { g.Key, Count = g.Count() })
            .Match(x => x.Count > 1)
            .Limit(20)
            .ToListAsync(ct);

        return [.. groups.Select(g => $"{g.Key.AssignedIp} на сервере {g.Key.ServerId} — {g.Count} шт.")];
    }
}
