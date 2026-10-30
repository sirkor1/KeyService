using AmneziaKeyService.Core.Models;
using Microsoft.Extensions.Options;
using MongoDB.Bson;
using MongoDB.Driver;

namespace AmneziaKeyService.Infrastructure.Migrations;

/// <summary>
/// Уникальность номера маршрута выхода xcore. Номер читается из конфига каждого входа и выбирает
/// выход (<c>vlessRoute</c>), поэтому два выхода с одним номером молча слили бы свои плечи в одно.
/// Назначение «наименьший свободный» смотрит на узлы без блокировки, и два выхода, ставящиеся
/// одновременно, могут получить один номер — отсекает это индекс, а не проверка в коде.
///
/// Индекс именно sparse, а не частичный. Частичный фильтр (<c>$type: "int"</c> или <c>$exists</c>)
/// работает на уровне документа: узел, в котором есть и выход с номером, и любой другой протокол
/// (awg, вход без номера), попадает в индекс целиком, а ключ по пути через массив для элемента без поля —
/// <c>null</c>. Тогда два таких узла упираются друг в друга на <c>null</c> (проверено на MongoDB 6.0.5).
/// Sparse пропускает элементы без поля, и уникальность действует только между настоящими номерами.
///
/// Внутри одного документа дубликат индекс не ловит (это свойство уникальных multikey-индексов), но два
/// xcore на одном узле поставить нельзя: они делят порты 80 и 443 (<c>ProtocolInstallRules</c>).
/// </summary>
public class M017_XCoreRouteIdUnique : IMongoMigration
{
    private readonly MongoDbOptions _opts;

    public M017_XCoreRouteIdUnique(IOptions<MongoDbOptions> opts) => _opts = opts.Value;

    public string Id => "017_xcore_route_id_unique";

    public async Task ApplyAsync(IMongoDatabase db, CancellationToken ct)
    {
        var servers = db.GetCollection<BsonDocument>(_opts.ServerConfigCollection);

        await servers.Indexes.CreateOneAsync(
            new CreateIndexModel<BsonDocument>(
                new BsonDocument("protocols.xcore.routeId", 1),
                new CreateIndexOptions { Unique = true, Sparse = true }),
            cancellationToken: ct);
    }
}
