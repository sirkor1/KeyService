using AmneziaKeyService.Core.Models;
using Microsoft.Extensions.Options;
using MongoDB.Bson;
using MongoDB.Driver;

namespace AmneziaKeyService.Infrastructure.Migrations;

/// <summary>
/// Чинит идентификаторы протоколов, испорченные соглашением драйвера об _id.
///
/// Драйвер MongoDB считает свойство с именем Id идентификатором документа
/// и сериализует его в _id, игнорируя BsonElement("id"). Для вложенного
/// ProtocolInstance это означало, что при чтении поле id не подхватывалось,
/// а при сохранении узла записывался _id со свежесгенерированным Guid —
/// то есть protocolId всех выданных ключей переставал на что-либо указывать.
///
/// Модель исправлена атрибутом BsonNoId; эта миграция приводит в порядок
/// уже записанные документы.
/// </summary>
public class M007_RepairProtocolIds : IMongoMigration
{
    private readonly MongoDbOptions _opts;

    public M007_RepairProtocolIds(IOptions<MongoDbOptions> opts) => _opts = opts.Value;

    public string Id => "007_repair_protocol_ids";

    public async Task ApplyAsync(IMongoDatabase db, CancellationToken ct)
    {
        var servers = db.GetCollection<BsonDocument>(_opts.ServerConfigCollection);

        foreach (var server in await servers.Find(FilterDefinition<BsonDocument>.Empty).ToListAsync(ct))
        {
            if (server.GetValue("protocols", BsonNull.Value) is not BsonArray protocols || protocols.Count == 0)
                continue;

            var defaultId = server.GetValue("defaultProtocolId", BsonNull.Value);
            var changed = false;

            foreach (var protocol in protocols.OfType<BsonDocument>())
            {
                if (protocol.Contains("id") && !protocol["id"].IsBsonNull)
                {
                    // Поле в порядке — убираем только паразитный _id, если он есть.
                    if (protocol.Contains("_id"))
                    {
                        protocol.Remove("_id");
                        changed = true;
                    }
                    continue;
                }

                // Восстанавливаем ИСХОДНЫЙ идентификатор, а не тот, что сгенерировал
                // драйвер: именно на исходный ссылаются defaultProtocolId и ключи.
                // _id здесь — мусорное значение, поэтому он лишь последний резерв.
                var restored =
                    protocols.Count == 1 && !defaultId.IsBsonNull ? defaultId.AsString
                    : protocol.GetValue("_id", BsonNull.Value) is { IsBsonNull: false } legacy ? legacy.ToString()!
                    : Guid.NewGuid().ToString("N");

                protocol["id"] = restored;
                protocol.Remove("_id");
                changed = true;
            }

            // defaultProtocolId мог указывать в пустоту — привязываем к первому протоколу.
            var ids = protocols.OfType<BsonDocument>()
                .Select(p => p.GetValue("id", BsonNull.Value).ToString())
                .ToList();

            if (defaultId.IsBsonNull || !ids.Contains(defaultId.ToString()))
            {
                server["defaultProtocolId"] = ids[0];
                changed = true;
            }

            if (!changed) continue;

            await servers.UpdateOneAsync(
                Builders<BsonDocument>.Filter.Eq("_id", server["_id"]),
                Builders<BsonDocument>.Update
                    .Set("protocols", protocols)
                    .Set("defaultProtocolId", server["defaultProtocolId"]),
                cancellationToken: ct);
        }
    }
}
