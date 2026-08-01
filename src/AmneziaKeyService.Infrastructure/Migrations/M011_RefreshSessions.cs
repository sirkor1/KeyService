using AmneziaKeyService.Core.Models;
using Microsoft.Extensions.Options;
using MongoDB.Driver;

namespace AmneziaKeyService.Infrastructure.Migrations;

/// <summary>Indexes for server-side panel refresh sessions. Applied only by Worker.</summary>
public class M011_RefreshSessions : IMongoMigration
{
    private readonly MongoDbOptions _opts;
    public M011_RefreshSessions(IOptions<MongoDbOptions> opts) => _opts = opts.Value;
    public string Id => "011_refresh_sessions";

    public Task ApplyAsync(IMongoDatabase db, CancellationToken ct)
    {
        var sessions = db.GetCollection<RefreshSession>(_opts.RefreshSessionsCollection);
        var keys = Builders<RefreshSession>.IndexKeys;
        return sessions.Indexes.CreateManyAsync([
            new CreateIndexModel<RefreshSession>(keys.Ascending(x => x.TokenHash), new CreateIndexOptions { Unique = true }),
            new CreateIndexModel<RefreshSession>(keys.Ascending(x => x.UserId).Ascending(x => x.RevokedAt)),
            new CreateIndexModel<RefreshSession>(keys.Ascending(x => x.FamilyId)),
            new CreateIndexModel<RefreshSession>(keys.Ascending(x => x.ExpiresAt), new CreateIndexOptions { ExpireAfter = TimeSpan.Zero }),
        ], ct);
    }
}
