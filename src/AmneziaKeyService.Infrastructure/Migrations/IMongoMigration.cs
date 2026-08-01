using MongoDB.Driver;

namespace AmneziaKeyService.Infrastructure.Migrations;

/// <summary>
/// Одна миграция схемы MongoDB. Применяется ровно один раз —
/// факт применения фиксируется в коллекции _migrations по <see cref="Id"/>.
///
/// Каждая миграция обязана быть идемпотентной: запись в _migrations делается
/// после успешного выполнения, поэтому падение на середине приведёт к повтору.
/// </summary>
public interface IMongoMigration
{
    /// <summary>Сортируемый идентификатор: "001_users_roles".</summary>
    string Id { get; }

    Task ApplyAsync(IMongoDatabase db, CancellationToken ct);
}
