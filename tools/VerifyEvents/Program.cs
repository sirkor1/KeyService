using System.Collections.Concurrent;
using System.Text;
using AmneziaKeyService.Core.Interfaces;
using AmneziaKeyService.Core.Models;
using AmneziaKeyService.Infrastructure.Events;
using AmneziaKeyService.Infrastructure.Migrations;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using MongoDB.Bson;
using MongoDB.Driver;

// Проверяет шину доменных событий на живой MongoDB.
//
// В отличие от остальных проверок эта требует базы: всё, что здесь важно —
// атомарность захвата, сериализация по партиции, поведение аренды, — это
// свойства конкретного драйвера и конкретного развёртывания, а не логики,
// которую можно проверить в памяти. Особенно на standalone, где нет ни
// транзакций, ни change streams: если бы что-то из этого молча не работало,
// узнали бы по двум одновременным правкам конфига одного узла.
//
// Работает на временной базе и удаляет её за собой.

var connection = args.FirstOrDefault(a => a.StartsWith("--mongo=", StringComparison.Ordinal))
                     ?.Split('=', 2)[1]
                 ?? Environment.GetEnvironmentVariable("MONGO_URL")
                 ?? "mongodb://localhost:27017";

var database = $"amnezia_events_probe_{Guid.NewGuid().ToString("N")[..8]}";

var failures = new List<string>();
var checks = 0;

void Check(string name, bool ok, string? detail = null)
{
    checks++;
    Console.WriteLine($"  [{(ok ? "OK  " : "ПРОВАЛ")}] {name}{(detail is null ? "" : $" — {detail}")}");
    if (!ok) failures.Add(name);
}

Console.OutputEncoding = Encoding.UTF8;
Console.WriteLine($"База {database} на {connection}");
Console.WriteLine();

var client = new MongoClient(connection);
var opts = Options.Create(new MongoDbOptions { DatabaseName = database });

try
{
    await new M010_DomainEvents(opts).ApplyAsync(client.GetDatabase(database), CancellationToken.None);

    var events = new DomainEventRepository(client, opts);
    var leases = new LeaseRepository(client, opts);

    const string Alpha = "worker-alpha";
    const string Beta  = "worker-beta";

    // Нейтральные типы: проверка ниже испытывает саму шину (захват, аренду,
    // возврат в очередь), а не выдачу или отзыв ключа. С появлением
    // KeyIssueHandler/KeyRevokeHandler в worker настоящие key.issue/key.revoke
    // читались бы как проверка выдачи, которой здесь нет, — репозиторий типы
    // не валидирует, так что для механизма шины подойдут любые строки.
    const string ProbeAlpha = "probe.alpha";
    const string ProbeBeta  = "probe.beta";

    string[] types = [ProbeAlpha, ProbeBeta];

    // ── Захват ───────────────────────────────────────────────────────────────

    Console.WriteLine("Захват события");

    var published = await events.PublishAsync(
        ProbeAlpha, new { serverId = "s1" },
        partitionKey: "s1", correlationId: "key-1");

    Check("Опубликованное событие в статусе pending",
        published.Status == DomainEventStatuses.Pending, published.Status);

    var claimed = await events.ClaimAsync(types, Alpha, TimeSpan.FromMinutes(1));

    Check("Событие захвачено", claimed?.Id == published.Id);
    Check("Статус после захвата — claimed",
        claimed?.Status == DomainEventStatuses.Claimed, claimed?.Status);
    Check("Владелец аренды записан", claimed?.Lease?.Owner == Alpha);
    Check("Счётчик попыток увеличен", claimed?.Attempt == 1, $"{claimed?.Attempt}");

    Check("Повторный захват ничего не возвращает — событие уже взято",
        await events.ClaimAsync(types, Beta, TimeSpan.FromMinutes(1)) is null);

    Check("Чужой тип не захватывается",
        await events.ClaimAsync([DomainEventTypes.ServerInstall], Beta, TimeSpan.FromMinutes(1)) is null);

    // ── Аренда ───────────────────────────────────────────────────────────────

    Console.WriteLine();
    Console.WriteLine("Аренда события");

    Check("Владелец продлевает свою аренду",
        await events.RenewLeaseAsync(published.Id, Alpha, TimeSpan.FromMinutes(1)));

    Check("Чужую аренду продлить нельзя",
        !await events.RenewLeaseAsync(published.Id, Beta, TimeSpan.FromMinutes(1)));

    // ── Завершение ───────────────────────────────────────────────────────────

    Console.WriteLine();
    Console.WriteLine("Завершение");

    await events.CompleteAsync(published.Id, new MongoDB.Bson.BsonDocument("keyId", "k-1"));
    var done = await events.GetByIdAsync(published.Id);

    Check("Успех переводит в succeeded",
        done?.Status == DomainEventStatuses.Succeeded, done?.Status);
    Check("Результат сохранён", done?.Result?["keyId"].AsString == "k-1");
    Check("Аренда снята", done?.Lease is null);
    Check("Момент завершения проставлен", done?.FinishedAt is not null);

    // ── Возврат в очередь ────────────────────────────────────────────────────

    Console.WriteLine();
    Console.WriteLine("Возврат в очередь");

    var retried = await events.PublishAsync(ProbeBeta, new { keyId = "k-2" });
    await events.ClaimAsync(types, Alpha, TimeSpan.FromMinutes(1));

    await events.RequeueAsync(retried.Id, DateTime.UtcNow.AddMinutes(-1), countsAsAttempt: true);
    var requeued = await events.GetByIdAsync(retried.Id);

    Check("Возврат делает событие снова pending",
        requeued?.Status == DomainEventStatuses.Pending, requeued?.Status);
    Check("Попытка засчитана", requeued?.Attempt == 1, $"{requeued?.Attempt}");
    Check("Аренда снята при возврате", requeued?.Lease is null);

    await events.ClaimAsync(types, Alpha, TimeSpan.FromMinutes(1));
    await events.RequeueAsync(retried.Id, DateTime.UtcNow.AddMinutes(-1), countsAsAttempt: false);
    var notCounted = await events.GetByIdAsync(retried.Id);

    // Занятая партиция не должна сжигать попытки: работа не начиналась.
    Check("Возврат без попытки возвращает счётчик назад",
        notCounted?.Attempt == 1, $"{notCounted?.Attempt}");

    var future = await events.PublishAsync(ProbeBeta, new { keyId = "k-3" });
    await events.RequeueAsync(future.Id, DateTime.UtcNow.AddHours(1), countsAsAttempt: true);

    // Забираем отложенное k-2, чтобы очередь опустела, и проверяем, что
    // событие из будущего не выдаётся.
    await events.ClaimAsync(types, Alpha, TimeSpan.FromMinutes(1));
    Check("Событие с будущим availableAt не выдаётся",
        await events.ClaimAsync(types, Beta, TimeSpan.FromMinutes(1)) is null);

    // ── Просроченные аренды ──────────────────────────────────────────────────

    Console.WriteLine();
    Console.WriteLine("Просроченные аренды");

    var abandoned = await events.PublishAsync(ProbeAlpha, new { serverId = "s2" });

    // Отрицательный срок = аренда, истёкшая в момент выдачи.
    await events.ClaimAsync(types, Alpha, TimeSpan.FromSeconds(-1));

    var expired = await events.FindExpiredAsync(types, 50);
    Check("Событие с истёкшей арендой найдено жнецом",
        expired.Any(e => e.Id == abandoned.Id), $"найдено: {expired.Count}");

    await events.FailAsync(abandoned.Id, "Исполнитель исчез.");
    var failed = await events.GetByIdAsync(abandoned.Id);

    Check("Провал переводит в failed", failed?.Status == DomainEventStatuses.Failed, failed?.Status);
    Check("Причина сохранена", failed?.Error == "Исполнитель исчез.");
    Check("Провалившееся событие больше не выдаётся",
        await events.ClaimAsync(types, Beta, TimeSpan.FromMinutes(1)) is null);

    // ── Состязание за события ────────────────────────────────────────────────
    // Главное свойство всей схемы: сколько бы процессов ни забирало работу
    // одновременно, одно событие достанется ровно одному. Последовательной
    // проверкой этого не показать, а нарушение выглядело бы как два peer-а
    // на один ключ или две установки на один узел.

    Console.WriteLine();
    Console.WriteLine("Состязание за события");

    const int Total = 60;
    const int Claimers = 8;

    for (var i = 0; i < Total; i++)
        await events.PublishAsync(ProbeBeta, new { keyId = $"race-{i}" });

    var taken = new System.Collections.Concurrent.ConcurrentBag<string>();

    await Task.WhenAll(Enumerable.Range(0, Claimers).Select(async n =>
    {
        var owner = $"racer-{n}";
        while (await events.ClaimAsync(types, owner, TimeSpan.FromMinutes(5)) is { } got)
            taken.Add(got.Id);
    }));

    var distinct = taken.Distinct(StringComparer.Ordinal).Count();

    Check($"{Claimers} потребителей разобрали все {Total} событий",
        taken.Count == Total, $"захвачено {taken.Count}");

    Check("Ни одно событие не досталось двоим",
        distinct == taken.Count, $"уникальных {distinct} из {taken.Count}");

    // ── Аренда партиции ──────────────────────────────────────────────────────

    Console.WriteLine();
    Console.WriteLine("Аренда партиции");

    var partition = LeaseKeys.Partition("server-42");

    Check("Свободная аренда берётся",
        await leases.TryAcquireAsync(partition, Alpha, TimeSpan.FromMinutes(1)));

    Check("Занятую аренду второй процесс не берёт",
        !await leases.TryAcquireAsync(partition, Beta, TimeSpan.FromMinutes(1)));

    Check("Свою аренду можно взять повторно",
        await leases.TryAcquireAsync(partition, Alpha, TimeSpan.FromMinutes(1)));

    Check("Владелец продлевает аренду",
        await leases.RenewAsync(partition, Alpha, TimeSpan.FromMinutes(1)));

    Check("Чужую аренду продлить нельзя",
        !await leases.RenewAsync(partition, Beta, TimeSpan.FromMinutes(1)));

    await leases.ReleaseAsync(partition, Beta);
    Check("Чужую аренду отпустить нельзя",
        !await leases.TryAcquireAsync(partition, Beta, TimeSpan.FromMinutes(1)));

    await leases.ReleaseAsync(partition, Alpha);
    Check("После освобождения аренду берёт другой",
        await leases.TryAcquireAsync(partition, Beta, TimeSpan.FromMinutes(1)));

    // Истёкшая аренда свободна: иначе падение держателя блокировало бы узел
    // навсегда, а TTL-монитор Mongo ходит лишь раз в минуту.
    await leases.TryAcquireAsync(partition, Beta, TimeSpan.FromSeconds(-1));
    Check("Истёкшую аренду перехватывает другой процесс",
        await leases.TryAcquireAsync(partition, Alpha, TimeSpan.FromMinutes(1)));
    // ── Диспетчер целиком ────────────────────────────────────────────────────
    // Всё предыдущее проверяло примитивы. Здесь работает настоящий диспетчер,
    // и проверяется то, ради чего он написан: два экземпляра разбирают очередь
    // параллельно, но операции над одним узлом не пересекаются во времени.
    //
    // Два экземпляра обязательны: один обрабатывает события последовательно
    // сам по себе, и проверка сериализации на нём была бы бессмысленной.

    Console.WriteLine();
    Console.WriteLine("Диспетчер: параллелизм и сериализация по партиции");

    var services = new ServiceCollection();
    services.AddLogging();
    services.AddSingleton<IMongoClient>(client);
    services.AddSingleton(opts);
    services.AddSingleton<DomainEventRepository>();
    services.AddSingleton<IDomainEventRepository>(sp => sp.GetRequiredService<DomainEventRepository>());
    services.AddSingleton<ILeaseRepository, LeaseRepository>();
    services.AddSingleton<DomainEventCatalog>();
    services.AddScoped<IDomainEventHandler, ProbeHandler>();

    await using var provider = services.BuildServiceProvider();

    var busOptions = Options.Create(new EventBusOptions
    {
        PollIntervalSeconds       = 1,
        StartupDelaySeconds       = 0,
        BatchSize                 = 10,
        LeaseTtlSeconds           = 30,
        HeartbeatSeconds          = 5,
        PartitionBusyDelaySeconds = 1,
    });

    var scopes  = provider.GetRequiredService<IServiceScopeFactory>();
    var catalog = provider.GetRequiredService<DomainEventCatalog>();
    var loggers = provider.GetRequiredService<ILoggerFactory>();

    string[] onPartitionA = ["a1", "a2", "a3"];
    string[] onPartitionB = ["b1", "b2"];

    foreach (var name in onPartitionA)
        await events.PublishAsync(ProbeHandler.Type, new { name }, partitionKey: "node-A");

    foreach (var name in onPartitionB)
        await events.PublishAsync(ProbeHandler.Type, new { name }, partitionKey: "node-B");

    var dispatchers = Enumerable.Range(0, 2)
        .Select(_ => new EventDispatcher(
            scopes, busOptions, catalog, loggers.CreateLogger<EventDispatcher>()))
        .ToList();

    foreach (var d in dispatchers) await d.StartAsync(CancellationToken.None);

    var expected = onPartitionA.Length + onPartitionB.Length;
    var deadline = DateTime.UtcNow.AddSeconds(40);

    while (ProbeHandler.Runs.Count < expected && DateTime.UtcNow < deadline)
        await Task.Delay(200);

    foreach (var d in dispatchers) await d.StopAsync(CancellationToken.None);

    Check($"Диспетчеры обработали все {expected} событий",
        ProbeHandler.Runs.Count == expected, $"обработано {ProbeHandler.Runs.Count}");

    var runs = ProbeHandler.Runs.ToList();

    // Пары по индексам, а не по значениям: отрезки — кортежи-значения,
    // и ReferenceEquals на них всегда false, из-за чего каждый отрезок
    // сравнивался бы сам с собой и «пересекался» всегда.
    var pairs = from i in Enumerable.Range(0, runs.Count)
                from j in Enumerable.Range(i + 1, Math.Max(0, runs.Count - i - 1))
                select (X: runs[i], Y: runs[j]);

    var pairList = pairs.ToList();

    static bool Overlaps(
        (string Partition, DateTime Start, DateTime End) x,
        (string Partition, DateTime Start, DateTime End) y)
        => x.Start < y.End && y.Start < x.End;

    var samePartitionOverlap = pairList
        .Any(p => p.X.Partition == p.Y.Partition && Overlaps(p.X, p.Y));

    Check("Операции над одним узлом не пересекаются во времени", !samePartitionOverlap);

    // Без этой проверки предыдущая проходила бы и на строго последовательной
    // обработке, то есть ничего бы не доказывала.
    var crossPartitionOverlap = pairList
        .Any(p => p.X.Partition != p.Y.Partition && Overlaps(p.X, p.Y));

    Check("Разные узлы обрабатывались параллельно — сериализация не вырождена",
        crossPartitionOverlap);

    var succeeded = 0;
    foreach (var evt in await client.GetDatabase(database)
                 .GetCollection<DomainEvent>(opts.Value.DomainEventsCollection)
                 .Find(Builders<DomainEvent>.Filter.Eq(x => x.Type, ProbeHandler.Type))
                 .ToListAsync())
    {
        if (evt.Status == DomainEventStatuses.Succeeded) succeeded++;
    }

    Check("Все события помечены succeeded", succeeded == expected, $"{succeeded} из {expected}");
}
finally
{
    await client.DropDatabaseAsync(database);
    Console.WriteLine();
    Console.WriteLine($"Временная база {database} удалена.");
}

Console.WriteLine();
Console.WriteLine(failures.Count == 0
    ? $"Все проверки пройдены: {checks}."
    : $"Провалено {failures.Count} из {checks}: {string.Join(", ", failures)}");

return failures.Count == 0 ? 0 : 1;

/// <summary>
/// Обработчик для проверки диспетчера: спит фиксированное время и записывает
/// отрезок, на котором работал. По этим отрезкам и видно, пересекались ли
/// операции над одним узлом.
/// </summary>
file sealed class ProbeHandler : IDomainEventHandler
{
    public const string Type = "probe.work";

    /// <summary>Отрезки работы. Статика — обработчик создаётся на каждое событие.</summary>
    public static readonly ConcurrentBag<(string Partition, DateTime Start, DateTime End)> Runs = [];

    public string EventType => Type;

    public DomainEventPolicy Policy => DomainEventPolicy.Once;

    public async Task<BsonDocument?> HandleAsync(DomainEvent evt, CancellationToken ct)
    {
        var start = DateTime.UtcNow;

        // Достаточно долго, чтобы пересечение было видно, и достаточно коротко,
        // чтобы проверка не тянулась.
        await Task.Delay(400, ct);

        Runs.Add((evt.PartitionKey ?? string.Empty, start, DateTime.UtcNow));
        return new BsonDocument("ok", true);
    }
}
