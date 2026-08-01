using AmneziaKeyService.Core.Models;
using Microsoft.Extensions.DependencyInjection;
using MongoDB.Bson;

namespace AmneziaKeyService.Infrastructure.Events;

/// <summary>
/// Исполнитель одного типа событий.
///
/// Регистрируется как scoped: обработчику нужны SSH-сессии и конфигураторы,
/// а они не рассчитаны на разделение между параллельными задачами.
/// </summary>
public interface IDomainEventHandler
{
    /// <summary>Тип из <see cref="DomainEventTypes"/>.</summary>
    string EventType { get; }

    /// <summary>
    /// Как обращаться с событием при сбое. Живёт здесь, а не в общей таблице,
    /// потому что идемпотентность — свойство самой операции, и знает о ней
    /// только тот, кто её выполняет.
    /// </summary>
    DomainEventPolicy Policy { get; }

    /// <summary>
    /// Делает работу. Возвращает результат для записи в событие — или null,
    /// если возвращать нечего.
    ///
    /// Секретам в результате не место: ссылку vpn:// и клиентский файл api
    /// собирает сам по идентификатору ключа, узел для этого не нужен.
    /// </summary>
    Task<BsonDocument?> HandleAsync(DomainEvent evt, CancellationToken ct);

    /// <summary>
    /// Вызывается, когда событие провалено окончательно — в том числе жнецом,
    /// если исполнитель исчез и <see cref="HandleAsync"/> уже не вернётся.
    ///
    /// Нужно там, где событие тянет за собой видимое оператору состояние.
    /// Задача установки, чей исполнитель умер, иначе осталась бы «выполняется»
    /// навсегда: сам оркестратор пометить её уже не может.
    /// </summary>
    Task OnFailedAsync(DomainEvent evt, string error, CancellationToken ct)
        => Task.CompletedTask;
}

/// <summary>
/// Какие типы событий умеет этот процесс и с какой политикой.
///
/// Строится один раз по зарегистрированным обработчикам: и диспетчеру,
/// и жнецу нужен список типов до того, как появится конкретное событие,
/// а держать его вторым списком рядом с обработчиками значило бы завести
/// два источника правды, которые однажды разойдутся.
/// </summary>
public class DomainEventCatalog
{
    private readonly IServiceScopeFactory _scopeFactory;
    private readonly Lock _gate = new();

    private IReadOnlyDictionary<string, DomainEventPolicy>? _policies;

    public DomainEventCatalog(IServiceScopeFactory scopeFactory) => _scopeFactory = scopeFactory;

    public IReadOnlyDictionary<string, DomainEventPolicy> Policies
    {
        get
        {
            if (_policies is not null) return _policies;

            lock (_gate)
            {
                if (_policies is not null) return _policies;

                using var scope = _scopeFactory.CreateScope();

                _policies = scope.ServiceProvider
                    .GetServices<IDomainEventHandler>()
                    .ToDictionary(h => h.EventType, h => h.Policy, StringComparer.Ordinal);

                return _policies;
            }
        }
    }

    public IReadOnlyCollection<string> HandledTypes => [.. Policies.Keys];

    public DomainEventPolicy PolicyFor(string type)
        => Policies.TryGetValue(type, out var policy) ? policy : DomainEventPolicy.Once;
}
