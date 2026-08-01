using AmneziaKeyService.Core.Interfaces;
using AmneziaKeyService.Core.Models;
using AmneziaKeyService.Infrastructure.Events;
using Microsoft.Extensions.Logging;
using MongoDB.Bson;

namespace AmneziaKeyService.Infrastructure.Install;

/// <summary>
/// Исполняет установку по событию.
///
/// Сам ничего не делает — вызывает тот же <see cref="InstallOrchestrator"/>,
/// что и прежний воркер очереди. Изменилась только доставка: канал в памяти
/// не переживал границу процессов, а событие переживает и её, и перезапуск.
/// </summary>
public class InstallEventHandler : IDomainEventHandler
{
    private readonly IInstallJobRepository _jobs;
    private readonly InstallOrchestrator _orchestrator;
    private readonly ILogger<InstallEventHandler> _logger;

    public InstallEventHandler(
        IInstallJobRepository jobs,
        InstallOrchestrator orchestrator,
        ILogger<InstallEventHandler> logger)
    {
        _jobs         = jobs;
        _orchestrator = orchestrator;
        _logger       = logger;
    }

    public string EventType => DomainEventTypes.ServerInstall;

    /// <summary>
    /// Повторов нет. Установка не идемпотентна на середине: оборвавшуюся
    /// на сборке образа нельзя запустить заново — вторая попытка пойдёт
    /// поверх наполовину настроенного узла.
    /// </summary>
    public DomainEventPolicy Policy => DomainEventPolicy.Once;

    public async Task<BsonDocument?> HandleAsync(DomainEvent evt, CancellationToken ct)
    {
        var jobId = evt.PayloadAs<ServerInstallPayload>().JobId;

        var job = await _jobs.GetByIdAsync(jobId, ct);
        if (job is null)
        {
            // Задачу могли удалить вместе с узлом, пока событие ждало очереди.
            _logger.LogWarning("Задача установки {JobId} не найдена — пропускаю.", jobId);
            return new BsonDocument { ["jobId"] = jobId, ["skipped"] = "not_found" };
        }

        if (job.IsTerminal)
        {
            _logger.LogInformation(
                "Задача установки {JobId} уже завершена ({Status}).", jobId, job.Status);

            return new BsonDocument { ["jobId"] = jobId, ["jobStatus"] = job.Status };
        }

        // Оркестратор разбирается со своими ошибками сам: помечает шаг, задачу
        // и узел. Поэтому неудачная установка — это успешно доставленное
        // и исполненное событие с неуспешной задачей, а не провал события.
        // Событие отвечает за доставку, задача — за то, что видит оператор.
        await _orchestrator.ExecuteAsync(job, ct);

        return new BsonDocument { ["jobId"] = jobId, ["jobStatus"] = job.Status };
    }

    /// <summary>
    /// Событие провалено окончательно — значит исполнитель исчез посреди работы
    /// и сам оркестратор задачу уже не пометит. Без этого панель показывала бы
    /// вечный прогресс, а на узле остался бы статус «устанавливается».
    /// </summary>
    public async Task OnFailedAsync(DomainEvent evt, string error, CancellationToken ct)
    {
        var jobId = evt.PayloadAs<ServerInstallPayload>().JobId;

        var job = await _jobs.GetByIdAsync(jobId, ct);
        if (job is null || job.IsTerminal) return;

        _logger.LogWarning(
            "Помечаю задачу установки {JobId} прерванной: {Error}", jobId, error);

        job.Status     = InstallJobStatuses.Failed;
        job.Error      = "Установка прервана: исполнитель перестал отвечать. Запустите её заново.";
        job.FinishedAt = DateTime.UtcNow;

        var step = job.Step(job.CurrentStepCode ?? string.Empty);
        if (step is not null)
        {
            step.Status     = InstallStepStatuses.Failed;
            step.Message    = job.Error;
            step.Detail     = null;
            step.FinishedAt = DateTime.UtcNow;
        }

        await _jobs.UpdateAsync(job, ct);
    }
}
