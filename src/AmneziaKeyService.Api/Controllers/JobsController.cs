using AmneziaKeyService.Core.DTOs;
using AmneziaKeyService.Core.DTOs.Panel;
using AmneziaKeyService.Core.Exceptions;
using AmneziaKeyService.Core.Interfaces;
using AmneziaKeyService.Core.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace AmneziaKeyService.Api.Controllers;

/// <summary>
/// Задачи установки. Панель опрашивает их, пока идёт развёртывание узла.
/// </summary>
[ApiController]
[Route("api/jobs")]
[Authorize(Policy = AuthPolicies.PanelAdmin)]
public class JobsController : ControllerBase
{
    private readonly IInstallJobRepository _jobs;

    public JobsController(IInstallJobRepository jobs) => _jobs = jobs;

    [HttpGet]
    [ProducesResponseType(typeof(Paged<JobDto>), StatusCodes.Status200OK)]
    public async Task<IActionResult> GetAll(
        [FromQuery] string? serverId,
        [FromQuery] string? status,
        [FromQuery] int? page,
        [FromQuery] int? pageSize,
        CancellationToken ct)
    {
        var jobs = await _jobs.SearchAsync(new JobQuery(serverId, status, page, pageSize), ct);
        return Ok(jobs.Map(JobDto.From));
    }

    [HttpGet("{id}")]
    [ProducesResponseType(typeof(JobDto), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> GetById(string id, CancellationToken ct)
    {
        var job = await _jobs.GetByIdAsync(id, ct)
            ?? throw new NotFoundException("Задача не найдена.");

        return Ok(JobDto.From(job));
    }

    /// <summary>
    /// Хвост лога после указанного seq. Панель дочитывает его порциями,
    /// а не перезагружает целиком: сборка образа даёт тысячи строк.
    /// </summary>
    [HttpGet("{id}/log")]
    [ProducesResponseType(typeof(JobLogDto), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> GetLog(
        string id,
        [FromQuery] long after = 0,
        [FromQuery] int limit = 200,
        CancellationToken ct = default)
    {
        var job = await _jobs.GetByIdAsync(id, ct)
            ?? throw new NotFoundException("Задача не найдена.");

        var entries = await _jobs.GetLogAsync(id, after, limit, ct);
        var nextSeq = entries.Count > 0 ? entries[^1].Seq : after;

        return Ok(new JobLogDto([.. entries.Select(JobLogEntryDto.From)], nextSeq, job.IsTerminal));
    }

    /// <summary>
    /// Запрашивает отмену. Отмена срабатывает на границе шага: прервать
    /// идущую сборку образа безопасно нельзя.
    /// </summary>
    [HttpPost("{id}/cancel")]
    [ProducesResponseType(typeof(JobDto), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> Cancel(string id, CancellationToken ct)
    {
        var requested = await _jobs.RequestCancelAsync(id, ct);

        var job = await _jobs.GetByIdAsync(id, ct)
            ?? throw new NotFoundException("Задача не найдена.");

        if (!requested && !job.IsTerminal)
            throw new BadRequestException("Задачу уже нельзя отменить.");

        return Ok(JobDto.From(job));
    }
}
