using AmneziaKeyService.Core.Interfaces;
using AmneziaKeyService.Core.Models;
using AmneziaKeyService.Core.Exceptions;
using AmneziaKeyService.Infrastructure.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using MongoDB.Bson;

namespace AmneziaKeyService.Api.Controllers;

[ApiController]
[Route("api/passcodes")]
[Authorize(Policy = AuthPolicies.PanelWrite)]
public class PassCodeController : ControllerBase
{
    private readonly IPassCodeRepository _repo;
    private readonly IAuditService _audit;

    public PassCodeController(IPassCodeRepository repo, IAuditService audit)
    {
        _repo  = repo;
        _audit = audit;
    }

    /// <summary>Список всех пригласительных кодов.</summary>
    [HttpGet]
    [ProducesResponseType(typeof(List<PassCodeDto>), StatusCodes.Status200OK)]
    public async Task<IActionResult> GetAll(CancellationToken ct)
        => Ok((await _repo.GetAllAsync(ct)).Select(PassCodeDto.From));

    /// <summary>Создать новый пригласительный код.</summary>
    [HttpPost]
    [ProducesResponseType(typeof(PassCodeDto), StatusCodes.Status201Created)]
    [ProducesResponseType(StatusCodes.Status409Conflict)]
    public async Task<IActionResult> Create([FromBody] CreatePassCodeRequest req, CancellationToken ct)
    {
        var code = NormalizeCode(req.Code);
        var passCode = new PassCode { Code = code };
        if (!await _repo.TryCreateAsync(passCode, ct))
            return Conflict(new { error = "Код уже существует." });

        var created = await _repo.FindByCodeAsync(code, ct);

        await _audit.WriteAsync(AuditEvents.PassCodeCreated,
            $"Создан пригласительный код {code}",
            User, AuditTargets.PassCode, created?.Id, code, ct: ct);

        // CreatedAtAction(nameof(GetAll), created) трактовал created как route values
        // и выдавал битый Location. У списка нет параметров — отдаём сам URL списка.
        return Created(Url.Action(nameof(GetAll)) ?? "/api/passcodes", PassCodeDto.From(created!));
    }

    /// <summary>Отзывает неиспользованный код без физического удаления его истории.</summary>
    [HttpDelete("{id}")]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    [ProducesResponseType(StatusCodes.Status409Conflict)]
    public async Task<IActionResult> Revoke(string id, CancellationToken ct)
    {
        if (!ObjectId.TryParse(id, out _))
            return BadRequest(new { error = "Некорректный идентификатор кода." });

        var passCode = await _repo.FindByIdAsync(id, ct);
        if (passCode is null)
            return NotFound();
        if (passCode.IsUsed || passCode.IsRevoked || !await _repo.TryRevokeUnusedAsync(id, ct))
            return Conflict(new { error = "Можно отозвать только неиспользованный активный код." });

        await _audit.WriteAsync(AuditEvents.PassCodeRevoked,
            $"Отозван пригласительный код {passCode.Code}",
            User, AuditTargets.PassCode, passCode.Id, passCode.Code, ct: ct);
        return NoContent();
    }

    private static string NormalizeCode(string? value)
    {
        var code = value?.Trim() ?? string.Empty;
        if (code.Length is < 4 or > 128 || code.Any(char.IsWhiteSpace))
            throw new BadRequestException("Код должен содержать от 4 до 128 символов без пробелов.");
        return code;
    }
}

public record CreatePassCodeRequest(string? Code);

/// <summary>Публичный вид инвайта. Данные незавершённого резерва никогда не отдаются панели.</summary>
public record PassCodeDto(
    string Id,
    string Code,
    bool IsUsed,
    bool IsRevoked,
    string? UsedByUserId,
    DateTime? UsedAt,
    DateTime? RevokedAt,
    DateTime CreatedAt)
{
    public static PassCodeDto From(PassCode value) => new(
        value.Id, value.Code, value.IsUsed, value.IsRevoked, value.UsedByUserId,
        value.UsedAt, value.RevokedAt, value.CreatedAt);
}
