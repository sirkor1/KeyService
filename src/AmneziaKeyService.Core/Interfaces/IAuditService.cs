using System.Security.Claims;
using AmneziaKeyService.Core.Models;

namespace AmneziaKeyService.Core.Interfaces;

/// <summary>
/// Запись событий в журнал панели.
///
/// Ошибка записи в журнал не должна ронять саму операцию: если сервер создан,
/// а журнал недоступен, правильнее потерять запись, чем ответить ошибкой на
/// уже выполненное действие. Реализация логирует такие сбои и проглатывает их.
/// </summary>
public interface IAuditService
{
    Task WriteAsync(
        string @event,
        string message,
        ClaimsPrincipal? actor = null,
        string? targetType = null,
        string? targetId = null,
        string? targetName = null,
        string level = AuditLevels.Info,
        Dictionary<string, string>? meta = null,
        CancellationToken ct = default);

    /// <summary>
    /// Перегрузка для вызовов вне HTTP-запроса — обработчиков доменных событий
    /// в worker, у которых нет ClaimsPrincipal. Тип <see cref="AuditActor"/>
    /// значимый, а не nullable-класс: null третьим аргументом по-прежнему
    /// однозначно разрешается в перегрузку с ClaimsPrincipal, поэтому
    /// существующие вызовы этим методом не задеты.
    /// </summary>
    Task WriteAsync(
        string @event,
        string message,
        AuditActor actor,
        string? targetType = null,
        string? targetId = null,
        string? targetName = null,
        string level = AuditLevels.Info,
        Dictionary<string, string>? meta = null,
        CancellationToken ct = default);
}
