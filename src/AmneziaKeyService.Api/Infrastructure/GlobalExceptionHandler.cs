using AmneziaKeyService.Core.Exceptions;
using AmneziaKeyService.Infrastructure.Services;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Mvc;

namespace AmneziaKeyService.Api.Infrastructure;

/// <summary>
/// Единая точка превращения исключений в ответ RFC 7807.
///
/// Главное правило: ex.Message произвольного исключения НИКОГДА не уходит клиенту.
/// Наружу идёт обезличенный текст плюс машинный код в поле "code";
/// подробности (включая текст SSH-команд) пишутся в лог.
/// </summary>
public class GlobalExceptionHandler : IExceptionHandler
{
    private readonly ILogger<GlobalExceptionHandler> _logger;

    public GlobalExceptionHandler(ILogger<GlobalExceptionHandler> logger) => _logger = logger;

    public async ValueTask<bool> TryHandleAsync(
        HttpContext context, Exception exception, CancellationToken ct)
    {
        var (status, code, title) = Map(exception);

        LogException(exception, context, status);

        var problem = new ProblemDetails
        {
            Status   = status,
            Title    = title,
            Type     = $"https://httpstatuses.io/{status}",
            Instance = context.Request.Path
        };
        problem.Extensions["code"] = code;

        context.Response.StatusCode = status;
        await context.Response.WriteAsJsonAsync(problem, ct);
        return true;
    }

    private static (int Status, string Code, string Title) Map(Exception ex) => ex switch
    {
        NotFoundException e => (
            StatusCodes.Status404NotFound, "NOT_FOUND", e.Message),

        // Единственный случай, когда Message уходит клиенту намеренно:
        // пользователь должен понять, что именно исправить в запросе.
        BadRequestException e => (
            StatusCodes.Status400BadRequest, "BAD_REQUEST", e.Message),

        ForbiddenException => (
            StatusCodes.Status403Forbidden, "FORBIDDEN", "Недостаточно прав для управления этим пользователем."),

        // Message самого SshCommandException безопасен — там только метка операции.
        SshCommandException e => (
            StatusCodes.Status502BadGateway, "SSH_COMMAND_FAILED", e.Message),

        SshConnectionException e => (
            StatusCodes.Status502BadGateway, "SSH_CONNECTION_FAILED", e.Message),

        UnauthorizedAccessException => (
            StatusCodes.Status401Unauthorized, "UNAUTHORIZED", "Требуется аутентификация."),

        OperationCanceledException => (
            StatusCodes.Status499ClientClosedRequest, "REQUEST_CANCELED", "Запрос отменён."),

        _ => (
            StatusCodes.Status500InternalServerError, "INTERNAL_ERROR",
            "Внутренняя ошибка сервиса.")
    };

    private void LogException(Exception ex, HttpContext context, int status)
    {
        var route = $"{context.Request.Method} {context.Request.Path}";

        if (ex is SshCommandException ssh)
        {
            // Команда содержит ключи и PSK — редактируем перед записью даже в лог.
            _logger.LogError(
                "SSH-операция {Operation} провалилась (код {ExitStatus}) на {Route}. Команда: {Command}. Stderr: {StdErr}",
                ssh.Operation, ssh.ExitStatus, route,
                SecretRedactor.Redact(ssh.Command), ssh.StdErr);
            return;
        }

        if (status >= 500)
            _logger.LogError(ex, "Необработанное исключение на {Route}", route);
        else
            _logger.LogWarning("Ошибка {Status} на {Route}: {Message}", status, route, ex.Message);
    }
}
