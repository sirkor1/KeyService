namespace AmneziaKeyService.Core.Exceptions;

/// <summary>
/// Команда на удалённом сервере завершилась ненулевым кодом.
///
/// ВАЖНО: <see cref="Exception.Message"/> содержит только безопасную метку операции.
/// Текст команды и stderr лежат в отдельных свойствах, пишутся в лог (после редактирования
/// секретов) и никогда не попадают в тело HTTP-ответа — команды docker exec содержат
/// приватные ключи, PSK и SSH-пароли.
/// </summary>
public class SshCommandException : Exception
{
    /// <summary>Безопасный код операции: "add_peer", "remove_peer", "read_server_params".</summary>
    public string Operation { get; }

    public int ExitStatus { get; }

    /// <summary>Полный текст команды. Только для логов.</summary>
    public string? Command { get; }

    /// <summary>Хвост stderr. Только для логов.</summary>
    public string? StdErr { get; }

    public SshCommandException(string operation, int exitStatus, string? command = null, string? stdErr = null)
        : base($"Операция '{operation}' на сервере завершилась с ошибкой (код {exitStatus}).")
    {
        Operation  = operation;
        ExitStatus = exitStatus;
        Command    = command;
        StdErr     = stdErr;
    }
}

/// <summary>Не удалось установить SSH-соединение с сервером.</summary>
public class SshConnectionException : Exception
{
    public string Host { get; }

    public SshConnectionException(string host, Exception? inner = null)
        : base($"Не удалось подключиться к серверу {host} по SSH.", inner)
        => Host = host;
}

/// <summary>Запрошенная сущность не найдена. Маппится в 404.</summary>
public class NotFoundException : Exception
{
    public NotFoundException(string message) : base(message) { }
}

/// <summary>
/// Запрос не проходит доменную проверку. Маппится в 400.
///
/// Message пишется для человека и уходит клиенту — в отличие от прочих
/// исключений, тут это осознанно: пользователь должен понять, что исправить.
/// </summary>
public class BadRequestException : Exception
{
    public BadRequestException(string message) : base(message) { }
}
