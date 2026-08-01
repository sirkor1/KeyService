using AmneziaKeyService.Core.Models;

namespace AmneziaKeyService.Core.Interfaces;

/// <summary>Результат выполнения команды на узле.</summary>
public record SshResult(int ExitStatus, string StdOut, string StdErr)
{
    public bool Ok => ExitStatus == 0;
}

/// <summary>
/// Одна SSH-сессия к узлу. Живёт в пределах логической операции
/// (выдача ключа, отзыв, чтение статистики) и закрывается вместе с ней:
/// SshClient не потокобезопасен и разделять его между запросами нельзя.
/// </summary>
public interface ISshSession : IAsyncDisposable
{
    /// <summary>
    /// Выполняет команду. Не бросает при ненулевом коде — решение принимает
    /// вызывающий, потому что часть команд ожидаемо завершается ошибкой
    /// (проверка занятости порта, наличие контейнера).
    /// </summary>
    Task<SshResult> RunAsync(string command, CancellationToken ct = default);

    /// <summary>
    /// Выполняет команду и бросает <see cref="Exceptions.SshCommandException"/>
    /// при ненулевом коде. В исключение попадает только метка операции —
    /// текст команды содержит ключи и наружу уходить не должен.
    /// </summary>
    Task<string> RunCheckedAsync(string command, string operation, CancellationToken ct = default);

    /// <summary>
    /// Читает файл из контейнера через <c>xxd -p</c> и hex-декодирование.
    /// Так же поступает upstream: вывод бинарно-безопасен и не зависит
    /// от локали и переносов строк.
    /// </summary>
    Task<string> ReadContainerFileAsync(string container, string path, CancellationToken ct = default);

    /// <summary>Записывает файл в контейнер: SFTP во временный файл на хосте, затем docker cp.</summary>
    Task WriteContainerFileAsync(
        string container, string path, string content, CancellationToken ct = default);

    /// <summary>Дописывает текст в конец файла внутри контейнера.</summary>
    Task AppendContainerFileAsync(
        string container, string path, string content, CancellationToken ct = default);

    /// <summary>Выполняет скрипт внутри контейнера: загрузка, запуск через bash, удаление.</summary>
    Task<string> RunInContainerScriptAsync(
        string container, string script, string operation, CancellationToken ct = default);

    // ── Хост ──────────────────────────────────────────────────────────────────

    /// <summary>Записывает файл на сам узел, создавая каталог при необходимости.</summary>
    Task WriteHostFileAsync(string path, string content, CancellationToken ct = default);

    /// <summary>
    /// Выполняет скрипт на узле: загрузка во временный файл, запуск через
    /// <c>sudo bash</c>, затирание. Бросает при ненулевом коде.
    ///
    /// Скрипт запускается целиком, а не построчно, как в оригинальном клиенте —
    /// так корректно работают heredoc и многострочные конструкции. При этом
    /// <c>set -e</c> не добавляется: скрипты upstream рассчитывают, что падение
    /// отдельной команды не прерывает остальные.
    /// </summary>
    Task<string> RunHostScriptAsync(string script, string operation, CancellationToken ct = default);

    /// <summary>То же, но без исключения: код возврата отдаётся вызывающему.</summary>
    Task<SshResult> RunHostScriptRawAsync(string script, CancellationToken ct = default);
}

/// <summary>Открывает SSH-сессии к узлам.</summary>
public interface ISshSessionFactory
{
    /// <summary>
    /// Подключается к узлу. Расшифровывает SSH-секреты и оборачивает ошибки
    /// транспорта в <see cref="Exceptions.SshConnectionException"/>.
    /// </summary>
    Task<ISshSession> ConnectAsync(VpnServer server, CancellationToken ct = default);
}
