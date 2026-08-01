using System.Globalization;
using System.Text;
using AmneziaKeyService.Core.Exceptions;
using AmneziaKeyService.Core.Interfaces;
using AmneziaKeyService.Core.Models;
using Microsoft.Extensions.Logging;
using Renci.SshNet;

namespace AmneziaKeyService.Infrastructure.Ssh;

/// <summary>
/// Сессия SSH к узлу. Держит подключённый <see cref="SshClient"/> и,
/// по требованию, <see cref="SftpClient"/> — второй нужен только для записи
/// файлов, а лишнее подключение стоит рукопожатия.
/// </summary>
public sealed class SshSession : ISshSession
{
    private readonly SshClient _ssh;
    private readonly Func<SftpClient> _sftpFactory;
    private readonly ILogger _logger;

    private SftpClient? _sftp;

    internal SshSession(SshClient ssh, Func<SftpClient> sftpFactory, ILogger logger)
    {
        _ssh         = ssh;
        _sftpFactory = sftpFactory;
        _logger      = logger;
    }

    public async Task<SshResult> RunAsync(string command, CancellationToken ct = default)
    {
        using var cmd = _ssh.CreateCommand(command);

        // SSH.NET синхронный: уводим в пул, чтобы не занимать поток запроса.
        await Task.Run(() => cmd.Execute(), ct);

        return new SshResult(cmd.ExitStatus ?? -1, cmd.Result, cmd.Error);
    }

    public async Task<string> RunCheckedAsync(
        string command, string operation, CancellationToken ct = default)
    {
        var result = await RunAsync(command, ct);
        if (result.Ok) return result.StdOut;

        _logger.LogDebug(
            "SSH-операция {Operation} завершилась с кодом {Exit}. Команда: {Command}",
            operation, result.ExitStatus, Services.SecretRedactor.Redact(command));

        throw new SshCommandException(
            operation,
            result.ExitStatus,
            command,
            Services.SecretRedactor.Tail(result.StdErr));
    }

    public async Task<string> ReadContainerFileAsync(
        string container, string path, CancellationToken ct = default)
    {
        // xxd -p, как в upstream: вывод не зависит от локали и переносов строк
        // и безопасен для бинарных файлов.
        var hex = await RunCheckedAsync(
            $"docker exec -i {container} sh -c \"xxd -p '{path}'\"",
            "read_container_file",
            ct);

        return DecodeHex(hex);
    }

    public async Task WriteContainerFileAsync(
        string container, string path, string content, CancellationToken ct = default)
    {
        var temp = TempPath();
        try
        {
            await UploadAsync(temp, content, ct);

            await RunCheckedAsync(
                $"docker exec -i {container} sh -c \"mkdir -p $(dirname '{path}')\"",
                "prepare_container_dir", ct);

            await RunCheckedAsync(
                $"docker cp {temp} {container}:{path}", "write_container_file", ct);
        }
        finally
        {
            await CleanupAsync(temp, ct);
        }
    }

    public async Task AppendContainerFileAsync(
        string container, string path, string content, CancellationToken ct = default)
    {
        var temp = TempPath();
        try
        {
            await UploadAsync(temp, content, ct);

            // Через docker cp дописать нельзя — он перезаписывает файл целиком.
            // Копируем во временный путь внутри контейнера и присоединяем cat-ом.
            var innerTemp = $"/tmp/{Guid.NewGuid():N}.part";
            await RunCheckedAsync($"docker cp {temp} {container}:{innerTemp}", "append_upload", ct);
            await RunCheckedAsync(
                $"docker exec -i {container} sh -c \"cat '{innerTemp}' >> '{path}' && rm -f '{innerTemp}'\"",
                "append_container_file", ct);
        }
        finally
        {
            await CleanupAsync(temp, ct);
        }
    }

    public async Task<string> RunInContainerScriptAsync(
        string container, string script, string operation, CancellationToken ct = default)
    {
        var inner = $"/opt/amnezia/{Guid.NewGuid():N}.sh";
        var temp = TempPath();

        try
        {
            await UploadAsync(temp, script, ct);
            await RunCheckedAsync($"docker cp {temp} {container}:{inner}", $"{operation}_upload", ct);

            // set -e намеренно НЕ добавляется: upstream выполняет каждую строку
            // отдельным exec-ом, поэтому его скрипты рассчитывают, что падение
            // одной команды не прерывает остальные.
            return await RunCheckedAsync(
                $"docker exec -i {container} bash {inner}", operation, ct);
        }
        finally
        {
            await RunAsync($"docker exec -i {container} rm -f {inner}", ct);
            await CleanupAsync(temp, ct);
        }
    }

    // ── Хост ──────────────────────────────────────────────────────────────────

    public async Task WriteHostFileAsync(string path, string content, CancellationToken ct = default)
    {
        var temp = TempPath();
        try
        {
            await UploadAsync(temp, content, ct);

            // Через sudo, а не SFTP напрямую: каталоги в /opt принадлежат root,
            // а SSH-пользователь не обязан быть им.
            await RunCheckedAsync($"sudo mkdir -p \"$(dirname '{path}')\"", "prepare_host_dir", ct);
            await RunCheckedAsync($"sudo cp {temp} {path}", "write_host_file", ct);
        }
        finally
        {
            await CleanupAsync(temp, ct);
        }
    }

    public async Task<string> RunHostScriptAsync(
        string script, string operation, CancellationToken ct = default)
    {
        var result = await RunHostScriptRawAsync(script, ct);
        if (result.Ok) return result.StdOut;

        _logger.LogDebug(
            "Скрипт {Operation} завершился с кодом {Exit}. Stderr: {StdErr}",
            operation, result.ExitStatus, Services.SecretRedactor.Tail(result.StdErr));

        throw new SshCommandException(
            operation, result.ExitStatus, null, Services.SecretRedactor.Tail(result.StdErr));
    }

    public async Task<SshResult> RunHostScriptRawAsync(
        string script, CancellationToken ct = default)
    {
        var path = TempPath();
        try
        {
            await UploadAsync(path, script, ct);

            // </dev/null и DEBIAN_FRONTEND: apt в install_docker.sh иначе
            // может остановиться на интерактивном вопросе и подвесить установку.
            return await RunAsync(
                $"sudo DEBIAN_FRONTEND=noninteractive bash {path} </dev/null 2>&1", ct);
        }
        finally
        {
            await CleanupAsync(path, ct);
        }
    }

    // ── Вспомогательное ───────────────────────────────────────────────────────

    private static string TempPath() => $"/tmp/amnezia-{Guid.NewGuid():N}.tmp";

    private async Task UploadAsync(string path, string content, CancellationToken ct)
    {
        var sftp = _sftp ??= _sftpFactory();
        if (!sftp.IsConnected) await Task.Run(() => sftp.Connect(), ct);

        using var stream = new MemoryStream(Encoding.UTF8.GetBytes(content));
        await Task.Run(() => sftp.UploadFile(stream, path, canOverride: true), ct);
    }

    /// <summary>
    /// Затирает временный файл. shred, а не rm: во временный файл попадают
    /// приватные ключи и PSK.
    /// </summary>
    private async Task CleanupAsync(string path, CancellationToken ct)
    {
        try
        {
            await RunAsync($"shred -u {path} 2>/dev/null || rm -f {path}", ct);
        }
        catch (Exception ex)
        {
            // Уборка не должна маскировать исходную ошибку операции.
            _logger.LogDebug(ex, "Не удалось удалить временный файл на узле.");
        }
    }

    private static string DecodeHex(string hex)
    {
        var clean = hex.Where(Uri.IsHexDigit).ToArray();
        if (clean.Length % 2 != 0)
            throw new InvalidOperationException("Нечётное число hex-символов в ответе узла.");

        var bytes = new byte[clean.Length / 2];
        for (var i = 0; i < bytes.Length; i++)
        {
            bytes[i] = byte.Parse(
                string.Concat(clean[i * 2], clean[i * 2 + 1]),
                NumberStyles.HexNumber,
                CultureInfo.InvariantCulture);
        }

        return Encoding.UTF8.GetString(bytes);
    }

    public async ValueTask DisposeAsync()
    {
        if (_sftp is not null)
        {
            await Task.Run(() => { if (_sftp.IsConnected) _sftp.Disconnect(); });
            _sftp.Dispose();
        }

        await Task.Run(() => { if (_ssh.IsConnected) _ssh.Disconnect(); });
        _ssh.Dispose();
    }
}
