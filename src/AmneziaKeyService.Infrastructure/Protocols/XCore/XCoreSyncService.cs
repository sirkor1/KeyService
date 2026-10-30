using AmneziaKeyService.Core.Interfaces;
using AmneziaKeyService.Core.Models;
using AmneziaKeyService.Infrastructure.Scripts;
using AmneziaKeyService.Infrastructure.Services;
using Microsoft.Extensions.Options;

namespace AmneziaKeyService.Infrastructure.Protocols.XCore;

/// <summary>Что синхронизация сделала с узлом.</summary>
public enum XCoreSyncAction
{
    /// <summary>Конфиг и живой список пользователей уже соответствуют желаемому.</summary>
    NoOp,

    /// <summary>Файл обновлён, пользователи добавлены и удалены через API без перезапуска.</summary>
    Diff,

    /// <summary>Файл обновлён, контейнер перезапущен: изменилась структура конфига.</summary>
    Restart,
}

/// <param name="Revision">Ревизия применённого конфига (с пользователями).</param>
/// <param name="StructureRevision">Ревизия того же конфига без пользователей.</param>
/// <param name="Added">Сколько пользователей добавлено через API; при перезапуске 0.</param>
/// <param name="Removed">Сколько пользователей удалено через API; при перезапуске 0.</param>
public sealed record XCoreSyncResult(
    XCoreSyncAction Action, string Revision, string StructureRevision, int Added, int Removed);

public enum XCoreCaddyAction
{
    /// <summary>Хеш Caddyfile совпал с применённым: на узле ничего не делалось.</summary>
    NoOp,

    /// <summary>Caddyfile заменён и проверен, Caddy перезапущен.</summary>
    Restart,

    /// <summary>
    /// Прошлый выпуск сертификата для этой ревизии не удался, пауза ещё идёт: на узле ничего не делалось и Caddy
    /// не перезапускался.
    /// </summary>
    Paused,
}

/// <param name="Revision">Хеш Caddyfile, соответствующего узлу после синхронизации.</param>
/// <param name="RetryAt">Для <see cref="XCoreCaddyAction.Paused"/> — когда пауза кончится (UTC).</param>
public sealed record XCoreCaddyResult(XCoreCaddyAction Action, string Revision, DateTime? RetryAt = null);

/// <summary>
/// Сбой синхронизации. Текст безопасен для показа оператору и записи в SyncError:
/// в нём нет ни UUID, ни ключей, ни текста команд.
/// </summary>
public sealed class XCoreSyncException : Exception
{
    public XCoreSyncException(string message) : base(message) { }
    public XCoreSyncException(string message, Exception inner) : base(message, inner) { }

    /// <summary>
    /// Причина — API Xray не ответил (контейнер упал, завис или ещё не поднялся). Это единственный
    /// сбой, который лечит принудительный перезапуск: отклонённый конфиг или ошибка добавления
    /// пользователя после него повторились бы.
    /// </summary>
    public bool ApiUnavailable { get; init; }

    /// <summary>
    /// Ревизия Caddyfile, чей выпуск сертификата не удался после перезапуска Caddy. Обработчик запоминает её с
    /// временем неудачи, и следующие попытки с той же ревизией ждут паузу. Сбои до перезапуска (Caddy отклонил
    /// файл) сюда не попадают: к Let's Encrypt они не обращались и повтор после правки ничем не грозит.
    /// </summary>
    public string? CaddyFailedRevision { get; init; }
}

/// <summary>
/// Приводит узел xcore к желаемому списку пользователей. Ревизии в базе не обновляет —
/// это дело вызывающего: он один знает, что результат записан, и не должен получить
/// «применено» от метода, чью запись потом не удалось сохранить.
///
/// Файл конфига на хосте всегда содержит полный список: после рестарта Xray
/// пользователи, добавленные через API, пропадают, и контейнер поднимается ровно с
/// тем, что в файле.
/// </summary>
public sealed class XCoreSyncService(ISecretProtector secrets, ScriptRegistry scripts, IOptions<XCoreOptions> options)
{
    private const int RemoveBatch = 100;

    /// <summary>Сколько раз и как часто спрашивать Caddy о сертификате домена подписки: 24 × 5 с = 120 с.</summary>
    public int CertificateAttempts { get; init; } = 24;

    public TimeSpan CertificatePollInterval { get; init; } = TimeSpan.FromSeconds(5);

    /// <summary>После перезапуска API поднимается не сразу: 15 × 1 с.</summary>
    public int RestartPollAttempts { get; init; } = 15;

    public TimeSpan RestartPollInterval { get; init; } = TimeSpan.FromSeconds(1);

    /// <param name="forceRestart">
    /// Перезапустить контейнер при любом исходе сверки. Нужен повтору после сбоя API: новый файл
    /// конфига к тому времени уже на месте, а процесс, который перестал отвечать, перезапуск
    /// поднимает с ровно этим файлом. Параметр последний и необязательный: на пятой позиции его
    /// принял бы за себя прежний аргумент <c>default</c> вместо токена отмены.
    /// </param>
    /// <param name="exits">
    /// Выходы входа; обязателен для роли «вход» (пустой список — вход без выходов, он закрыт) и
    /// игнорируется для выхода. Отсутствие списка у входа — ошибка вызова, а не «выходов нет»:
    /// иначе забытый аргумент молча закрыл бы вход.
    /// </param>
    public async Task<XCoreSyncResult> SyncAsync(
        ISshSession ssh, VpnServer server, ProtocolInstance protocol,
        IReadOnlyList<XCoreUser> users, CancellationToken ct = default, bool forceRestart = false,
        IReadOnlyList<XCoreExitTarget>? exits = null)
    {
        var node = protocol.XCore;
        if (protocol.Kind != ProtocolKinds.XCore || node is null || server.FindProtocol(protocol.Id) is null)
            throw new InvalidOperationException("Протокол не является xcore этого узла.");
        if (!XCoreNode.IsSafeImageRef(node.ImageRef))
            throw new XCoreSyncException("Ссылка на образ Xray в параметрах узла некорректна.");

        var privateKey = secrets.Unprotect(node.RealityPrivateKey)
            ?? throw new XCoreSyncException("У узла нет приватного ключа Reality: конфиг собрать нельзя.");

        // Пустая строка при включённом шифровании не подменяется на none: рендерер на ней откажет.
        var vlessDecryption = node.VlessEncryption ? secrets.Unprotect(node.VlessDecryption) : null;

        XCoreRenderedConfig full;
        string structureRevision;
        try
        {
            if (node.Role == XCoreRoles.Entry)
            {
                if (exits is null)
                    throw new InvalidOperationException("Для входа не передан список выходов.");
                var relayUuid = secrets.Unprotect(node.RelayUuid)
                    ?? throw new XCoreSyncException("У входа нет служебного UUID: конфиг собрать нельзя.");
                full = XCoreConfigRenderer.RenderEntry(node, privateKey, users, relayUuid, exits, vlessDecryption);
                structureRevision = XCoreConfigRenderer.RenderEntryStructureRevision(
                    node, privateKey, relayUuid, exits, vlessDecryption);
            }
            else
            {
                full = XCoreConfigRenderer.Render(node, privateKey, users, vlessDecryption);
                structureRevision = XCoreConfigRenderer.RenderStructureRevision(node, privateKey, vlessDecryption);
            }
        }
        catch (Exception ex) when (ex is InvalidOperationException or NotSupportedException)
        {
            // Тексты рендерера говорят про email и поля узла, ключей и UUID в них нет.
            throw new XCoreSyncException($"Не удалось собрать конфиг xcore: {ex.Message}", ex);
        }

        IReadOnlyList<XCoreUser>? live = null;
        if (full.Revision == node.AppliedRevision && !forceRestart)
        {
            // Ревизия в базе — слова самой синхронизации. Узел мог перезапуститься с
            // другим файлом или потерять пользователей, поэтому доверять ей без сверки
            // с живым списком нельзя.
            live = await ReadLiveUsersAsync(ssh, node.ApiPort, ct);
            if (SameUsers(live, users))
                return new XCoreSyncResult(XCoreSyncAction.NoOp, full.Revision, structureRevision, 0, 0);
        }

        // Конфиг со ссылками на ext:rf-… проверяется с каталогом списков входа, как его увидит контейнер.
        var usesRfLists = node.Role == XCoreRoles.Entry && !string.IsNullOrEmpty(node.RfListsTag);
        await ReplaceConfigAsync(ssh, node.ImageRef, full.Json, usesRfLists ? XCoreNode.GeoDir : null, ct);

        // Неизвестная прежняя структура (null) трактуется как изменённая: перезапуск
        // безопасен всегда, а применить дифф к неизвестному состоянию — нет.
        if (forceRestart || node.AppliedStructureRevision != structureRevision)
        {
            await ssh.RunCheckedAsync($"sudo docker restart {XCoreNode.XrayContainer}", "xcore_restart", ct);
            await WaitForUserCountAsync(ssh, node.ApiPort, users.Count, ct);
            return new XCoreSyncResult(XCoreSyncAction.Restart, full.Revision, structureRevision, 0, 0);
        }

        live ??= await ReadLiveUsersAsync(ssh, node.ApiPort, ct);
        var (added, removed) = await ApplyDiffAsync(ssh, node, live, users, ct);
        if (added + removed > 0)
            await WaitForUserCountAsync(ssh, node.ApiPort, users.Count, ct, attempts: 1);

        return new XCoreSyncResult(XCoreSyncAction.Diff, full.Revision, structureRevision, added, removed);
    }

    // ── Caddy ─────────────────────────────────────────────────────────────────

    /// <summary>
    /// Приводит Caddyfile узла к рендеру из базы. Сравнивается хеш текста с <c>AppliedCaddyRevision</c>: совпал —
    /// на узле ничего не делается, не нужно даже обращаться к нему.
    ///
    /// Новый текст пишется рядом (<c>Caddyfile.new</c>) и проверяется одноразовым контейнером того же образа,
    /// как конфиг Xray: проверка живого контейнера через <c>docker exec</c> видела бы уже подменённый файл, и
    /// отказ оставил бы на хосте сломанный Caddyfile, с которым Caddy не поднимется после перезагрузки узла.
    /// Рабочий файл перезаписывается на месте (<c>cp</c>), а не заменяется переименованием: он смонтирован в
    /// контейнер как отдельный файл, и после подмены inode контейнер видит прежний файл до пересоздания
    /// монтирования (а в Docker Desktop перезапуск после такой подмены вовсе падает). Перезапуск нужен всё
    /// равно: Caddy читает Caddyfile только при старте.
    ///
    /// Ревизия в базе остаётся прежней, пока сертификат домена подписки не получен: повтор после сбоя
    /// перезапишет и перезапустит Caddy заново — но не сразу. Каждый перезапуск просит у Let's Encrypt
    /// сертификат, а после серии неудач он блокирует выпуск для домена, поэтому обработчик запоминает ревизию
    /// и время неудачи (<see cref="XCoreSyncException.CaddyFailedRevision"/>), и до конца
    /// <c>XCore:CaddyRetryMinutes</c> та же ревизия возвращает <see cref="XCoreCaddyAction.Paused"/>. Другая
    /// ревизия (оператор поправил домен) и сохранение настроек в панели (очищает пометку) паузу снимают.
    /// </summary>
    public async Task<XCoreCaddyResult> SyncCaddyAsync(
        ISshSession ssh, ProtocolInstance protocol, CancellationToken ct = default)
    {
        var node = protocol.XCore;
        if (protocol.Kind != ProtocolKinds.XCore || node is null)
            throw new InvalidOperationException("Протокол не является xcore этого узла.");

        // Домен подписки бывает только у входа: у выхода прежнее значение (если оно каким-то образом
        // осталось в базе) в конфиг не попадает.
        var subscriptionHost = node.Role == XCoreRoles.Entry ? node.SubscriptionHost : null;

        XCoreRenderedCaddyfile rendered;
        try
        {
            XCoreInput.TryNormalizeAcmeEmail(options.Value.AcmeEmail, out var email);
            string? upstream = null;
            if (subscriptionHost is not null)
            {
                if (!XCoreInput.TryNormalizeUpstream(options.Value.SubscriptionUpstream, out var normalized))
                    throw new InvalidOperationException(
                        "Не задан адрес для проксирования подписки (XCore:SubscriptionUpstream): Caddyfile собрать нельзя.");
                upstream = normalized;
            }

            rendered = XCoreCaddyRenderer.Render(scripts, node.Domain, email, subscriptionHost, upstream);
        }
        catch (InvalidOperationException ex)
        {
            throw new XCoreSyncException($"Не удалось собрать Caddyfile: {ex.Message}", ex);
        }

        if (rendered.Revision == node.AppliedCaddyRevision)
            return new XCoreCaddyResult(XCoreCaddyAction.NoOp, rendered.Revision);

        if (PausedUntil(node, rendered.Revision) is { } retryAt && retryAt > DateTime.UtcNow)
            return new XCoreCaddyResult(XCoreCaddyAction.Paused, rendered.Revision, retryAt);

        await ReplaceCaddyfileAsync(ssh, rendered.Text, ct);

        await ssh.RunCheckedAsync($"sudo docker restart {XCoreNode.WebContainer}", "xcore_restart_web", ct);

        if (subscriptionHost is not null)
        {
            var wait = await XCoreCaddyProbe.WaitForCertificateAsync(
                ssh, subscriptionHost, "404", CertificateAttempts, CertificatePollInterval, null, ct);
            if (wait == XCoreCertificateWait.CurlMissing)
                throw new XCoreSyncException("На узле нет curl: сертификат домена подписки проверить нельзя.")
                {
                    CaddyFailedRevision = rendered.Revision,
                };
            if (wait == XCoreCertificateWait.Timeout)
                throw new XCoreSyncException(
                    $"Не удалось получить сертификат для домена подписки {subscriptionHost}: " +
                    "проверьте A-запись домена и что порт 80 открыт снаружи.")
                {
                    CaddyFailedRevision = rendered.Revision,
                };
        }

        return new XCoreCaddyResult(XCoreCaddyAction.Restart, rendered.Revision);
    }

    /// <summary>Когда кончается пауза после неудачного выпуска сертификата для этой ревизии; null — паузы нет.</summary>
    private DateTime? PausedUntil(XCoreProtocolParams node, string revision) =>
        options.Value.CaddyRetryMinutes > 0 && node.CaddyFailedRevision == revision && node.CaddyFailedAt is { } failedAt
            ? failedAt.AddMinutes(options.Value.CaddyRetryMinutes)
            : null;

    /// <summary>Текст для <c>SyncError</c> на время паузы. Время в UTC: оператор может быть в другом часовом поясе.</summary>
    public static string CaddyPausedMessage(DateTime retryAt) =>
        "Сертификат домена подписки не получен (проверьте A-запись домена и порт 80); повтор не раньше " +
        retryAt.ToUniversalTime().ToString("HH:mm", System.Globalization.CultureInfo.InvariantCulture) +
        " UTC. Чтобы повторить сразу, поправьте домен или сохраните настройки узла.";

    private static async Task ReplaceCaddyfileAsync(ISshSession ssh, string text, CancellationToken ct)
    {
        try
        {
            await ssh.WriteHostFileAsync(XCoreNode.NewCaddyfilePath, text, ct);

            var test = await ssh.RunAsync(XCoreNode.ValidateCaddyfileCommand, ct);
            if (!test.Ok)
                throw new XCoreSyncException(
                    $"Caddy отклонил новый Caddyfile: {SecretRedactor.Tail(test.StdErr, 300)}");

            await ssh.RunCheckedAsync(
                $"sudo cp -f {XCoreNode.NewCaddyfilePath} {XCoreNode.CaddyfilePath}", "xcore_replace_caddyfile", ct);
        }
        finally
        {
            await RemoveFileQuietlyAsync(ssh, XCoreNode.NewCaddyfilePath);
        }
    }

    // ── Файл конфига ──────────────────────────────────────────────────────────

    /// <summary>
    /// Пишет новый конфиг рядом, проверяет его Xray и только потом подменяет рабочий
    /// переименованием: на той же файловой системе оно атомарно, и контейнер при
    /// внезапном рестарте не прочитает половину файла.
    /// </summary>
    private static async Task ReplaceConfigAsync(
        ISshSession ssh, string imageRef, string json, string? geoDir, CancellationToken ct)
    {
        var replaced = false;
        try
        {
            await ssh.WriteHostFileAsync(XCoreNode.NewConfigPath, json, ct);
            await ssh.RunCheckedAsync($"sudo chmod 600 {XCoreNode.NewConfigPath}", "xcore_chmod_config", ct);

            var test = await ssh.RunAsync(XCoreNode.TestConfigCommand(imageRef, XCoreNode.NewConfigFile, geoDir), ct);
            var verdict = XrayApiOutput.ParseConfigTest(test.StdOut + "\n" + test.StdErr);
            if (!verdict.Ok)
                throw new XCoreSyncException($"Xray отклонил новый конфиг: {verdict.Error}");

            await ssh.RunCheckedAsync(
                $"sudo mv -f {XCoreNode.NewConfigPath} {XCoreNode.ConfigPath}", "xcore_replace_config", ct);
            replaced = true;
        }
        finally
        {
            // Непроверенный конфиг с приватным ключом не должен остаться на хосте.
            if (!replaced) await RemoveFileQuietlyAsync(ssh, XCoreNode.NewConfigPath);
        }
    }

    // ── Пользователи через API ────────────────────────────────────────────────

    private static async Task<IReadOnlyList<XCoreUser>> ReadLiveUsersAsync(
        ISshSession ssh, int apiPort, CancellationToken ct)
    {
        var output = await RunApiAsync(ssh, XCoreNode.InboundUsersCommand(apiPort), "inbounduser", ct);
        try
        {
            return XrayApiOutput.ParseInboundUsers(output);
        }
        catch (XrayOutputException ex)
        {
            throw new XCoreSyncException($"Не удалось прочитать пользователей узла: {ex.Message}", ex);
        }
    }

    private static async Task<(int Added, int Removed)> ApplyDiffAsync(
        ISshSession ssh, XCoreProtocolParams node, IReadOnlyList<XCoreUser> live,
        IReadOnlyList<XCoreUser> desired, CancellationToken ct)
    {
        var liveByEmail = live.ToDictionary(u => u.Email, StringComparer.Ordinal);
        var desiredByEmail = desired.ToDictionary(u => u.Email, StringComparer.Ordinal);

        // Пользователь с тем же email, но другим UUID (перевыпуск подписки) нельзя просто
        // добавить: xray ответит «already exists». Его сначала удаляют, потом добавляют.
        var toRemove = live
            .Where(l => !desiredByEmail.TryGetValue(l.Email, out var d) || !SameUuid(d.Uuid, l.Uuid))
            .Select(l => l.Email).ToList();
        var toAdd = desired
            .Where(d => !liveByEmail.TryGetValue(d.Email, out var l) || !SameUuid(l.Uuid, d.Uuid))
            .ToList();

        var removed = 0;
        foreach (var batch in toRemove.Chunk(RemoveBatch))
        {
            var emails = string.Join(' ', batch.Select(XCoreNode.Quote));
            var output = await RunApiAsync(ssh,
                XCoreNode.ApiCommand(node.ApiPort, "rmu", $"-tag={XCoreConfigRenderer.InboundTag} {emails}"), "rmu", ct);
            var result = ParseOrFail(() => XrayApiOutput.ParseRemoveUsers(output), "rmu");
            if (!result.IsSuccess)
                throw new XCoreSyncException($"Xray не удалил пользователей: {string.Join("; ", result.Errors)}");
            removed += result.Removed;
        }

        var added = 0;
        if (toAdd.Count > 0)
            added = await AddUsersAsync(ssh, node, toAdd, ct);

        return (added, removed);
    }

    private static async Task<int> AddUsersAsync(
        ISshSession ssh, XCoreProtocolParams node, List<XCoreUser> toAdd, CancellationToken ct)
    {
        var file = $"adu-{Guid.NewGuid():N}.json";
        var hostPath = $"{XCoreNode.OpsDir}/{file}";
        try
        {
            // В файле UUID: он живёт на узле только на время одной команды.
            await ssh.WriteHostFileAsync(hostPath, XCoreConfigRenderer.RenderUsersFile(node, toAdd), ct);
            await ssh.RunCheckedAsync($"sudo chmod 600 {hostPath}", "xcore_chmod_ops", ct);

            var output = await RunApiAsync(ssh,
                XCoreNode.ApiCommand(node.ApiPort, "adu", $"{XCoreNode.ContainerOpsDir}/{file}"), "adu", ct);
            var result = ParseOrFail(() => XrayApiOutput.ParseAddUsers(output), "adu");
            if (!result.IsSuccess)
                throw new XCoreSyncException($"Xray не добавил пользователей: {string.Join("; ", result.Errors)}");
            return result.Added;
        }
        finally
        {
            await RemoveFileQuietlyAsync(ssh, hostPath);
        }
    }

    /// <summary>
    /// Сверяет число пользователей на узле с желаемым. Разбор вывода <c>adu</c> и
    /// <c>rmu</c> уже подтвердил каждого поимённо, но этот счётчик ловит расхождение, о
    /// котором они молчат: рестарт без части пользователей или пользователя с чужим email.
    /// </summary>
    private async Task WaitForUserCountAsync(
        ISshSession ssh, int apiPort, int expected, CancellationToken ct, int? attempts = null)
    {
        var total = attempts ?? RestartPollAttempts;
        var actual = -1;
        for (var attempt = 1; attempt <= total; attempt++)
        {
            var result = await ssh.RunAsync(XCoreNode.InboundUserCountCommand(apiPort), ct);
            if (result.Ok)
            {
                try { actual = XrayApiOutput.ParseInboundUserCount(result.StdOut); }
                catch (XrayOutputException) { actual = -1; }
                if (actual == expected) return;
            }

            if (attempt < total) await Task.Delay(RestartPollInterval, ct);
        }

        throw new XCoreSyncException(actual < 0
            ? "API Xray не отвечает после применения конфига."
            : $"После применения конфига на узле {actual} пользователей вместо {expected}.")
        {
            ApiUnavailable = actual < 0,
        };
    }

    // ── Вспомогательное ───────────────────────────────────────────────────────

    /// <summary>
    /// Выполняет <c>xray api</c>. Код возврата проверяем, хотя «api» по большей части
    /// завершается нулём даже при ошибке: на недоступный сервер или несуществующий
    /// тег он отвечает ненулевым кодом, а <c>docker exec</c> — на остановленный контейнер.
    /// В сообщение идёт только stderr: stdout у inbounduser содержит UUID.
    /// </summary>
    private static async Task<string> RunApiAsync(ISshSession ssh, string command, string label, CancellationToken ct)
    {
        var result = await ssh.RunAsync(command, ct);
        if (!result.Ok)
            throw new XCoreSyncException(
                $"xray api {label} завершился с кодом {result.ExitStatus}: {SecretRedactor.Tail(result.StdErr, 300)}")
            {
                ApiUnavailable = true,
            };
        return result.StdOut;
    }

    private static T ParseOrFail<T>(Func<T> parse, string label)
    {
        try
        {
            return parse();
        }
        catch (XrayOutputException ex)
        {
            throw new XCoreSyncException($"Не удалось разобрать ответ xray api {label}: {ex.Message}", ex);
        }
    }

    private static bool SameUsers(IReadOnlyList<XCoreUser> live, IReadOnlyList<XCoreUser> desired)
    {
        if (live.Count != desired.Count) return false;
        var liveByEmail = live.GroupBy(u => u.Email, StringComparer.Ordinal)
            .ToDictionary(g => g.Key, g => g.First().Uuid, StringComparer.Ordinal);
        return liveByEmail.Count == live.Count
            && desired.All(d => liveByEmail.TryGetValue(d.Email, out var uuid) && SameUuid(uuid, d.Uuid));
    }

    private static bool SameUuid(string a, string b) =>
        Guid.TryParse(a, out var x) && Guid.TryParse(b, out var y) && x == y;

    private static async Task RemoveFileQuietlyAsync(ISshSession ssh, string path)
    {
        try
        {
            await ssh.RunAsync($"sudo rm -f {path}", CancellationToken.None);
        }
        catch (Exception)
        {
            // Уборка не должна маскировать исходную ошибку синхронизации.
        }
    }
}
