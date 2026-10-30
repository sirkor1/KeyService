using AmneziaKeyService.Core.Interfaces;
using AmneziaKeyService.Core.Models;
using Microsoft.Extensions.Options;

namespace AmneziaKeyService.Infrastructure.Protocols.XCore;

/// <summary>
/// Сбой обновления российских списков. Текст безопасен для показа оператору и записи в <c>GeoError</c>:
/// в нём нет ни ключей, ни UUID, ни текста команд.
/// </summary>
public sealed class XCoreGeoException : Exception
{
    public XCoreGeoException(string message) : base(message) { }
    public XCoreGeoException(string message, Exception inner) : base(message, inner) { }
}

/// <summary>
/// Кладёт на вход новый релиз российских списков так, чтобы сбой на любом шаге оставлял прежние файлы и
/// запущенный контейнер нетронутыми:
///
/// 1. релиз скачивается в отдельный каталог (<see cref="XCoreNode.GeoStageDir"/>) под временным именем;
/// 2. сумма файла сверяется с <c>*.sha256sum</c> того же релиза, и только совпавший получает рабочее имя;
/// 3. кандидаты проверяются `xray run -test` — пробным конфигом со всеми тегами рендерера и, если у входа есть
///    выходы, настоящим будущим конфигом: именно в нём Xray впервые прочтёт файл;
/// 4. проверенные файлы переименованием попадают в рабочий каталог.
///
/// Перезапуск Xray здесь не выполняется: конфиг с <c>ext:</c>-правилами и рестарт применяет следующая
/// синхронизация узла (<c>xcore.sync</c>), когда обработчик запишет тег. Пока она не прошла, живой процесс
/// продолжает работать со старым конфигом и уже прочитанными в память списками.
/// </summary>
public sealed class XCoreGeoService(ISecretProtector secrets, IOptions<XCoreOptions> options)
{
    private const string ProbeFile = "config.geo-probe.json";
    private const string FutureFile = "config.geo-test.json";

    /// <summary>
    /// Потолок на скачивание одного файла (geosite.dat ≈ 73 МБ). Пока идёт скачивание, партиция узла занята
    /// и синхронизация подписчиков ждёт, поэтому потолок небольшой, а повторов в команде нет.
    /// </summary>
    public int DownloadTimeoutSeconds { get; init; } = 300;

    public async Task UpdateAsync(
        ISshSession ssh, ProtocolInstance protocol, string tag, IReadOnlyList<XCoreExitTarget> exits,
        CancellationToken ct = default)
    {
        var node = protocol.XCore;
        if (protocol.Kind != ProtocolKinds.XCore || node is not { Role: XCoreRoles.Entry })
            throw new InvalidOperationException("Российские списки обновляются только у входа xcore.");

        var repo = options.Value.RfListsRepo?.Trim();
        if (!XCoreRfLists.IsSafeRepo(repo))
            throw new XCoreGeoException("Настройка XCore:RfListsRepo не в формате «владелец/репозиторий».");
        if (!XCoreRfLists.IsSafeTag(tag))
            throw new XCoreGeoException("Тег релиза списков содержит недопустимые символы.");
        if (!XCoreNode.IsSafeImageRef(node.ImageRef))
            throw new XCoreGeoException("Ссылка на образ Xray в параметрах узла некорректна.");

        await EnsureContainerSeesGeoAsync(ssh, ct);

        try
        {
            await DownloadAsync(ssh, repo!, tag, ct);
            await TestCandidatesAsync(ssh, node, tag, exits, ct);
            await PromoteAsync(ssh, ct);
        }
        finally
        {
            // Тестовые конфиги — с приватным ключом, кандидаты — недопроверенные файлы: на узле не остаются.
            await RemoveQuietlyAsync(ssh, $"{XCoreNode.ConfDir}/{FutureFile}");
            await RemoveQuietlyAsync(ssh, $"{XCoreNode.ConfDir}/{ProbeFile}");
            await RemoveQuietlyAsync(ssh, XCoreNode.GeoStageDir, recursive: true);
        }
    }

    /// <summary>
    /// Контейнер, созданный до появления списков, каталога не видит: скачанные файлы лежали бы мёртвым грузом, а
    /// конфиг с <c>ext:</c> после перезапуска не стартовал бы (в `run -test` каталог подключается отдельно, и он
    /// это не поймал бы). Починка — переустановка протокола; здесь только честный отказ.
    /// </summary>
    private static async Task EnsureContainerSeesGeoAsync(ISshSession ssh, CancellationToken ct)
    {
        var inspect = await ssh.RunAsync(XCoreNode.InspectGeoMountCommand, ct);
        if (!inspect.Ok)
            throw new XCoreGeoException($"Контейнер {XCoreNode.XrayContainer} не найден на узле.");

        var parts = inspect.StdOut.Trim().Split('|', 2);
        var mounts = parts[0].Split(' ', StringSplitOptions.RemoveEmptyEntries);
        var env = parts.Length > 1 ? parts[1].Split(' ', StringSplitOptions.RemoveEmptyEntries) : [];
        if (!mounts.Contains($"{XCoreNode.GeoDir}={XCoreNode.ContainerGeoDir}", StringComparer.Ordinal)
            || !env.Contains($"{XCoreNode.AssetEnv}={XCoreNode.ContainerGeoDir}", StringComparer.Ordinal))
            throw new XCoreGeoException(
                "Контейнер входа создан до поддержки российских списков и не видит их каталог: " +
                "переустановите протокол xcore на этом узле, и вход начнёт использовать списки.");
    }

    private async Task DownloadAsync(ISshSession ssh, string repo, string tag, CancellationToken ct)
    {
        var curl = await ssh.RunAsync("command -v curl", ct);
        if (!curl.Ok)
            throw new XCoreGeoException("На узле нет curl: российские списки скачать нельзя.");

        // Каталог кандидатов всегда начинается пустым: остаток прерванного скачивания не должен сойти за файл.
        await ssh.RunCheckedAsync($"sudo rm -rf {XCoreNode.GeoStageDir}", "xcore_geo_stage_clean", ct);
        await ssh.RunCheckedAsync($"sudo mkdir -p {XCoreNode.GeoStageDir}", "xcore_geo_stage", ct);

        foreach (var (remote, local) in XCoreRfLists.Files)
        {
            var url = XCoreNode.Quote(XCoreRfLists.DownloadUrl(repo, tag, remote));
            var sums = await ssh.RunAsync(
                $"curl -fsSL --connect-timeout 15 --max-time 60 {XCoreNode.Quote(XCoreRfLists.DownloadUrl(repo, tag, remote + ".sha256sum"))}", ct);
            if (!sums.Ok)
                throw new XCoreGeoException(
                    $"Не удалось получить контрольную сумму {remote} релиза {tag} (curl, код {sums.ExitStatus}).");
            var expected = XCoreRfLists.ParseSha256Sum(sums.StdOut, remote)
                ?? throw new XCoreGeoException($"В релизе {tag} нет контрольной суммы для {remote}.");

            var part = $"{XCoreNode.GeoStageDir}/{local}.part";
            var download = await ssh.RunAsync(
                $"sudo curl -fsSL --connect-timeout 15 --max-time {DownloadTimeoutSeconds} -o {part} {url}", ct);
            if (!download.Ok)
                throw new XCoreGeoException($"Не удалось скачать {remote} релиза {tag} (curl, код {download.ExitStatus}).");

            var hashed = await ssh.RunAsync($"sudo sha256sum {part}", ct);
            var actual = hashed.Ok ? XCoreRfLists.ParseSha256Output(hashed.StdOut) : null;
            if (actual != expected)
                throw new XCoreGeoException(
                    $"Контрольная сумма {remote} не совпала с опубликованной в релизе {tag}: файлы не применены.");

            // Рабочее имя файл получает только после сверки суммы.
            await ssh.RunCheckedAsync(
                $"sudo mv -f {part} {XCoreNode.GeoStageDir}/{local}", "xcore_geo_accept", ct);
        }
    }

    private async Task TestCandidatesAsync(
        ISshSession ssh, XCoreProtocolParams node, string tag, IReadOnlyList<XCoreExitTarget> exits,
        CancellationToken ct)
    {
        await ssh.WriteHostFileAsync($"{XCoreNode.ConfDir}/{ProbeFile}", XCoreRfLists.ProbeConfig(), ct);
        await RunTestAsync(ssh, node.ImageRef, ProbeFile, "В новом релизе списков не хватает нужных тегов", ct);

        if (exits.Count == 0) return;

        var privateKey = secrets.Unprotect(node.RealityPrivateKey)
            ?? throw new XCoreGeoException("У входа нет приватного ключа Reality: конфиг собрать нельзя.");
        var relayUuid = secrets.Unprotect(node.RelayUuid)
            ?? throw new XCoreGeoException("У входа нет служебного UUID: конфиг собрать нельзя.");

        var vlessDecryption = node.VlessEncryption ? secrets.Unprotect(node.VlessDecryption) : null;

        XCoreRenderedConfig future;
        try
        {
            future = XCoreConfigRenderer.RenderEntryWithRfLists(node, privateKey, [], relayUuid, exits, tag, vlessDecryption);
        }
        catch (Exception ex) when (ex is InvalidOperationException or NotSupportedException)
        {
            // Тексты рендерера говорят про поля узла, ключей и UUID в них нет.
            throw new XCoreGeoException($"Не удалось собрать конфиг входа с новыми списками: {ex.Message}", ex);
        }

        var path = $"{XCoreNode.ConfDir}/{FutureFile}";
        await ssh.WriteHostFileAsync(path, future.Json, ct);
        await ssh.RunCheckedAsync($"sudo chmod 600 {path}", "xcore_chmod_geo_test", ct);
        await RunTestAsync(ssh, node.ImageRef, FutureFile, "Xray отклонил конфиг входа с новыми списками", ct);
    }

    private static async Task RunTestAsync(
        ISshSession ssh, string imageRef, string file, string failure, CancellationToken ct)
    {
        var test = await ssh.RunAsync(XCoreNode.TestConfigCommand(imageRef, file, XCoreNode.GeoStageDir), ct);
        var verdict = XrayApiOutput.ParseConfigTest(test.StdOut + "\n" + test.StdErr);
        if (!verdict.Ok)
            throw new XCoreGeoException($"{failure}: {verdict.Error}");
    }

    /// <summary>
    /// Переименование внутри одного дерева <c>/opt/amnezia-xcore</c> атомарно, а каталог остаётся тем же inode,
    /// поэтому контейнер видит новый файл сразу, без пересоздания монтирования. Между двумя файлами пары
    /// окно есть, но обе версии каждого файла рабочие.
    /// </summary>
    private static async Task PromoteAsync(ISshSession ssh, CancellationToken ct)
    {
        foreach (var (_, local) in XCoreRfLists.Files)
        {
            var staged = $"{XCoreNode.GeoStageDir}/{local}";
            await ssh.RunCheckedAsync($"sudo chmod 644 {staged}", "xcore_geo_chmod", ct);
            await ssh.RunCheckedAsync($"sudo mv -f {staged} {XCoreNode.GeoDir}/{local}", "xcore_geo_promote", ct);
        }
    }

    private static async Task RemoveQuietlyAsync(ISshSession ssh, string path, bool recursive = false)
    {
        try
        {
            await ssh.RunAsync($"sudo rm {(recursive ? "-rf" : "-f")} {path}", CancellationToken.None);
        }
        catch (Exception)
        {
            // Уборка не должна маскировать исходную ошибку обновления.
        }
    }
}
