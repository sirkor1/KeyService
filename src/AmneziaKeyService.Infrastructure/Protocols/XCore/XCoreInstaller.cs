using System.Security.Cryptography;
using AmneziaKeyService.Core.Exceptions;
using AmneziaKeyService.Core.Interfaces;
using AmneziaKeyService.Core.Models;
using AmneziaKeyService.Infrastructure.Scripts;
using Microsoft.Extensions.Options;

namespace AmneziaKeyService.Infrastructure.Protocols.XCore;

/// <summary>
/// Развёртывание собственного Xray для подписок: Caddy с настоящим сертификатом на
/// домен узла (сюда Reality отдаёт чужие рукопожатия) и Xray с XHTTP+Reality на 443.
///
/// Не наследует <see cref="ProtocolInstallerBase"/>: тот собирает образ из Dockerfile
/// и настраивает контейнер через <c>docker exec … sh</c>, а официальный образ Xray
/// без shell. Конфиг лежит на хосте и монтируется в контейнер.
/// </summary>
public sealed class XCoreInstaller(
    ScriptRegistry scripts,
    ISecretProtector secrets,
    IDnsResolver dns,
    IOptions<XCoreOptions> options) : IProtocolInstaller
{
    private const string Alphabet = "abcdefghijklmnopqrstuvwxyz0123456789";

    /// <summary>Сколько раз и как часто спрашивать Caddy о сертификате: 24 × 5 с = 120 с.</summary>
    public int CertificateAttempts { get; init; } = 24;

    public TimeSpan CertificatePollInterval { get; init; } = TimeSpan.FromSeconds(5);

    public string Kind => ProtocolKinds.XCore;

    /// <summary>443: Reality выглядит обычным HTTPS только на нём.</summary>
    public string DefaultPort => XCoreNode.HttpsPort;

    public bool RequiresModernKernel => false;

    public async Task<ProtocolInstance> InstallAsync(
        ISshSession ssh, VpnServer server, ProtocolSpec spec, IInstallProgress progress,
        CancellationToken ct = default)
    {
        // Всё, что можно проверить без узла, — до первой команды на нём.
        var role = string.IsNullOrWhiteSpace(spec.Role) ? XCoreRoles.Exit : spec.Role;
        if (role is not (XCoreRoles.Exit or XCoreRoles.Entry))
            throw new BadRequestException("Неизвестная роль xcore: допустимы «exit» и «entry».");
        var domain = XCoreInput.RequireDomain(spec.Domain);
        var email = XCoreInput.RequireAcmeEmail(options.Value.AcmeEmail);

        await progress.DetailAsync($"Проверка A-записи домена {domain}", ct);
        await EnsureDomainPointsToNodeAsync(server, domain, ct);

        var existing = await ssh.RunCheckedAsync("sudo docker ps -a --format '{{.Names}}'", "list_containers", ct);
        var names = existing.Split('\n', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
        if (names.Contains(XCoreNode.XrayContainer) || names.Contains(XCoreNode.WebContainer))
            throw new BadRequestException(
                "Контейнер уже существует. Установка остановлена, существующие данные сохранены.");

        try
        {
            return await DeployAsync(ssh, role, domain, email, progress, ct);
        }
        catch
        {
            // Оставленный Caddy держал бы порт 80, а повторная установка упёрлась бы в
            // «контейнер уже существует». Каталог не трогаем: в нём сертификат, а у Let's
            // Encrypt лимит на выпуск для одного домена в неделю.
            await RemoveContainersQuietlyAsync(ssh);
            throw;
        }
    }

    private async Task<ProtocolInstance> DeployAsync(
        ISshSession ssh, string role, string domain, string email, IInstallProgress progress, CancellationToken ct)
    {
        await progress.DetailAsync("Подготовка каталогов xcore", ct);
        await ssh.RunCheckedAsync(
            $"sudo mkdir -p {XCoreNode.ConfDir} {XCoreNode.OpsDir} {XCoreNode.CaddyDir}/site " +
            $"{XCoreNode.CaddyDir}/data {XCoreNode.CaddyDir}/config", "xcore_prepare_dirs", ct);
        await ssh.RunCheckedAsync($"sudo chmod 700 {XCoreNode.ConfDir} {XCoreNode.OpsDir}", "xcore_chmod_dirs", ct);

        // Каталог российских списков есть только у входа и создаётся пустым до запуска контейнера: иначе Docker
        // создал бы его сам при монтировании. Сами списки скачивает событие xcore.geo_update после установки, и
        // его сбой установку не проваливает — вход работает на встроенных списках образа.
        if (role == XCoreRoles.Entry)
            await ssh.RunCheckedAsync($"sudo mkdir -p {XCoreNode.GeoDir}", "xcore_prepare_geo_dir", ct);

        var caddyfile = XCoreCaddyRenderer.Render(scripts, domain, email);
        await ssh.WriteHostFileAsync(XCoreNode.CaddyfilePath, caddyfile.Text, ct);
        await ssh.WriteHostFileAsync($"{XCoreNode.CaddyDir}/site/index.html", scripts.Read("xcore/index.html"), ct);

        // ufw включает сам оператор; включённый по нашей воле он закрыл бы SSH.
        var ufw = await ssh.RunAsync("sudo ufw status", ct);
        if (ufw.Ok && ufw.StdOut.Contains("Status: active", StringComparison.Ordinal))
        {
            await progress.DetailAsync("Открытие портов 80 и 443 в ufw", ct);
            await ssh.RunCheckedAsync("sudo ufw allow 80/tcp", "xcore_ufw_80", ct);
            await ssh.RunCheckedAsync("sudo ufw allow 443/tcp", "xcore_ufw_443", ct);
        }

        await progress.DetailAsync("Запуск Caddy и выпуск сертификата", ct);
        await ssh.RunCheckedAsync(
            $"sudo docker run -d --name {XCoreNode.WebContainer} --network host --restart always " +
            $"{XCoreNode.MountArgs(XCoreNode.WebContainer)} {XCoreNode.CaddyImage}", "xcore_start_web", ct);
        await WaitForCertificateAsync(ssh, domain, progress, ct);

        await progress.DetailAsync("Генерация ключей Reality", ct);
        var keys = ParseKeys(await ssh.RunCheckedAsync(
            $"sudo docker run --rm {XCoreNode.XrayImage} x25519", "xcore_x25519", ct));

        var node = new XCoreProtocolParams
        {
            Role = role,
            Domain = domain,
            ImageRef = XCoreNode.XrayImage,
            RealityPrivateKey = secrets.Protect(keys.PrivateKey),
            RealityPublicKey = keys.PublicKey,
            ShortIds = [Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(8))],
            XhttpPath = "/" + RandomNumberGenerator.GetString(Alphabet, 16),
            Fingerprint = "firefox",
            SubscriptionEnabled = true,
            // Синхронизация сравнивает рендер из базы с этой ревизией: записанный здесь Caddyfile
            // совпадёт с ним, и первый же проход не станет перезапускать только что поднятый Caddy.
            AppliedCaddyRevision = caddyfile.Revision,
        };

        // Конфиг без пользователей: подписчиков добавляет синхронизация, а у только что
        // поставленного узла их ещё нет. Вход ставится без выходов (то есть закрытым): список
        // выходов известен только синхронизации, и первая же она его применит.
        string? relayUuid = null;
        if (role == XCoreRoles.Entry)
        {
            relayUuid = Guid.NewGuid().ToString("D");
            node.RelayUuid = secrets.Protect(relayUuid);
        }

        var config = relayUuid is null
            ? XCoreConfigRenderer.Render(node, keys.PrivateKey, [])
            : XCoreConfigRenderer.RenderEntry(node, keys.PrivateKey, [], relayUuid, []);
        await progress.DetailAsync("Проверка конфигурации Xray", ct);
        await ssh.WriteHostFileAsync(XCoreNode.ConfigPath, config.Json, ct);
        await ssh.RunCheckedAsync($"sudo chmod 600 {XCoreNode.ConfigPath}", "xcore_chmod_config", ct);

        var test = await ssh.RunAsync(XCoreNode.TestConfigCommand(node.ImageRef, "config.json"), ct);
        var verdict = XrayApiOutput.ParseConfigTest(test.StdOut + "\n" + test.StdErr);
        if (!verdict.Ok)
            throw new BadRequestException($"Xray отклонил конфигурацию xcore: {verdict.Error}");

        await progress.DetailAsync("Запуск Xray", ct);
        await ssh.RunCheckedAsync(
            $"sudo docker run -d --name {XCoreNode.XrayContainer} --network host --user 0:0 --restart always " +
            $"{XCoreNode.MountArgs(XCoreNode.XrayContainer, role)} {node.ImageRef} run -c {XCoreNode.ContainerConfDir}/config.json",
            "xcore_start_xray", ct);

        node.AppliedRevision = config.Revision;
        node.AppliedStructureRevision = config.Revision;
        node.AppliedAt = DateTime.UtcNow;

        return new ProtocolInstance
        {
            Kind = ProtocolKinds.XCore,
            ContainerName = XCoreNode.XrayContainer,
            Port = DefaultPort,
            TransportProto = "tcp",
            State = ProtocolStates.Installed,
            InstalledAt = DateTime.UtcNow,
            XCore = node,
        };
    }

    public async Task RemoveAsync(
        ISshSession ssh, VpnServer server, ProtocolInstance protocol, IInstallProgress progress,
        CancellationToken ct = default)
    {
        await progress.DetailAsync("Удаление контейнеров xcore", ct);
        // Код возврата не смотрим: если одного из контейнеров нет, docker всё равно
        // удалит второй, но завершится с ошибкой. Результат проверяет список ниже.
        await ssh.RunAsync($"sudo docker rm -f {XCoreNode.XrayContainer} {XCoreNode.WebContainer}", ct);

        var left = await ssh.RunCheckedAsync("sudo docker ps -a --format '{{.Names}}'", "list_containers", ct);
        var names = left.Split('\n', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
        if (names.Contains(XCoreNode.XrayContainer) || names.Contains(XCoreNode.WebContainer))
            throw new BadRequestException("Контейнеры xcore не удалились. Проверьте их на узле: docker ps -a.");

        await progress.DetailAsync($"Удаление каталога {XCoreNode.Root}", ct);
        await ssh.RunCheckedAsync($"sudo rm -rf {XCoreNode.Root}", "xcore_remove_dir", ct);
    }

    public Task RestartAsync(
        ISshSession ssh, VpnServer server, ProtocolInstance protocol, CancellationToken ct = default)
        => ssh.RunCheckedAsync($"sudo docker restart {XCoreNode.XrayContainer}", "restart_container", ct);

    // ── Шаги ──────────────────────────────────────────────────────────────────

    /// <summary>
    /// Let's Encrypt проверяет домен по HTTP-01 с порта 80, и при чужой A-записи
    /// Caddy ушёл бы в повторы, а установка ждала бы сертификата до таймаута.
    /// Расхождение видно сразу и без обращения к узлу.
    /// </summary>
    private Task EnsureDomainPointsToNodeAsync(VpnServer server, string domain, CancellationToken ct)
        => XCoreDomainCheck.EnsurePointsToNodeAsync(dns, server.Host, domain, "повторите установку", ct);

    private async Task WaitForCertificateAsync(ISshSession ssh, string domain, IInstallProgress progress, CancellationToken ct)
    {
        var wait = await XCoreCaddyProbe.WaitForCertificateAsync(
            ssh, domain, "200", CertificateAttempts, CertificatePollInterval,
            (attempt, token) => progress.DetailAsync($"Ожидание сертификата ({attempt}/{CertificateAttempts})", token), ct);

        switch (wait)
        {
            case XCoreCertificateWait.CurlMissing:
                throw new BadRequestException("На узле нет curl, без него нельзя проверить сертификат. Установите curl и повторите установку.");
            case XCoreCertificateWait.Timeout:
                throw new BadRequestException(
                    "Не удалось получить сертификат: проверьте A-запись домена и что порт 80 открыт снаружи.");
        }
    }

    private static XrayKeyPair ParseKeys(string output)
    {
        try
        {
            return XrayApiOutput.ParseX25519(output);
        }
        catch (XrayOutputException ex)
        {
            // Сообщение парсера не содержит вывода, а значит и ключей.
            throw new BadRequestException($"Не удалось получить ключи Reality: {ex.Message}");
        }
    }

    private static async Task RemoveContainersQuietlyAsync(ISshSession ssh)
    {
        try
        {
            await ssh.RunAsync($"sudo docker rm -f {XCoreNode.XrayContainer} {XCoreNode.WebContainer}", CancellationToken.None);
        }
        catch (Exception)
        {
            // Уборка не должна маскировать исходную ошибку установки.
        }
    }
}
