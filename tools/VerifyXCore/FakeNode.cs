using System.Net;
using System.Reflection;
using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using AmneziaKeyService.Core.Exceptions;
using AmneziaKeyService.Core.Interfaces;
using AmneziaKeyService.Core.Models;
using AmneziaKeyService.Infrastructure.Protocols.XCore;
using AmneziaKeyService.Infrastructure.Monitoring;
using AmneziaKeyService.Infrastructure.Subscriptions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

/// <summary>
/// Узел xcore в памяти: понимает ровно те команды, которые выполняют установщик, синхронизация
/// и оркестратор, и отвечает на них текстами, снятыми с xray-core 26.10.21 (см. VerifyXCore).
/// Неизвестная команда — исключение: тихий «успех» на незнакомую команду скрыл бы ошибку
/// в самой проверке.
/// </summary>
sealed class FakeNode
{
    public const string PrivateKey = "CCjvIm9FrG2plFwEag9_EIjqZ5YegsIIzTRa7ysTNF8";
    public const string PublicKey = "vN5-VmKdoRXOgLJeJ1n3uX2nGxzPDE48X9qHZUT32is";

    /// <summary>
    /// Вывод <c>xray vlessenc</c> образа 26.10.21 (снят живым запуском; ключи одноразовые, нигде не используются).
    /// Второй вариант в оригинале — ML-KEM-768 со строкой около 1,6 КБ; здесь она сокращена до формы, различимой
    /// по заголовку, потому что разбор обязан не брать её, а не разбирать.
    /// </summary>
    public const string VlessEncDecryption = "mlkem768x25519plus.native.600s.sPv_EiUoTTSalsbq-6-eyImENJ7r1Dq03mTkHEaEz3s";
    public const string VlessEncEncryption = "mlkem768x25519plus.native.0rtt.SbrjbVAwvkucHzXzSUC52rCKMdM-ZRKiduLBlpzzzjo";
    public static readonly string VlessEncOutput =
        "Choose one Authentication to use, do not mix them. Ephemeral key exchange is Post-Quantum safe anyway.\n\n" +
        "Authentication: X25519, not Post-Quantum\n" +
        $"\"decryption\": \"{VlessEncDecryption}\"\n" +
        $"\"encryption\": \"{VlessEncEncryption}\"\n\n" +
        "Authentication: ML-KEM-768, Post-Quantum\n" +
        $"\"decryption\": \"mlkem768x25519plus.native.600s.{new string('Q', 86)}\"\n" +
        $"\"encryption\": \"mlkem768x25519plus.native.0rtt.{new string('1', 1568)}\"\n";

    /// <summary>Каждая выполненная команда и каждая запись файла, в порядке выполнения.</summary>
    public List<string> Commands { get; } = [];

    /// <summary>Метки операций RunCheckedAsync.</summary>
    public List<string> Labels { get; } = [];

    /// <summary>Записи файлов: путь → содержимое. Единственное место, где допустим приватный ключ.</summary>
    public List<(string Path, string Content)> Writes { get; } = [];

    public Dictionary<string, string> Files { get; } = new(StringComparer.Ordinal);
    public Dictionary<string, string> Modes { get; } = new(StringComparer.Ordinal);
    public HashSet<string> Containers { get; } = new(StringComparer.Ordinal);
    public List<XCoreUser> Live { get; set; } = [];
    public HashSet<string> BusyPorts { get; } = [];

    public bool UfwActive, CertificateNever, TestFails, AduReportsError, AduThrows, ApiDown, RestartLosesUsers;

    /// <summary>`caddy validate` отклоняет файл (одноразовый контейнер завершается с ошибкой).</summary>
    public bool CaddyValidateFails;

    /// <summary>Сколько раз перезапускали Caddy и сколько раз его проверяли.</summary>
    public int WebRestarts, CaddyValidations;

    /// <summary>
    /// Caddyfile, который Caddy прочитал при последнем запуске. Файл смонтирован в контейнер отдельным
    /// файлом, поэтому подмена на хосте без перезапуска сайтов не меняет — как и на настоящем узле.
    /// </summary>
    public string LoadedCaddyfile { get; private set; } = "";

    /// <summary>Ответы на проверку плеч (curl с входа): домен выхода → (код возврата curl, вывод).</summary>
    public Dictionary<string, (int Exit, string Out)> ExitProbes { get; } = new(StringComparer.Ordinal);

    /// <summary>Домены, чьи плечи проверялись, в порядке проверки.</summary>
    public List<string> ExitProbed { get; } = [];

    /// <summary>Перезапуск контейнера возвращает API к жизни: так ведёт себя зависший процесс.</summary>
    public bool RestartRevivesApi;

    // ── Российские списки ─────────────────────────────────────────────────────

    /// <summary>«Интернет» узла: адрес → тело ответа. Нет адреса — curl завершается с кодом 22 (HTTP 404).</summary>
    public Dictionary<string, string> Internet { get; } = new(StringComparer.Ordinal);

    /// <summary>Адреса, по которым узел ходил, в порядке запросов.</summary>
    public List<string> Downloads { get; } = [];

    /// <summary>Нет curl; контейнер входа создан без каталога списков; релиз без нужных тегов; Xray отклоняет будущий конфиг.</summary>
    public bool CurlMissing, GeoNotMounted, RfListsLackTags, FutureConfigTestFails;

    /// <summary>Команда, которой запущен контейнер Xray: по ней `docker inspect` отвечает про монтирования.</summary>
    public string? XrayRunCommand { get; private set; }

    /// <summary>Каждая проверка конфига: файл и каталог списков, подключённый к одноразовому контейнеру ("" — не подключён).</summary>
    public List<(string File, string GeoDir)> ConfigTests { get; } = [];

    public int XrayRestarts => Commands.Count(c => c == "sudo docker restart amnezia-xcore");

    /// <summary>Счётчики Xray: email → (uplink, downlink). Нулевое значение Xray не печатает.</summary>
    public Dictionary<string, (long Uplink, long Downlink)> Stats { get; } = new(StringComparer.Ordinal);
    public int CurlCalls;

    public ISshSession Session { get; }

    public FakeNode() => Session = Stub.Create<ISshSession>(Handle);

    public bool Ran(string fragment) => Commands.Any(c => c.Contains(fragment, StringComparison.Ordinal));

    public int IndexOf(string fragment) => Commands.FindIndex(c => c.Contains(fragment, StringComparison.Ordinal));

    private object? Handle(MethodInfo method, object?[] args)
    {
        switch (method.Name)
        {
            case nameof(ISshSession.DisposeAsync):
                return ValueTask.CompletedTask;
            case nameof(ISshSession.WriteHostFileAsync):
            {
                var path = (string)args[0]!;
                var content = (string)args[1]!;
                Commands.Add("WRITE " + path);
                Writes.Add((path, content));
                Files[path] = content;
                return Task.CompletedTask;
            }
            case nameof(ISshSession.RunCheckedAsync):
            {
                var command = (string)args[0]!;
                Labels.Add((string)args[1]!);
                Commands.Add(command);
                var result = Exec(command);
                return result.Ok
                    ? Task.FromResult(result.StdOut)
                    : Task.FromException<string>(new SshCommandException((string)args[1]!, result.ExitStatus, null, null));
            }
            case nameof(ISshSession.RunAsync):
            {
                var command = (string)args[0]!;
                Commands.Add(command);
                try { return Task.FromResult(Exec(command)); }
                catch (Exception ex) { return Task.FromException<SshResult>(ex); }
            }
            case nameof(ISshSession.RunHostScriptRawAsync):
                Commands.Add("SCRIPT");
                return Task.FromResult(new SshResult(0, "", ""));
            case nameof(ISshSession.RunHostScriptAsync):
                Commands.Add("SCRIPT");
                return Task.FromResult("Linux 6.8.0\n");
        }
        throw new NotSupportedException("Неожиданный вызов SSH: " + method.Name);
    }

    private static SshResult Ok(string stdout = "") => new(0, stdout, "");

    private SshResult Exec(string command)
    {
        if (command.StartsWith("sudo docker ps", StringComparison.Ordinal)) return Ok(string.Join('\n', Containers));
        if (command.StartsWith("sudo mkdir -p", StringComparison.Ordinal)) return Ok();
        if (command.StartsWith("sudo chmod ", StringComparison.Ordinal))
        {
            var parts = command.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            foreach (var path in parts[3..]) Modes[path] = parts[2];
            return Ok();
        }
        if (command.StartsWith("sudo rm -f ", StringComparison.Ordinal))
        {
            Files.Remove(command["sudo rm -f ".Length..].Trim());
            return Ok();
        }
        if (command.StartsWith("sudo rm -rf ", StringComparison.Ordinal))
        {
            var root = command["sudo rm -rf ".Length..].Trim();
            foreach (var key in Files.Keys.Where(k => k.StartsWith(root, StringComparison.Ordinal)).ToList()) Files.Remove(key);
            return Ok();
        }
        if (command.StartsWith("sudo cp -f ", StringComparison.Ordinal))
        {
            var parts = command.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (!Files.TryGetValue(parts[3], out var copied)) return new SshResult(1, "", "cp: cannot stat");
            Files[parts[4]] = copied;
            return Ok();
        }
        if (command.StartsWith("sudo mv -f ", StringComparison.Ordinal))
        {
            var parts = command.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (!Files.Remove(parts[3], out var content)) return new SshResult(1, "", "mv: no such file");
            Files[parts[4]] = content;
            return Ok();
        }
        if (command == "sudo ufw status") return Ok(UfwActive ? "Status: active\n" : "Status: inactive\n");
        if (command.StartsWith("sudo ufw allow ", StringComparison.Ordinal)) return Ok();
        if (command.Contains("echo \"boot_seconds=", StringComparison.Ordinal))
            return Ok("boot_seconds=1000.5\ncpus=2\nload1=0.10\nmem_percent=20.0\ndisk_percent=30\ndocker=Docker version 26.1.0\nkernel=6.8.0\n");
        if (command.StartsWith("curl -s -o /dev/null --max-time 8 ", StringComparison.Ordinal))
        {
            // Проверка плеча вход → выход: домен выхода берётся из адреса в конце команды.
            var exitDomain = Regex.Match(command, @"https://(\S+)/$").Groups[1].Value;
            ExitProbed.Add(exitDomain);
            return ExitProbes.TryGetValue(exitDomain, out var answer) ? new SshResult(answer.Exit, answer.Out, "") : Ok("200");
        }
        if (command == "command -v curl") return CurlMissing ? new SshResult(1, "", "") : Ok("/usr/bin/curl\n");
        if (command.StartsWith("curl -fsSL ", StringComparison.Ordinal))
        {
            // Контрольная сумма релиза: тело ответа в stdout.
            var url = Regex.Match(command, @"'([^']+)'$").Groups[1].Value;
            Downloads.Add(url);
            return Internet.TryGetValue(url, out var body) ? Ok(body) : new SshResult(22, "", "curl: (22) The requested URL returned error: 404");
        }
        if (command.StartsWith("sudo curl -fsSL ", StringComparison.Ordinal))
        {
            var m = Regex.Match(command, @" -o (\S+) '([^']+)'$");
            Downloads.Add(m.Groups[2].Value);
            if (!Internet.TryGetValue(m.Groups[2].Value, out var body))
                return new SshResult(22, "", "curl: (22) The requested URL returned error: 404");
            Files[m.Groups[1].Value] = body;
            return Ok();
        }
        if (command.StartsWith("sudo sha256sum ", StringComparison.Ordinal))
        {
            var path = command["sudo sha256sum ".Length..].Trim();
            return Files.TryGetValue(path, out var data)
                ? Ok($"{Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(Encoding.UTF8.GetBytes(data)))}  {path}\n")
                : new SshResult(1, "", $"sha256sum: {path}: No such file or directory");
        }
        if (command.StartsWith("sudo docker inspect -f ", StringComparison.Ordinal))
        {
            if (!Containers.Contains(XCoreNode.XrayContainer)) return new SshResult(1, "", "Error: No such object: amnezia-xcore");
            var geo = !GeoNotMounted && XrayRunCommand is not null
                && XrayRunCommand.Contains($"-v {XCoreNode.GeoDir}:{XCoreNode.ContainerGeoDir}:ro", StringComparison.Ordinal);
            var env = !GeoNotMounted && XrayRunCommand is not null && XrayRunCommand.Contains(XCoreNode.GeoEnvArg, StringComparison.Ordinal);
            return Ok($"{XCoreNode.ConfDir}={XCoreNode.ContainerConfDir} {XCoreNode.OpsDir}={XCoreNode.ContainerOpsDir} " +
                      (geo ? $"{XCoreNode.GeoDir}={XCoreNode.ContainerGeoDir} " : "") +
                      "|PATH=/usr/local/sbin:/usr/local/bin " + (env ? $"{XCoreNode.AssetEnv}={XCoreNode.ContainerGeoDir} " : "") + "\n");
        }
        if (command.StartsWith("curl ", StringComparison.Ordinal))
        {
            CurlCalls++;
            var served = CertificateNever ? "000" : ServedCode(command);
            return served == "000" ? new SshResult(60, "000", "curl: (60) SSL certificate problem") : Ok(served);
        }
        if (command.StartsWith("sudo docker run --rm -v /opt/amnezia-xcore/caddy/Caddyfile.new:/etc/caddy/Caddyfile:ro ", StringComparison.Ordinal))
        {
            CaddyValidations++;
            if (!Files.ContainsKey(XCoreNode.NewCaddyfilePath)) return new SshResult(1, "", "Error: reading config from file: open /etc/caddy/Caddyfile: no such file");
            return CaddyValidateFails
                ? new SshResult(1, "", "Error: adapting config using caddyfile: parsing caddyfile tokens for 'tls': wrong argument count")
                : new SshResult(0, "", "valid configuration\n");
        }
        if (command == "sudo docker restart amnezia-xcore-web")
        {
            WebRestarts++;
            LoadedCaddyfile = Files.GetValueOrDefault(XCoreNode.CaddyfilePath, "");
            return Ok(XCoreNode.WebContainer);
        }
        if (command.EndsWith(" vlessenc", StringComparison.Ordinal)) return Ok(VlessEncOutput);
        if (command.Contains(" x25519", StringComparison.Ordinal))
            return Ok($"PrivateKey: {PrivateKey}\nPassword (PublicKey): {PublicKey}\nHash32: y_iNQ3haw4Fzn6WETRTggcYN6eUvB4nLPii1HJe2u0c\n");
        if (command.Contains(" run -test -c ", StringComparison.Ordinal)) return TestConfig(command);
        if (command.StartsWith("sudo docker run -d --name amnezia-xcore-web ", StringComparison.Ordinal))
        {
            Containers.Add(XCoreNode.WebContainer);
            LoadedCaddyfile = Files.GetValueOrDefault(XCoreNode.CaddyfilePath, "");
            return Ok("0123456789abcdef");
        }
        if (command.StartsWith("sudo docker run -d --name amnezia-xcore ", StringComparison.Ordinal))
        {
            XrayRunCommand = command;
            Containers.Add(XCoreNode.XrayContainer);
            Live = ConfigUsers();
            return Ok("fedcba9876543210");
        }
        if (command == "sudo docker restart amnezia-xcore")
        {
            if (RestartRevivesApi) ApiDown = false;
            Live = ConfigUsers();
            if (RestartLosesUsers && Live.Count > 0) Live = Live[1..];
            return Ok(XCoreNode.XrayContainer);
        }
        if (command.StartsWith("sudo docker rm -f amnezia-xcore", StringComparison.Ordinal))
        {
            var missing = !Containers.Contains(XCoreNode.XrayContainer) || !Containers.Contains(XCoreNode.WebContainer);
            Containers.Remove(XCoreNode.XrayContainer);
            Containers.Remove(XCoreNode.WebContainer);
            return missing ? new SshResult(1, "", "Error response from daemon: No such container") : Ok();
        }
        if (command == XCoreNode.VersionCommand)
            return Ok("Xray 26.10.21 (Xray, Penetrates Everything.) Custom (go1.27.3 linux/amd64)\nA unified platform for anti-censorship.\n");
        if (command.StartsWith("sudo ss -H ", StringComparison.Ordinal))
        {
            var port = Regex.Match(command, @"sport = :(\d+)").Groups[1].Value;
            return Ok(BusyPorts.Contains(port) ? $"LISTEN 0 511 0.0.0.0:{port} 0.0.0.0:*\n" : "");
        }
        if (command.StartsWith("sudo docker exec amnezia-xcore xray api ", StringComparison.Ordinal)) return Api(command);
        if (command is "uname -a" or "uname -sr" or "sudo docker info >/dev/null 2>&1") return Ok("Linux 6.8.0\n");
        if (command.StartsWith("ssh-keyscan", StringComparison.Ordinal)) return Ok("SHA256:fingerprint\n");

        throw new NotSupportedException("Неожиданная команда на узле: " + command);
    }

    /// <summary>
    /// Код ответа корня сайта, как его отдал бы Caddy по загруженному Caddyfile: сайт домена с заглушкой — 200,
    /// сайт с `respond 404` — 404, сайта нет — Caddy отвечает сертификатом другого домена, и curl падает с 60.
    /// </summary>
    private string ServedCode(string command)
    {
        var domain = Regex.Match(command, @"--resolve (\S+?):8443:").Groups[1].Value;
        var header = $"https://{domain}:8443 {{";
        var start = LoadedCaddyfile.IndexOf(header, StringComparison.Ordinal);
        if (start < 0) return "000";
        var end = LoadedCaddyfile.IndexOf("\n}\n", start, StringComparison.Ordinal);
        var site = LoadedCaddyfile[start..(end < 0 ? LoadedCaddyfile.Length : end)];
        return site.Contains("respond 404", StringComparison.Ordinal) ? "404" : "200";
    }

    private SshResult TestConfig(string command)
    {
        var file = Regex.Match(command, @"-c /etc/xcore/(\S+)$").Groups[1].Value;
        var geoDir = Regex.Match(command, @"-v (\S+):/etc/xcore-geo:ro").Groups[1].Value;
        ConfigTests.Add((file, geoDir));
        if (!Files.TryGetValue(XCoreNode.ConfDir + "/" + file, out var content))
            return new SshResult(23, "", $"Failed to start: main: failed to load config files: [/etc/xcore/{file}] > open: no such file or directory");
        if (TestFails || (FutureConfigTestFails && file == "config.geo-test.json"))
            return new SshResult(23, "", "Failed to start: main: failed to load config files: [/etc/xcore/" + file + "] > infra/conf: bad");
        try { JsonNode.Parse(content); }
        catch (Exception) { return new SshResult(23, "", "Failed to start: not json"); }

        // ext:-списки Xray ищет в каталоге XRAY_LOCATION_ASSET: нет подключения или файла — отказ, как у настоящего.
        foreach (var rf in new[] { XCoreRfLists.GeositeFile, XCoreRfLists.GeoipFile })
        {
            if (!content.Contains("ext:" + rf, StringComparison.Ordinal)) continue;
            if (geoDir == "" || !command.Contains(XCoreNode.GeoEnvArg, StringComparison.Ordinal) || !Files.ContainsKey($"{geoDir}/{rf}"))
                return new SshResult(23, "", $"Failed to start: main: failed to load config files: [/etc/xcore/{file}] > common/geodata: failed to open {rf} > no such file or directory");
            if (RfListsLackTags && geoDir == XCoreNode.GeoStageDir)
                return new SshResult(23, "", $"Failed to start: main: failed to load config files: [/etc/xcore/{file}] > common/geodata: failed to check code RU-BLOCKED from {rf} > EOF");
        }
        return Ok("Xray 26.10.21 (Xray, Penetrates Everything.) Custom (go1.27.3 linux/amd64)\nA unified platform for anti-censorship.\nConfiguration OK.\n");
    }

    private List<XCoreUser> ConfigUsers()
    {
        var config = JsonNode.Parse(Files[XCoreNode.ConfigPath])!;
        return [.. config["inbounds"]![0]!["settings"]!["clients"]!.AsArray()
            .Select(c => new XCoreUser(c!["email"]!.GetValue<string>(), c["id"]!.GetValue<string>()))];
    }

    private SshResult Api(string command)
    {
        if (ApiDown) return new SshResult(1, "", "failed to dial 127.0.0.1:10085");
        var sub = Regex.Match(command, @"xray api (\w+) ").Groups[1].Value;
        switch (sub)
        {
            case "inboundusercount":
                return Ok(Live.Count == 0 ? "{}\n\n" : $"{{\n    \"count\": {Live.Count}\n}}\n\n");
            case "inbounduser":
                if (Live.Count == 0) return Ok("{}\n\n");
                var users = string.Join(",\n", Live.Select(u =>
                    $"        {{\n            \"account\": {{\n                \"_TypedMessage_\": \"xray.proxy.vless.Account\",\n" +
                    $"                \"id\": \"{u.Uuid}\"\n            }},\n            \"email\": \"{u.Email}\"\n        }}"));
                return Ok($"{{\n    \"users\": [\n{users}\n    ]\n}}\n\n");
            case "adu":
                return Adu(command);
            case "rmu":
                return Rmu(command);
            case "statsquery":
                return StatsQuery(command);
        }
        throw new NotSupportedException("Неожиданная подкоманда xray api: " + sub);
    }

    private SshResult StatsQuery(string command)
    {
        // Сброс счётчиков при чтении потерял бы трафик при сбое записи: команда не должна его просить.
        if (command.Contains("-reset", StringComparison.Ordinal))
            throw new NotSupportedException("statsquery с -reset: поллер обязан читать счётчики без сброса.");

        var prefix = Regex.Match(command, "-pattern '([^']*)'").Groups[1].Value;
        var entries = new List<string>();
        foreach (var (email, counters) in Stats)
        {
            foreach (var (direction, value) in new[] { ("uplink", counters.Uplink), ("downlink", counters.Downlink) })
            {
                var name = $"user>>>{email}>>>traffic>>>{direction}";
                if (!name.StartsWith(prefix, StringComparison.Ordinal)) continue;
                entries.Add(value == 0
                    ? $"        {{\n            \"name\": \"{name}\"\n        }}"
                    : $"        {{\n            \"name\": \"{name}\",\n            \"value\": {value}\n        }}");
            }
        }

        return Ok(entries.Count == 0
            ? "{}\n\n"
            : $"{{\n    \"stat\": [\n{string.Join(",\n", entries)}\n    ]\n}}\n\n");
    }

    private SshResult Adu(string command)
    {
        if (AduThrows) throw new InvalidOperationException("обрыв соединения");
        var file = Regex.Match(command, @"(/etc/xcore-ops/\S+)$").Groups[1].Value;
        if (!Files.TryGetValue(XCoreNode.OpsDir + file["/etc/xcore-ops".Length..], out var content))
            return new SshResult(1, $"failed to load {file}: open {file}: no such file or directory\n", "");
        if (AduReportsError)
            return Ok("processing inbound: vless-xhttp\nrpc error: code = Unknown desc = proxy/vless: boom\nAdded 0 user(s) in total.\n");

        var lines = new StringBuilder("processing inbound: vless-xhttp\n");
        var added = 0;
        foreach (var c in JsonNode.Parse(content)!["inbounds"]![0]!["settings"]!["clients"]!.AsArray())
        {
            var email = c!["email"]!.GetValue<string>();
            lines.Append($"add user: {email}\n");
            if (Live.Any(u => u.Email == email))
                lines.Append($"rpc error: code = Unknown desc = proxy/vless: User {email} already exists.\n");
            else
            {
                Live.Add(new XCoreUser(email, c["id"]!.GetValue<string>()));
                lines.Append("result: ok\n");
                added++;
            }
        }
        lines.Append($"Added {added} user(s) in total.\n");
        return Ok(lines.ToString());
    }

    private SshResult Rmu(string command)
    {
        var emails = Regex.Matches(command[(command.IndexOf("-tag=vless-xhttp", StringComparison.Ordinal) + 16)..], "'([^']*)'")
            .Select(m => m.Groups[1].Value).ToList();
        var lines = new StringBuilder();
        var removed = 0;
        foreach (var email in emails)
        {
            lines.Append($"remove user: {email}\n");
            if (Live.RemoveAll(u => u.Email == email) > 0) removed++;
            else lines.Append($"rpc error: code = Unknown desc = proxy/vless: User {email} not found.\n");
        }
        lines.Append($"Removed {removed} user(s) in total.\n");
        return Ok(lines.ToString());
    }
}

sealed class FakeDns(Dictionary<string, string[]> records) : IDnsResolver
{
    public List<string> Queries { get; } = [];

    public Task<IReadOnlyList<IPAddress>> ResolveIPv4Async(string host, CancellationToken ct = default)
    {
        Queries.Add(host);
        IReadOnlyList<IPAddress> result = records.TryGetValue(host, out var ips) ? [.. ips.Select(IPAddress.Parse)] : [];
        return Task.FromResult(result);
    }
}

sealed class RecordingProgress : IInstallProgress
{
    public List<string> Texts { get; } = [];
    public Task DetailAsync(string detail, CancellationToken ct = default) { Texts.Add(detail); return Task.CompletedTask; }
    public Task LogAsync(string text, string level = AuditLevels.Info, CancellationToken ct = default) { Texts.Add(text); return Task.CompletedTask; }
}

public class Stub : DispatchProxy
{
    private Func<MethodInfo, object?[], object?> handler = null!;

    public static T Create<T>(Func<MethodInfo, object?[], object?> handler) where T : class
    {
        var value = Create<T, Stub>();
        ((Stub)(object)value).handler = handler;
        return value;
    }

    protected override object? Invoke(MethodInfo? method, object?[]? args) => handler(method!, args ?? []);
}

/// <summary>Публикатор событий в памяти: запоминает xcore.sync, которые у него просили.</summary>
sealed class RecordingEvents
{
    public List<(string Type, object Payload, string? Partition, string? Actor)> Published { get; } = [];

    /// <summary>Публикация падает: так ведёт себя недоступная база.</summary>
    public bool Fail;

    public IDomainEventPublisher Publisher { get; }

    public RecordingEvents() => Publisher = Stub.Create<IDomainEventPublisher>(Handle);

    private object? Handle(MethodInfo method, object?[] args)
    {
        if (method.Name != nameof(IDomainEventPublisher.PublishIfNoPendingAsync))
            throw new NotSupportedException("Неожиданная публикация: " + method.Name);
        if (Fail) return Task.FromException<DomainEvent?>(new InvalidOperationException("база недоступна"));

        Published.Add(((string)args[0]!, args[1]!, (string?)args[2], (string?)args[4]));
        return Task.FromResult<DomainEvent?>(new DomainEvent { Type = (string)args[0]! });
    }
}

/// <summary>
/// XCoreSyncHandler на заглушках репозиториев и живом FakeNode. Записи в базу эмулируются на самом
/// объекте узла, как их выполнил бы Mongo, — иначе повторный запуск не видел бы прежних ревизий.
/// </summary>
sealed class SyncHarness
{
    public List<(string ServerId, string ProtocolId, string Revision, string Structure)> Applied { get; } = [];
    public List<(string ServerId, string ProtocolId, string Error)> Errors { get; } = [];

    /// <summary>Записи ревизии Caddyfile, которые обработчик сохранил в базу.</summary>
    public List<(string ServerId, string ProtocolId, string Revision)> CaddyApplied { get; } = [];
    public List<Subscription> Desired { get; } = [];
    public int Connections { get; private set; }
    public XCoreSyncHandler Handler { get; }

    /// <summary>Обработчик xcore.geo_update на тех же заглушках; тег релиза и сбои GitHub задаёт <see cref="Releases"/>.</summary>
    public XCoreGeoUpdateHandler GeoHandler { get; }

    public FakeReleases Releases { get; } = new();

    /// <summary>Неудачные выпуски сертификата, которые обработчик запомнил (ревизия и время), и записи о российских списках.</summary>
    public List<(string Revision, DateTime At)> CaddyFailures { get; } = [];

    public List<string> RfListsApplied { get; } = [];
    public List<string?> GeoErrors { get; } = [];

    /// <summary>Остальные узлы базы: GetAllAsync отдаёт их вместе с проверяемым.</summary>
    public List<VpnServer> Others { get; } = [];

    /// <summary>Назначения номера маршрута, которые обработчик записал в базу.</summary>
    public List<(string ServerId, string ProtocolId, int RouteId)> RouteAssignments { get; } = [];

    /// <summary>События xcore.sync, опубликованные обработчиком.</summary>
    public RecordingEvents Events { get; } = new();

    /// <summary>Условная запись номера проигрывает гонку: другой процесс назначил номер раньше.</summary>
    public bool LoseRouteRace { get; set; }

    /// <summary>
    /// Сколько следующих записей номера отклонит уникальный индекс: соперник успел занять тот же номер, и он
    /// появляется среди узлов базы, как после настоящей гонки.
    /// </summary>
    public int RouteConflicts { get; set; }

    public SyncHarness(
        FakeNode fake, VpnServer? server, XCoreSyncService sync, ISecretProtector secrets, XCoreOptions? xcoreOptions = null)
    {
        xcoreOptions ??= new XCoreOptions();
        var servers = Stub.Create<IVpnServerRepository>((method, args) =>
        {
            switch (method.Name)
            {
                case nameof(IVpnServerRepository.GetByIdAsync):
                    return Task.FromResult(server is not null && server.Id == (string)args[0]! ? server : null);
                case nameof(IVpnServerRepository.GetAllAsync):
                    return Task.FromResult(server is null ? Others.ToList() : [server, .. Others]);
                case nameof(IVpnServerRepository.SetXCoreRouteIdAsync):
                {
                    // Условная запись Mongo: номер ставится, только если его ещё нет.
                    var xcore = server!.FindProtocol((string)args[1]!)!.XCore!;
                    if (RouteConflicts > 0)
                    {
                        RouteConflicts--;
                        Others.Add(new VpnServer
                        {
                            Id = "rival-" + (int)args[2]!, Name = "rival", Host = "198.51.100.9",
                            Protocols =
                            [
                                new ProtocolInstance
                                {
                                    Id = "rival-p", Kind = ProtocolKinds.XCore, State = ProtocolStates.Installed,
                                    XCore = new XCoreProtocolParams { Role = XCoreRoles.Exit, Domain = "rival.example.com", RouteId = (int)args[2]! },
                                },
                            ],
                        });
                        return Task.FromException<bool>(new RouteIdTakenException());
                    }
                    if (xcore.RouteId is not null || LoseRouteRace) return Task.FromResult(false);
                    xcore.RouteId = (int)args[2]!;
                    RouteAssignments.Add(((string)args[0]!, (string)args[1]!, (int)args[2]!));
                    return Task.FromResult(true);
                }
                case nameof(IVpnServerRepository.MarkXCoreAppliedAsync):
                {
                    var xcore = server!.FindProtocol((string)args[1]!)!.XCore!;
                    Applied.Add(((string)args[0]!, (string)args[1]!, (string)args[2]!, (string)args[3]!));
                    xcore.AppliedRevision = (string)args[2]!;
                    xcore.AppliedStructureRevision = (string)args[3]!;
                    xcore.AppliedAt = (DateTime)args[4]!;
                    xcore.SyncError = null;
                    return Task.CompletedTask;
                }
                case nameof(IVpnServerRepository.MarkXCoreCaddyAppliedAsync):
                    CaddyApplied.Add(((string)args[0]!, (string)args[1]!, (string)args[2]!));
                    server!.FindProtocol((string)args[1]!)!.XCore!.AppliedCaddyRevision = (string)args[2]!;
                    server.FindProtocol((string)args[1]!)!.XCore!.CaddyFailedRevision = null;
                    server.FindProtocol((string)args[1]!)!.XCore!.CaddyFailedAt = null;
                    return Task.CompletedTask;
                case nameof(IVpnServerRepository.SetXCoreCaddyFailedAsync):
                {
                    var xcore = server!.FindProtocol((string)args[1]!)!.XCore!;
                    CaddyFailures.Add(((string)args[2]!, (DateTime)args[3]!));
                    xcore.CaddyFailedRevision = (string)args[2]!;
                    xcore.CaddyFailedAt = (DateTime)args[3]!;
                    return Task.CompletedTask;
                }
                case nameof(IVpnServerRepository.MarkXCoreRfListsAppliedAsync):
                {
                    var xcore = server!.FindProtocol((string)args[1]!)!.XCore!;
                    xcore.RfListsTag = (string)args[2]!;
                    xcore.RfListsAppliedAt = xcore.RfListsCheckedAt = (DateTime)args[3]!;
                    xcore.GeoError = null;
                    RfListsApplied.Add((string)args[2]!);
                    return Task.CompletedTask;
                }
                case nameof(IVpnServerRepository.SetXCoreRfListsCheckedAsync):
                    server!.FindProtocol((string)args[1]!)!.XCore!.RfListsCheckedAt = (DateTime)args[2]!;
                    return Task.CompletedTask;
                case nameof(IVpnServerRepository.SetXCoreGeoErrorAsync):
                    GeoErrors.Add((string?)args[2]);
                    server!.FindProtocol((string)args[1]!)!.XCore!.GeoError = (string?)args[2];
                    return Task.CompletedTask;
                case nameof(IVpnServerRepository.SetXCoreSyncErrorAsync):
                    Errors.Add(((string)args[0]!, (string)args[1]!, (string)args[2]!));
                    server!.FindProtocol((string)args[1]!)!.XCore!.SyncError = (string)args[2]!;
                    return Task.CompletedTask;
            }
            throw new NotSupportedException("Неожиданный вызов репозитория узлов: " + method.Name);
        });

        var subscriptions = Stub.Create<ISubscriptionRepository>((method, _) =>
            method.Name == nameof(ISubscriptionRepository.FindDesiredAsync)
                ? Task.FromResult(Desired.ToList())
                : throw new NotSupportedException("Неожиданный вызов репозитория подписок: " + method.Name));

        var factory = Stub.Create<ISshSessionFactory>((_, _) =>
        {
            Connections++;
            return Task.FromResult(fake.Session);
        });

        var publisher = new XCoreSyncPublisher(servers, Events.Publisher, NullLogger<XCoreSyncPublisher>.Instance);
        Handler = new XCoreSyncHandler(
            servers, subscriptions, factory, sync, secrets, publisher, NullLogger<XCoreSyncHandler>.Instance);
        GeoHandler = new XCoreGeoUpdateHandler(
            servers, factory, new XCoreGeoService(secrets, Options.Create(xcoreOptions)), Releases, publisher,
            Options.Create(xcoreOptions), NullLogger<XCoreGeoUpdateHandler>.Instance);
    }
}

/// <summary>Источник релизов без сети: отдаёт заданный тег или сбой.</summary>
sealed class FakeReleases : IXCoreReleaseSource
{
    public string Tag { get; set; } = "202610291019";
    public bool Fail { get; set; }
    public int Calls { get; private set; }

    public Task<string> GetLatestTagAsync(string repo, CancellationToken ct = default)
    {
        Calls++;
        return Fail ? Task.FromException<string>(new XCoreGeoException("GitHub недоступен.")) : Task.FromResult(Tag);
    }
}

/// <summary>
/// XCoreStatsPoller на заглушках: хранилище подписок эмулирует то, что делает ApplyUsageAsync в Mongo
/// (прибавляет приращения и заменяет сырые значения по узлу), чтобы несколько тиков подряд видели
/// результат друг друга.
/// </summary>
sealed class PollHarness
{
    public Dictionary<string, Subscription> Subscriptions { get; } = new(StringComparer.Ordinal);
    public List<SubscriptionUsageUpdate> Updates { get; } = [];
    public List<(string SubscriptionId, long Rx, long Tx)> Daily { get; } = [];
    public List<(string ServerId, long Rx, long Tx)> ServerDaily { get; } = [];
    public int ApplyCalls { get; private set; }

    /// <summary>Что вернёт фабрика сессий; подмена на бросающую имитирует недоступный узел.</summary>
    public Func<ISshSession> Connect { get; set; }

    private readonly XCoreStatsPoller _poller;
    private readonly ServiceProvider _provider;

    public PollHarness(FakeNode fake)
    {
        Connect = () => fake.Session;

        var subscriptions = Stub.Create<ISubscriptionRepository>((method, args) =>
        {
            switch (method.Name)
            {
                case nameof(ISubscriptionRepository.FindByIdsAsync):
                    var ids = ((IEnumerable<string>)args[0]!).ToHashSet();
                    return Task.FromResult(Subscriptions.Values.Where(s => ids.Contains(s.Id)).ToList());
                case nameof(ISubscriptionRepository.ApplyUsageAsync):
                    ApplyCalls++;
                    foreach (var u in (IReadOnlyCollection<SubscriptionUsageUpdate>)args[0]!)
                    {
                        Updates.Add(u);
                        var s = Subscriptions[u.SubscriptionId];
                        s.Usage.RxBytes += u.RxDelta;
                        s.Usage.TxBytes += u.TxDelta;
                        s.RawByNode[u.ServerId] = new SubscriptionNodeRaw { Rx = u.RxRaw, Tx = u.TxRaw };
                    }
                    return Task.CompletedTask;
            }
            throw new NotSupportedException("Неожиданный вызов репозитория подписок: " + method.Name);
        });

        var usage = Stub.Create<IUsageRepository>((method, args) =>
        {
            switch (method.Name)
            {
                case nameof(IUsageRepository.IncrementSubscriptionAsync):
                    Daily.Add(((string)args[0]!, (long)args[2]!, (long)args[3]!));
                    return Task.CompletedTask;
                case nameof(IUsageRepository.IncrementServerAsync):
                    ServerDaily.Add(((string)args[0]!, (long)args[2]!, (long)args[3]!));
                    return Task.CompletedTask;
            }
            throw new NotSupportedException("Неожиданный вызов репозитория трафика: " + method.Name);
        });

        var factory = Stub.Create<ISshSessionFactory>((_, _) => Task.FromResult(Connect()));

        _provider = new ServiceCollection()
            .AddSingleton(subscriptions)
            .AddSingleton(usage)
            .AddSingleton(factory)
            .BuildServiceProvider();

        _poller = new XCoreStatsPoller(
            _provider.GetRequiredService<IServiceScopeFactory>(),
            Options.Create(new PollingOptions()),
            NullLogger<XCoreStatsPoller>.Instance);
    }

    public Task PollAsync(VpnServer server) => _poller.PollAsync(_provider, server, default);
}
