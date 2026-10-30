using System.Diagnostics;
using System.Text.Json.Nodes;
using AmneziaKeyService.Core.Interfaces;
using AmneziaKeyService.Core.Models;
using AmneziaKeyService.Infrastructure.Protocols.XCore;

/// <summary>
/// Сквозная проверка VLESS Encryption на настоящем Xray: выход с шифрованием и выход без, три входа (открытый,
/// с шифрованием и «слепой», не знающий о шифровании выхода), клиент и цель — в изолированной сети Docker.
/// Конфиги узлов — вывод боевых рендереров, ключи — настоящий <c>xray vlessenc</c> образа через тот же
/// <see cref="XCoreVlessEncryption.GenerateAsync"/>, что вызывает панель; подменено только окружение (заглушка
/// сайта для Reality, как в RunEndToEnd).
///
/// Что доказывает: шифрованный выход принимает клиента и вход со строкой, отвергает клиента без неё, с чужой
/// строкой и вход со «слепым» outbound-ом; пользователь, добавленный через <c>xray api adu</c> с файлом, где
/// <c>decryption</c> = <c>none</c> (так синхронизация добавляет подписчиков), проходит в зашифрованный inbound.
///
/// Flow не используется. Опыт при выборе: те же сценарии с <c>flow: xtls-rprx-vision</c> у клиентов зашифрованных
/// звеньев (inbound-ы выхода и входа, их клиенты в файле adu, клиентские outbound-ы и outbound-ы входа к
/// зашифрованному выходу) проходят так же, как без него; на незашифрованном XHTTP vision не работает вовсе. Выигрыша
/// от vision на XHTTP нет (он убирает TLS в TLS на TCP), а цена — flow в каждом клиенте inbound-а, в файле adu и
/// в каждой ссылке; поэтому продукт его не выпускает.
/// </summary>
static class VlessEncryptionE2E
{
    private const string CurlImage = "curlimages/curl:8.11.1";

    public sealed record Outcome(string Name, bool Ok, string? Detail);

    public static async Task<List<Outcome>> RunAsync(
        string dir, string xrayImage, string privateKey, string publicKey, string subUuid, string subEmail,
        string relayUuid)
    {
        var results = new List<Outcome>();
        void Report(string name, bool ok, string? detail = null) => results.Add(new Outcome(name, ok, ok ? null : detail));
        static string Tail((int Code, string Out, string Err) r, int lines = 4) =>
            string.Join(" ", (r.Out + r.Err).Split('\n').TakeLast(lines)).Trim();

        var id = Guid.NewGuid().ToString("N")[..8];
        var net = "vx-enc-" + id;
        var containers = new List<string>();
        string Name(string role) { var n = $"vx-enc-{id}-{role}"; containers.Add(n); return n; }

        var configDir = Path.Combine(dir, "enc");
        Directory.CreateDirectory(configDir);
        var mount = $"{configDir}:/c:ro";

        try
        {
            // Ключи — настоящей командой через тот же код, что и панель; «SSH» здесь — локальный docker.
            var secrets = new PlainSecrets();
            var ssh = LocalSession.Create();
            var exitKeys = await XCoreVlessEncryption.GenerateAsync(ssh, xrayImage, secrets);
            var entryKeys = await XCoreVlessEncryption.GenerateAsync(ssh, xrayImage, secrets);
            var strangerKeys = await XCoreVlessEncryption.GenerateAsync(ssh, xrayImage, secrets);
            var exitDecryption = secrets.Unprotect(exitKeys.Decryption)!;
            var entryDecryption = secrets.Unprotect(entryKeys.Decryption)!;
            Report("e2e/enc: xray vlessenc образа разобран, пары различаются",
                exitKeys.Client != entryKeys.Client && exitKeys.Client != strangerKeys.Client && exitDecryption != entryDecryption);

            var subnet = "";
            for (var i = 0; i < 20 && subnet.Length == 0; i++)
            {
                var candidate = $"21.{(Convert.ToInt32(id[..2], 16) + 100 + i * 7) % 256}.0.0/24";
                if (Docker("network", "create", "--subnet", candidate, net).Code == 0) subnet = candidate;
            }
            if (subnet.Length == 0) { Report("e2e/enc: создана сеть Docker с публичными адресами", false, "нет свободной подсети"); return results; }

            // Заглушка сайта для Reality и цель — те же, что в RunEndToEnd.
            var cert = JsonNode.Parse(Docker("run", "--rm", xrayImage, "tls", "cert", "-domain=e2e.test", "-expire=2h").Out)!.AsObject();
            File.WriteAllText(Path.Combine(configDir, "dest.json"), new JsonObject
            {
                ["log"] = new JsonObject { ["loglevel"] = "warning" },
                ["inbounds"] = new JsonArray(new JsonObject
                {
                    ["listen"] = "127.0.0.1", ["port"] = 8443, ["protocol"] = "socks",
                    ["settings"] = new JsonObject { ["auth"] = "noauth" },
                    ["streamSettings"] = new JsonObject
                    {
                        ["network"] = "tcp", ["security"] = "tls",
                        ["tlsSettings"] = new JsonObject
                        {
                            ["alpn"] = new JsonArray("h2", "http/1.1"),
                            ["certificates"] = new JsonArray(new JsonObject
                            {
                                ["certificate"] = cert["certificate"]!.DeepClone(), ["key"] = cert["key"]!.DeepClone(),
                            }),
                        },
                    },
                }),
                ["outbounds"] = new JsonArray(new JsonObject { ["protocol"] = "blackhole" }),
            }.ToJsonString());
            File.WriteAllText(Path.Combine(configDir, "target.json"), new JsonObject
            {
                ["log"] = new JsonObject { ["loglevel"] = "warning" },
                ["inbounds"] = new JsonArray(new JsonObject
                {
                    ["listen"] = "0.0.0.0", ["port"] = 8080, ["protocol"] = "dokodemo-door",
                    ["settings"] = new JsonObject { ["address"] = "127.0.0.1", ["port"] = 9, ["network"] = "tcp" },
                }),
                ["outbounds"] = new JsonArray(new JsonObject
                {
                    ["protocol"] = "blackhole",
                    ["settings"] = new JsonObject { ["response"] = new JsonObject { ["type"] = "http" } },
                }),
            }.ToJsonString());

            XCoreProtocolParams NodeOf(string role, string domain, string shortId, string path, bool encrypted) => new()
            {
                Role = role, Domain = domain, ImageRef = xrayImage, RealityPublicKey = publicKey, ShortIds = [shortId], XhttpPath = path,
                VlessEncryption = encrypted,
            };

            var exitE = NodeOf(XCoreRoles.Exit, "exite.test", "1111111111111111", "/exitepath", true);
            exitE.VlessDecryption = exitKeys.Decryption;
            exitE.VlessEncryptionClient = exitKeys.Client;
            var exitP = NodeOf(XCoreRoles.Exit, "exitp.test", "2222222222222222", "/exitppath", false);
            XCoreUser[] relay = [new("relay-e2e", relayUuid)];

            // Шифрованный выход стартует без подписчика: подписчика добавит adu ниже.
            File.WriteAllText(Path.Combine(configDir, "exite.json"),
                XCoreConfigRenderer.Render(exitE, privateKey, relay, exitDecryption).Json);
            File.WriteAllText(Path.Combine(configDir, "exitp.json"),
                XCoreConfigRenderer.Render(exitP, privateKey, relay).Json);

            XCoreExitTarget[] targets =
            [
                new(1, "exite.test", 443, publicKey, "1111111111111111", "/exitepath", "firefox", exitKeys.Client),
                new(2, "exitp.test", 443, publicKey, "2222222222222222", "/exitppath", "firefox"),
            ];
            // Вход, не знающий о шифровании выхода 1: так выглядел бы вход со старой топологией.
            XCoreExitTarget[] blindTargets = [targets[0] with { Encryption = null }, targets[1]];
            XCoreUser[] subscriber = [new(subEmail, subUuid)];

            var entry = NodeOf(XCoreRoles.Entry, "entry.test", "e0e0e0e0e0e0e0e0", "/entrypath", false);
            var entryX = NodeOf(XCoreRoles.Entry, "entryx.test", "e1e1e1e1e1e1e1e1", "/entryxpath", true);
            entryX.VlessDecryption = entryKeys.Decryption;
            entryX.VlessEncryptionClient = entryKeys.Client;
            var entryBlind = NodeOf(XCoreRoles.Entry, "entryb.test", "e2e2e2e2e2e2e2e2", "/entrybpath", false);
            File.WriteAllText(Path.Combine(configDir, "entry.json"),
                XCoreConfigRenderer.RenderEntry(entry, privateKey, subscriber, relayUuid, targets).Json);
            File.WriteAllText(Path.Combine(configDir, "entryx.json"),
                XCoreConfigRenderer.RenderEntry(entryX, privateKey, subscriber, relayUuid, targets, entryDecryption).Json);
            File.WriteAllText(Path.Combine(configDir, "entryb.json"),
                XCoreConfigRenderer.RenderEntry(entryBlind, privateKey, subscriber, relayUuid, blindTargets).Json);

            // Файл для adu — ровно тот, что строит синхронизация (decryption в нём none).
            File.WriteAllText(Path.Combine(configDir, "adu-e.json"), XCoreConfigRenderer.RenderUsersFile(exitE, subscriber));

            // Клиент: по одному socks-входу на вариант.
            (string Tag, int Port, string Host, string ShortId, string Path, string Uuid, string Encryption)[] variants =
            [
                ("e-enc", 1081, "exite.test", "1111111111111111", "/exitepath", subUuid, exitKeys.Client!),
                ("e-none", 1082, "exite.test", "1111111111111111", "/exitepath", subUuid, "none"),
                ("e-stranger", 1083, "exite.test", "1111111111111111", "/exitepath", subUuid, strangerKeys.Client!),
                ("entry-r1", 1084, "entry.test", "e0e0e0e0e0e0e0e0", "/entrypath", XCoreRoute.WithRoute(subUuid, 1), "none"),
                ("entry-r2", 1085, "entry.test", "e0e0e0e0e0e0e0e0", "/entrypath", XCoreRoute.WithRoute(subUuid, 2), "none"),
                ("entryx-r1", 1086, "entryx.test", "e1e1e1e1e1e1e1e1", "/entryxpath", XCoreRoute.WithRoute(subUuid, 1), entryKeys.Client!),
                ("entryx-none", 1087, "entryx.test", "e1e1e1e1e1e1e1e1", "/entryxpath", XCoreRoute.WithRoute(subUuid, 1), "none"),
                ("entryb-r1", 1088, "entryb.test", "e2e2e2e2e2e2e2e2", "/entrybpath", XCoreRoute.WithRoute(subUuid, 1), "none"),
                ("entryb-r2", 1089, "entryb.test", "e2e2e2e2e2e2e2e2", "/entrybpath", XCoreRoute.WithRoute(subUuid, 2), "none"),
            ];
            var client = new JsonObject
            {
                ["log"] = new JsonObject { ["loglevel"] = "warning" },
                ["inbounds"] = new JsonArray([.. variants.Select(v => (JsonNode)new JsonObject
                {
                    ["tag"] = "in-" + v.Tag, ["listen"] = "0.0.0.0", ["port"] = v.Port, ["protocol"] = "socks",
                    ["settings"] = new JsonObject { ["auth"] = "noauth", ["udp"] = false },
                })]),
                ["outbounds"] = new JsonArray([.. variants.Select(v => (JsonNode)new JsonObject
                {
                    ["tag"] = "out-" + v.Tag, ["protocol"] = "vless",
                    ["settings"] = new JsonObject
                    {
                        ["vnext"] = new JsonArray(new JsonObject
                        {
                            ["address"] = v.Host, ["port"] = 443,
                            ["users"] = new JsonArray(new JsonObject { ["id"] = v.Uuid, ["encryption"] = v.Encryption }),
                        }),
                    },
                    ["streamSettings"] = new JsonObject
                    {
                        ["network"] = "xhttp", ["security"] = "reality",
                        ["realitySettings"] = new JsonObject
                        {
                            ["serverName"] = v.Host, ["publicKey"] = publicKey, ["shortId"] = v.ShortId,
                            ["fingerprint"] = "firefox", ["spiderX"] = "",
                        },
                        ["xhttpSettings"] = new JsonObject { ["path"] = v.Path, ["mode"] = "auto" },
                    },
                })]),
                ["routing"] = new JsonObject
                {
                    ["rules"] = new JsonArray([.. variants.Select(v => (JsonNode)new JsonObject
                    {
                        ["type"] = "field", ["inboundTag"] = new JsonArray("in-" + v.Tag), ["outboundTag"] = "out-" + v.Tag,
                    })]),
                },
            };
            File.WriteAllText(Path.Combine(configDir, "client.json"), client.ToJsonString());

            string Start(string role, string alias, string config)
            {
                var name = Name(role);
                var started = Docker("run", "-d", "--name", name, "--network", net, "--network-alias", alias,
                    "--user", "0:0", "-v", mount, xrayImage, "run", "-c", $"/c/{config}");
                if (started.Code != 0) Report($"e2e/enc: контейнер {role} запущен", false, started.Err);
                return name;
            }
            void StartDest(string node)
            {
                var started = Docker("run", "-d", "--name", Name("dest-" + node.Split('-')[^1]), "--network", "container:" + node,
                    "--user", "0:0", "-v", mount, xrayImage, "run", "-c", "/c/dest.json");
                if (started.Code != 0) Report($"e2e/enc: заглушка сайта для {node} запущена", false, started.Err);
            }

            var exitEName = Start("exite", "exite.test", "exite.json");
            var exitPName = Start("exitp", "exitp.test", "exitp.json");
            var entryName = Start("entry", "entry.test", "entry.json");
            var entryXName = Start("entryx", "entryx.test", "entryx.json");
            var entryBName = Start("entryb", "entryb.test", "entryb.json");
            var nodes = new[] { exitEName, exitPName, entryName, entryXName, entryBName };
            foreach (var n in nodes) StartDest(n);
            Start("target", "target.test", "target.json");
            var clientName = Start("client", "client.test", "client.json");

            bool Ready(string container)
            {
                for (var i = 0; i < 30; i++)
                {
                    if (Docker("exec", container, "xray", "api", "inboundusercount", "--server=127.0.0.1:10085",
                            $"-tag={XCoreConfigRenderer.InboundTag}").Code == 0) return true;
                    Thread.Sleep(500);
                }
                return false;
            }
            var ready = nodes.All(Ready);
            Report("e2e/enc: пять узлов подняты с боевыми конфигами (выход и вход с decryption, выход и вход без)", ready,
                string.Join(" | ", nodes.Select(c => c[^6..] + ": " + Tail(Docker("logs", c)))));
            if (!ready) return results;
            Thread.Sleep(1500);

            // Подписчик на шифрованный выход — через adu, как делает синхронизация.
            var adu = Docker("exec", exitEName, "xray", "api", "adu", "--server=127.0.0.1:10085", "/c/adu-e.json");
            var added = XrayApiOutput.ParseAddUsers(adu.Out);
            Report("e2e/enc: adu добавил подписчика в inbound с decryption (файл с decryption=none)",
                added is { Added: 1, IsSuccess: true }, Tail(adu));

            long Counter(string container, string prefix)
            {
                var q = Docker("exec", container, "xray", "api", "statsquery", "--server=127.0.0.1:10085", "-pattern", $"user>>>{prefix}");
                return q.Code != 0 ? -1 : XrayApiOutput.ParseUserTraffic(q.Out).Values.Sum(t => t.Uplink + t.Downlink);
            }

            string Fetch(int port, int attempts = 1)
            {
                var status = "000";
                for (var i = 0; i < attempts && status == "000"; i++)
                {
                    var r = Docker("run", "--rm", "--network", net, CurlImage, "-s", "-o", "/dev/null", "-w", "%{http_code}",
                        "--max-time", "30", "--socks5-hostname", $"{clientName}:{port}", "http://target.test:8080/");
                    status = r.Out.Trim().Length == 0 ? "000" : r.Out.Trim();
                }
                return status;
            }

            void Scenario(string title, string tag, string expected, bool? exitEGrows, bool? exitPGrows, int attempts = 1)
            {
                var port = variants.First(v => v.Tag == tag).Port;
                var before = (E: Counter(exitEName, "relay-"), P: Counter(exitPName, "relay-"));
                var status = Fetch(port, attempts);
                var after = (E: Counter(exitEName, "relay-"), P: Counter(exitPName, "relay-"));
                Report($"e2e/enc: {title} — ответ {expected}", status == expected,
                    $"получено {status}; клиент: {Tail(Docker("logs", clientName), 6)}; выход: {Tail(Docker("logs", exitEName), 4)}");
                if (exitEGrows is { } e)
                    Report($"e2e/enc: {title} — служебный трафик шифрованного выхода {(e ? "вырос" : "не изменился")}",
                        (after.E > before.E) == e, $"{before.E} → {after.E}");
                if (exitPGrows is { } p)
                    Report($"e2e/enc: {title} — служебный трафик открытого выхода {(p ? "вырос" : "не изменился")}",
                        (after.P > before.P) == p, $"{before.P} → {after.P}");
            }

            Scenario("клиент напрямую в шифрованный выход со строкой", "e-enc", "403", null, null, attempts: 3);
            Scenario("клиент напрямую в шифрованный выход без encryption отклонён", "e-none", "000", null, null);
            Scenario("клиент со строкой от чужого ключа отклонён", "e-stranger", "000", null, null);
            Scenario("клиент → открытый вход → шифрованный выход (маршрут 1)", "entry-r1", "403", true, false, attempts: 3);
            Scenario("клиент → открытый вход → открытый выход (маршрут 2): none к обычному", "entry-r2", "403", false, true);
            Scenario("клиент со строкой → шифрованный вход → шифрованный выход", "entryx-r1", "403", true, false, attempts: 3);
            Scenario("клиент без encryption к шифрованному входу отклонён", "entryx-none", "000", false, false);
            Scenario("вход, не знающий о шифровании выхода, до цели не доходит (выход отклоняет его)", "entryb-r1", "000", false, false);
            Scenario("тот же «слепой» вход к открытому выходу работает", "entryb-r2", "403", false, true);
        }
        finally
        {
            if (containers.Count > 0) Docker(["rm", "-f", .. containers]);
            Docker("network", "rm", net);
        }

        return results;
    }

    private static (int Code, string Out, string Err) Docker(params string[] args)
    {
        var psi = new ProcessStartInfo("docker")
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };
        foreach (var a in args) psi.ArgumentList.Add(a);
        using var process = Process.Start(psi)!;
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        process.WaitForExit();
        return (process.ExitCode, stdout.Result, stderr.Result);
    }

    /// <summary>Шифрование «на месте»: проверке нужна лишь обратимость и узнаваемость значения.</summary>
    private sealed class PlainSecrets : ISecretProtector
    {
        public EncryptedValue? Protect(string? plainText) =>
            string.IsNullOrEmpty(plainText) ? null : new EncryptedValue { KeyId = "test", Nonce = "", CipherText = plainText };

        public string? Unprotect(EncryptedValue? value) => value?.CipherText;

        public bool NeedsRotation(EncryptedValue? value) => false;
    }

    /// <summary>
    /// Сессия, которая выполняет команды продукта локальным docker: «sudo docker …» превращается в «docker …».
    /// Реализован только RunCheckedAsync — единственное, что нужно генерации ключей.
    /// </summary>
    private static class LocalSession
    {
        public static ISshSession Create() => Stub.Create<ISshSession>((method, args) =>
        {
            if (method.Name != nameof(ISshSession.RunCheckedAsync))
                throw new NotSupportedException(method.Name);

            var command = ((string)args[0]!).Replace("sudo docker", "docker");
            var parts = command.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            var result = Docker(parts[1..]);
            return result.Code == 0
                ? Task.FromResult(result.Out)
                : Task.FromException<string>(new InvalidOperationException($"docker завершился с кодом {result.Code}"));
        });
    }
}
