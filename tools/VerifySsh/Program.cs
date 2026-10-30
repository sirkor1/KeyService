// Проверка SSH-слоя на настоящем sshd в Docker: пароль, ключ (с парольной фразой и без),
// RunAsync, загрузка файла через SFTP и сверка отпечатка хоста тем же способом, что и установка.
// Нужна при смене версии SSH.NET: остальные Verify* работают на заглушках ISshSession и
// сломанный транспорт не заметят. Требует Docker и сеть (apk внутри контейнера).
using System.Diagnostics;
using System.Security.Cryptography;
using AmneziaKeyService.Core.Exceptions;
using AmneziaKeyService.Core.Models;
using AmneziaKeyService.Infrastructure.Services;
using AmneziaKeyService.Infrastructure.Ssh;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

const string Container = "verify-ssh-sshd";
const string User = "vsk";
const int HostPort = 22022;

var password = Convert.ToHexString(RandomNumberGenerator.GetBytes(12));
var failures = 0;
var total = 0;

void Check(string name, bool ok, string? detail = null)
{
    total++;
    if (!ok) failures++;
    Console.WriteLine($"{(ok ? "ok  " : "FAIL")} {name}{(!ok && detail is not null ? " — " + detail : "")}");
}

static (int Exit, string Out) Docker(params string[] args)
{
    var psi = new ProcessStartInfo("docker") { RedirectStandardOutput = true, RedirectStandardError = true };
    foreach (var a in args) psi.ArgumentList.Add(a);
    using var p = Process.Start(psi)!;
    var o = p.StandardOutput.ReadToEndAsync();
    var e = p.StandardError.ReadToEndAsync();
    p.WaitForExit();
    return (p.ExitCode, o.Result + e.Result);
}

Docker("rm", "-f", Container);

try
{
    // Пароль только через переменную окружения контейнера, в аргументы команды он не попадает.
    var run = Docker("run", "-d", "--name", Container, "-p", $"127.0.0.1:{HostPort}:22",
        "-e", $"SSH_USER={User}", "-e", $"SSH_PASSWORD={password}", "alpine:3.20", "sh", "-c",
        "apk add --no-cache openssh openssh-client sudo bash coreutils shadow >/dev/null " +
        "&& adduser -D -s /bin/bash $SSH_USER && echo \"$SSH_USER:$SSH_PASSWORD\" | chpasswd " +
        "&& echo \"$SSH_USER ALL=(ALL) NOPASSWD:ALL\" > /etc/sudoers.d/vsk " +
        "&& ssh-keygen -A && mkdir -p /run/sshd " +
        "&& sed -i 's/^#\\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config " +
        "&& exec /usr/sbin/sshd -D -e");
    if (run.Exit != 0) { Console.WriteLine("Не удалось запустить контейнер: " + run.Out); return 2; }

    var ready = false;
    for (var i = 0; i < 120 && !ready; i++)
    {
        await Task.Delay(1000);
        ready = Docker("exec", Container, "sh", "-c", "pgrep sshd >/dev/null && echo up").Out.Contains("up");
    }
    if (!ready) { Console.WriteLine("sshd не поднялся за 120 с:\n" + Docker("logs", Container).Out); return 2; }

    var secrets = new AesGcmSecretProtector(Options.Create(new SecurityOptions
    {
        DataProtectionKey = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)),
    }));
    var factory = new SshSessionFactory(secrets, NullLoggerFactory.Instance, NullLogger<SshSessionFactory>.Instance);

    VpnServer Server(string pwd = "", EncryptedValue? key = null, EncryptedValue? phrase = null) => new()
    {
        Host = "127.0.0.1",
        Ssh = new SshCredentials
        {
            Port = HostPort, User = User,
            Password = key is null ? secrets.Protect(pwd) : null,
            PrivateKey = key, KeyPassphrase = phrase,
        },
    };

    // 1. Пароль, команды, SFTP
    await using (var ssh = await factory.ConnectAsync(Server(password)))
    {
        var echo = await ssh.RunAsync("echo привет; id -un");
        Check("пароль: RunAsync вернул stdout и код 0",
            echo.Ok && echo.StdOut.Contains("привет") && echo.StdOut.Contains(User), echo.StdOut);

        var fail = await ssh.RunAsync("echo err >&2; exit 7");
        Check("пароль: код возврата 7 и stderr сохраняются",
            fail.ExitStatus == 7 && fail.StdErr.Trim() == "err", $"{fail.ExitStatus} '{fail.StdErr}'");

        var content = "{\n  \"строка\": \"значение\"\n}\n";
        await ssh.WriteHostFileAsync("/opt/vsk-test/dir/файл.json", content);
        var back = Docker("exec", Container, "cat", "/opt/vsk-test/dir/файл.json").Out;
        Check("SFTP: WriteHostFileAsync записал файл на хост побайтово", back == content, back);

        var leftovers = await ssh.RunAsync("ls /tmp | grep -c '^amnezia-' || true");
        Check("SFTP: временные файлы убраны", leftovers.StdOut.Trim() == "0", leftovers.StdOut);

        await ssh.WriteHostFileAsync("/opt/vsk-test/dir/файл.json", "второй\n");
        var rewritten = Docker("exec", Container, "cat", "/opt/vsk-test/dir/файл.json").Out;
        Check("SFTP: повторная запись перезаписывает файл", rewritten == "второй\n", rewritten);

        var script = await ssh.RunHostScriptAsync("echo из-скрипта; id -u", "verify");
        Check("RunHostScriptAsync выполняет скрипт от root",
            script.Contains("из-скрипта") && script.TrimEnd().EndsWith('0'), script);

        // Отпечаток хоста: та же команда, что в InstallOrchestrator.VerifyFingerprintAsync.
        var fp = (await ssh.RunAsync(
            "ssh-keyscan -t ed25519 localhost 2>/dev/null | ssh-keygen -lf - 2>/dev/null | awk '{print $2}'")).StdOut.Trim();
        var expected = Docker("exec", Container, "sh", "-c",
            "ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub | awk '{print $2}'").Out.Trim();
        Check("отпечаток хоста совпадает с ключом sshd", fp.StartsWith("SHA256:") && fp == expected, $"'{fp}' vs '{expected}'");
    }

    // 2. Ключи: без фразы и с фразой
    var phraseText = "фраза-" + Convert.ToHexString(RandomNumberGenerator.GetBytes(4));
    var keys = Docker("exec", Container, "sh", "-c",
        "set -e; d=/home/vsk/.ssh; mkdir -p $d; " +
        "ssh-keygen -q -t ed25519 -N '' -f /tmp/k1; " +
        $"ssh-keygen -q -t ed25519 -N '{phraseText}' -f /tmp/k2; " +
        "ssh-keygen -q -t rsa -b 2048 -m PEM -N '' -f /tmp/k3; " +
        "cat /tmp/k1.pub /tmp/k2.pub /tmp/k3.pub > $d/authorized_keys; " +
        "chown -R vsk:vsk $d; chmod 700 $d; chmod 600 $d/authorized_keys; echo done");
    Check("ключи сгенерированы в контейнере", keys.Out.Contains("done"), keys.Out);

    async Task KeyCase(string title, string file, string? phrase)
    {
        var pem = Docker("exec", Container, "cat", file).Out;
        try
        {
            await using var ssh = await factory.ConnectAsync(Server(
                key: secrets.Protect(pem), phrase: phrase is null ? null : secrets.Protect(phrase)));
            var r = await ssh.RunAsync("echo key-ok");
            Check(title, r.Ok && r.StdOut.Trim() == "key-ok", r.StdOut);

            await ssh.WriteHostFileAsync("/opt/vsk-test/key.txt", "k\n");
            Check(title + ": SFTP по ключу", Docker("exec", Container, "cat", "/opt/vsk-test/key.txt").Out == "k\n");
        }
        catch (Exception ex)
        {
            Check(title, false, ex.GetType().Name + ": " + ex.InnerException?.Message);
        }
    }

    await KeyCase("ключ ed25519 (OpenSSH) без фразы", "/tmp/k1", null);
    await KeyCase("ключ ed25519 (OpenSSH) с фразой", "/tmp/k2", phraseText);
    await KeyCase("ключ RSA (PEM)", "/tmp/k3", null);

    // 3. Отказы
    try
    {
        await using var _ = await factory.ConnectAsync(Server("неверный-пароль"));
        Check("неверный пароль даёт SshConnectionException", false, "подключение прошло");
    }
    catch (SshConnectionException ex)
    {
        Check("неверный пароль даёт SshConnectionException без пароля в тексте",
            !ex.ToString().Contains("неверный-пароль") && !ex.ToString().Contains(password));
    }

    try
    {
        var closed = Server(password);
        closed.Ssh.Port = 1;
        await using var _ = await factory.ConnectAsync(closed);
        Check("закрытый порт даёт SshConnectionException", false, "подключение прошло");
    }
    catch (SshConnectionException)
    {
        Check("закрытый порт даёт SshConnectionException", true);
    }
}
finally
{
    Docker("rm", "-f", Container);
}

Console.WriteLine();
Console.WriteLine($"Проверок: {total}, провалено: {failures}");
return failures == 0 ? 0 : 1;
