using System.Text;
using AmneziaKeyService.Core.Exceptions;
using AmneziaKeyService.Core.Interfaces;
using AmneziaKeyService.Core.Models;
using Microsoft.Extensions.Logging;
using Renci.SshNet;

namespace AmneziaKeyService.Infrastructure.Ssh;

public class SshSessionFactory : ISshSessionFactory
{
    /// <summary>
    /// Пинг раз в 15 секунд. Без него канал простаивает во время долгих операций
    /// (сборка образа занимает минуты) и промежуточный NAT его закрывает.
    /// </summary>
    private static readonly TimeSpan KeepAlive = TimeSpan.FromSeconds(15);

    private static readonly TimeSpan ConnectTimeout = TimeSpan.FromSeconds(20);

    private readonly ISecretProtector _secrets;
    private readonly ILoggerFactory _loggerFactory;
    private readonly ILogger<SshSessionFactory> _logger;

    public SshSessionFactory(
        ISecretProtector secrets,
        ILoggerFactory loggerFactory,
        ILogger<SshSessionFactory> logger)
    {
        _secrets       = secrets;
        _loggerFactory = loggerFactory;
        _logger        = logger;
    }

    public async Task<ISshSession> ConnectAsync(VpnServer server, CancellationToken ct = default)
    {
        var connectionInfo = BuildConnectionInfo(server);

        var ssh = new SshClient(connectionInfo) { KeepAliveInterval = KeepAlive };

        try
        {
            await Task.Run(() => ssh.Connect(), ct);
        }
        catch (Exception ex)
        {
            ssh.Dispose();
            // Исключения SSH.NET содержат хост, порт и иногда данные аутентификации.
            _logger.LogWarning(ex, "Не удалось подключиться к узлу {Host}.", server.Host);
            throw new SshConnectionException(server.Host, ex);
        }

        return new SshSession(
            ssh,
            () => new SftpClient(BuildConnectionInfo(server)),
            _loggerFactory.CreateLogger<SshSession>());
    }

    /// <summary>
    /// Собирает параметры подключения. Приватный ключ берётся из базы
    /// (зашифрованным), путь на диске — только как наследие прежней схемы.
    /// </summary>
    private ConnectionInfo BuildConnectionInfo(VpnServer server)
    {
        var ssh = server.Ssh;
        var method = BuildAuthMethod(server);

        return new ConnectionInfo(server.Host, ssh.Port, ssh.User, method)
        {
            Timeout = ConnectTimeout,
        };
    }

    private AuthenticationMethod BuildAuthMethod(VpnServer server)
    {
        var ssh = server.Ssh;

        var privateKey = _secrets.Unprotect(ssh.PrivateKey);
        if (!string.IsNullOrEmpty(privateKey))
        {
            var passphrase = _secrets.Unprotect(ssh.KeyPassphrase);
            using var stream = new MemoryStream(Encoding.UTF8.GetBytes(privateKey));

            var keyFile = string.IsNullOrEmpty(passphrase)
                ? new PrivateKeyFile(stream)
                : new PrivateKeyFile(stream, passphrase);

            return new PrivateKeyAuthenticationMethod(ssh.User, keyFile);
        }

        if (!string.IsNullOrEmpty(ssh.PrivateKeyPath))
        {
            var keyFile = new PrivateKeyFile(ssh.PrivateKeyPath);
            return new PrivateKeyAuthenticationMethod(ssh.User, keyFile);
        }

        var password = _secrets.Unprotect(ssh.Password)
            ?? throw new SshConnectionException(server.Host,
                new InvalidOperationException("Для узла не заданы ни пароль, ни приватный ключ."));

        return new PasswordAuthenticationMethod(ssh.User, password);
    }
}
