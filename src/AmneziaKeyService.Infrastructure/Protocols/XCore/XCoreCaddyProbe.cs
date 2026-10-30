using AmneziaKeyService.Core.Interfaces;

namespace AmneziaKeyService.Infrastructure.Protocols.XCore;

public enum XCoreCertificateWait
{
    Ready,

    /// <summary>На узле нет curl: ждать до таймаута и обвинять DNS было бы ложью.</summary>
    CurlMissing,

    Timeout,
}

/// <summary>
/// Ожидание сертификата Let's Encrypt у Caddy узла. Общее для установщика (домен узла) и синхронизации
/// (домен подписки входа): обе ждут одного и того же события, и расхождение в способе проверки означало бы,
/// что один из путей принимает самоподписанный сертификат за настоящий.
/// </summary>
public static class XCoreCaddyProbe
{
    /// <summary>
    /// Без <c>-k</c>: проверяем именно настоящий сертификат, самоподписанный временный Caddy выдаёт и до
    /// получения нового. Запрос идёт на 127.0.0.1:8443 с подменой адреса, а не на публичный адрес: проверка
    /// не должна зависеть от DNS и от того, пропускает ли сеть узла собственный трафик на себя.
    /// </summary>
    public static string CertificateProbeCommand(string domain) =>
        $"curl -sS --max-time 10 -o /dev/null -w '%{{http_code}}' " +
        $"--resolve {domain}:8443:127.0.0.1 https://{domain}:8443/";

    /// <param name="expectedCode">
    /// Код ответа корня сайта: 200 у домена узла (заглушка), 404 у домена подписки (отвечает только
    /// <c>/sub/*</c>). Успешное рукопожатие без ошибки сертификата и есть признак, что сертификат получен.
    /// </param>
    /// <param name="onWaiting">Вызывается после каждой неудачной попытки с её номером — для строки прогресса установки.</param>
    public static async Task<XCoreCertificateWait> WaitForCertificateAsync(
        ISshSession ssh, string domain, string expectedCode, int attempts, TimeSpan interval,
        Func<int, CancellationToken, Task>? onWaiting, CancellationToken ct)
    {
        var probe = CertificateProbeCommand(domain);
        for (var attempt = 1; attempt <= attempts; attempt++)
        {
            var result = await ssh.RunAsync(probe, ct);
            // 127 — «команда не найдена».
            if (result.ExitStatus == 127) return XCoreCertificateWait.CurlMissing;
            if (result.Ok && result.StdOut.Trim() == expectedCode) return XCoreCertificateWait.Ready;

            if (onWaiting is not null) await onWaiting(attempt, ct);
            if (attempt < attempts) await Task.Delay(interval, ct);
        }

        return XCoreCertificateWait.Timeout;
    }
}
