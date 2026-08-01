using AmneziaKeyService.Core.Interfaces;
using AmneziaKeyService.Core.Models;
using AmneziaKeyService.Infrastructure.Services;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace AmneziaKeyService.Infrastructure.Monitoring;

/// <summary>
/// Следит за сроками и квотами: отзывает то, что истекло или исчерпано,
/// предупреждает о скором истечении и дожимает застрявшие отзывы.
///
/// Сам ничего не делает с узлом напрямую — вызывает
/// <see cref="IVpnConfigService.RevokeAsync"/>, который уже умеет и удалять
/// peer, и корректно вести себя при недоступном узле.
/// </summary>
public class EnforcementService : PeriodicWorker
{
    /// <summary>За сколько до истечения предупреждать в журнале.</summary>
    private static readonly TimeSpan WarnWindow = TimeSpan.FromDays(7);

    /// <summary>
    /// Сколько застрявших отзывов дожимаем за тик. Потолок нужен: каждый
    /// повтор — это попытка SSH-подключения, и сотня ключей на лежащем узле
    /// растянула бы тик на минуты таймаутов.
    /// </summary>
    private const int PendingRevokeBatch = 25;

    public EnforcementService(
        IServiceScopeFactory scopeFactory,
        IOptions<PollingOptions> options,
        ILogger<EnforcementService> logger)
        : base(scopeFactory,
               options.Value.For(TimeSpan.FromSeconds(options.Value.EnforcementIntervalSeconds)),
               logger)
    {
    }

    protected override string Name => "enforcement";

    protected override async Task TickAsync(IServiceProvider services, CancellationToken ct)
    {
        await RevokeDueAsync(services, ct);
        await RetryPendingAsync(services, ct);
        await WarnExpiringAsync(services, ct);
    }

    // ── Отзыв по сроку и квоте ────────────────────────────────────────────────

    private async Task RevokeDueAsync(IServiceProvider services, CancellationToken ct)
    {
        var clients = services.GetRequiredService<IVpnClientRepository>();

        var due = await clients.FindEnforcementCandidatesAsync(DateTime.UtcNow, ct);
        if (due.Count == 0) return;

        foreach (var client in due)
        {
            if (ct.IsCancellationRequested) return;

            // Срок проверяется первым: ключ мог одновременно и истечь,
            // и выбрать квоту, но истёкший срок — более точная причина.
            var reason = client.IsExpired ? RevokeReasons.Expired : RevokeReasons.Quota;

            await RevokeAsync(services, client, reason, ct);
        }
    }

    /// <summary>
    /// Повторяет отзывы, застрявшие из-за недоступного узла. Причину берём
    /// из самой записи: перезаписать «отозван вручную» на «истёк срок» значило бы
    /// подменить историю.
    /// </summary>
    private async Task RetryPendingAsync(IServiceProvider services, CancellationToken ct)
    {
        var clients = services.GetRequiredService<IVpnClientRepository>();

        var stuck = await clients.FindPendingRevokeAsync(PendingRevokeBatch, ct);
        if (stuck.Count == 0) return;

        Logger.LogInformation("Повторный отзыв застрявших ключей: {Count}.", stuck.Count);

        foreach (var client in stuck)
        {
            if (ct.IsCancellationRequested) return;

            await RevokeAsync(services, client, client.RevokeReason ?? RevokeReasons.Manual, ct);
        }
    }

    private async Task RevokeAsync(
        IServiceProvider services, VpnClient client, string reason, CancellationToken ct)
    {
        // Свойствами, а не текстом: в Seq по KeyId собирается вся история
        // ключа — от выдачи до отзыва, включая неудачные попытки.
        using var logScope = Logger.BeginScope(new Dictionary<string, object>
        {
            ["Worker"]   = Name,
            ["KeyId"]    = client.Id,
            ["ServerId"] = client.ServerId,
        });

        try
        {
            // revokedByUserId остаётся null: отозвал сервис, а не человек.
            var result = await services.GetRequiredService<IVpnConfigService>()
                .RevokeAsync(client.Id, reason, revokedByUserId: null, ct);

            if (result.Status == KeyStatuses.PendingRevoke)
            {
                // Узел недоступен, peer жив. Повторим на следующем тике —
                // запись об отзыве в журнал пойдёт только по факту удаления.
                Logger.LogWarning(
                    "Ключ {ShortId} ({KeyId}): узел недоступен, отзыв отложен.",
                    client.ShortId, client.Id);

                return;
            }

            Logger.LogInformation(
                "Ключ {ShortId} ({KeyId}) отозван автоматически: {Reason}.",
                client.ShortId, client.Id, reason);

            await services.GetRequiredService<IAuditService>().WriteAsync(
                AuditEvents.KeyRevoked,
                $"Ключ {client.ShortId} отозван автоматически: {Describe(reason)}",
                targetType: AuditTargets.Key, targetId: client.Id, targetName: client.ShortId,
                level: AuditLevels.Warn, ct: ct);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            // Один проблемный ключ не должен останавливать обработку остальных.
            Logger.LogError(ex,
                "Не удалось отозвать ключ {ShortId} ({KeyId}) по причине {Reason}.",
                client.ShortId, client.Id, reason);
        }
    }

    // ── Предупреждение о скором истечении ─────────────────────────────────────

    private async Task WarnExpiringAsync(IServiceProvider services, CancellationToken ct)
    {
        var clients = services.GetRequiredService<IVpnClientRepository>();

        var expiring = await clients.FindExpiringUnwarnedAsync(DateTime.UtcNow + WarnWindow, ct);
        if (expiring.Count == 0) return;

        var audit = services.GetRequiredService<IAuditService>();

        foreach (var client in expiring)
        {
            var daysLeft = Math.Max(0, (int)Math.Ceiling(
                (client.ExpiresAt!.Value - DateTime.UtcNow).TotalDays));

            await audit.WriteAsync(AuditEvents.KeyExpiringSoon,
                $"Ключ {client.ShortId} истекает через {daysLeft} дн.",
                targetType: AuditTargets.Key, targetId: client.Id, targetName: client.ShortId,
                level: AuditLevels.Warn, ct: ct);
        }

        // Отметка ставится после записи в журнал: если сервис упадёт между
        // ними, предупреждение повторится — это лучше, чем потерять его.
        await clients.MarkExpiryWarnedAsync([.. expiring.Select(c => c.Id)], ct);

        Logger.LogInformation("Предупреждений о скором истечении: {Count}.", expiring.Count);
    }

    private static string Describe(string reason) => reason switch
    {
        RevokeReasons.Expired => "истёк срок действия",
        RevokeReasons.Quota   => "исчерпана квота трафика",
        _                     => reason,
    };
}
