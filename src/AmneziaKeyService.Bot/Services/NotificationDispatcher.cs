using AmneziaKeyService.Core.Interfaces;
using AmneziaKeyService.Core.Models;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Telegram.Bot;
using Telegram.Bot.Exceptions;

namespace AmneziaKeyService.Bot.Services;

/// <summary>
/// Доставляет массовые уведомления отдельно от обработки входящих сообщений.
/// Задания и аренды лежат в MongoDB, поэтому очередь переживает рестарт бота.
/// </summary>
public class NotificationDispatcher : BackgroundService
{
    private readonly ITelegramBotClient _bot;
    private readonly INotificationRepository _notifications;
    private readonly NotificationOptions _options;
    private readonly ILogger<NotificationDispatcher> _logger;
    private readonly string _owner =
        $"{Environment.MachineName}/{Environment.ProcessId}/{Guid.NewGuid().ToString("N")[..6]}";

    public NotificationDispatcher(
        ITelegramBotClient bot,
        INotificationRepository notifications,
        IOptions<NotificationOptions> options,
        ILogger<NotificationDispatcher> logger)
    {
        _bot = bot;
        _notifications = notifications;
        _options = options.Value;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!_options.Enabled)
        {
            _logger.LogInformation("Диспетчер массовых уведомлений выключен настройкой.");
            return;
        }

        try
        {
            await Task.Delay(TimeSpan.FromSeconds(Math.Max(0, _options.StartupDelaySeconds)), stoppingToken);
        }
        catch (OperationCanceledException)
        {
            return;
        }

        var leaseTtl = TimeSpan.FromSeconds(Math.Max(10, _options.LeaseTtlSeconds));
        var sendDelay = TimeSpan.FromSeconds(1d / Math.Clamp(_options.MessagesPerSecond, 1, 25));
        var pollDelay = TimeSpan.FromMilliseconds(Math.Clamp(_options.PollIntervalMilliseconds, 100, 30_000));
        var batchSize = Math.Clamp(_options.BatchSize, 1, 100);

        _logger.LogInformation(
            "Диспетчер уведомлений запущен: до {Rate} сообщений/с, пачка {BatchSize}.",
            Math.Clamp(_options.MessagesPerSecond, 1, 25), batchSize);

        while (!stoppingToken.IsCancellationRequested)
        {
            var taken = 0;
            for (; taken < batchSize && !stoppingToken.IsCancellationRequested; taken++)
            {
                var delivery = await _notifications.ClaimNextAsync(_owner, leaseTtl, stoppingToken);
                if (delivery is null) break;

                await DeliverAsync(delivery, stoppingToken);
                await Task.Delay(sendDelay, stoppingToken);
            }

            if (taken == 0)
                await Task.Delay(pollDelay, stoppingToken);
        }
    }

    private async Task DeliverAsync(NotificationDelivery delivery, CancellationToken ct)
    {
        var campaign = await _notifications.GetCampaignAsync(delivery.CampaignId, ct);
        if (campaign is null || campaign.Status != NotificationCampaignStatuses.Running)
        {
            await _notifications.MarkCanceledAsync(delivery, _owner, ct);
            return;
        }

        try
        {
            var message = await _bot.SendMessage(
                delivery.TelegramId,
                campaign.Text,
                disableNotification: campaign.DisableNotification,
                cancellationToken: ct);

            await _notifications.MarkSentAsync(delivery, _owner, message.MessageId, ct);
        }
        catch (ApiRequestException ex) when (ex.ErrorCode == 429)
        {
            var retrySeconds = Math.Max(1, ex.Parameters?.RetryAfter ?? 5);
            await _notifications.MarkRetryAsync(
                delivery, _owner, DateTime.UtcNow.AddSeconds(retrySeconds),
                ex.ErrorCode, ex.Message, CancellationToken.None);
            _logger.LogWarning("Telegram ограничил рассылку на {RetryAfter} с.", retrySeconds);
            await Task.Delay(TimeSpan.FromSeconds(retrySeconds), ct);
        }
        catch (ApiRequestException ex) when (ex.ErrorCode is 400 or 403)
        {
            await _notifications.MarkFailedAsync(
                delivery, _owner, ex.ErrorCode, ex.Message, CancellationToken.None);
            _logger.LogInformation(
                "Уведомление пользователю {UserId} недоставимо: Telegram {ErrorCode}.",
                delivery.UserId, ex.ErrorCode);
        }
        catch (Exception ex) when (!ct.IsCancellationRequested)
        {
            if (delivery.Attempt >= Math.Max(1, _options.MaxAttempts))
            {
                await _notifications.MarkFailedAsync(
                    delivery, _owner, null, ex.Message, CancellationToken.None);
                _logger.LogWarning(ex,
                    "Уведомление пользователю {UserId} провалено после {Attempts} попыток.",
                    delivery.UserId, delivery.Attempt);
                return;
            }

            var backoffSeconds = Math.Min(300, 5 * (1 << Math.Min(delivery.Attempt - 1, 6)));
            await _notifications.MarkRetryAsync(
                delivery, _owner, DateTime.UtcNow.AddSeconds(backoffSeconds),
                null, ex.Message, CancellationToken.None);
            _logger.LogWarning(ex,
                "Уведомление пользователю {UserId} не отправлено, повтор через {Backoff} с.",
                delivery.UserId, backoffSeconds);
        }
    }
}
