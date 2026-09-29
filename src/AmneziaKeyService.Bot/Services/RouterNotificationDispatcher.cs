using AmneziaKeyService.Core.Interfaces;
using AmneziaKeyService.Core.Models;
using AmneziaKeyService.Infrastructure.Repositories;
using Telegram.Bot;
using Telegram.Bot.Exceptions;

namespace AmneziaKeyService.Bot.Services;

public sealed class RouterNotificationDispatcher(
    RouterMonitorRepository routers, IUserRepository users, ITelegramBotClient bot,
    ILogger<RouterNotificationDispatcher> logger) : BackgroundService
{
    private readonly string _owner = Guid.NewGuid().ToString("N");

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                var item = await routers.ClaimDeliveryAsync(_owner, stoppingToken);
                if (item is not null) await DeliverAsync(item, stoppingToken);
            }
            catch (Exception ex) when (!stoppingToken.IsCancellationRequested)
            {
                logger.LogWarning(ex, "Не удалось обработать очередь наблюдения за роутерами");
            }
            try { await Task.Delay(TimeSpan.FromSeconds(2), stoppingToken); }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
        }
    }

    private async Task DeliverAsync(RouterTransition item, CancellationToken ct)
    {
        try
        {
            var router = await routers.GetAsync(item.RouterId, ct);
            var user = await users.FindByIdAsync(item.UserId, ct);
            if (!RouterMonitorRules.CanDeliver(router, item, DateTime.UtcNow))
            {
                await routers.CompleteDeliveryAsync(item, _owner, "skipped", "Настройки изменены или состояние уже не актуально", 0, ct);
                return;
            }
            if (!RouterMonitorRules.CanReceive(user))
            {
                await routers.CompleteDeliveryAsync(item, _owner, "failed", "Получатель недоступен или Telegram не привязан", 0, ct);
                return;
            }
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(TimeSpan.FromSeconds(30));
            await bot.SendMessage(user!.TelegramId!.Value, Format(item), cancellationToken: timeout.Token);
            await routers.CompleteDeliveryAsync(item, _owner, "sent", null, 0, ct);
        }
        catch (ApiRequestException ex) when (ex.ErrorCode == 429)
        {
            await routers.CompleteDeliveryAsync(item, _owner, "pending", "Telegram ограничил частоту отправки", Math.Max(1, ex.Parameters?.RetryAfter ?? 30), ct);
        }
        catch (ApiRequestException ex) when (ex.ErrorCode is 400 or 403)
        {
            await routers.CompleteDeliveryAsync(item, _owner, "failed", $"Telegram {ex.ErrorCode}: чат недоступен или бот заблокирован", 0, ct);
        }
        catch (Exception) when (!ct.IsCancellationRequested)
        {
            await routers.CompleteDeliveryAsync(item, _owner, item.Attempts >= 5 ? "failed" : "pending",
                "Не удалось доставить сообщение", Math.Min(300, 15 * item.Attempts), ct);
        }
    }

    private static string Format(RouterTransition item)
    {
        var time = item.At.ToUniversalTime().ToString("dd.MM.yyyy HH:mm 'UTC'");
        if (item.State == "test") return $"🔔 {item.RouterName}: тестовое уведомление. Привязка Telegram работает.";
        if (item.State == RouterStates.Offline)
            return $"🔴 {item.RouterName}: связь с роутером потеряна.\nОбнаружено: {time}.\nПоследний handshake: {item.LastHandshakeAt:dd.MM.yyyy HH:mm} UTC.\nВозможно отключение электричества или интернета.";
        var duration = item.OutageSeconds is { } seconds ? $"\nНаблюдаемый перерыв: около {Math.Ceiling(seconds / 60)} мин." : "";
        return $"🟢 {item.RouterName}: связь с роутером подтверждена.\n{time}.{duration}";
    }
}
