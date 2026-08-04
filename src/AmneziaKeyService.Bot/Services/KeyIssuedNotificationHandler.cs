using AmneziaKeyService.Core.Interfaces;
using AmneziaKeyService.Core.Models;
using AmneziaKeyService.Infrastructure.Events;
using Microsoft.Extensions.Logging;
using MongoDB.Bson;
using Telegram.Bot;
using Telegram.Bot.Types.ReplyMarkups;

namespace AmneziaKeyService.Bot.Services;

/// <summary>
/// Досылает результат выдачи, начатой публикацией key.issue из
/// <see cref="TelegramBotService.CreateNewVpnConfigAsync"/> — worker создаёт
/// ключ и публикует это событие с адресом чата и плейсхолдером «⏳ Готовлю…».
///
/// После успешной выдачи предлагает получить ключ как VPN URI или файл .conf.
/// Сами конфигурации строятся только после выбора пользователя и не попадают
/// в payload события.
/// </summary>
public class KeyIssuedNotificationHandler : IDomainEventHandler
{
    private readonly ITelegramBotClient _bot;
    private readonly IVpnClientRepository _clients;
    private readonly ILogger<KeyIssuedNotificationHandler> _logger;

    public KeyIssuedNotificationHandler(
        ITelegramBotClient bot,
        IVpnClientRepository clients,
        ILogger<KeyIssuedNotificationHandler> logger)
    {
        _bot     = bot;
        _clients = clients;
        _logger  = logger;
    }

    public string EventType => DomainEventTypes.NotifyKeyIssued;

    /// <summary>
    /// Повторная доставка сообщения безопаснее молчания: пользователь уже
    /// увидел «⏳ Готовлю…» и ждёт ответа, а недоступность Telegram API
    /// на полминуты — обычное дело.
    /// </summary>
    public DomainEventPolicy Policy => DomainEventPolicy.Retrying(5, TimeSpan.FromSeconds(30));

    public async Task<BsonDocument?> HandleAsync(DomainEvent evt, CancellationToken ct)
    {
        var payload = evt.PayloadAs<NotifyKeyIssuedPayload>();

        if (payload.Error is { } error)
        {
            await ReplyAsync(payload.Target, error, ct);
            return new BsonDocument
            {
                ["chatId"]    = payload.Target.ChatId,
                ["delivered"] = "error",
            };
        }

        // KeyId заполняет KeyIssueHandler ровно тогда, когда выдача
        // состоялась, — но к моменту доставки уведомления ключ мог быть уже
        // отозван. Это не повод бесконечно повторять доставку: сообщаем
        // пользователю и завершаем событие успешно.
        var client = payload.KeyId is null ? null : await _clients.FindByIdAsync(payload.KeyId, ct);
        if (client is null)
        {
            _logger.LogWarning("Ключ {KeyId} для уведомления notify.key_issued не найден — пропускаю.", payload.KeyId);
            await ReplyAsync(payload.Target, "Ключ создан, но уже недоступен. Загляните в «Мои ключи».", ct);
            return new BsonDocument
            {
                ["chatId"]    = payload.Target.ChatId,
                ["delivered"] = "missing_key",
            };
        }

        var keyboard = new InlineKeyboardMarkup(new[]
        {
            new[]
            {
                InlineKeyboardButton.WithCallbackData(
                    "🔗 Получить VPN URI", $"keyuri:{client.Id}:m")
            },
            new[]
            {
                InlineKeyboardButton.WithCallbackData(
                    "📄 Скачать файл .conf", $"keyconf:{client.Id}:m")
            }
        });

        await ReplyAsync(
            payload.Target,
            "✅ Ключ создан. Выберите, как получить конфигурацию:",
            keyboard,
            ct);

        return new BsonDocument
        {
            ["chatId"] = payload.Target.ChatId,
            ["keyId"]  = client.Id,
        };
    }

    /// <summary>Правит сообщение-плейсхолдер, если оно есть, иначе шлёт новое.</summary>
    private Task ReplyAsync(
        TelegramTarget target,
        string text,
        CancellationToken ct)
        => ReplyAsync(target, text, replyMarkup: null, ct);

    private Task ReplyAsync(
        TelegramTarget target,
        string text,
        InlineKeyboardMarkup? replyMarkup,
        CancellationToken ct)
        => target.MessageId is { } messageId
            ? _bot.EditMessageText(
                target.ChatId, messageId, text,
                replyMarkup: replyMarkup, cancellationToken: ct)
            : _bot.SendMessage(
                target.ChatId, text,
                replyMarkup: replyMarkup, cancellationToken: ct);
}
