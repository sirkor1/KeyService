using System.Collections.Concurrent;
using AmneziaKeyService.Core.DTOs;
using AmneziaKeyService.Core.Interfaces;
using AmneziaKeyService.Core.Models;
using Microsoft.Extensions.DependencyInjection;
using Telegram.Bot;
using Telegram.Bot.Polling;
using Telegram.Bot.Types;
using Telegram.Bot.Types.Enums;
using Telegram.Bot.Types.ReplyMarkups;
using MongoDB.Bson;

using AppUser = AmneziaKeyService.Core.Models.User;

namespace AmneziaKeyService.Bot.Services;

public class TelegramBotService : IHostedService
{
    private readonly IUserRepository _users;
    private readonly IPassCodeRepository _passCodes;
    private readonly IVpnServerRepository _servers;
    private readonly IVpnClientRepository _clients;
    private readonly IDomainEventPublisher _events;
    private readonly IServiceScopeFactory _scopeFactory;
    private readonly ILogger<TelegramBotService> _logger;

    private const int CopyTextButtonMaxLength = 256;
    private const int TelegramMessageMaxLength = 4096;

    private static readonly BotCommand[] PrivateChatCommands =
    [
        new() { Command = "start",   Description = "Начать работу или регистрацию" },
        new() { Command = "menu",    Description = "Открыть главное меню" },
        new() { Command = "servers", Description = "Показать доступные серверы" },
        new() { Command = "keys",    Description = "Показать мои ключи" },
        new() { Command = "help",    Description = "Показать справку" }
    ];

    /// <summary>
    /// Null, если TelegramBot:Token не задан — тогда клиент не регистрируется
    /// в контейнере вовсе (см. Program.cs) и бот не поднимается, оставаясь
    /// исправным процессом.
    /// </summary>
    private readonly ITelegramBotClient? _bot;

    private CancellationTokenSource? _cts;

    // Состояние диалога для каждого чата
    private readonly ConcurrentDictionary<long, ChatState> _states = new();

    private enum ChatState { Idle, AwaitingPassCode }

    public TelegramBotService(
        IUserRepository users,
        IPassCodeRepository passCodes,
        IVpnServerRepository servers,
        IVpnClientRepository clients,
        IDomainEventPublisher events,
        IServiceScopeFactory scopeFactory,
        ILogger<TelegramBotService> logger,
        ITelegramBotClient? bot = null)
    {
        _users        = users;
        _passCodes    = passCodes;
        _servers      = servers;
        _clients      = clients;
        _events       = events;
        _scopeFactory = scopeFactory;
        _logger       = logger;
        _bot          = bot;
    }

    // ── IHostedService ────────────────────────────────────────────────────────

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        if (_bot is null)
        {
            _logger.LogWarning("TelegramBot:Token не задан. Telegram бот не запущен.");
            return;
        }

        _cts = new CancellationTokenSource();

        try
        {
            await _bot.SetMyCommands(
                PrivateChatCommands,
                scope: BotCommandScope.AllPrivateChats(),
                cancellationToken: cancellationToken);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            return;
        }
        catch (Exception ex)
        {
            // Сбой Telegram API не должен останавливать polling: Telegram может
            // быть временно недоступен именно во время старта контейнера.
            _logger.LogWarning(ex, "Не удалось зарегистрировать меню команд Telegram. Polling будет запущен без него.");
        }

        _bot.StartReceiving(
            updateHandler: HandleUpdateAsync,
            errorHandler:  HandleErrorAsync,
            receiverOptions: new ReceiverOptions
            {
                AllowedUpdates = new[] { UpdateType.Message, UpdateType.CallbackQuery }
            },
            cancellationToken: _cts.Token);

        _logger.LogInformation("Telegram бот запущен.");
    }

    public Task StopAsync(CancellationToken cancellationToken)
    {
        _cts?.Cancel();
        return Task.CompletedTask;
    }

    // ── Update router ─────────────────────────────────────────────────────────

    private async Task HandleUpdateAsync(ITelegramBotClient bot, Update update, CancellationToken ct)
    {
        try
        {
            if (update.Message is { } msg)
                await HandleMessageAsync(bot, msg, ct);
            else if (update.CallbackQuery is { } cbq)
                await HandleCallbackQueryAsync(bot, cbq, ct);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Ошибка обработки Telegram update");
        }
    }

    private Task HandleErrorAsync(ITelegramBotClient bot, Exception ex, HandleErrorSource source, CancellationToken ct)
    {
        _logger.LogError(ex, "Ошибка Telegram polling ({Source})", source);
        return Task.CompletedTask;
    }

    // ── Message handler ───────────────────────────────────────────────────────

    private async Task HandleMessageAsync(ITelegramBotClient bot, Message message, CancellationToken ct)
    {
        if (message.Text is not { } text) return;

        var chatId     = message.Chat.Id;
        var telegramId = message.From?.Id ?? chatId;

        if (TryGetCommand(text, out var command))
        {
            if (message.Chat.Type != ChatType.Private)
            {
                await bot.SendMessage(chatId,
                    "Этот бот работает только в личном чате. Откройте диалог с ботом и используйте /start.",
                    cancellationToken: ct);
            }
            else
            {
                await HandleCommandAsync(bot, chatId, telegramId, command, ct);
            }
            return;
        }

        // Конфигурации и пригласительные коды не должны попадать в групповые чаты.
        if (message.Chat.Type != ChatType.Private) return;

        var state = _states.GetValueOrDefault(chatId, ChatState.Idle);

        if (state == ChatState.AwaitingPassCode)
        {
            await HandlePassCodeInputAsync(bot, chatId, telegramId, message.From?.Username, text.Trim(), ct);
            return;
        }

        // Любое другое сообщение — проверяем регистрацию и показываем меню
        var existingUser = await _users.FindByTelegramIdAsync(telegramId, ct);
        if (existingUser is null)
        {
            _states[chatId] = ChatState.AwaitingPassCode;
            await bot.SendMessage(chatId,
                "Для использования бота необходимо зарегистрироваться. Введите пригласительный код:",
                cancellationToken: ct);
        }
        else
        {
            await SendMainMenuAsync(bot, chatId, "Выберите действие:", ct);
        }
    }

    private async Task HandleCommandAsync(
        ITelegramBotClient bot, long chatId, long telegramId, string command, CancellationToken ct)
    {
        var user = await _users.FindByTelegramIdAsync(telegramId, ct);

        if (command == "help")
        {
            await SendHelpAsync(bot, chatId, user is null, ct);
            return;
        }

        if (command == "start")
        {
            if (user is not null)
            {
                _states.TryRemove(chatId, out _);
                await SendMainMenuAsync(bot, chatId, $"С возвращением, {user.Username}!", ct);
            }
            else
            {
                await PromptForRegistrationAsync(bot, chatId, ct, "Добро пожаловать! Для регистрации введите пригласительный код:");
            }
            return;
        }

        if (user is null)
        {
            await PromptForRegistrationAsync(bot, chatId, ct,
                "Сначала зарегистрируйтесь. Введите пригласительный код или используйте /start:");
            return;
        }

        switch (command)
        {
            case "menu":
                await SendMainMenuAsync(bot, chatId, "Выберите действие:", ct);
                break;
            case "servers":
                await SendServerListAsync(bot, chatId, ct);
                break;
            case "keys":
                await SendMyKeysAsync(bot, chatId, user.Id, ct);
                break;
            default:
                await SendHelpAsync(bot, chatId, false, ct);
                break;
        }
    }

    private async Task PromptForRegistrationAsync(
        ITelegramBotClient bot, long chatId, CancellationToken ct, string text)
    {
        _states[chatId] = ChatState.AwaitingPassCode;
        await bot.SendMessage(chatId, text, cancellationToken: ct);
    }

    private static Task SendHelpAsync(ITelegramBotClient bot, long chatId, bool registrationRequired, CancellationToken ct)
    {
        var registrationHint = registrationRequired
            ? "\n\nДля начала регистрации используйте /start и введите пригласительный код."
            : string.Empty;

        return bot.SendMessage(chatId,
            "Доступные команды:\n" +
            "/start — начать работу или регистрацию\n" +
            "/menu — открыть главное меню\n" +
            "/servers — список доступных серверов\n" +
            "/keys — мои VPN-ключи\n" +
            "/help — эта справка" + registrationHint,
            cancellationToken: ct);
    }

    private static bool TryGetCommand(string text, out string command)
    {
        var trimmed = text.TrimStart();
        if (!trimmed.StartsWith('/'))
        {
            command = string.Empty;
            return false;
        }

        var tokenEnd = trimmed.IndexOfAny([' ', '\t', '\r', '\n']);
        var token = tokenEnd < 0 ? trimmed : trimmed[..tokenEnd];
        var commandWithOptionalBotName = token[1..];
        var botNameSeparator = commandWithOptionalBotName.IndexOf('@');
        command = (botNameSeparator < 0
                ? commandWithOptionalBotName
                : commandWithOptionalBotName[..botNameSeparator])
            .ToLowerInvariant();

        return command.Length > 0;
    }

    private async Task HandlePassCodeInputAsync(
        ITelegramBotClient bot, long chatId, long telegramId,
        string? tgUsername, string code, CancellationToken ct)
    {
        var passCode = await _passCodes.FindByCodeAsync(code, ct);
        var existingByTelegram = await _users.FindByTelegramIdAsync(telegramId, ct);

        if (passCode is null || passCode.IsRevoked)
        {
            await bot.SendMessage(chatId,
                "Неверный или уже использованный код. Попробуйте ещё раз:",
                cancellationToken: ct);
            return;
        }

        if (passCode.IsUsed && passCode.UsedByUserId is not null)
        {
            if (existingByTelegram?.Id == passCode.UsedByUserId)
            {
                _states.TryRemove(chatId, out _);
                await SendMainMenuAsync(bot, chatId, "Вы успешно зарегистрированы! Добро пожаловать 🎉", ct);
                return;
            }
            await bot.SendMessage(chatId,
                "Неверный или уже использованный код. Попробуйте ещё раз:",
                cancellationToken: ct);
            return;
        }

        // Используем Telegram username, или fallback на tg_{id}
        var username = !string.IsNullOrWhiteSpace(tgUsername) ? tgUsername : $"tg_{telegramId}";
        if (passCode.IsUsed)
        {
            if (passCode.ClaimTelegramId != telegramId || string.IsNullOrEmpty(passCode.ClaimToken)
                || string.IsNullOrEmpty(passCode.ClaimUsername))
            {
                await bot.SendMessage(chatId,
                    "Неверный или уже использованный код. Попробуйте ещё раз:",
                    cancellationToken: ct);
                return;
            }
            username = passCode.ClaimUsername;
        }

        // Если username уже занят — добавляем суффикс
        if (existingByTelegram is not null)
        {
            if (passCode.IsUsed && passCode.ClaimTelegramId == telegramId
                && !string.IsNullOrEmpty(passCode.ClaimToken)
                && await _passCodes.CompleteClaimAsync(passCode.Id, passCode.ClaimToken, existingByTelegram.Id, ct))
            {
                _states.TryRemove(chatId, out _);
                await SendMainMenuAsync(bot, chatId, $"Вы успешно зарегистрированы! Добро пожаловать, {username} 🎉", ct);
                return;
            }
            await SendMainMenuAsync(bot, chatId, "Вы уже зарегистрированы.", ct);
            return;
        }

        if (!passCode.IsUsed)
        {
            var existingByName = await _users.FindByUsernameAsync(username, ct);
            if (existingByName is not null)
                username = $"{username}_{telegramId}";

            var newClaimToken = Guid.NewGuid().ToString("N");
            if (!await _passCodes.TryClaimAsync(passCode.Id, newClaimToken, username, string.Empty, telegramId, ct))
            {
                await bot.SendMessage(chatId,
                    "Неверный или уже использованный код. Попробуйте ещё раз:",
                    cancellationToken: ct);
                return;
            }
            passCode = await _passCodes.FindByIdAsync(passCode.Id, ct)
                ?? throw new InvalidOperationException("Не удалось зарезервировать код.");
        }

        var claimToken = passCode.ClaimToken!;

        var user = new AppUser
        {
            Username     = username,
            TelegramId   = telegramId,
            PasswordHash = string.Empty
        };

        var userCreated = false;
        try
        {
            await _users.CreateAsync(user, ct);
            userCreated = true;
            var created = await _users.FindByTelegramIdAsync(telegramId, ct)
                ?? throw new InvalidOperationException("Не удалось создать пользователя.");
            if (!await _passCodes.CompleteClaimAsync(passCode.Id, claimToken, created.Id, ct))
                throw new InvalidOperationException("Не удалось завершить регистрацию.");
        }
        catch
        {
            // См. HTTP-регистрацию: duplicate-key у параллельного retry означает,
            // что другой запрос уже мог вставить того же Telegram-пользователя.
            if (!userCreated)
            {
                var claimedUser = await _users.FindByTelegramIdAsync(telegramId, ct);
                if (claimedUser is null)
                    await _passCodes.ReleaseClaimAsync(passCode.Id, claimToken, ct);
                else if (await _passCodes.CompleteClaimAsync(passCode.Id, claimToken, claimedUser.Id, ct))
                {
                    _states.TryRemove(chatId, out _);
                    await SendMainMenuAsync(bot, chatId, $"Вы успешно зарегистрированы! Добро пожаловать, {username} 🎉", ct);
                    return;
                }
            }
            throw;
        }
        _states.TryRemove(chatId, out _);

        await SendMainMenuAsync(bot, chatId, $"Вы успешно зарегистрированы! Добро пожаловать, {username} 🎉", ct);
    }

    // ── Callback query handler ────────────────────────────────────────────────

    private async Task HandleCallbackQueryAsync(ITelegramBotClient bot, CallbackQuery query, CancellationToken ct)
    {
        var chatId     = query.Message!.Chat.Id;
        var messageId  = query.Message.MessageId;
        var telegramId = query.From.Id;
        var data       = query.Data ?? string.Empty;

        await bot.AnswerCallbackQuery(query.Id, cancellationToken: ct);

        var user = await _users.FindByTelegramIdAsync(telegramId, ct);
        if (user is null)
        {
            await bot.SendMessage(chatId,
                "Сначала зарегистрируйтесь — введите /start",
                cancellationToken: ct);
            return;
        }

        switch (data)
        {
            case "cmd:menu":
                await EditMainMenuAsync(bot, chatId, messageId, "Выберите действие:", ct);
                break;

            case "cmd:servers":
                await ShowServerListAsync(bot, chatId, messageId, ct);
                break;

            case "cmd:mykeys":
                await ShowMyKeysAsync(bot, chatId, messageId, user.Id, ct);
                break;

            default:
                if (data.StartsWith("np:"))
                {
                    var parts = data.Split(':');
                    if (parts.Length == 3)
                        await CreateNewVpnConfigAsync(bot, chatId, messageId, user.Id, parts[1], parts[2], ct);
                }
                else if (data.StartsWith("server:"))
                {
                    var serverId = data["server:".Length..];
                    await HandleServerSelectedAsync(bot, chatId, messageId, user.Id, serverId, ct);
                }
                else if (data.StartsWith("serverkeys:"))
                {
                    var serverId = data["serverkeys:".Length..];
                    await ShowServerKeysAsync(bot, chatId, messageId, user.Id, serverId, ct);
                }
                else if (TryParseKeyCallback(data, "key", out var clientId, out var origin))
                    await ShowKeyActionsAsync(bot, chatId, messageId, user.Id, clientId, origin, ct);
                else if (TryParseKeyCallback(data, "keyuri", out clientId, out _))
                    await SendKeyUriAsync(bot, chatId, user.Id, clientId, ct);
                else if (TryParseKeyCallback(data, "keyconf", out clientId, out _))
                    await SendKeyFileAsync(bot, chatId, user.Id, clientId, ct);
                else if (data.StartsWith("newkey:"))
                {
                    var serverId = data["newkey:".Length..];
                    await ShowProtocolSelectionAsync(bot, chatId, messageId, serverId, ct);
                }
                break;
        }
    }

    // ── Screens ───────────────────────────────────────────────────────────────

    private static Task SendMainMenuAsync(ITelegramBotClient bot, long chatId, string text, CancellationToken ct)
        => bot.SendMessage(chatId, text, replyMarkup: MainMenuKeyboard(), cancellationToken: ct);

    private static Task EditMainMenuAsync(ITelegramBotClient bot, long chatId, int messageId, string text, CancellationToken ct)
        => bot.EditMessageText(chatId, messageId, text, replyMarkup: MainMenuKeyboard(), cancellationToken: ct);

    private async Task SendServerListAsync(ITelegramBotClient bot, long chatId, CancellationToken ct)
    {
        var message = await bot.SendMessage(chatId, "Загружаю список серверов…", cancellationToken: ct);
        await ShowServerListAsync(bot, chatId, message.MessageId, ct);
    }

    private async Task SendMyKeysAsync(ITelegramBotClient bot, long chatId, string userId, CancellationToken ct)
    {
        var message = await bot.SendMessage(chatId, "Загружаю ключи…", cancellationToken: ct);
        await ShowMyKeysAsync(bot, chatId, message.MessageId, userId, ct);
    }

    private async Task ShowServerListAsync(ITelegramBotClient bot, long chatId, int messageId, CancellationToken ct)
    {
        var servers = await _servers.GetAllAsync(ct);
        if (servers.Count == 0)
        {
            await bot.EditMessageText(chatId, messageId,
                "Серверов пока нет.",
                replyMarkup: BackKeyboard(), cancellationToken: ct);
            return;
        }

        var rows = servers
            .Select(s => new[] { InlineKeyboardButton.WithCallbackData(
                s.Name, $"server:{s.Id}") })
            .Append(new[] { InlineKeyboardButton.WithCallbackData("⬅️ Назад", "cmd:menu") })
            .ToArray();

        await bot.EditMessageText(chatId, messageId,
            "Выберите сервер:",
            replyMarkup: new InlineKeyboardMarkup(rows),
            cancellationToken: ct);
    }

    private async Task ShowMyKeysAsync(ITelegramBotClient bot, long chatId, int messageId, string userId, CancellationToken ct)
    {
        var clientConfigs = await _clients.GetByUserIdAsync(userId, ct);
        if (clientConfigs.Count == 0)
        {
            await bot.EditMessageText(chatId, messageId,
                "У вас нет активных ключей.",
                replyMarkup: BackKeyboard(), cancellationToken: ct);
            return;
        }

        var servers   = await _servers.GetAllAsync(ct);
        var serverMap = servers.ToDictionary(s => s.Id, s => s.Name);

        var rows = clientConfigs.Select((c, i) =>
        {
            var name = serverMap.TryGetValue(c.ServerId, out var n) ? n : c.ServerId;
            return new[]
            {
                InlineKeyboardButton.WithCallbackData(
                    KeyButtonLabel(name, c, i), KeyCallback("key", c.Id, "m"))
            };
        })
        .Append(new[] { InlineKeyboardButton.WithCallbackData("⬅️ Назад", "cmd:menu") })
        .ToArray();

        await bot.EditMessageText(chatId, messageId,
            "Ваши активные ключи. Выберите ключ, чтобы получить URI или файл .conf:",
            replyMarkup: new InlineKeyboardMarkup(rows), cancellationToken: ct);
    }

    private async Task HandleServerSelectedAsync(
        ITelegramBotClient bot, long chatId, int messageId,
        string userId, string serverId, CancellationToken ct)
    {
        var keys = await _clients.GetByUserIdAndServerAsync(userId, serverId, ct);

        if (keys.Count > 0)
        {
            await bot.EditMessageText(chatId, messageId,
                $"У вас {keys.Count} {PluralKeys(keys.Count)} для этого сервера.",
                replyMarkup: new InlineKeyboardMarkup(new[]
                {
                    new[] { InlineKeyboardButton.WithCallbackData("📋 Мои ключи для сервера", $"serverkeys:{serverId}") },
                    new[] { InlineKeyboardButton.WithCallbackData("➕ Новый ключ",             $"newkey:{serverId}") },
                    new[] { InlineKeyboardButton.WithCallbackData("⬅️ Назад",                 "cmd:servers") }
                }),
                cancellationToken: ct);
        }
        else
        {
            await ShowProtocolSelectionAsync(bot, chatId, messageId, serverId, ct);
        }
    }

    private async Task ShowServerKeysAsync(
        ITelegramBotClient bot, long chatId, int messageId,
        string userId, string serverId, CancellationToken ct)
    {
        var keys = await _clients.GetByUserIdAndServerAsync(userId, serverId, ct);

        var rows = keys
            .Select((k, i) => new[]
            {
                InlineKeyboardButton.WithCallbackData($"🔑 #{i + 1} — {ProtocolKinds.DisplayName(k.ProtocolKind ?? "")} — {k.AssignedIp}", KeyCallback("key", k.Id, "s"))
            })
            .Append(new[] { InlineKeyboardButton.WithCallbackData("➕ Новый ключ", $"newkey:{serverId}") })
            .Append(new[] { InlineKeyboardButton.WithCallbackData("⬅️ Назад",     $"server:{serverId}") })
            .ToArray();

        await bot.EditMessageText(chatId, messageId,
            "Выберите ключ или создайте новый:",
            replyMarkup: new InlineKeyboardMarkup(rows),
            cancellationToken: ct);
    }

    private async Task ShowKeyActionsAsync(
        ITelegramBotClient bot, long chatId, int messageId, string userId,
        string clientId, string origin, CancellationToken ct)
    {
        var client = await GetOwnedActiveClientAsync(userId, clientId, ct);
        if (client is null)
        {
            await ShowUnavailableKeyAsync(bot, chatId, messageId, ct);
            return;
        }

        try
        {
            var vpnUri = await BuildVpnUriAsync(client, ct);
            var rows = new List<InlineKeyboardButton[]>();

            if (vpnUri.Length <= CopyTextButtonMaxLength)
            {
                rows.Add(new[]
                {
                    InlineKeyboardButton.WithCopyText("📋 Скопировать VPN URI", vpnUri)
                });
            }

            rows.Add(new[]
            {
                InlineKeyboardButton.WithCallbackData(
                    vpnUri.Length <= CopyTextButtonMaxLength
                        ? "👁 Показать VPN URI"
                        : "📋 Показать VPN URI для копирования",
                    KeyCallback("keyuri", client.Id, origin))
            });
            rows.Add(new[]
            {
                InlineKeyboardButton.WithCallbackData(
                    "📃 Скачать .conf", KeyCallback("keyconf", client.Id, origin))
            });
            rows.Add(new[]
            {
                InlineKeyboardButton.WithCallbackData("⬅️ Назад", KeyBackCallback(client, origin))
            });

            await bot.EditMessageText(chatId, messageId,
                $"🔑 Ключ {KeyDisplayName(client)}\n\nВыберите, как получить конфигурацию:",
                replyMarkup: new InlineKeyboardMarkup(rows), cancellationToken: ct);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Не удалось подготовить опции для ключа {ClientId}", client.Id);
            await bot.EditMessageText(chatId, messageId,
                "Не удалось подготовить конфигурацию. Попробуйте позже.",
                replyMarkup: KeyBackKeyboard(client, origin), cancellationToken: ct);
        }
    }

    private async Task SendKeyUriAsync(
        ITelegramBotClient bot, long chatId, string userId, string clientId, CancellationToken ct)
    {
        var client = await GetOwnedActiveClientAsync(userId, clientId, ct);
        if (client is null)
        {
            await bot.SendMessage(chatId, "Ключ не найден или недоступен.", cancellationToken: ct);
            return;
        }

        try
        {
            var vpnUri = await BuildVpnUriAsync(client, ct);
            if (vpnUri.Length <= TelegramMessageMaxLength)
            {
                await bot.SendMessage(chatId, vpnUri, cancellationToken: ct);
                return;
            }

            await bot.SendMessage(chatId,
                "VPN URI не помещается в сообщение. Отправлю его в текстовом файле:",
                cancellationToken: ct);
            await SendDocumentAsync(bot, chatId, "vpn-uri.txt", vpnUri, ct);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Не удалось отправить VPN URI ключа {ClientId}", client.Id);
            await bot.SendMessage(chatId,
                "Не удалось получить VPN URI. Попробуйте позже.", cancellationToken: ct);
        }
    }

    private async Task SendKeyFileAsync(
        ITelegramBotClient bot, long chatId, string userId, string clientId, CancellationToken ct)
    {
        var client = await GetOwnedActiveClientAsync(userId, clientId, ct);
        if (client is null)
        {
            await bot.SendMessage(chatId, "Ключ не найден или недоступен.", cancellationToken: ct);
            return;
        }

        try
        {
            var file = await BuildClientFileAsync(client, ct);
            await SendDocumentAsync(bot, chatId, file.FileName, file.Content, ct,
                "Конфигурация AmneziaVPN");
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Не удалось отправить .conf ключа {ClientId}", client.Id);
            await bot.SendMessage(chatId,
                "Не удалось получить файл .conf. Попробуйте позже.", cancellationToken: ct);
        }
    }

    private async Task<VpnClient?> GetOwnedActiveClientAsync(string userId, string clientId, CancellationToken ct)
    {
        var client = await _clients.FindByIdAsync(clientId, ct);
        return client is { IsActive: true } && client.UserId == userId ? client : null;
    }

    private async Task<string> BuildVpnUriAsync(VpnClient client, CancellationToken ct)
    {
        using var scope = _scopeFactory.CreateScope();
        var reader = scope.ServiceProvider.GetRequiredService<IVpnConfigReader>();
        return await reader.BuildVpnUriAsync(client, ct);
    }

    private async Task<ClientFile> BuildClientFileAsync(VpnClient client, CancellationToken ct)
    {
        using var scope = _scopeFactory.CreateScope();
        var reader = scope.ServiceProvider.GetRequiredService<IVpnConfigReader>();
        return await reader.BuildClientFileAsync(client, ct);
    }

    private static async Task SendDocumentAsync(
        ITelegramBotClient bot, long chatId, string fileName, string content, CancellationToken ct,
        string? caption = null)
    {
        await using var stream = new MemoryStream(System.Text.Encoding.UTF8.GetBytes(content), writable: false);
        await bot.SendDocument(chatId, InputFile.FromStream(stream, fileName), caption: caption, cancellationToken: ct);
    }

    private static Task ShowUnavailableKeyAsync(
        ITelegramBotClient bot, long chatId, int messageId, CancellationToken ct)
        => bot.EditMessageText(chatId, messageId,
            "Ключ не найден или недоступен.",
            replyMarkup: BackKeyboard(), cancellationToken: ct);

    private static bool TryParseKeyCallback(
        string data, string action, out string clientId, out string origin)
    {
        var parts = data.Split(':');
        if (parts is [var callbackAction, var id, var source]
            && callbackAction == action
            && source is "m" or "s"
            && ObjectId.TryParse(id, out _))
        {
            clientId = id;
            origin = source;
            return true;
        }

        clientId = string.Empty;
        origin = string.Empty;
        return false;
    }

    private static string KeyCallback(string action, string clientId, string origin)
        => $"{action}:{clientId}:{origin}";

    private static string KeyBackCallback(VpnClient client, string origin)
        => origin == "s" ? $"serverkeys:{client.ServerId}" : "cmd:mykeys";

    private static InlineKeyboardMarkup KeyBackKeyboard(VpnClient client, string origin) => new(new[]
    {
        new[] { InlineKeyboardButton.WithCallbackData("⬅️ Назад", KeyBackCallback(client, origin)) }
    });

    private static string KeyDisplayName(VpnClient client)
        => client.AssignedIp ?? client.ShortId ?? "без IP";

    private static string KeyButtonLabel(string serverName, VpnClient client, int index)
    {
        var name = serverName.Length > 32 ? serverName[..29] + "..." : serverName;
        return $"🔑 {name} — {client.AssignedIp ?? client.ShortId ?? $"Ключ #{index + 1}"}";
    }

    /// <summary>
    /// Больше не заводит peer сам — публикует заявку key.issue и отвечает
    /// «готовлю». Выбор способа получения присылает <see cref="KeyIssuedNotificationHandler"/>
    /// по событию notify.key_issued, которое worker публикует по завершении
    /// выдачи.
    /// </summary>
    private async Task CreateNewVpnConfigAsync(
        ITelegramBotClient bot, long chatId, int messageId,
        string userId, string serverId, string protocolId, CancellationToken ct)
    {
        // Проверяем сервер здесь: узел worker не читает синхронно, и NotFoundException
        // из IVpnConfigService, которым раньше ловилась эта ситуация, теперь
        // некому бросить — бот вообще не открывает SSH.
        var server = await _servers.GetByIdAsync(serverId, ct);
        if (server is null)
        {
            await bot.EditMessageText(chatId, messageId,
                "Сервер не найден. Возможно, он был удалён.",
                replyMarkup: BackKeyboard(), cancellationToken: ct);
            return;
        }

        if (server.IssuanceProtocol(protocolId) is null)
        {
            await ShowProtocolSelectionAsync(bot, chatId, messageId, serverId, ct);
            return;
        }

        await bot.EditMessageText(chatId, messageId,
            "⏳ Готовлю ключ… после создания предложу VPN URI или файл .conf",
            cancellationToken: ct);

        // Идентификатор назначаем здесь же — по нему KeyIssueHandler.OnFailedAsync
        // отличает «выдача не состоялась» от «состоялась, но событие не закрылось».
        var keyId = ObjectId.GenerateNewId().ToString();

        try
        {
            await _events.PublishAsync(
                DomainEventTypes.KeyIssue,
                new KeyIssuePayload(
                    KeyId: keyId,
                    ServerId: serverId,
                    OwnerUserId: userId,
                    OwnerCreated: false,
                    ProtocolId: protocolId,
                    OwnerName: null,
                    DeviceName: null,
                    Label: null,
                    ExpiryDays: null,
                    TrafficLimitBytes: null,
                    Source: KeySources.Telegram,
                    CreatedByUserId: null,
                    Notify: new TelegramTarget(chatId, messageId)),
                partitionKey: serverId,
                correlationId: keyId,
                actorUserId: userId,
                ct);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Не удалось опубликовать заявку на выдачу ключа userId={UserId} serverId={ServerId}", userId, serverId);
            await bot.EditMessageText(chatId, messageId,
                "Ошибка при создании ключа. Попробуйте позже.",
                replyMarkup: BackKeyboard(), cancellationToken: ct);
        }
    }

    private async Task ShowProtocolSelectionAsync(ITelegramBotClient bot, long chatId, int messageId,
        string serverId, CancellationToken ct)
    {
        var server = await _servers.GetByIdAsync(serverId, ct);
        var protocols = server?.Protocols.Where(server.CanIssue).ToList() ?? [];
        var rows = protocols.Select(p => new[] {
            InlineKeyboardButton.WithCallbackData(ProtocolKinds.DisplayName(p.Kind), $"np:{serverId}:{p.Id}")
        }).Append(new[] { InlineKeyboardButton.WithCallbackData("⬅️ Назад", $"server:{serverId}") }).ToArray();
        await bot.EditMessageText(chatId, messageId,
            protocols.Count == 0 ? "На сервере сейчас нет протоколов для выдачи новых ключей."
                : $"Выберите протокол для нового ключа на сервере «{server!.Name}». Для AmneziaWG 3.1 нужен актуальный AmneziaVPN.",
            replyMarkup: new InlineKeyboardMarkup(rows), cancellationToken: ct);
    }

    private static string PluralKeys(int count) => count switch
    {
        1 => "ключ",
        2 or 3 or 4 => "ключа",
        _ => "ключей"
    };

    // ── Keyboards ─────────────────────────────────────────────────────────────

    private static InlineKeyboardMarkup MainMenuKeyboard() => new(new[]
    {
        new[] { InlineKeyboardButton.WithCallbackData("📋 Список серверов", "cmd:servers") },
        new[] { InlineKeyboardButton.WithCallbackData("🔑 Мои ключи",       "cmd:mykeys") }
    });

    private static InlineKeyboardMarkup BackKeyboard() => new(new[]
    {
        new[] { InlineKeyboardButton.WithCallbackData("⬅️ Назад", "cmd:menu") }
    });
}
