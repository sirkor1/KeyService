using AmneziaKeyService.Bot.Services;
using AmneziaKeyService.Infrastructure.DependencyInjection;
using AmneziaKeyService.Infrastructure.Events;
using AmneziaKeyService.Infrastructure.Logging;
using AmneziaKeyService.Infrastructure.Migrations;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Telegram.Bot;

// Telegram-бот: пользователь вводит пригласительный код, выбирает узел
// и получает ссылку vpn://.
//
// Отдельный процесс, а не хост внутри API: у бота своя связность с внешним
// миром (long polling к api.telegram.org) и свой темп отказов. Токен теперь
// нужен только здесь.
//
// SSH в этом процессе нет: выдачу ключа бот только заказывает публикацией
// key.issue, а заводит peer worker — см. KeyIssuedNotificationHandler.

var host = Host.CreateDefaultBuilder(args)
    .UseAmneziaLogging("bot")
    .ConfigureServices((context, services) =>
    {
        var config = context.Configuration;
        var telegramToken = config["TelegramBot:Token"];

        services.AddAmneziaData(config);
        services.AddAmneziaMigrations();
        services.AddAmneziaProtocols();

        // Клиент Telegram, диспетчер событий и обработчик уведомления
        // регистрируются вместе и только при заданном токене.
        // TelegramBotClient не строится на пустой строке, а диспетчер без
        // клиента забирал бы notify.key_issued и ронял обработчик — они
        // копились бы в failed, и после того как токен появится, пользователь
        // так ничего бы и не получил.
        if (!string.IsNullOrWhiteSpace(telegramToken))
        {
            services.AddSingleton<ITelegramBotClient>(_ => new TelegramBotClient(telegramToken));
            services.AddAmneziaEventProcessing(config);
            services.AddScoped<IDomainEventHandler, KeyIssuedNotificationHandler>();
        }

        // Схему правит worker. Бот дожидается, а не мигрирует сам:
        // три раннера на одной базе дали бы гонку на _migrations.
        services.AddHostedService<MongoSchemaGate>();
        services.AddHostedService<TelegramBotService>();
    })
    .Build();

await host.RunAsync();
