using AmneziaKeyService.Core.Models;
using AmneziaKeyService.Infrastructure.DependencyInjection;
using AmneziaKeyService.Infrastructure.Events;
using AmneziaKeyService.Infrastructure.Install;
using AmneziaKeyService.Infrastructure.Keys;
using AmneziaKeyService.Infrastructure.Logging;
using AmneziaKeyService.Infrastructure.Migrations;
using AmneziaKeyService.Infrastructure.Monitoring;
using AmneziaKeyService.Infrastructure.Services;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

// Фоновая часть сервиса: миграции схемы, сидирование владельца и четыре
// воркера эксплуатации — статистика, здоровье узлов, сроки с квотами и сверка
// peer-ов.
//
// Отдельный процесс, потому что эта работа не имеет отношения к HTTP: опрос
// узлов идёт по SSH минутами, а перезапуск ради правки контроллера панели
// не должен её прерывать.

var host = Host.CreateDefaultBuilder(args)
    .UseAmneziaLogging("worker")
    .ConfigureServices((context, services) =>
    {
        var config = context.Configuration;

        services.Configure<AdminOptions>(config.GetSection("Admin"));
        services.Configure<PollingOptions>(config.GetSection("Polling"));

        services.AddAmneziaData(config);
        services.AddAmneziaMigrations();
        services.AddAmneziaProtocols();
        services.AddAmneziaNodeAccess();
        services.AddAmneziaInstallExecution();
        services.AddAmneziaKeyIssuing();
        services.AddScoped<RouterObservationService>();

        // Шина событий и обработчики. Установка исполняется здесь: она идёт
        // минутами и не должна прерываться перезапуском веб-процесса.
        services.AddAmneziaEventProcessing(config);
        services.AddScoped<IDomainEventHandler, InstallEventHandler>();
        services.AddScoped<IDomainEventHandler, KeyIssueHandler>();
        services.AddScoped<IDomainEventHandler, KeyRevokeHandler>();

        // Порядок важен: миграции применяются до всего остального.
        // Схему правит только этот процесс — api и бот её дожидаются,
        // см. MongoSchemaGate.
        services.AddHostedService<MongoMigrationRunner>();
        services.AddHostedService<AdminSeederService>();

        // Интервалы и общий выключатель — в секции Polling.
        services.AddHostedService<StatsPollerService>();
        services.AddHostedService<HealthPollerService>();
        services.AddHostedService<EnforcementService>();
        services.AddHostedService<ReconcileService>();
    })
    .Build();

await host.RunAsync();
