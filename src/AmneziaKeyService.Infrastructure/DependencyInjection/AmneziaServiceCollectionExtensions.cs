using AmneziaKeyService.Core.Interfaces;
using AmneziaKeyService.Core.Models;
using AmneziaKeyService.Infrastructure.Events;
using AmneziaKeyService.Infrastructure.Install;
using AmneziaKeyService.Infrastructure.Migrations;
using AmneziaKeyService.Infrastructure.Protocols;
using AmneziaKeyService.Infrastructure.Repositories;
using AmneziaKeyService.Infrastructure.Scripts;
using AmneziaKeyService.Infrastructure.Services;
using AmneziaKeyService.Infrastructure.Ssh;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using MongoDB.Driver;

namespace AmneziaKeyService.Infrastructure.DependencyInjection;

/// <summary>
/// Композиция сервиса, разложенная по слоям доступа.
///
/// Процессов теперь три — api, worker и bot, — и у них разные права на узлы.
/// Три копии одного списка регистраций разошлись бы на первой правке, поэтому
/// список один, а разделение проходит по границам методов: кто не вызвал
/// <see cref="AddAmneziaNodeAccess"/>, тот физически не может открыть SSH,
/// потому что в его контейнере нет <see cref="ISshSessionFactory"/>.
/// </summary>
public static class AmneziaServiceCollectionExtensions
{
    /// <summary>
    /// База, нужная всем трём процессам: настройки, MongoDB, репозитории,
    /// шифрование секретов и журнал.
    /// </summary>
    public static IServiceCollection AddAmneziaData(
        this IServiceCollection services, IConfiguration config)
    {
        services.Configure<MongoDbOptions>(config.GetSection("MongoDb"));
        services.Configure<SecurityOptions>(config.GetSection("Security"));

        services.AddSingleton<IMongoClient>(_ =>
            new MongoClient(config["MongoDb:ConnectionString"]));

        // Синглтоны: держат IMongoCollection, которая потокобезопасна
        // и не имеет состояния.
        services.AddSingleton<IUserRepository, UserRepository>();
        services.AddSingleton<IRefreshSessionRepository, RefreshSessionRepository>();
        services.AddSingleton<IVpnClientRepository, VpnClientRepository>();
        services.AddSingleton<IVpnServerRepository, VpnServerRepository>();
        services.AddSingleton<IPassCodeRepository, PassCodeRepository>();
        services.AddSingleton<IAuditLogRepository, AuditLogRepository>();
        services.AddSingleton<IPanelSettingsRepository, PanelSettingsRepository>();
        services.AddSingleton<IInstallJobRepository, InstallJobRepository>();
        services.AddSingleton<IUsageRepository, UsageRepository>();
        services.AddSingleton<INotificationRepository, NotificationRepository>();

        services.AddSingleton<ISecretProtector, AesGcmSecretProtector>();
        services.AddScoped<IAuditService, AuditService>();

        // Публикация событий доступна всем: просить о работе может кто угодно,
        // исполняет её только тот, кто вызвал AddAmneziaEventProcessing.
        services.AddSingleton<DomainEventRepository>();
        services.AddSingleton<IDomainEventRepository>(sp => sp.GetRequiredService<DomainEventRepository>());
        services.AddSingleton<IDomainEventPublisher>(sp => sp.GetRequiredService<DomainEventRepository>());
        services.AddSingleton<ILeaseRepository, LeaseRepository>();

        return services;
    }

    /// <summary>
    /// Исполнение событий: диспетчер, жнец просроченных аренд и каталог
    /// обработчиков. Сами обработчики регистрирует процесс — набор у worker
    /// и у бота разный.
    /// </summary>
    public static IServiceCollection AddAmneziaEventProcessing(
        this IServiceCollection services, IConfiguration config)
    {
        services.Configure<EventBusOptions>(config.GetSection("EventBus"));

        services.AddSingleton<DomainEventCatalog>();
        services.AddHostedService<EventDispatcher>();
        services.AddHostedService<ExpiredEventReaper>();

        return services;
    }

    /// <summary>
    /// Список миграций. Регистрируется во всех процессах, но применяет их
    /// только worker: остальным он нужен, чтобы знать, чего ждать —
    /// см. <see cref="MongoSchemaGate"/>.
    /// </summary>
    public static IServiceCollection AddAmneziaMigrations(this IServiceCollection services)
    {
        services.AddSingleton<IMongoMigration, M001_UsersRoles>();
        services.AddSingleton<IMongoMigration, M002_UnsetNullTelegramId>();
        services.AddSingleton<IMongoMigration, M003_ServersV2>();
        services.AddSingleton<IMongoMigration, M004_ClientsV2>();
        services.AddSingleton<IMongoMigration, M005_Indexes>();
        services.AddSingleton<IMongoMigration, M006_UniqueAssignedIpIndex>();
        services.AddSingleton<IMongoMigration, M007_RepairProtocolIds>();
        services.AddSingleton<IMongoMigration, M008_InstallJobIndexes>();
        services.AddSingleton<IMongoMigration, M009_UsageIndexes>();
        services.AddSingleton<IMongoMigration, M010_DomainEvents>();
        services.AddSingleton<IMongoMigration, M011_RefreshSessions>();
        services.AddSingleton<IMongoMigration, M012_DropLegacy>();
        services.AddSingleton<IMongoMigration, M013_Notifications>();

        return services;
    }

    /// <summary>
    /// Протоколы: генерация ключей, аллокатор адресов и конфигураторы.
    ///
    /// SSH здесь не нужен, и это не случайность: конфигуратор получает
    /// <see cref="ISshSession"/> параметром метода, а не в конструктор.
    /// Поэтому api может собирать ссылку vpn:// и клиентский файл, ни разу
    /// не подключившись к узлу — <see cref="IVpnConfigReader"/> регистрируется
    /// здесь же, отдельно от выдачи ключей, требующей SSH.
    /// </summary>
    public static IServiceCollection AddAmneziaProtocols(this IServiceCollection services)
    {
        services.AddSingleton<ScriptRegistry>();
        services.AddScoped<KeyGenerationService>();
        services.AddScoped<IpAllocator>();

        // Семейство WireGuard обслуживает один конфигуратор, параметризованный
        // профилем: awg2, awg legacy и обычный WireGuard различаются четырьмя
        // значениями.
        services.AddScoped<IProtocolConfigurator>(sp => WireGuard(sp, WireGuardProfile.Awg3));
        services.AddScoped<IProtocolInstaller>(sp =>
            new WireGuardInstaller(WireGuardInstallProfile.Awg3, sp.GetRequiredService<ScriptRegistry>()));
        services.AddScoped<IProtocolConfigurator>(sp => WireGuard(sp, WireGuardProfile.Awg2));
        services.AddScoped<IProtocolConfigurator>(sp => WireGuard(sp, WireGuardProfile.AwgLegacy));
        services.AddScoped<IProtocolConfigurator>(sp => WireGuard(sp, WireGuardProfile.WireGuard));

        services.AddScoped<IProtocolConfigurator, XrayConfigurator>();
        services.AddScoped<IProtocolRegistry, ProtocolRegistry>();
        services.AddScoped<IVpnConfigReader, VpnConfigReader>();

        // Инсталляторы тоже SSH не требуют: сессию они получают параметром.
        // Api нужен их реестр, чтобы отклонить установку неподдерживаемого
        // протокола до создания задачи.
        services.AddScoped<IProtocolInstaller>(sp =>
            new WireGuardInstaller(WireGuardInstallProfile.Awg2, sp.GetRequiredService<ScriptRegistry>()));
        services.AddScoped<IProtocolInstaller>(sp =>
            new WireGuardInstaller(WireGuardInstallProfile.AwgLegacy, sp.GetRequiredService<ScriptRegistry>()));
        services.AddScoped<IProtocolInstaller>(sp =>
            new WireGuardInstaller(WireGuardInstallProfile.WireGuard, sp.GetRequiredService<ScriptRegistry>()));
        services.AddScoped<IProtocolInstaller, XrayInstaller>();
        services.AddScoped<IProtocolInstallerRegistry, ProtocolInstallerRegistry>();

        return services;
    }

    /// <summary>
    /// Доступ к узлам по SSH: сессии, инсталляторы, оркестратор установки
    /// и выдача ключей.
    ///
    /// Регистрируется **только в worker**. Это и есть граница, ради которой
    /// затевалось разделение процессов: веб-процесс не должен открывать
    /// SSH-соединения к боевым узлам из обработчика HTTP-запроса.
    /// </summary>
    public static IServiceCollection AddAmneziaNodeAccess(this IServiceCollection services)
    {
        services.AddScoped<ISshSessionFactory, SshSessionFactory>();
        services.AddScoped<IServerParamsService, ServerParamsService>();

        return services;
    }

    /// <summary>
    /// Исполнение установки. Регистрируется **только в worker**: минуты сборки
    /// образа на узле не место в процессе, отдающем панель, и перезапуск ради
    /// правки контроллера не должен обрывать установку.
    ///
    /// Api создаёт задачу и публикует событие, но оркестратора у него нет.
    /// </summary>
    public static IServiceCollection AddAmneziaInstallExecution(this IServiceCollection services)
    {
        services.AddScoped<InstallOrchestrator>();
        return services;
    }

    /// <summary>
    /// Выдача и отзыв ключей.
    ///
    /// Требует <see cref="AddAmneziaNodeAccess"/>: заведение peer-а идёт
    /// по SSH. Сборка ссылки vpn:// и клиентского файла узла не требует —
    /// это <see cref="IVpnConfigReader"/> из <see cref="AddAmneziaProtocols"/>,
    /// здесь остаётся только писатель.
    /// </summary>
    public static IServiceCollection AddAmneziaKeyIssuing(this IServiceCollection services)
    {
        services.AddScoped<IVpnConfigService, VpnConfigService>();
        return services;
    }

    private static WireGuardConfigurator WireGuard(IServiceProvider sp, WireGuardProfile profile)
        => new(
            profile,
            sp.GetRequiredService<ScriptRegistry>(),
            sp.GetRequiredService<KeyGenerationService>(),
            sp.GetRequiredService<IpAllocator>());
}
