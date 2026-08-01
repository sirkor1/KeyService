using Microsoft.Extensions.Hosting;
using Serilog;

namespace AmneziaKeyService.Infrastructure.Logging;

/// <summary>
/// Единый бутстрап логирования для всех процессов сервиса.
///
/// Живёт в Infrastructure, а не в каждом хосте, ради одного свойства:
/// обёртка редактирования секретов должна стоять на всех стоках во всех
/// процессах. Скопированный в три Program.cs код рано или поздно разошёлся бы,
/// и разошёлся бы он молча — узнать об этом можно было бы только найдя
/// приватный ключ в базе Seq.
/// </summary>
public static class AmneziaLoggingExtensions
{
    /// <param name="applicationName">
    /// Различает процессы в общем потоке Seq: запрос
    /// <c>Application = 'worker'</c> отделяет фоновую работу от HTTP.
    /// </param>
    public static IHostBuilder UseAmneziaLogging(
        this IHostBuilder host, string applicationName)
        => host.UseSerilog((context, services, configuration) => configuration
            // Уровни и переопределения по неймспейсам читаются из секции Serilog —
            // так «Infrastructure.Monitoring» можно временно поднять до Debug
            // переменной окружения, не пересобирая образ.
            .ReadFrom.Configuration(context.Configuration)
            .ReadFrom.Services(services)
            .Enrich.FromLogContext()
            .Enrich.WithProperty("Application", applicationName)
            .Enrich.WithProperty("Environment", context.HostingEnvironment.EnvironmentName)
            .Enrich.WithProperty("MachineName", Environment.MachineName)
            // Оба стока внутри обёртки: docker logs тоже нередко куда-то уезжают,
            // и держать редактирование только на одном канале было бы половинчато.
            .WriteTo.RedactingSecrets(to =>
            {
                // Консоль остаётся всегда: при недоступном Seq процесс
                // не должен ослепнуть.
                to.Console();

                var seqUrl = context.Configuration["Seq:ServerUrl"];
                if (!string.IsNullOrWhiteSpace(seqUrl))
                    to.Seq(seqUrl, apiKey: context.Configuration["Seq:ApiKey"]);
            }));
}
