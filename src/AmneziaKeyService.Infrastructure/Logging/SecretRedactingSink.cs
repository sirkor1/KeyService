using AmneziaKeyService.Infrastructure.Services;
using Serilog;
using Serilog.Configuration;
using Serilog.Core;
using Serilog.Events;
using Serilog.Parsing;

namespace AmneziaKeyService.Infrastructure.Logging;

/// <summary>
/// Прогоняет каждое событие через <see cref="SecretRedactor"/> перед записью
/// в нижележащий сток.
///
/// Зачем обёртка стока, а не дисциплина на местах. До появления Seq логи жили
/// в <c>docker logs</c> одного контейнера и умирали вместе с ним, поэтому
/// точечных вызовов <c>Redact</c> на выводе SSH хватало. Внешнее хранилище
/// меняет цену ошибки: одной новой строки <c>LogDebug</c> с сырым выводом
/// <c>wg show dump</c> достаточно, чтобы приватный ключ сервера осел в базе
/// Seq и пережил там и удаление узла, и пересоздание контейнера. Обёртка
/// делает редактирование свойством транспорта: чтобы секрет утёк, недостаточно
/// написать неосторожный вызов логгера — надо специально снять этот слой.
///
/// Обрабатываются оба канала, которыми секрет может пройти:
/// строковые свойства события и текст самого сообщения.
/// </summary>
public class SecretRedactingSink : ILogEventSink
{
    private readonly ILogEventSink _inner;

    public SecretRedactingSink(ILogEventSink inner) => _inner = inner;

    public void Emit(LogEvent logEvent)
    {
        _inner.Emit(Redact(logEvent));
    }

    private static LogEvent Redact(LogEvent logEvent)
    {
        var properties = RedactProperties(logEvent);
        var template   = RedactTemplate(logEvent);

        if (properties is null && template is null) return logEvent;

        var result = new LogEvent(
            logEvent.Timestamp,
            logEvent.Level,
            logEvent.Exception,
            template ?? logEvent.MessageTemplate,
            properties ?? logEvent.Properties.Select(p =>
                new LogEventProperty(p.Key, p.Value)));

        return result;
    }

    /// <summary>
    /// Заменяет строковые свойства на очищенные. Null — ни одно свойство
    /// не изменилось, и пересобирать событие незачем.
    /// </summary>
    private static List<LogEventProperty>? RedactProperties(LogEvent logEvent)
    {
        List<LogEventProperty>? redacted = null;

        foreach (var (name, value) in logEvent.Properties)
        {
            var replacement = RedactValue(value);
            if (replacement is null) continue;

            // Первое же изменение заставляет скопировать весь набор:
            // коллекция свойств события неизменяема.
            redacted ??= [.. logEvent.Properties.Select(p => new LogEventProperty(p.Key, p.Value))];

            var index = redacted.FindIndex(p => p.Name == name);
            if (index >= 0) redacted[index] = new LogEventProperty(name, replacement);
        }

        return redacted;
    }

    /// <summary>
    /// Очищает скалярное строковое значение. Составные значения (списки,
    /// структуры) не разбираем: в этом коде их не логируют, а рекурсивный
    /// обход ради гипотетического случая усложнил бы горячий путь.
    /// Текст сообщения при этом всё равно проверяется целиком — см. ниже.
    /// </summary>
    private static LogEventPropertyValue? RedactValue(LogEventPropertyValue value)
    {
        if (value is not ScalarValue { Value: string text }) return null;

        var clean = SecretRedactor.Redact(text);
        return clean == text ? null : new ScalarValue(clean);
    }

    /// <summary>
    /// Проверяет текст шаблона и, если секрет нашёлся прямо в нём,
    /// заменяет шаблон плоским текстом.
    ///
    /// Так ловится интерполяция: <c>LogDebug($"dump: {raw}")</c> не создаёт
    /// свойств вовсе — весь секрет попадает в текст шаблона, до которого
    /// обработка свойств не достаёт. Плейсхолдеры при такой замене перестают
    /// подставляться, но происходит это только с событиями, где что-то
    /// действительно вырезано, — и остаться с невнятным сообщением лучше,
    /// чем с приватным ключом в базе логов.
    /// </summary>
    private static MessageTemplate? RedactTemplate(LogEvent logEvent)
    {
        var text = logEvent.MessageTemplate.Text;

        var clean = SecretRedactor.Redact(text);
        if (clean == text) return null;

        return new MessageTemplate(clean, [new TextToken(clean)]);
    }
}

public static class SecretRedactingSinkExtensions
{
    /// <summary>
    /// Оборачивает стоки редактированием секретов:
    /// <c>WriteTo.RedactingSecrets(to =&gt; to.Seq(...))</c>.
    /// </summary>
    public static LoggerConfiguration RedactingSecrets(
        this LoggerSinkConfiguration configuration,
        Action<LoggerSinkConfiguration> configureWrapped)
        => LoggerSinkConfiguration.Wrap(
            configuration,
            inner => new SecretRedactingSink(inner),
            configureWrapped,
            LevelAlias.Minimum,
            levelSwitch: null);
}
