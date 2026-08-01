namespace AmneziaKeyService.Core.Models;

/// <summary>
/// Аргументы доменных событий.
///
/// Записи намеренно тощие: событие ссылается на документ, а не копирует его.
/// Копия разошлась бы с оригиналом — задача установки правится по ходу работы,
/// и аргументы события устарели бы к моменту исполнения.
/// </summary>
public record ServerInstallPayload(string JobId);

/// <summary>Куда в Telegram доставить уведомление: чат и, если есть, сообщение для правки.</summary>
public record TelegramTarget(long ChatId, int? MessageId);

/// <summary>
/// Заявка на выдачу ключа.
///
/// Толще принципа «событие ссылается на документ, а не копирует его» из
/// шапки файла намеренно: на момент публикации документа ключа ещё нет —
/// событие и есть заявка на его создание, ссылаться не на что.
///
/// <see cref="ExpiryDays"/> и <see cref="TrafficLimitBytes"/> приходят уже
/// нормализованными продюсером: 0 означает «без ограничения», null — «взять
/// из настроек панели». Обработчик подстановкой по умолчанию не занимается.
///
/// Секретов здесь нет — приватный ключ клиента и PSK рождаются на узле
/// внутри обработчика, а не приходят с заявкой.
/// </summary>
public record KeyIssuePayload(
    string KeyId, string ServerId, string OwnerUserId, bool OwnerCreated,
    string? ProtocolId, string? OwnerName, string? DeviceName, string? Label,
    int? ExpiryDays, long? TrafficLimitBytes, string Source,
    string? CreatedByUserId, TelegramTarget? Notify);

/// <summary>Заявка на отзыв ключа. Ключ уже существует — ссылка на него достаточна.</summary>
public record KeyRevokePayload(
    string KeyId, string Reason, string? RevokedByUserId, string? Comment);

/// <summary>
/// Результат выдачи для бота. Worker не интерпретирует поля — просто копирует
/// их из <see cref="KeyIssuePayload.Notify"/> и заполняет <see cref="Error"/>
/// при неудаче; читает и превращает в текст сообщения только бот.
/// </summary>
public record NotifyKeyIssuedPayload(
    string? KeyId, string? ServerName, string? Error, TelegramTarget Target);
