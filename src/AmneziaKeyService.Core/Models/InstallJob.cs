using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;

namespace AmneziaKeyService.Core.Models;

/// <summary>
/// Долгая операция над узлом: установка, добавление или удаление протокола.
///
/// Живёт в базе, а не только в памяти: установка занимает минуты, панель
/// опрашивает состояние, а при перезапуске сервиса незавершённые задачи
/// должны честно помечаться прерванными.
/// </summary>
[BsonIgnoreExtraElements]
public class InstallJob
{
    [BsonId]
    [BsonRepresentation(BsonType.ObjectId)]
    public string Id { get; set; } = default!;

    [BsonElement("serverId")]
    public string ServerId { get; set; } = default!;

    /// <summary>См. <see cref="InstallJobKinds"/>.</summary>
    [BsonElement("kind")]
    public string Kind { get; set; } = InstallJobKinds.InstallServer;

    /// <summary>Что именно устанавливаем.</summary>
    [BsonElement("spec")]
    public List<ProtocolSpec> Spec { get; set; } = [];

    /// <summary>См. <see cref="InstallJobStatuses"/>.</summary>
    [BsonElement("status")]
    public string Status { get; set; } = InstallJobStatuses.Queued;

    [BsonElement("currentStepCode")]
    public string? CurrentStepCode { get; set; }

    [BsonElement("progressPercent")]
    public int ProgressPercent { get; set; }

    [BsonElement("steps")]
    public List<InstallStep> Steps { get; set; } = [];

    /// <summary>Счётчик строк лога — по нему панель дочитывает хвост.</summary>
    [BsonElement("logSeq")]
    public long LogSeq { get; set; }

    /// <summary>Запрошена отмена. Проверяется на границах шагов.</summary>
    [BsonElement("cancelRequested")]
    public bool CancelRequested { get; set; }

    [BsonElement("error")]
    public string? Error { get; set; }

    [BsonElement("createdAt")]
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    [BsonElement("startedAt")]
    public DateTime? StartedAt { get; set; }

    [BsonElement("finishedAt")]
    public DateTime? FinishedAt { get; set; }

    [BsonElement("createdByUserId")]
    public string? CreatedByUserId { get; set; }

    public bool IsTerminal => InstallJobStatuses.Terminal.Contains(Status);

    public InstallStep? Step(string code) => Steps.FirstOrDefault(s => s.Code == code);
}

/// <summary>Какой протокол и с какими параметрами разворачиваем.</summary>
[BsonIgnoreExtraElements]
public class ProtocolSpec
{
    [BsonElement("kind")]
    public string Kind { get; set; } = default!;

    [BsonElement("port")]
    public string? Port { get; set; }

    [BsonElement("mtu")]
    public string? Mtu { get; set; }

    /// <summary>Подсеть для семейства WireGuard.</summary>
    [BsonElement("subnetAddress")]
    public string? SubnetAddress { get; set; }

    [BsonElement("subnetCidr")]
    public string? SubnetCidr { get; set; }

    /// <summary>SNI для Xray.</summary>
    [BsonElement("siteName")]
    public string? SiteName { get; set; }

    /// <summary>Существующий протокол, который переустанавливаем или удаляем.</summary>
    [BsonElement("protocolId")]
    public string? ProtocolId { get; set; }
}

/// <summary>Шаг установки. Соответствует строке чеклиста в панели.</summary>
[BsonIgnoreExtraElements]
public class InstallStep
{
    [BsonElement("code")]
    public string Code { get; set; } = default!;

    [BsonElement("title")]
    public string Title { get; set; } = default!;

    /// <summary>См. <see cref="InstallStepStatuses"/>.</summary>
    [BsonElement("status")]
    public string Status { get; set; } = InstallStepStatuses.Pending;

    /// <summary>Что происходит прямо сейчас: «сборка образа amnezia-xray…».</summary>
    [BsonElement("detail")]
    public string? Detail { get; set; }

    /// <summary>Сообщение об ошибке — уже безопасное, без текста команд.</summary>
    [BsonElement("message")]
    public string? Message { get; set; }

    [BsonElement("startedAt")]
    public DateTime? StartedAt { get; set; }

    [BsonElement("finishedAt")]
    public DateTime? FinishedAt { get; set; }
}

/// <summary>Строка лога задачи. Отдельная коллекция: docker build даёт тысячи строк.</summary>
[BsonIgnoreExtraElements]
public class InstallJobLog
{
    [BsonId]
    [BsonRepresentation(BsonType.ObjectId)]
    public string Id { get; set; } = default!;

    [BsonElement("jobId")]
    public string JobId { get; set; } = default!;

    [BsonElement("seq")]
    public long Seq { get; set; }

    [BsonElement("at")]
    public DateTime At { get; set; } = DateTime.UtcNow;

    [BsonElement("stepCode")]
    public string? StepCode { get; set; }

    /// <summary>"info" | "warn" | "error".</summary>
    [BsonElement("level")]
    public string Level { get; set; } = AuditLevels.Info;

    /// <summary>Текст, уже прогнанный через редактор секретов.</summary>
    [BsonElement("text")]
    public string Text { get; set; } = default!;
}

public static class InstallJobKinds
{
    public const string InstallServer     = "install_server";
    public const string AddProtocol       = "add_protocol";
    public const string ReinstallProtocol = "reinstall_protocol";
    public const string RemoveProtocol    = "remove_protocol";
}

public static class InstallJobStatuses
{
    public const string Queued    = "queued";
    public const string Running   = "running";
    public const string Succeeded = "succeeded";
    public const string Failed    = "failed";
    public const string Canceled  = "canceled";

    public static readonly string[] Terminal = [Succeeded, Failed, Canceled];
}

public static class InstallStepStatuses
{
    public const string Pending = "pending";
    public const string Running = "running";
    public const string Done    = "done";
    public const string Failed  = "failed";
    public const string Skipped = "skipped";
}

/// <summary>
/// Коды шагов. Панель сопоставляет их со строками чеклиста, поэтому набор
/// и порядок должны совпадать с макетом.
/// </summary>
public static class InstallStepCodes
{
    public const string Ssh         = "ssh";
    public const string Fingerprint = "fingerprint";
    public const string Docker      = "docker";
    public const string Containers  = "containers";
    public const string KeysAndFw   = "keys_fw";
    public const string Verify      = "verify";

    /// <summary>
    /// Вес шага в процентах прогресса. Сборка образов занимает основную часть
    /// времени — равномерная шкала показывала бы 83% половину установки.
    /// </summary>
    public static readonly (string Code, string Title, int Weight)[] All =
    [
        (Ssh,         "SSH-подключение",             5),
        (Fingerprint, "Отпечаток хоста подтверждён",  5),
        (Docker,      "Docker и зависимости",        20),
        (Containers,  "Контейнеры протоколов",       55),
        (KeysAndFw,   "Генерация ключей и файрвол",  10),
        (Verify,      "Первая проверка соединения",   5),
    ];
}
