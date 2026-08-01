using System.ComponentModel.DataAnnotations;

namespace AmneziaKeyService.Core.DTOs.Panel;

/// <summary>
/// Запрос на выдачу ключа.
///
/// Владелец задаётся либо ссылкой на существующего пользователя (UserId),
/// либо просто именем (OwnerName) — тогда клиент заводится на лету, как
/// предполагает форма «Выдать ключ» в макете.
/// </summary>
public class IssueKeyRequest
{
    [Required]
    public string ServerId { get; set; } = default!;

    /// <summary>Протокол узла. Не задан — протокол по умолчанию.</summary>
    public string? ProtocolId { get; set; }

    public string? UserId { get; set; }

    /// <summary>Имя владельца. Используется, если UserId не передан.</summary>
    public string? OwnerName { get; set; }

    /// <summary>Контакт нового клиента: e-mail или @telegram.</summary>
    public string? Contact { get; set; }

    public string? DeviceName { get; set; }

    public string? Label { get; set; }

    /// <summary>Срок действия в днях. Null — из настроек панели, 0 — бессрочно.</summary>
    public int? ExpiryDays { get; set; }

    /// <summary>Квота трафика в байтах. Null — без ограничения.</summary>
    public long? TrafficLimitBytes { get; set; }
}

/// <summary>Запрос на отзыв.</summary>
public class RevokeKeyRequest
{
    /// <summary>Свободный комментарий для журнала.</summary>
    public string? Comment { get; set; }
}
