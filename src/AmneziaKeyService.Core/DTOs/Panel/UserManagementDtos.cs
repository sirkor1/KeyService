namespace AmneziaKeyService.Core.DTOs.Panel;

/// <summary>Создание учётной записи панели. Роль owner и роль client этим API не назначаются.</summary>
public record CreatePanelUserRequest(
    string? Username,
    string? Password,
    string? DisplayName,
    string? Contact,
    string? Role);

/// <summary>
/// Полное редактирование публичных полей учётной записи. При первом повышении client до
/// роли панели требуется пароль; во всех остальных случаях пароль меняется отдельным
/// маршрутом. Пароль никогда не возвращается в ответе или журнале.
/// </summary>
public record UpdatePanelUserRequest(
    string? DisplayName,
    string? Contact,
    string? Role,
    string? Status,
    string? Password = null);

/// <summary>Новый пароль задаётся администратором только по защищённому API.</summary>
public record ResetUserPasswordRequest(string? Password);
