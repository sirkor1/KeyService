namespace AmneziaKeyService.Core.Models;

/// <summary>
/// Учётка владельца панели, создаваемая при первом запуске.
/// Задаётся через ADMIN__USERNAME / ADMIN__PASSWORD (или секцию "Admin" в конфиге).
///
/// Если владельца в базе ещё нет и пароль не задан — приложение не стартует:
/// иначе панель осталась бы без единого способа войти.
/// </summary>
public class AdminOptions
{
    public string Username { get; set; } = "admin";

    public string? Password { get; set; }

    public string? DisplayName { get; set; }

    /// <summary>
    /// Обновлять пароль существующего владельца при каждом старте.
    /// По умолчанию false — иначе смена пароля в панели откатывалась бы при рестарте.
    /// Полезно один раз для восстановления доступа.
    /// </summary>
    public bool ResetPasswordOnStartup { get; set; }
}
