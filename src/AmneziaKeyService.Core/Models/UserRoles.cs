namespace AmneziaKeyService.Core.Models;

/// <summary>
/// Роли пользователей. Хранятся в User.Role, попадают в JWT как ClaimTypes.Role.
/// </summary>
public static class UserRoles
{
    /// <summary>Владелец панели. Единственный, создаётся сидированием, не удаляется.</summary>
    public const string Owner = "owner";

    /// <summary>Администратор: всё, кроме управления владельцем и сменой ролей admin+.</summary>
    public const string Admin = "admin";

    /// <summary>Оператор: выдача и отзыв ключей, без правки серверов и пользователей.</summary>
    public const string Operator = "operator";

    /// <summary>Наблюдатель: только чтение панели.</summary>
    public const string Viewer = "viewer";

    /// <summary>Конечный VPN-пользователь. Доступ только к /api/vpn/* и Telegram-боту.</summary>
    public const string Client = "client";

    /// <summary>Роли, допущенные в панель (любой экран, хотя бы на чтение).</summary>
    public static readonly string[] PanelRead = [Owner, Admin, Operator, Viewer];

    /// <summary>Роли, которым разрешены мутации данных панели.</summary>
    public static readonly string[] PanelWrite = [Owner, Admin, Operator];

    /// <summary>Роли, которым разрешено администрирование (серверы, пользователи, настройки).</summary>
    public static readonly string[] PanelAdmin = [Owner, Admin];

    /// <summary>Роли, назначаемые пользователям панели через API.</summary>
    public static readonly string[] Assignable = [Admin, Operator, Viewer];

    public static readonly string[] All = [Owner, Admin, Operator, Viewer, Client];

    public static bool IsKnown(string? role) => role is not null && All.Contains(role);
}

/// <summary>Статус учётной записи — соответствует тегам «активен / ограничен / заблокирован» в панели.</summary>
public static class UserStatuses
{
    public const string Active = "active";
    public const string Restricted = "restricted";
    public const string Blocked = "blocked";

    public static readonly string[] All = [Active, Restricted, Blocked];

    public static bool IsKnown(string? status) => status is not null && All.Contains(status);
}
