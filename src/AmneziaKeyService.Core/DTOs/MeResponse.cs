using AmneziaKeyService.Core.Models;

namespace AmneziaKeyService.Core.DTOs;

/// <summary>
/// Профиль текущего пользователя. Панель показывает Username/DisplayName в шапке
/// и по Permissions решает, какие кнопки рендерить.
/// </summary>
public record MeResponse(
    string Id,
    string Username,
    string? DisplayName,
    string Role,
    string Status,
    string[] Permissions
)
{
    public static MeResponse From(User user) => new(
        user.Id,
        user.Username,
        user.DisplayName,
        user.Role,
        user.Status,
        PermissionsFor(user.Role));

    /// <summary>
    /// Разрешения выводятся из роли. Фронтенд использует их только чтобы скрыть
    /// недоступные действия — настоящая проверка остаётся на политиках сервера.
    /// </summary>
    private static string[] PermissionsFor(string role)
    {
        var permissions = new List<string>();

        if (UserRoles.PanelRead.Contains(role))  permissions.Add("panel:read");
        if (UserRoles.PanelWrite.Contains(role)) permissions.Add("panel:write");
        if (UserRoles.PanelAdmin.Contains(role)) permissions.Add("panel:admin");
        if (role == UserRoles.Owner)             permissions.Add("panel:owner");

        return [.. permissions];
    }
}
