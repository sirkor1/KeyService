using System.Text.RegularExpressions;

namespace AmneziaKeyService.Core.Models;

/// <summary>
/// Чистые правила управления учётными записями панели. Они не зависят от HTTP
/// или MongoDB, чтобы критичные инварианты можно было проверять автономно.
/// </summary>
public static partial class PanelUserManagementRules
{
    public static bool TryNormalizeUsername(string? value, out string username, out string? error)
    {
        username = value?.Trim() ?? string.Empty;
        if (!UsernamePattern().IsMatch(username))
        {
            error = "Логин должен состоять из 3–64 латинских букв, цифр, '.', '_' или '-'; первый символ — буква или цифра.";
            return false;
        }

        error = null;
        return true;
    }

    public static bool TryValidatePassword(string? password, out string? error)
    {
        if (password is null || password.Length is < 12 or > 128)
        {
            error = "Пароль должен содержать от 12 до 128 символов.";
            return false;
        }

        error = null;
        return true;
    }

    public static bool CanAssignPanelRole(string actorRole, string requestedRole) =>
        UserRoles.Assignable.Contains(requestedRole) &&
        (actorRole == UserRoles.Owner || RoleRank(requestedRole) < RoleRank(actorRole));

    /// <summary>
    /// Владелец неизменяем через API управления пользователями: это исключает
    /// блокировку или понижение последнего владельца. Владелец восстанавливается
    /// только контролируемым сидированием из конфигурации.
    /// </summary>
    public static bool CanManageTarget(string actorRole, string targetRole, bool isSelf) =>
        isSelf ||
        (actorRole == UserRoles.Owner && targetRole != UserRoles.Owner) ||
        (actorRole == UserRoles.Admin && RoleRank(targetRole) < RoleRank(UserRoles.Admin));

    public static int RoleRank(string role) => role switch
    {
        UserRoles.Owner    => 4,
        UserRoles.Admin    => 3,
        UserRoles.Operator => 2,
        UserRoles.Viewer   => 1,
        UserRoles.Client   => 0,
        _ => -1
    };

    [GeneratedRegex("^[A-Za-z0-9][A-Za-z0-9._-]{2,63}$", RegexOptions.CultureInvariant)]
    private static partial Regex UsernamePattern();
}
