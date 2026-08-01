using AmneziaKeyService.Core.Models;
using MongoDB.Bson;
using MongoDB.Bson.Serialization;

// Документ, созданный до поля isRevoked, обязан читаться как активный. Репозиторий
// сопоставляет его тем же образом через $ne: true, а не Eq(false).
var legacyPassCode = BsonSerializer.Deserialize<PassCode>(new BsonDocument
{
    { "_id", ObjectId.GenerateNewId() },
    { "code", "LEGACY-CODE" },
    { "isUsed", false },
    { "createdAt", DateTime.UtcNow }
});

var checks = new (bool Passed, string Name)[]
{
    (PanelUserManagementRules.TryNormalizeUsername("admin.user-1", out _, out _), "допустимый логин"),
    (!PanelUserManagementRules.TryNormalizeUsername("..", out _, out _), "короткий логин отклонён"),
    (!PanelUserManagementRules.TryNormalizeUsername("user space", out _, out _), "логин с пробелом отклонён"),
    (PanelUserManagementRules.TryValidatePassword("123456789012", out _), "пароль из 12 символов допустим"),
    (!PanelUserManagementRules.TryValidatePassword("short", out _), "короткий пароль отклонён"),
    (PanelUserManagementRules.CanAssignPanelRole(UserRoles.Owner, UserRoles.Admin), "owner назначает admin"),
    (!PanelUserManagementRules.CanAssignPanelRole(UserRoles.Admin, UserRoles.Admin), "admin не назначает admin"),
    (!PanelUserManagementRules.CanAssignPanelRole(UserRoles.Admin, UserRoles.Owner), "owner не назначается API"),
    (!PanelUserManagementRules.CanAssignPanelRole(UserRoles.Admin, UserRoles.Client), "client не назначается API"),
    (!PanelUserManagementRules.CanManageTarget(UserRoles.Admin, UserRoles.Admin, false), "admin не управляет другим admin"),
    (!PanelUserManagementRules.CanManageTarget(UserRoles.Owner, UserRoles.Owner, false), "owner не управляет owner"),
    (PanelUserManagementRules.CanManageTarget(UserRoles.Admin, UserRoles.Client, false), "admin управляет client"),
    (PanelUserManagementRules.CanManageTarget(UserRoles.Admin, UserRoles.Admin, true), "самопрофиль допускается отдельно от привилегий"),
    (!legacyPassCode.IsRevoked && !legacyPassCode.IsUsed, "legacy BSON код без isRevoked остаётся активным")
};

var failed = checks.Where(x => !x.Passed).ToList();
foreach (var check in checks)
    Console.WriteLine($"{(check.Passed ? "PASS" : "FAIL")}: {check.Name}");

return failed.Count == 0 ? 0 : 1;
