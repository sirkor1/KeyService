using AmneziaKeyService.Core.Models;

var minTraffic = PanelSettingsRules.MinDefaultTrafficLimitBytes;
var maxTraffic = PanelSettingsRules.MaxDefaultTrafficLimitBytes;

var checks = new (bool Passed, string Name)[]
{
    (PanelSettingsRules.TryValidate(null, null, out _), "оба лимита можно отключить"),
    (PanelSettingsRules.TryValidate(1, minTraffic, out _), "минимальные значения допустимы"),
    (PanelSettingsRules.TryValidate(3650, maxTraffic, out _), "максимальные значения допустимы"),
    (!PanelSettingsRules.TryValidate(0, null, out _), "нулевой срок отклонён"),
    (!PanelSettingsRules.TryValidate(3651, null, out _), "слишком длинный срок отклонён"),
    (!PanelSettingsRules.TryValidate(null, minTraffic - 1, out _), "квота менее 1 МиБ отклонена"),
    (!PanelSettingsRules.TryValidate(null, maxTraffic + 1, out _), "квота больше 10 ТиБ отклонена")
};

foreach (var check in checks)
    Console.WriteLine($"{(check.Passed ? "PASS" : "FAIL")}: {check.Name}");

return checks.All(x => x.Passed) ? 0 : 1;
