namespace AmneziaKeyService.Core.Models;

/// <summary>
/// Виды протоколов. Значения соответствуют контейнерам Amnezia
/// (см. containers_defs.cpp в amnezia-client).
/// </summary>
public static class ProtocolKinds
{
    /// <summary>AmneziaWG актуальной версии, контейнер amnezia-awg2, бинарь awg.</summary>
    public const string Awg3 = "awg3";

    public const string Awg2 = "awg2";

    /// <summary>AmneziaWG legacy, контейнер amnezia-awg, бинарь wg.</summary>
    public const string AwgLegacy = "awg";

    /// <summary>Обычный WireGuard, контейнер amnezia-wireguard.</summary>
    public const string WireGuard = "wireguard";

    /// <summary>VLESS Reality на Xray-core, контейнер amnezia-xray.</summary>
    public const string Xray = "xray";

    public static readonly string[] All = [Awg3, Awg2, AwgLegacy, WireGuard, Xray];

    /// <summary>Семейство WireGuard: общий формат конфига, peer-ы и чтение статистики.</summary>
    public static readonly string[] WireGuardFamily = [Awg3, Awg2, AwgLegacy, WireGuard];

    public static bool IsWireGuardFamily(string kind) => WireGuardFamily.Contains(kind);

    /// <summary>Название для интерфейса — как в макете панели.</summary>
    public static string DisplayName(string kind) => kind switch
    {
        Awg3      => "AmneziaWG 3.1",
        Awg2      => "AmneziaWG 2.0",
        AwgLegacy => "AmneziaWG 1.0",
        WireGuard => "WireGuard",
        Xray      => "VLESS Reality",
        _         => kind
    };

    /// <summary>Имя docker-контейнера по умолчанию.</summary>
    public static string DefaultContainerName(string kind) => kind switch
    {
        Awg3      => "amnezia-awg3",
        Awg2      => "amnezia-awg2",
        AwgLegacy => "amnezia-awg",
        WireGuard => "amnezia-wireguard",
        Xray      => "amnezia-xray",
        _         => throw new ArgumentOutOfRangeException(nameof(kind), kind, "Неизвестный протокол.")
    };
}

/// <summary>Состояние контейнера протокола на узле.</summary>
public static class ProtocolStates
{
    public const string Installed  = "installed";
    public const string Installing = "installing";
    public const string Failed     = "failed";
    public const string Absent     = "absent";
}

/// <summary>Статус узла. Соответствует тегам «работает / установка / недоступен» в макете.</summary>
public static class ServerStatuses
{
    public const string Ok      = "ok";
    public const string Setup   = "setup";
    public const string Offline = "offline";
    public const string Error   = "error";

    public static readonly string[] All = [Ok, Setup, Offline, Error];
}

/// <summary>Статус выданного ключа.</summary>
public static class KeyStatuses
{
    public const string Active    = "active";
    public const string Revoked   = "revoked";
    public const string Expired   = "expired";
    public const string Suspended = "suspended";

    /// <summary>
    /// Отзыв запрошен, но peer на сервере ещё не удалён (SSH был недоступен).
    /// Фоновый воркер повторит попытку. Помечать ключ отозванным, пока его peer
    /// жив на узле, нельзя — доступ остался бы рабочим.
    /// </summary>
    public const string PendingRevoke = "pendingRevoke";

    public static readonly string[] All = [Active, Revoked, Expired, Suspended, PendingRevoke];
}

/// <summary>Откуда пришёл ключ.</summary>
public static class KeySources
{
    public const string Telegram = "telegram";
    public const string Panel    = "panel";
    public const string Api      = "api";
}
