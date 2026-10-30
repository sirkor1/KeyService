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

    /// <summary>
    /// Свой Xray-core для подписок Happ, контейнер amnezia-xcore. Не протокол Amnezia:
    /// клиент AmneziaVPN его не знает, поэтому в выдаче vpn:// он не участвует.
    /// </summary>
    public const string XCore = "xcore";

    /// <summary>
    /// Виды семейства Amnezia — те, что знает клиент AmneziaVPN. XCore сюда не входит
    /// намеренно: «все виды Amnezia» и «все виды, которые панель умеет ставить» —
    /// разные вопросы, и ответ на второй — <see cref="Installable"/>.
    /// </summary>
    public static readonly string[] All = [Awg3, Awg2, AwgLegacy, WireGuard, Xray];

    /// <summary>
    /// Виды, для которых в панели есть установщик и которые очистка узла считает своими.
    /// Отдельный набор, а не правка <see cref="All"/>: проверка «всё из All выдаваемо
    /// по vpn://» остаётся верной, а xcore не может случайно попасть туда, где ждут
    /// только протоколы Amnezia.
    /// </summary>
    public static readonly string[] Installable = [.. All, XCore];

    /// <summary>Семейство WireGuard: общий формат конфига, peer-ы и чтение статистики.</summary>
    public static readonly string[] WireGuardFamily = [Awg3, Awg2, AwgLegacy, WireGuard];

    /// <summary>Виды, по которым выдаётся ключ vpn:// для AmneziaVPN.</summary>
    public static readonly string[] AmneziaIssuable = [.. WireGuardFamily, Xray];

    public static bool IsWireGuardFamily(string kind) => WireGuardFamily.Contains(kind);

    public static bool IsAmneziaIssuable(string kind) => AmneziaIssuable.Contains(kind);

    /// <summary>Название для интерфейса — как в макете панели.</summary>
    public static string DisplayName(string kind) => kind switch
    {
        Awg3      => "AmneziaWG 3.1",
        Awg2      => "AmneziaWG 2.0",
        AwgLegacy => "AmneziaWG 1.0",
        WireGuard => "WireGuard",
        Xray      => "VLESS Reality",
        XCore     => "Xray (подписки)",
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
        XCore     => "amnezia-xcore",
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
    public const string Empty   = "empty";
    public const string Ok      = "ok";
    public const string Setup   = "setup";
    public const string Offline = "offline";
    public const string Error   = "error";

    public static readonly string[] All = [Ok, Setup, Offline, Error, Empty];
}

/// <summary>Статус выданного ключа.</summary>
public static class KeyStatuses
{
    public const string Active    = "active";
    public const string Revoked   = "revoked";
    public const string Expired   = "expired";
    public const string Suspended = "suspended";
    /// <summary>Узел удалён из панели без подтверждённого отзыва доступа на сервере.</summary>
    public const string Detached = "detached";

    /// <summary>
    /// Отзыв запрошен, но peer на сервере ещё не удалён (SSH был недоступен).
    /// Фоновый воркер повторит попытку. Помечать ключ отозванным, пока его peer
    /// жив на узле, нельзя — доступ остался бы рабочим.
    /// </summary>
    public const string PendingRevoke = "pendingRevoke";

    public static readonly string[] All = [Active, Revoked, Expired, Suspended, PendingRevoke, Detached];
}

/// <summary>Откуда пришёл ключ.</summary>
public static class KeySources
{
    public const string Telegram = "telegram";
    public const string Panel    = "panel";
    public const string Api      = "api";
}
