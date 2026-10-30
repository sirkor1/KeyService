using AmneziaKeyService.Core.Models;

namespace AmneziaKeyService.Infrastructure.Protocols.XCore;

/// <summary>
/// Раскладка xcore на узле и команды, общие для установщика, синхронизации,
/// оркестратора и очистки узла. Собраны в одном месте, чтобы пути и образы не
/// расходились между теми, кто их создаёт, и теми, кто по ним проверяет.
/// </summary>
public static class XCoreNode
{
    /// <summary>Тег 26.10.21. Digest, а не тег: образ нельзя подменить незаметно.</summary>
    public const string XrayImage =
        "ghcr.io/xtls/xray-core@sha256:d5c3729dfeed7c412af17a63b941c48c76ba68afee5b6184fe4078f8fa8bedcc";

    /// <summary>Caddy 2.10.2-alpine.</summary>
    public const string CaddyImage =
        "caddy@sha256:4c6e91c6ed0e2fa03efd5b44747b625fec79bc9cd06ac5235a779726618e530d";

    /// <summary>Порт Xray (Reality). Порт 80 Caddy занимает под ACME HTTP-01.</summary>
    public const string HttpsPort = "443";

    public const string AcmePort = "80";

    public const string XrayContainer = "amnezia-xcore";
    public const string WebContainer = "amnezia-xcore-web";

    public const string Root = "/opt/amnezia-xcore";
    public const string ConfDir = Root + "/conf";
    public const string ConfigPath = ConfDir + "/config.json";

    /// <summary>
    /// Имя обязано заканчиваться на «.json»: Xray определяет формат по расширению и для
    /// «config.json.new» отвечает «Failed to get format», не читая файл.
    /// </summary>
    public const string NewConfigFile = "config.new.json";

    public const string NewConfigPath = ConfDir + "/" + NewConfigFile;

    /// <summary>Файлы для <c>xray api adu</c>: удаляются сразу после применения.</summary>
    public const string OpsDir = Root + "/ops";

    public const string CaddyDir = Root + "/caddy";

    public const string CaddyfilePath = CaddyDir + "/Caddyfile";

    /// <summary>Кандидат на замену Caddyfile: проверяется, и только потом подменяет рабочий файл.</summary>
    public const string NewCaddyfilePath = CaddyDir + "/Caddyfile.new";

    /// <summary>
    /// Проверка кандидата одноразовым контейнером Caddy. Файл подключается под тем же путём, что и в рабочем
    /// контейнере, поэтому относительные ссылки и пути в нём (например, <c>root</c>) читаются так же.
    /// </summary>
    public const string ValidateCaddyfileCommand =
        "sudo docker run --rm -v " + NewCaddyfilePath + ":/etc/caddy/Caddyfile:ro " + CaddyImage +
        " caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile";

    /// <summary>Где каталоги хоста видны внутри контейнера Xray.</summary>
    public const string ContainerConfDir = "/etc/xcore";

    public const string ContainerOpsDir = "/etc/xcore-ops";

    /// <summary>
    /// Российские списки входа (<c>rf-geosite.dat</c>, <c>rf-geoip.dat</c>). Монтируется каталог целиком, а не
    /// файлы: Docker превращает монтирование несуществующего файла в каталог, а файл, заменённый на хосте
    /// переименованием, контейнер продолжает видеть старым (тот же inode-капкан, что у Caddyfile). Каталог
    /// может быть пустым — вход тогда работает на встроенных списках образа.
    /// </summary>
    public const string GeoDir = Root + "/geo";

    /// <summary>
    /// Куда скачиваются и где проверяются новые списки до подмены рабочих. Рядом с <see cref="GeoDir"/> —
    /// на той же файловой системе, чтобы подмена была переименованием, — но вне каталога, который видит Xray:
    /// недокачанный файл не может попасть к нему ни при каком сбое.
    /// </summary>
    public const string GeoStageDir = Root + "/geo-stage";

    public const string ContainerGeoDir = "/etc/xcore-geo";

    /// <summary>
    /// Каталог, где Xray ищет <c>ext:</c>-файлы. Встроенные <c>geoip.dat</c> и <c>geosite.dat</c> в нём
    /// отсутствуют, и Xray 26.10.21 берёт их из <c>/usr/local/share/xray</c> образа — поэтому списки образа
    /// не нужно копировать на хост, и они не устаревают вместе с копией. Проверено `run -test` и запуском в
    /// закреплённом образе (tools/VerifyXCore --docker).
    /// </summary>
    public const string AssetEnv = "XRAY_LOCATION_ASSET";

    /// <summary>Аргумент <c>-e</c> для контейнера входа и для проверки конфига, использующего <c>ext:</c>-списки.</summary>
    public const string GeoEnvArg = "-e " + AssetEnv + "=" + ContainerGeoDir;

    // Один список и для docker run -v, и для проверки при очистке узла: так набор
    // монтирований, который создаёт установщик, не может разойтись с тем, что очистка
    // считает «своим». EntryOnly — монтирование есть только у входа; очистка признаёт его для любой роли.
    private static readonly (string Source, string Destination, bool ReadOnly, bool EntryOnly)[] XrayMounts =
    [
        (ConfDir, ContainerConfDir, true, false),
        (OpsDir, ContainerOpsDir, true, false),
        (GeoDir, ContainerGeoDir, true, true),
    ];

    private static readonly (string Source, string Destination, bool ReadOnly, bool EntryOnly)[] WebMounts =
    [
        (CaddyDir + "/Caddyfile", "/etc/caddy/Caddyfile", true, false),
        (CaddyDir + "/site", "/srv/site", true, false),
        (CaddyDir + "/data", "/data", false, false),
        (CaddyDir + "/config", "/config", false, false),
    ];

    private static (string Source, string Destination, bool ReadOnly, bool EntryOnly)[] MountsOf(string container) =>
        container switch
        {
            XrayContainer => XrayMounts,
            WebContainer => WebMounts,
            _ => [],
        };

    /// <summary>
    /// Аргументы docker run контейнера xcore: <c>-v</c> и, для контейнера входа, <c>-e</c> с каталогом
    /// российских списков. Роль выхода монтирований входа не получает: ему такие списки не нужны.
    /// </summary>
    public static string MountArgs(string container, string role = XCoreRoles.Exit)
    {
        var entry = container == XrayContainer && role == XCoreRoles.Entry;
        var mounts = MountsOf(container).Where(m => entry || !m.EntryOnly)
            .Select(m => $"-v {m.Source}:{m.Destination}{(m.ReadOnly ? ":ro" : "")}");
        return string.Join(' ', entry ? mounts.Append(GeoEnvArg) : mounts);
    }

    /// <summary>
    /// Входит ли bind-монтирование в известный набор контейнеров xcore. Очистка узла
    /// отклоняет контейнеры с внешними данными; здесь данные внешние лишь формально —
    /// каталог <see cref="Root"/> очистка удаляет сама.
    /// </summary>
    public static bool IsKnownMount(string container, string? source, string? destination) =>
        MountsOf(container).Any(m => m.Source == source && m.Destination == destination);

    /// <summary>
    /// Команда <c>xray api</c> внутри контейнера. Образ без shell, поэтому вызываем
    /// бинарь напрямую, а не через <c>sh -c</c>. Аргументы подставляет вызывающий и
    /// отвечает за их безопасность для shell (<see cref="Quote"/>).
    /// </summary>
    public static string ApiCommand(int apiPort, string subcommand, string arguments) =>
        $"sudo docker exec {XrayContainer} xray api {subcommand} --server=127.0.0.1:{apiPort} {arguments}";

    public static string InboundUserCountCommand(int apiPort) =>
        ApiCommand(apiPort, "inboundusercount", $"-tag={XCoreConfigRenderer.InboundTag}");

    public static string InboundUsersCommand(int apiPort) =>
        ApiCommand(apiPort, "inbounduser", $"-tag={XCoreConfigRenderer.InboundTag}");

    /// <summary>
    /// Счётчики трафика подписчиков. Без <c>-reset</c>: сброс со сбоем записи потерял бы трафик,
    /// а обнуление при рестарте контейнера <c>UsageMath.Delta</c> уже переживает. Шаблон в кавычках:
    /// «>» для shell — перенаправление вывода, без кавычек команда ушла бы в файл.
    /// </summary>
    public static string UserStatsCommand(int apiPort) =>
        ApiCommand(apiPort, "statsquery", $"-pattern {Quote("user>>>" + Subscription.XrayEmailPrefix)}");

    public const string VersionCommand = "sudo docker exec " + XrayContainer + " xray version";

    /// <summary>
    /// Проверка файла конфига одноразовым контейнером. <c>--user 0:0</c>: каталог конфига
    /// закрыт (700, root), а образ по умолчанию работает от 65532 и его бы не прочитал.
    /// </summary>
    public static string TestConfigCommand(string imageRef, string fileName, string? geoDir = null) =>
        $"sudo docker run --rm --user 0:0 -v {ConfDir}:{ContainerConfDir}:ro " +
        // Каталог списков подключается, только если конфиг на них ссылается: без ссылок проверка идёт ровно как
        // раньше, и узел без каталога (вход, поставленный до списков) её не ломает.
        (geoDir is null ? "" : $"{GeoEnvArg} -v {geoDir}:{ContainerGeoDir}:ro ") +
        $"{imageRef} run -test -c {ContainerConfDir}/{fileName}";

    /// <summary>
    /// Генерация пары строк VLESS Encryption одноразовым контейнером того же образа, что у узла: формат строк
    /// определяет версия Xray, а не панели. Образ вызывающий обязан проверить через <see cref="IsSafeImageRef"/>.
    /// </summary>
    public static string VlessEncCommand(string imageRef) => $"sudo docker run --rm {imageRef} vlessenc";

    /// <summary>
    /// Монтирования и окружение живого контейнера Xray: по ним проверяется, что вход создан с каталогом
    /// российских списков. Контейнер, поставленный до их появления, каталога не видит, и конфиг с
    /// <c>ext:</c> не запустился бы после перезапуска.
    /// </summary>
    public const string InspectGeoMountCommand =
        "sudo docker inspect -f '{{range .Mounts}}{{.Source}}={{.Destination}} {{end}}|{{range .Config.Env}}{{.}} {{end}}' " +
        XrayContainer;

    /// <summary>Строка в одинарных кавычках для shell; внутри кавычек они экранируются.</summary>
    public static string Quote(string value) => "'" + value.Replace("'", "'\\''") + "'";

    /// <summary>
    /// Ссылка на образ, допустимая для подстановки в команду: имя, необязательный тег и
    /// digest. Значение приходит из базы, но попадает в shell, поэтому проверяется.
    /// </summary>
    public static bool IsSafeImageRef(string? imageRef) =>
        !string.IsNullOrEmpty(imageRef) && System.Text.RegularExpressions.Regex.IsMatch(
            imageRef, @"\A[a-z0-9][a-z0-9._/-]*(:[A-Za-z0-9._-]+)?(@sha256:[0-9a-f]{64})?\z");
}
