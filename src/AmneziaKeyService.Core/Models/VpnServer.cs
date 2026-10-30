using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;

namespace AmneziaKeyService.Core.Models;

/// <summary>
/// Узел VPN со списком установленных протоколов. Коллекция server_config —
/// та же, что у прежнего AwgServerConfig, и с теми же _id: на serverId
/// ссылаются все выданные ботом ключи, пересоздавать документы нельзя.
///
/// BsonIgnoreExtraElements оставлен для forward compatibility: актуальная
/// схема хранит параметры в ssh{} и protocols[]. Плоские поля прежней схемы
/// удаляются миграцией 012 после завершения периода отката.
/// </summary>
[BsonIgnoreExtraElements]
public class VpnServer
{
    [BsonId]
    [BsonRepresentation(BsonType.ObjectId)]
    public string Id { get; set; } = default!;

    [BsonElement("schemaVersion")]
    public int SchemaVersion { get; set; } = 2;

    /// <summary>Имя узла в панели и в приложении AmneziaVPN (бывшее description).</summary>
    [BsonElement("name")]
    public string Name { get; set; } = "AmneziaVPN Server";

    /// <summary>IP или hostname.</summary>
    [BsonElement("host")]
    public string Host { get; set; } = default!;

    /// <summary>Локация: «Нидерланды, Амстердам».</summary>
    [BsonElement("geo")]
    public string? Geo { get; set; }

    /// <summary>Провайдер: Hetzner, Netcup.</summary>
    [BsonElement("provider")]
    public string? Provider { get; set; }

    /// <summary>Заметка оператора.</summary>
    [BsonElement("note")]
    public string? Note { get; set; }

    /// <summary>Лимит ключей на узел. Null — без ограничения.</summary>
    [BsonElement("keyLimit")]
    public int? KeyLimit { get; set; }

    [BsonElement("ssh")]
    public SshCredentials Ssh { get; set; } = new();

    /// <summary>См. <see cref="ServerStatuses"/>.</summary>
    [BsonElement("status")]
    public string Status { get; set; } = ServerStatuses.Ok;

    /// <summary>Протокол, используемый по умолчанию при выдаче ключа.</summary>
    [BsonElement("defaultProtocolId")]
    public string? DefaultProtocolId { get; set; }

    [BsonElement("dns1")]
    public string Dns1 { get; set; } = "1.1.1.1";

    [BsonElement("dns2")]
    public string Dns2 { get; set; } = "8.8.8.8";

    [BsonElement("protocols")]
    public List<ProtocolInstance> Protocols { get; set; } = [];

    [BsonElement("disabledProtocolIds")]
    public List<string> DisabledProtocolIds { get; set; } = [];

    /// <summary>
    /// Протокол включён, не отключён администратором и установлен. Это «работает»,
    /// а не «выдаёт vpn://»: для xcore ключи выдаются подпиской, а не этим путём.
    /// </summary>
    public bool IsServing(ProtocolInstance protocol) => protocol.Enabled
        && !DisabledProtocolIds.Contains(protocol.Id) && protocol.State == ProtocolStates.Installed;

    /// <summary>
    /// Можно ли выдать по протоколу новый ключ vpn://. Виды вне AmneziaIssuable
    /// (xcore) исключены: AmneziaVPN не умеет их импортировать, а без этой проверки
    /// узел с одним xcore стал бы выбором по умолчанию и сломал выдачу.
    /// </summary>
    public bool CanIssue(ProtocolInstance protocol) =>
        ProtocolKinds.IsAmneziaIssuable(protocol.Kind) && IsServing(protocol);

    /// <summary>
    /// Отдаётся ли узел в подписках: xcore любой роли (выход или вход), работающий и не
    /// скрытый из подписок. В ссылки он попадает по роли — см. <see cref="IsSubscriptionExit"/>
    /// и <see cref="IsSubscriptionEntry"/>. Синхронизация и учёт трафика идут шире — на все
    /// установленные xcore (XCoreSyncPublisher.SyncTargets): у скрытого узла остаётся живой
    /// Xray, и с него обязаны уходить отозванные подписчики.
    /// </summary>
    public bool IsSubscriptionNode(ProtocolInstance protocol) =>
        protocol.Kind == ProtocolKinds.XCore
        && protocol.XCore is { Role: XCoreRoles.Exit or XCoreRoles.Entry, SubscriptionEnabled: true }
        && IsServing(protocol);

    /// <summary>Выход подписки: к нему ведёт прямая ссылка и плечо от каждого входа.</summary>
    public bool IsSubscriptionExit(ProtocolInstance protocol) =>
        IsSubscriptionNode(protocol) && protocol.XCore!.Role == XCoreRoles.Exit;

    /// <summary>Вход подписки: клиент подключается к нему, а дальше трафик идёт на выходы.</summary>
    public bool IsSubscriptionEntry(ProtocolInstance protocol) =>
        IsSubscriptionNode(protocol) && protocol.XCore!.Role == XCoreRoles.Entry;

    public ProtocolInstance? IssuanceProtocol(string? protocolId) => protocolId is not null
        ? Protocols.FirstOrDefault(p => p.Id == protocolId && CanIssue(p))
        : Protocols.FirstOrDefault(p => p.Id == DefaultProtocolId && CanIssue(p))
          ?? Protocols.FirstOrDefault(CanIssue);

    [BsonElement("health")]
    public ServerHealth? Health { get; set; }

    /// <summary>
    /// Сколько peer-ов на узле не соответствует ни одному выданному ключу.
    /// Считается суточной сверкой; сервис их не удаляет — за такими peer-ами
    /// стоят живые люди, заведённые мимо панели.
    /// </summary>
    [BsonElement("orphanPeerCount")]
    public int OrphanPeerCount { get; set; }

    [BsonElement("reconciledAt")]
    public DateTime? ReconciledAt { get; set; }

    [BsonElement("createdAt")]
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    [BsonElement("updatedAt")]
    public DateTime? UpdatedAt { get; set; }

    [BsonElement("createdByUserId")]
    public string? CreatedByUserId { get; set; }

    /// <summary>
    /// Протокол для vpn:// по умолчанию: явно указанный, иначе первый установленный,
    /// иначе первый вообще — но только среди <see cref="ProtocolKinds.AmneziaIssuable"/>.
    /// Он же владелец ключей без protocolId: они выданы до появления нескольких
    /// протоколов на узле и никогда не принадлежали xcore. Без фильтра
    /// <c>DefaultProtocolId</c> на xcore (его ставят на пустой узел первым) отдал бы
    /// такие ключи протоколу, у которого нет конфигуратора.
    /// Для «любого протокола узла» это свойство не подходит — берите <see cref="Protocols"/>.
    /// </summary>
    public ProtocolInstance? DefaultProtocol =>
        Protocols.FirstOrDefault(p => p.Id == DefaultProtocolId && ProtocolKinds.IsAmneziaIssuable(p.Kind))
        ?? Protocols.FirstOrDefault(p => ProtocolKinds.IsAmneziaIssuable(p.Kind) && p.State == ProtocolStates.Installed)
        ?? Protocols.FirstOrDefault(p => ProtocolKinds.IsAmneziaIssuable(p.Kind));

    public ProtocolInstance? FindProtocol(string protocolId) =>
        Protocols.FirstOrDefault(p => p.Id == protocolId);
}

/// <summary>SSH-доступ к узлу. Пароль и приватный ключ шифруются AES-GCM.</summary>
[BsonIgnoreExtraElements]
public class SshCredentials
{
    [BsonElement("port")]
    public int Port { get; set; } = 22;

    [BsonElement("user")]
    public string User { get; set; } = "root";

    /// <summary>"password" | "privateKey" | "agent".</summary>
    [BsonElement("authType")]
    public string AuthType { get; set; } = SshAuthTypes.Password;

    [BsonElement("password")]
    public EncryptedValue? Password { get; set; }

    /// <summary>Приватный ключ в PEM. Хранится в базе, а не файлом на хосте API.</summary>
    [BsonElement("privateKey")]
    public EncryptedValue? PrivateKey { get; set; }

    [BsonElement("keyPassphrase")]
    public EncryptedValue? KeyPassphrase { get; set; }

    /// <summary>Тип ключа для строки «•••• ed25519» в панели.</summary>
    [BsonElement("keyType")]
    public string? KeyType { get; set; }

    /// <summary>SHA256-отпечаток хоста, зафиксированный при первой установке.</summary>
    [BsonElement("hostFingerprint")]
    public string? HostFingerprint { get; set; }

    /// <summary>
    /// Путь к файлу ключа на хосте API. Legacy: до перехода на хранение ключа
    /// в базе. Используется, если PrivateKey пуст.
    /// </summary>
    [BsonElement("privateKeyPath")]
    public string? PrivateKeyPath { get; set; }
}

public static class SshAuthTypes
{
    public const string Password   = "password";
    public const string PrivateKey = "privateKey";
    public const string Agent      = "agent";
}

/// <summary>
/// Установленный на узле контейнер протокола.
///
/// wg и xray — nullable-группы, а не полиморфный список с BSON-дискриминаторами:
/// полиморфные коллекции в драйвере MongoDB регулярно ломаются на десериализации,
/// а плоские группы тривиально фильтруются запросом.
/// </summary>
/// <remarks>
/// BsonNoId обязателен. Драйвер по соглашению считает свойство с именем Id
/// идентификатором документа и пишет его как _id, игнорируя BsonElement("id").
/// Для вложенного документа это ломало всё: при чтении поле id не подхватывалось,
/// BsonIgnoreExtraElements его проглатывал, и Id получал новый Guid при каждом
/// чтении — то есть любое сохранение узла осиротило бы protocolId всех ключей.
/// </remarks>
[BsonIgnoreExtraElements]
[BsonNoId]
public class ProtocolInstance
{
    /// <summary>Стабильный идентификатор, фигурирует в маршрутах и в ключах.</summary>
    [BsonElement("id")]
    public string Id { get; set; } = Guid.NewGuid().ToString("N");

    /// <summary>См. <see cref="ProtocolKinds"/>.</summary>
    [BsonElement("kind")]
    public string Kind { get; set; } = default!;

    [BsonElement("containerName")]
    public string ContainerName { get; set; } = default!;

    [BsonElement("enabled")]
    public bool Enabled { get; set; } = true;

    /// <summary>См. <see cref="ProtocolStates"/>.</summary>
    [BsonElement("state")]
    public string State { get; set; } = ProtocolStates.Installed;

    [BsonElement("port")]
    public string Port { get; set; } = default!;

    /// <summary>"udp" для WireGuard-семейства, "tcp" для Xray.</summary>
    [BsonElement("transportProto")]
    public string TransportProto { get; set; } = "udp";

    [BsonElement("mtu")]
    public string? Mtu { get; set; }

    /// <summary>Версия бинаря в контейнере — моноширинная строка в карточке протокола.</summary>
    [BsonElement("containerVersion")]
    public string? ContainerVersion { get; set; }

    [BsonElement("installedAt")]
    public DateTime? InstalledAt { get; set; }

    /// <summary>Когда последний раз вычитывались параметры с сервера.</summary>
    [BsonElement("lastSyncedAt")]
    public DateTime? LastSyncedAt { get; set; }

    /// <summary>Заполнено для awg2 / awg / wireguard.</summary>
    [BsonElement("wg")]
    public WgProtocolParams? Wg { get; set; }

    /// <summary>Заполнено для xray.</summary>
    [BsonElement("xray")]
    public XrayProtocolParams? Xray { get; set; }

    /// <summary>Заполнено для xcore.</summary>
    [BsonElement("xcore")]
    [BsonIgnoreIfNull]
    public XCoreProtocolParams? XCore { get; set; }

    /// <summary>Название для интерфейса и журнала.</summary>
    public string DisplayNameOrKind() => ProtocolKinds.DisplayName(Kind);
}

/// <summary>Параметры контейнера семейства WireGuard.</summary>
[BsonIgnoreExtraElements]
public class WgProtocolParams
{
    /// <summary>Имя интерфейса внутри контейнера: wg0 или awg0.</summary>
    [BsonElement("interfaceName")]
    public string InterfaceName { get; set; } = "wg0";

    /// <summary>Бинарь: "wg" для legacy-образа, "awg" для нового.</summary>
    [BsonElement("binary")]
    public string Binary { get; set; } = "wg";

    [BsonElement("serverConfigPath")]
    public string ServerConfigPath { get; set; } = "/opt/amnezia/awg/wg0.conf";

    [BsonElement("serverPubKeyPath")]
    public string ServerPubKeyPath { get; set; } = "/opt/amnezia/awg/wireguard_server_public_key.key";

    [BsonElement("pskKeyPath")]
    public string PskKeyPath { get; set; } = "/opt/amnezia/awg/wireguard_psk.key";

    [BsonElement("subnetAddress")]
    public string SubnetAddress { get; set; } = "10.8.1.0";

    [BsonElement("subnetCidr")]
    public string SubnetCidr { get; set; } = "24";

    // ── Кэш, вычитываемый с сервера ───────────────────────────────────────────

    [BsonElement("serverPubKey")]
    public string? ServerPubKey { get; set; }

    [BsonElement("pskKey")]
    public string? PskKey { get; set; }

    /// <summary>
    /// Максимальный IP среди peer-ов в конфиге на момент последней синхронизации.
    /// Диагностический кэш; при выдаче занятые адреса читаются с узла заново.
    /// </summary>
    [BsonElement("lastKnownPeerIp")]
    public string? LastKnownPeerIp { get; set; }

    /// <summary>Параметры обфускации. Null для обычного WireGuard.</summary>
    [BsonElement("obfuscation")]
    public AwgObfuscationParams? Obfuscation { get; set; }

    public bool IsCached => ServerPubKey is not null;
}

/// <summary>Параметры контейнера Xray (VLESS Reality).</summary>
[BsonIgnoreExtraElements]
public class XrayProtocolParams
{
    /// <summary>SNI, под который маскируется трафик.</summary>
    [BsonElement("siteName")]
    public string SiteName { get; set; } = "www.googletagmanager.com";

    [BsonElement("serverConfigPath")]
    public string ServerConfigPath { get; set; } = "/opt/amnezia/xray/server.json";

    /// <summary>Публичный ключ Reality, вычитанный из контейнера. Приватный сервер не покидает.</summary>
    [BsonElement("publicKey")]
    public string? PublicKey { get; set; }

    [BsonElement("shortId")]
    public string? ShortId { get; set; }

    public bool IsCached => PublicKey is not null && ShortId is not null;
}

public static class XCoreRoles
{
    public const string Exit  = "exit";
    public const string Entry = "entry";
}

/// <summary>
/// Параметры собственного Xray-core (подписки Happ). Конфиг контейнера не хранится
/// в базе: он целиком выводится из этих полей и списка подписчиков, поэтому здесь
/// только то, что нельзя вывести.
/// </summary>
/// <remarks>
/// Свойства Id здесь нет, но BsonNoId оставлен на случай, если оно появится: правило
/// про вложенные документы описано у <see cref="ProtocolInstance"/>.
/// </remarks>
[BsonIgnoreExtraElements]
[BsonNoId]
public class XCoreProtocolParams
{
    /// <summary>См. <see cref="XCoreRoles"/>.</summary>
    [BsonElement("role")]
    public string Role { get; set; } = XCoreRoles.Exit;

    /// <summary>Домен узла: он же SNI Reality и имя сертификата Caddy.</summary>
    [BsonElement("domain")]
    public string Domain { get; set; } = default!;

    /// <summary>Образ Xray, закреплённый по digest.</summary>
    [BsonElement("imageRef")]
    public string ImageRef { get; set; } = default!;

    /// <summary>Приватный ключ Reality. Только в зашифрованном виде; наружу не отдаётся.</summary>
    [BsonElement("realityPrivateKey")]
    public EncryptedValue? RealityPrivateKey { get; set; }

    [BsonElement("realityPublicKey")]
    public string? RealityPublicKey { get; set; }

    [BsonElement("shortIds")]
    public List<string> ShortIds { get; set; } = [];

    [BsonElement("xhttpPath")]
    public string? XhttpPath { get; set; }

    [BsonElement("xhttpPort")]
    public int XhttpPort { get; set; } = 443;

    /// <summary>Порт API Xray на 127.0.0.1 (HandlerService и StatsService).</summary>
    [BsonElement("apiPort")]
    public int ApiPort { get; set; } = 10085;

    /// <summary>TLS-отпечаток, который клиент подставляет в ссылку подписки.</summary>
    [BsonElement("fingerprint")]
    public string Fingerprint { get; set; } = "firefox";

    /// <summary>Название подключения в приложении Happ, до 30 символов.</summary>
    [BsonElement("title")]
    public string? Title { get; set; }

    [BsonElement("sortOrder")]
    public int SortOrder { get; set; }

    /// <summary>Отдавать ли узел в подписках.</summary>
    [BsonElement("subscriptionEnabled")]
    public bool SubscriptionEnabled { get; set; } = true;

    /// <summary>
    /// Номер маршрута выхода (1..65535) — только у выхода. Входы выбирают по нему выход
    /// (<see cref="XCoreRoute"/>). Назначается при установке выхода; выход без номера в
    /// маршрутизацию входов не попадает, пока синхронизация его не назначит.
    /// </summary>
    [BsonElement("routeId")]
    [BsonIgnoreIfNull]
    public int? RouteId { get; set; }

    /// <summary>
    /// Служебный UUID входа — только у входа: по нему вход подключается к выходам. Это учётные
    /// данные, поэтому только в зашифрованном виде и наружу не отдаётся.
    /// </summary>
    [BsonElement("relayUuid")]
    [BsonIgnoreIfNull]
    public EncryptedValue? RelayUuid { get; set; }

    /// <summary>Российские сайты и адреса идут со входа напрямую, минуя выходы. Только у входа.</summary>
    [BsonElement("ruDirect")]
    public bool RuDirect { get; set; } = true;

    /// <summary>Домены «всегда напрямую» со входа (формат — <c>XCoreRoutingDomains</c>). Только у входа.</summary>
    [BsonElement("directDomains")]
    public List<string> DirectDomains { get; set; } = [];

    /// <summary>Домены «всегда через VPN», сильнее российских списков. Только у входа.</summary>
    [BsonElement("proxyDomains")]
    public List<string> ProxyDomains { get; set; } = [];

    /// <summary>
    /// Домен подписки, A-запись которого указывает на этот вход, — только у входа. Caddy входа
    /// проксирует по нему <c>/sub/</c> на API панели, чтобы ссылка подписки открывалась из РФ и в
    /// зонах белых списков, где сервер панели за рубежом недоступен. Null — вход подписку не обслуживает.
    /// </summary>
    [BsonElement("subscriptionHost")]
    [BsonIgnoreIfNull]
    public string? SubscriptionHost { get; set; }

    /// <summary>
    /// Состояние плеч вход → выход по последней проверке — только у входа. Это наблюдение для
    /// оператора: маршрутизацию оно не меняет. Пишется точечно, без перезаписи документа узла.
    /// </summary>
    [BsonElement("exitHealth")]
    public List<XCoreExitHealth> ExitHealth { get; set; } = [];

    /// <summary>
    /// VLESS Encryption (<c>mlkem768x25519plus</c>) на inbound-е этого узла. Выключено по умолчанию: поддержка в
    /// Happ документацией не подтверждена, а клиент без неё не подключится к узлу вовсе. Включается из панели и
    /// генерирует ключи на узле; выключение стирает их. Флаг без ключей (запись правили в обход панели) рендерер
    /// не молчит, а отказывает: тихое «none» отключило бы шифрование, а ссылка с пустым параметром не подключилась бы.
    /// </summary>
    [BsonElement("vlessEncryption")]
    public bool VlessEncryption { get; set; }

    /// <summary>Серверная строка <c>decryption</c> из <c>xray vlessenc</c>: содержит приватный ключ, только в зашифрованном виде.</summary>
    [BsonElement("vlessDecryption")]
    [BsonIgnoreIfNull]
    public EncryptedValue? VlessDecryption { get; set; }

    /// <summary>Клиентская строка <c>encryption</c> из <c>xray vlessenc</c>: публичная, идёт в ссылки подписки и в outbound-ы входов.</summary>
    [BsonElement("vlessEncryptionClient")]
    [BsonIgnoreIfNull]
    public string? VlessEncryptionClient { get; set; }

    /// <summary>Хеш Caddyfile, записанного на узел в последний раз; сверяется с рендером из базы.</summary>
    [BsonElement("appliedCaddyRevision")]
    [BsonIgnoreIfNull]
    public string? AppliedCaddyRevision { get; set; }

    /// <summary>
    /// Ревизия Caddyfile, на которой последний раз не удался выпуск сертификата домена подписки. Вместе с
    /// <see cref="CaddyFailedAt"/> задаёт паузу: Let's Encrypt после серии неудач блокирует выпуск, а каждая
    /// синхронизация иначе перезапускала бы Caddy и просила сертификат заново. Только у входа.
    /// </summary>
    [BsonElement("caddyFailedRevision")]
    [BsonIgnoreIfNull]
    public string? CaddyFailedRevision { get; set; }

    [BsonElement("caddyFailedAt")]
    [BsonIgnoreIfNull]
    public DateTime? CaddyFailedAt { get; set; }

    /// <summary>
    /// Тег релиза российских geo-списков (runetfreedom), файлы которого лежат на узле, — только у входа. Пусто —
    /// на узле только встроенные списки образа, и конфиг не имеет права ссылаться на <c>ext:rf-…</c>: файла нет.
    /// Пишется после подмены файлов на узле, поэтому тег в базе означает «файлы этого релиза на месте».
    /// </summary>
    [BsonElement("rfListsTag")]
    [BsonIgnoreIfNull]
    public string? RfListsTag { get; set; }

    /// <summary>Когда файлы <see cref="RfListsTag"/> были положены на узел; от этого считается минимальный возраст.</summary>
    [BsonElement("rfListsAppliedAt")]
    [BsonIgnoreIfNull]
    public DateTime? RfListsAppliedAt { get; set; }

    /// <summary>Когда списки в последний раз сверяли с GitHub: и применили релиз, и убедились, что новее нет.</summary>
    [BsonElement("rfListsCheckedAt")]
    [BsonIgnoreIfNull]
    public DateTime? RfListsCheckedAt { get; set; }

    /// <summary>
    /// Причина последнего неудачного обновления списков; null — обновление удалось или не пробовалось. Отдельно
    /// от <see cref="SyncError"/>: тот стирается каждой успешной синхронизацией подписчиков, а проблема со
    /// списками от неё не уходит.
    /// </summary>
    [BsonElement("geoError")]
    [BsonIgnoreIfNull]
    public string? GeoError { get; set; }

    /// <summary>Хеш конфига (вместе с пользователями), применённого к узлу в последний раз.</summary>
    [BsonElement("appliedRevision")]
    public string? AppliedRevision { get; set; }

    /// <summary>
    /// Хеш того же конфига без пользователей. Отличие от него означает структурное
    /// изменение (ключи, порт, путь), которое применяется только перезапуском; смена
    /// состава пользователей идёт через API без перезапуска.
    /// </summary>
    [BsonElement("appliedStructureRevision")]
    public string? AppliedStructureRevision { get; set; }

    [BsonElement("appliedAt")]
    public DateTime? AppliedAt { get; set; }

    /// <summary>Причина последнего неудачного применения; null, если всё применено.</summary>
    [BsonElement("syncError")]
    public string? SyncError { get; set; }
}

/// <summary>Результат последней проверки одного плеча вход → выход.</summary>
[BsonIgnoreExtraElements]
[BsonNoId]
public class XCoreExitHealth
{
    /// <summary>Узел-выход, к которому проверялось плечо.</summary>
    [BsonElement("serverId")]
    public string ServerId { get; set; } = default!;

    [BsonElement("ok")]
    public bool Ok { get; set; }

    [BsonElement("checkedAt")]
    public DateTime CheckedAt { get; set; }

    /// <summary>Короткая причина сбоя без текста команд; null, если плечо открыто.</summary>
    [BsonElement("error")]
    [BsonIgnoreIfNull]
    public string? Error { get; set; }
}

/// <summary>Состояние узла по данным фоновой проверки.</summary>
[BsonIgnoreExtraElements]
public class ServerHealth
{
    [BsonElement("lastCheckAt")]
    public DateTime? LastCheckAt { get; set; }

    [BsonElement("online")]
    public bool Online { get; set; }

    [BsonElement("uptimeSince")]
    public DateTime? UptimeSince { get; set; }

    [BsonElement("load1")]
    public double? Load1 { get; set; }

    [BsonElement("cpuCount")]
    public int? CpuCount { get; set; }

    [BsonElement("memPercent")]
    public double? MemPercent { get; set; }

    [BsonElement("diskPercent")]
    public double? DiskPercent { get; set; }

    [BsonElement("dockerVersion")]
    public string? DockerVersion { get; set; }

    [BsonElement("kernel")]
    public string? Kernel { get; set; }

    /// <summary>Загрузка в процентах для полосы в таблице: load1 / число ядер.</summary>
    public double? LoadPercent =>
        Load1 is { } l && CpuCount is { } c && c > 0 ? Math.Round(l / c * 100, 1) : null;
}
