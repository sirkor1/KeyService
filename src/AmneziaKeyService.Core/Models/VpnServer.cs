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
    /// Протокол по умолчанию: явно указанный, иначе первый установленный,
    /// иначе первый вообще. Используется legacy-адаптером и выдачей ключей.
    /// </summary>
    public ProtocolInstance? DefaultProtocol =>
        Protocols.FirstOrDefault(p => p.Id == DefaultProtocolId)
        ?? Protocols.FirstOrDefault(p => p.State == ProtocolStates.Installed)
        ?? Protocols.FirstOrDefault();

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
    /// Нужен, чтобы не пересечься с peer-ами, заведёнными мимо сервиса.
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
