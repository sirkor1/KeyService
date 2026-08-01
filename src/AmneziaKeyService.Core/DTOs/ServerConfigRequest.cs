using System.ComponentModel.DataAnnotations;

namespace AmneziaKeyService.Core.DTOs;

/// <summary>
/// Данные AWG-сервера: IP/хост, SSH-кредиты и параметры подключения.
/// Сохраняются в MongoDB коллекцию server_config.
/// </summary>
public class ServerConfigRequest
{
    [Required]
    public string Host { get; set; } = default!;

    /// <summary>Название сервера в приложении AmneziaVPN.</summary>
    public string Description { get; set; } = "AmneziaVPN Server";

    public int SshPort { get; set; } = 22;

    [Required]
    public string SshUser { get; set; } = default!;

    /// <summary>SSH-пароль. Указывается либо пароль, либо путь к ключу.</summary>
    public string? SshPassword { get; set; }

    /// <summary>Путь к приватному SSH-ключу на машине где запущен сервис.</summary>
    public string? SshPrivateKeyPath { get; set; }

    public string AwgPort { get; set; } = "55424";
    public string ContainerName { get; set; } = "amnezia-awg";
    public string AwgConfigPath { get; set; } = "/opt/amnezia/awg/wg0.conf";
    public string ServerPublicKeyPath { get; set; } = "/opt/amnezia/awg/wireguard_server_public_key.key";
    public string PskKeyPath { get; set; } = "/opt/amnezia/awg/wireguard_psk.key";
    public string AwgInterface { get; set; } = "wg0";
    /// <summary>"wg" для legacy-контейнера, "awg" для нового образа.</summary>
    public string WgBin { get; set; } = "wg";
    public string SubnetAddress { get; set; } = "10.8.1.0";
    public string SubnetCidr { get; set; } = "24";

    // ── Метаданные для панели ─────────────────────────────────────────────────

    /// <summary>Локация: «Нидерланды, Амстердам».</summary>
    public string? Geo { get; set; }

    /// <summary>Провайдер: Hetzner, Netcup.</summary>
    public string? Provider { get; set; }

    public string? Note { get; set; }

    /// <summary>Лимит ключей на узел. Null — без ограничения.</summary>
    public int? KeyLimit { get; set; }
}

/// <summary>
/// Частичное обновление узла: применяются только переданные поля.
///
/// Прежний PUT принимал полный ServerConfigRequest со значениями по умолчанию,
/// поэтому запрос без awgPort молча переписывал реальный порт узла на 55424,
/// и все последующие конфиги выдавались нерабочими. Здесь всё nullable,
/// и не присланное поле остаётся как есть.
/// </summary>
public class ServerPatchRequest
{
    public string? Host { get; set; }
    public string? Name { get; set; }
    public string? Geo { get; set; }
    public string? Provider { get; set; }
    public string? Note { get; set; }
    public int? KeyLimit { get; set; }

    public int? SshPort { get; set; }
    public string? SshUser { get; set; }

    /// <summary>Новый пароль. Не передан — прежний сохраняется.</summary>
    public string? SshPassword { get; set; }

    public string? SshPrivateKeyPath { get; set; }

    public string? Dns1 { get; set; }
    public string? Dns2 { get; set; }
}
