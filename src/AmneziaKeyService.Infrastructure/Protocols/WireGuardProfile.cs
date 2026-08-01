using AmneziaKeyService.Core.Models;

namespace AmneziaKeyService.Infrastructure.Protocols;

/// <summary>
/// Различия между awg2, awg legacy и обычным WireGuard.
///
/// Их ровно четыре, поэтому три отдельных конфигуратора не нужны — хватает
/// одного, параметризованного этой записью.
/// </summary>
public record WireGuardProfile(
    string Kind,
    /// <summary>Папка шаблона в ServerScripts.</summary>
    string TemplateFolder,
    /// <summary>Ключ протокола в конфиге AmneziaVPN: "awg" или "wireguard".</summary>
    string ConfigKey,
    /// <summary>Есть ли параметры обфускации Jc/S/H/I.</summary>
    bool HasObfuscation,
    /// <summary>Поддерживает ли S3/S4 — их нет в awg legacy.</summary>
    bool HasExtendedJunk,
    /// <summary>Значение protocol_version в конфиге. Null — поле не добавляется.</summary>
    string? ProtocolVersion)
{
    public static readonly WireGuardProfile Awg2 = new(
        Kind: ProtocolKinds.Awg2,
        TemplateFolder: "awg",
        ConfigKey: "awg",
        HasObfuscation: true,
        HasExtendedJunk: true,
        ProtocolVersion: "2");

    public static readonly WireGuardProfile AwgLegacy = new(
        Kind: ProtocolKinds.AwgLegacy,
        TemplateFolder: "awg_legacy",
        ConfigKey: "awg",
        HasObfuscation: true,
        HasExtendedJunk: false,
        ProtocolVersion: null);

    public static readonly WireGuardProfile WireGuard = new(
        Kind: ProtocolKinds.WireGuard,
        TemplateFolder: "wireguard",
        ConfigKey: "wireguard",
        HasObfuscation: false,
        HasExtendedJunk: false,
        ProtocolVersion: null);

    public static WireGuardProfile For(string kind) => kind switch
    {
        ProtocolKinds.Awg2      => Awg2,
        ProtocolKinds.AwgLegacy => AwgLegacy,
        ProtocolKinds.WireGuard => WireGuard,
        _ => throw new ArgumentOutOfRangeException(
            nameof(kind), kind, "Протокол не относится к семейству WireGuard."),
    };
}
