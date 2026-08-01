namespace AmneziaKeyService.Core.DTOs.Panel;

/// <summary>
/// Один запрос, питающий строку статистики в шапке, четыре плитки KPI
/// и все бейджи сайдбара. Панель дёргает его на каждом экране, поэтому
/// он собирается агрегатами, а не выборкой документов.
/// </summary>
public record DashboardSummaryDto(
    int ServersOk,
    int ServersTotal,
    long KeysActive,
    long KeysTotal,
    long TrafficMonthBytes,
    AttentionDto Attention,
    NavBadgesDto NavBadges,
    DateTime? LastSyncAt,
    string AppVersion);

/// <summary>
/// Плитка «Требуют внимания». Items — расшифровка, чтобы плитка была кликабельной.
/// </summary>
public record AttentionDto(int Total, IReadOnlyList<AttentionItemDto> Items);

/// <summary>Kind: "server_offline" | "server_error" | "keys_expiring" | "server_uncached".</summary>
public record AttentionItemDto(string Kind, string Message, long Count);

/// <summary>Числа рядом с пунктами меню.</summary>
public record NavBadgesDto(long Servers, long Keys, long Users, long Logs);
