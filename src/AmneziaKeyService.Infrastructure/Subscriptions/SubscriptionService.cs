using AmneziaKeyService.Core.Exceptions;
using AmneziaKeyService.Core.Interfaces;
using AmneziaKeyService.Core.Models;
using AmneziaKeyService.Infrastructure.Services;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using MongoDB.Bson;

namespace AmneziaKeyService.Infrastructure.Subscriptions;

/// <param name="ExpiryDays">Null — из настроек панели, 0 — бессрочно (как при выдаче ключа).</param>
/// <param name="TrafficLimitBytes">Null — из настроек панели, 0 — без квоты.</param>
/// <param name="Actor">Кто выдаёт: попадает в журнал и в createdByUserId.</param>
public record SubscriptionCreateOptions(
    int? ExpiryDays = null,
    long? TrafficLimitBytes = null,
    string Source = KeySources.Panel,
    AuditActor Actor = default);

/// <summary>
/// Итог самообслуживания (кнопка в боте): подписка либо осознанный отказ с причиной. Отказ — штатный
/// исход, а не ошибка, поэтому это не исключение и не null: вызывающий обязан обработать обе ветки.
/// </summary>
public abstract record SelfServiceSubscriptionResult
{
    private SelfServiceSubscriptionResult() { }

    /// <summary>Подписка выдана пользователю; <paramref name="Created"/> — создана только что, а не найдена активной.</summary>
    public sealed record Granted(Subscription Subscription, bool Created) : SelfServiceSubscriptionResult;

    /// <summary>
    /// Новую подписку самообслуживанием не выдать: прежнюю отозвали по причине, которую пользователь
    /// не снимает сам. <paramref name="Reason"/> — одно из <see cref="RevokeReasons"/>.
    /// </summary>
    public sealed record Denied(string Reason) : SelfServiceSubscriptionResult;
}

/// <summary>
/// Жизненный цикл подписок. SSH не использует: узлам об изменениях сообщает событие
/// <c>xcore.sync</c>, которое исполняет worker. Поэтому сервис доступен и api, и боту, и worker.
///
/// Порядок во всех мутациях один: запись в базу, журнал, затем публикация синхронизации.
/// Публикация после записи — требование <see cref="IDomainEventPublisher.PublishIfNoPendingAsync"/>.
/// В журнал не попадают ни токен, ни UUID: журнал выгружается из панели целиком.
/// </summary>
public class SubscriptionService
{
    private readonly ISubscriptionRepository _subscriptions;
    private readonly IUserRepository _users;
    private readonly IPanelSettingsRepository _settings;
    private readonly IVpnServerRepository _servers;
    private readonly ISecretProtector _secrets;
    private readonly IAuditService _audit;
    private readonly XCoreSyncPublisher _publisher;
    private readonly SubscriptionOptions _options;
    private readonly ILogger<SubscriptionService> _logger;

    public SubscriptionService(
        ISubscriptionRepository subscriptions,
        IUserRepository users,
        IPanelSettingsRepository settings,
        IVpnServerRepository servers,
        ISecretProtector secrets,
        IAuditService audit,
        XCoreSyncPublisher publisher,
        IOptions<SubscriptionOptions> options,
        ILogger<SubscriptionService> logger)
    {
        _subscriptions = subscriptions;
        _users         = users;
        _settings      = settings;
        _servers       = servers;
        _secrets       = secrets;
        _audit         = audit;
        _publisher     = publisher;
        _options       = options.Value;
        _logger        = logger;
    }

    public async Task<Subscription> CreateAsync(
        string userId, SubscriptionCreateOptions options, CancellationToken ct = default)
    {
        var user = await _users.FindByIdAsync(userId, ct)
            ?? throw new NotFoundException("Пользователь не найден.");

        if (await _subscriptions.FindActiveByUserAsync(user.Id, ct) is not null)
            throw new BadRequestException("У пользователя уже есть активная подписка.");

        var settings = await _settings.GetAsync(ct);

        // Семантика та же, что при выдаче ключа: null — из настроек, 0 — без ограничения.
        // Ноль нельзя пропускать как есть: квота в ноль байт исчерпана первым же пакетом.
        var expiryDays = options.ExpiryDays ?? settings.DefaultExpiryDays;
        if (expiryDays is <= 0) expiryDays = null;
        var trafficLimit = options.TrafficLimitBytes ?? settings.DefaultTrafficLimitBytes;
        if (trafficLimit is <= 0) trafficLimit = null;

        if (expiryDays > PanelSettingsRules.MaxDefaultExpiryDays)
            throw new BadRequestException(
                $"Срок подписки не может превышать {PanelSettingsRules.MaxDefaultExpiryDays} дней.");
        RequireLimitInBounds(trafficLimit);

        var now = DateTime.UtcNow;
        var token = SubscriptionTokenCrypto.Create();
        var subscription = new Subscription
        {
            Id                = ObjectId.GenerateNewId().ToString(),
            UserId            = user.Id,
            Status            = SubscriptionStatuses.Active,
            ExpiresAt         = expiryDays is { } days ? now.AddDays(days) : null,
            TrafficLimitBytes = trafficLimit,
            XrayUuid          = Guid.NewGuid().ToString("D"),
            TokenHash         = SubscriptionTokenCrypto.Hash(token),
            TokenEncrypted    = _secrets.Protect(token),
            CreatedAt         = now,
            CreatedByUserId   = options.Actor.UserId,
            Source            = options.Source,
        };

        // Вторая подписка пользователя из-за гонки отсекается уникальным индексом, а не проверкой выше.
        if (!await _subscriptions.TryCreateAsync(subscription, ct))
            throw new BadRequestException("У пользователя уже есть активная подписка.");

        await _audit.WriteAsync(AuditEvents.SubscriptionCreated,
            $"Выдана подписка пользователю «{DisplayName(user)}»",
            options.Actor, AuditTargets.Subscription, subscription.Id, DisplayName(user),
            meta: new Dictionary<string, string> { ["source"] = options.Source }, ct: ct);

        await _publisher.PublishForAllAsync(options.Actor.UserId, ct);
        return subscription;
    }

    /// <summary>
    /// Самообслуживание (бот). Активная подписка отдаётся как есть. Если её нет, решает причина отзыва
    /// последней: истёкший срок — повод выдать новую (срок и квота по умолчанию), а исчерпанная квота
    /// или ручной отзыв — нет, иначе кнопка в боте обходила бы решение администратора и лимит трафика.
    /// Первая подписка пользователя создаётся. Администратор из панели создаёт подписку всегда
    /// через <see cref="CreateAsync"/> — это правило его не касается.
    /// </summary>
    public async Task<SelfServiceSubscriptionResult> GetOrCreateForUserAsync(
        string userId, string source, CancellationToken ct = default)
    {
        if (await _subscriptions.FindActiveByUserAsync(userId, ct) is { } existing)
            return new SelfServiceSubscriptionResult.Granted(existing, Created: false);

        var user = await _users.FindByIdAsync(userId, ct)
            ?? throw new NotFoundException("Пользователь не найден.");

        // Отказывает всё, кроме явного «expired»: подписка без причины (данные до появления
        // поля) безопаснее считать отключённой администратором, чем выдавать новую молча.
        if (await _subscriptions.FindLatestByUserAsync(userId, ct) is { IsActive: false } latest
            && latest.RevokeReason != RevokeReasons.Expired)
            return new SelfServiceSubscriptionResult.Denied(latest.RevokeReason ?? RevokeReasons.Manual);

        try
        {
            var created = await CreateAsync(userId,
                new SubscriptionCreateOptions(Source: source, Actor: new AuditActor(user.Id, user.Username)), ct);
            return new SelfServiceSubscriptionResult.Granted(created, Created: true);
        }
        catch (BadRequestException)
        {
            // Параллельный запрос мог успеть создать её между проверкой и вставкой; тогда
            // отдаём её. Если активной всё равно нет, отказ был по другой причине.
            var raced = await _subscriptions.FindActiveByUserAsync(userId, ct);
            if (raced is null) throw;
            return new SelfServiceSubscriptionResult.Granted(raced, Created: false);
        }
    }

    public async Task<Subscription> RevokeAsync(
        string id, string reason, AuditActor actor, CancellationToken ct = default)
    {
        if (reason is not (RevokeReasons.Manual or RevokeReasons.Expired or RevokeReasons.Quota))
            throw new ArgumentException("Неизвестная причина отзыва.", nameof(reason));

        var subscription = await RequireAsync(id, ct);

        // Отозвать уже отозванную — не ошибка и не повод ни для журнала, ни для синхронизации:
        // переход сделал кто-то другой и он же опубликовал событие.
        if (!await _subscriptions.TryRevokeAsync(id, reason, DateTime.UtcNow, ct))
            return await RequireAsync(id, ct);

        await WriteRevokedAuditAsync(subscription, reason, actor, ct);
        await _publisher.PublishForAllAsync(actor.UserId, ct);
        return await RequireAsync(id, ct);
    }

    /// <summary>
    /// Отзывает подписки с истёкшим сроком и исчерпанной квотой и один раз публикует
    /// синхронизацию на все узлы. Возвращает, сколько отозвано.
    /// </summary>
    public async Task<int> RevokeDueAsync(DateTime now, CancellationToken ct = default)
    {
        var revoked = 0;
        foreach (var subscription in await _subscriptions.FindEnforcementCandidatesAsync(now, ct))
        {
            ct.ThrowIfCancellationRequested();

            // Срок проверяется первым: истёк и выбрал квоту одновременно — истёкший срок точнее.
            var reason = subscription.IsExpired(now) ? RevokeReasons.Expired : RevokeReasons.Quota;
            try
            {
                if (!await _subscriptions.TryRevokeAsync(subscription.Id, reason, now, ct)) continue;
                revoked++;
                await WriteRevokedAuditAsync(subscription, reason, new AuditActor(null, null), ct);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                // Одна неудача не должна оставить без отзыва остальные.
                _logger.LogError(ex, "Не удалось отозвать подписку {SubscriptionId} по причине {Reason}.",
                    subscription.Id, reason);
            }
        }

        if (revoked > 0) await _publisher.PublishForAllAsync(null, ct);
        return revoked;
    }

    /// <summary>
    /// Меняет токен и UUID разом. Токена мало: UUID есть в каждой ссылке на узел, и старая
    /// ссылка с прежним UUID продолжала бы подключать уже настроенные устройства.
    /// </summary>
    public async Task<Subscription> RegenerateAsync(string id, AuditActor actor, CancellationToken ct = default)
    {
        var subscription = await RequireAsync(id, ct);
        RequireActive(subscription, "Перевыпустить можно только активную подписку.");

        var token = SubscriptionTokenCrypto.Create();
        if (!await _subscriptions.TryReplaceCredentialsAsync(
                id, SubscriptionTokenCrypto.Hash(token), _secrets.Protect(token)!,
                Guid.NewGuid().ToString("D"), DateTime.UtcNow, ct))
            throw new BadRequestException("Подписка уже отозвана — перевыпустить её нельзя.");

        var name = await OwnerNameAsync(subscription.UserId, ct);
        await _audit.WriteAsync(AuditEvents.SubscriptionRegenerated,
            $"Перевыпущена подписка пользователя «{name}»: прежняя ссылка перестала работать",
            actor, AuditTargets.Subscription, id, name, AuditLevels.Warn, ct: ct);

        await _publisher.PublishForAllAsync(actor.UserId, ct);
        return await RequireAsync(id, ct);
    }

    /// <summary>
    /// Заменяет срок и квоту целиком: null (для квоты и 0) снимает ограничение. Синхронизация
    /// не нужна — на узлах список пользователей от границ не зависит, их проверяет принуждение.
    /// </summary>
    public async Task<Subscription> UpdateLimitsAsync(
        string id, DateTime? expiresAt, long? trafficLimitBytes, AuditActor actor, CancellationToken ct = default)
    {
        var subscription = await RequireAsync(id, ct);
        RequireActive(subscription, "Изменить границы можно только у активной подписки.");

        var expires = expiresAt?.ToUniversalTime();
        if (expires is { } e && e <= DateTime.UtcNow)
            throw new BadRequestException("Срок подписки должен быть в будущем.");
        var limit = trafficLimitBytes is <= 0 ? null : trafficLimitBytes;
        RequireLimitInBounds(limit);

        if (!await _subscriptions.TryUpdateLimitsAsync(id, expires, limit, ct))
            throw new BadRequestException("Подписка уже отозвана — изменить её границы нельзя.");

        var name = await OwnerNameAsync(subscription.UserId, ct);
        await _audit.WriteAsync(AuditEvents.SubscriptionLimitsChanged,
            $"Изменены срок и квота подписки пользователя «{name}»",
            actor, AuditTargets.Subscription, id, name, ct: ct);

        return await RequireAsync(id, ct);
    }

    /// <summary>
    /// Публичная ссылка активной подписки. Токен расшифровывается здесь и никуда не сохраняется. Адрес — домен
    /// подписки входа, если он задан (<see cref="SubscriptionRenderer.TryBuildSubscriptionUrl"/>), иначе глобальный.
    /// </summary>
    public async Task<string> BuildLinkAsync(Subscription subscription, CancellationToken ct = default)
    {
        RequireActive(subscription, "Подписка отозвана: ссылка больше не действует.");

        var token = _secrets.Unprotect(subscription.TokenEncrypted)
            ?? throw new BadRequestException("Ссылку подписки восстановить нельзя: токен не сохранён.");

        return SubscriptionRenderer.TryBuildSubscriptionUrl(token, await _servers.GetAllAsync(ct), _options, out var url)
            ? url
            : throw new BadRequestException(
                "Не задан публичный адрес подписок: укажите настройку Subscription:PublicBaseUrl " +
                "(переменная Subscription__PublicBaseUrl), например https://sub.example.com, " +
                "либо домен подписки на входе.");
    }

    /// <summary>Можно ли сейчас построить ссылку подписки: задан глобальный адрес или домен подписки входа.</summary>
    public async Task<bool> CanBuildLinkAsync(CancellationToken ct = default) =>
        SubscriptionRenderer.TryBuildSubscriptionUrl("probe", await _servers.GetAllAsync(ct), _options, out _);

    // ── Вспомогательное ───────────────────────────────────────────────────────

    private async Task<Subscription> RequireAsync(string id, CancellationToken ct) =>
        await _subscriptions.FindByIdAsync(id, ct) ?? throw new NotFoundException("Подписка не найдена.");

    private static void RequireActive(Subscription subscription, string message)
    {
        if (!subscription.IsActive) throw new BadRequestException(message);
    }

    private static void RequireLimitInBounds(long? limit)
    {
        if (limit > PanelSettingsRules.MaxDefaultTrafficLimitBytes)
            throw new BadRequestException("Квота трафика не может превышать 10 ТиБ.");
    }

    private async Task WriteRevokedAuditAsync(
        Subscription subscription, string reason, AuditActor actor, CancellationToken ct)
    {
        var name = await OwnerNameAsync(subscription.UserId, ct);
        await _audit.WriteAsync(AuditEvents.SubscriptionRevoked,
            $"Отозвана подписка пользователя «{name}»: {Describe(reason)}",
            actor, AuditTargets.Subscription, subscription.Id, name,
            reason == RevokeReasons.Manual ? AuditLevels.Info : AuditLevels.Warn,
            new Dictionary<string, string> { ["reason"] = reason }, ct);
    }

    private async Task<string> OwnerNameAsync(string userId, CancellationToken ct) =>
        await _users.FindByIdAsync(userId, ct) is { } user ? DisplayName(user) : userId;

    private static string DisplayName(User user) => user.DisplayName ?? user.Username;

    private static string Describe(string reason) => reason switch
    {
        RevokeReasons.Expired => "истёк срок действия",
        RevokeReasons.Quota   => "исчерпана квота трафика",
        _                     => "отозвана вручную",
    };
}
