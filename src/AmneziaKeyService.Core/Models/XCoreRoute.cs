namespace AmneziaKeyService.Core.Models;

/// <summary>
/// Маршрут выхода в UUID ссылки через вход (Xray <c>vlessRoute</c>): клиент подменяет третью
/// группу UUID (<c>xxxxxxxx-xxxx-NNNN-xxxx-xxxxxxxxxxxx</c>, big-endian uint16) номером маршрута,
/// а правило входа <c>{"vlessRoute": "N"}</c> по нему выбирает выход. Сервер при аутентификации эти
/// два байта игнорирует, поэтому на входе достаточно одного пользователя на подписку.
///
/// Чистые функции без состояния: формат ошибается молча — подмена не в той группе даёт
/// ссылку, которая подключается, но уходит не на тот выход.
/// </summary>
public static class XCoreRoute
{
    public const int MinRouteId = 1;
    public const int MaxRouteId = 65535;

    /// <summary>
    /// Сколько раз выход берёт следующий свободный номер, если уникальный индекс отклонил выбранный:
    /// проиграть гонку пять раз подряд могут только пять одновременно ставящихся выходов.
    /// </summary>
    public const int AssignAttempts = 5;

    /// <summary>Смещение третьей группы в записи UUID формата «D» (8 + дефис + 4 + дефис).</summary>
    private const int ThirdGroupOffset = 14;

    private const int GroupLength = 4;

    public static bool IsValid(int routeId) => routeId is >= MinRouteId and <= MaxRouteId;

    /// <summary>
    /// UUID с третьей группой, равной <paramref name="routeId"/> (четыре hex-цифры в нижнем
    /// регистре). Работает с текстом формата «D», а не с байтами <see cref="Guid"/>: у него первые
    /// три группы хранятся в порядке байт платформы, и подмена по индексам массива попала бы не туда.
    /// </summary>
    public static string WithRoute(string uuid, int routeId)
    {
        if (!IsValid(routeId))
            throw new ArgumentOutOfRangeException(nameof(routeId), routeId,
                $"Номер маршрута должен быть от {MinRouteId} до {MaxRouteId}.");
        if (!Guid.TryParse(uuid, out var guid))
            throw new ArgumentException("UUID не в формате GUID.", nameof(uuid));

        var text = guid.ToString("D");
        return string.Concat(
            text.AsSpan(0, ThirdGroupOffset),
            routeId.ToString("x4"),
            text.AsSpan(ThirdGroupOffset + GroupLength));
    }

    /// <summary>
    /// Наименьший свободный номер маршрута. Освободившиеся номера используются повторно: их всего
    /// 65535, а выходов обычно единицы, и компактные номера проще узнавать в конфиге.
    /// </summary>
    public static int NextFree(IEnumerable<int> used)
    {
        var taken = used.ToHashSet();
        for (var id = MinRouteId; id <= MaxRouteId; id++)
            if (!taken.Contains(id)) return id;
        throw new InvalidOperationException("Свободных номеров маршрута не осталось.");
    }
}
