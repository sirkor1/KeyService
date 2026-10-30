namespace AmneziaKeyService.Core.Exceptions;

/// <summary>
/// Номер маршрута выхода уже занят другим узлом: уникальный индекс M017 отклонил запись. Репозиторий
/// превращает ошибку драйвера в это исключение, чтобы вызывающий мог взять следующий свободный номер,
/// не разбирая коды MongoDB, — и чтобы проверки обходились без живой базы.
/// </summary>
public class RouteIdTakenException : Exception
{
    public RouteIdTakenException(Exception? inner = null)
        : base("Номер маршрута выхода xcore уже занят другим узлом.", inner) { }
}
