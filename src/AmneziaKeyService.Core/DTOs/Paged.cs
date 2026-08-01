namespace AmneziaKeyService.Core.DTOs;

/// <summary>Страница результатов. Единый формат для всех списков панели.</summary>
public record Paged<T>(IReadOnlyList<T> Items, long Total, int Page, int PageSize)
{
    public static Paged<T> Empty(int page, int pageSize) => new([], 0, page, pageSize);

    public Paged<TOut> Map<TOut>(Func<T, TOut> selector)
        => new([.. Items.Select(selector)], Total, Page, PageSize);
}

/// <summary>
/// Параметры постраничного запроса. Значения нормализуются в конструкторе:
/// на страницу приходит любой мусор из query-строки.
/// </summary>
public record PageRequest
{
    private const int MaxPageSize = 200;

    public int Page { get; }
    public int PageSize { get; }

    public PageRequest(int? page = null, int? pageSize = null)
    {
        Page     = page is null or < 1 ? 1 : page.Value;
        PageSize = pageSize switch
        {
            null or < 1  => 25,
            > MaxPageSize => MaxPageSize,
            _             => pageSize.Value
        };
    }

    public int Skip => (Page - 1) * PageSize;
}
