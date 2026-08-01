namespace AmneziaKeyService.Infrastructure.Monitoring;

/// <summary>Арифметика счётчиков трафика. Вынесена отдельно, чтобы проверяться без SSH.</summary>
public static class UsageMath
{
    /// <summary>
    /// Приращение между двумя показаниями сырого счётчика.
    ///
    /// Счётчики wg монотонны с момента старта контейнера и обнуляются при его
    /// перезапуске. Если новое показание меньше сохранённого, контейнер
    /// перезапустился — и всё, что видно сейчас, целиком является новым
    /// приращением. Трафик, прошедший между последним опросом и перезапуском,
    /// при этом теряется: узнать его уже неоткуда.
    /// </summary>
    public static long Delta(long raw, long previousRaw)
    {
        if (raw < 0) return 0;
        return raw >= previousRaw ? raw - previousRaw : raw;
    }
}
