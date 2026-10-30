using System.Net;
using System.Net.Sockets;

namespace AmneziaKeyService.Infrastructure.Protocols.XCore;

/// <summary>
/// Разрешение имён вынесено в интерфейс, чтобы проверку «домен указывает на узел»
/// можно было прогнать без сети: от неё зависит, будет ли вообще выпущен сертификат.
/// </summary>
public interface IDnsResolver
{
    /// <summary>A-записи имени (IPv4). Несуществующее имя — пустой список, а не ошибка.</summary>
    Task<IReadOnlyList<IPAddress>> ResolveIPv4Async(string host, CancellationToken ct = default);
}

/// <summary>Системный резолвер. Следует за CNAME, как и Let's Encrypt при проверке HTTP-01.</summary>
public sealed class SystemDnsResolver : IDnsResolver
{
    public async Task<IReadOnlyList<IPAddress>> ResolveIPv4Async(string host, CancellationToken ct = default)
    {
        try
        {
            return await Dns.GetHostAddressesAsync(host, AddressFamily.InterNetwork, ct);
        }
        catch (SocketException)
        {
            // NXDOMAIN и «нет данных» приходят исключением; для проверки это «записей нет».
            return [];
        }
    }
}
