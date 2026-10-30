using System.Text.RegularExpressions;
using AmneziaKeyService.Core.Interfaces;
using AmneziaKeyService.Core.Models;

namespace AmneziaKeyService.Infrastructure.Protocols.XCore;

/// <summary>Переход состояния плеча между двумя проверками: из рабочего в упавшее или обратно.</summary>
public sealed record XCoreExitTransition(string ServerId, bool NowOk, string? Error);

/// <summary>
/// Проверка плеча вход → выход с хоста входа. Reality выхода отдаёт запрос, не прошедший Reality, Caddy выхода,
/// и тот отвечает 200 заглушкой с настоящим сертификатом: 200 значит, что плечо открыто на уровне TCP и TLS.
/// Маршрутизацию проверка не меняет — это наблюдение для оператора. Разбор и переходы — чистые функции:
/// они ошибаются молча (ложная тревога на каждом тике или молчание о падении), поэтому проверяются
/// на образцах в tools/VerifyXCore.
/// </summary>
public static partial class XCoreExitProbe
{
    public const int TimeoutSeconds = 8;

    /// <summary>
    /// Домен идёт из базы, но попадает в shell: проверенное имя подставлять безопасно, а значение с
    /// пробелами, кавычками или переводом строки сюда не доходит (<see cref="Targets"/>).
    /// </summary>
    public static string Command(string domain) =>
        $"curl -s -o /dev/null --max-time {TimeoutSeconds} -w '%{{http_code}}' https://{domain}/";

    /// <summary>
    /// Выходы, которые надо проверить: те же, что вход получает в конфиг (<see cref="XCoreTopology.RoutableExits"/>).
    /// Выход с некорректным доменом пропускается — собрать для него команду безопасно нельзя.
    /// </summary>
    public static IReadOnlyList<(VpnServer Server, string Domain)> Targets(IEnumerable<VpnServer> servers) =>
    [
        .. XCoreTopology.RoutableExits(servers)
            .Where(n => XCoreInput.TryNormalizeDomain(n.Protocol.XCore!.Domain, out var d) && d == n.Protocol.XCore.Domain)
            .Select(n => (n.Server, n.Protocol.XCore!.Domain)),
    ];

    [GeneratedRegex(@"\A[0-9]{3}\z")]
    private static partial Regex HttpCode();

    /// <summary>
    /// Итог одной проверки. Текст ошибки короткий и без вывода команды: он попадает в журнал и в панель.
    /// </summary>
    public static XCoreExitHealth Interpret(string serverId, SshResult result, DateTime now)
    {
        var code = result.StdOut.Trim();
        var health = new XCoreExitHealth { ServerId = serverId, CheckedAt = now };

        if (result.ExitStatus == 0 && code == "200")
        {
            health.Ok = true;
            return health;
        }

        health.Error = result.ExitStatus switch
        {
            0 => HttpCode().IsMatch(code) ? $"выход ответил кодом {code}" : "выход дал неожиданный ответ",
            127 => "на входе нет curl",
            6 => "домен выхода не разрешается с входа",
            7 => "соединение с выходом отклонено",
            28 => $"выход не ответил за {TimeoutSeconds} с",
            35 or 51 or 58 or 60 => "ошибка TLS при подключении к выходу",
            _ => $"curl завершился с кодом {result.ExitStatus}",
        };
        return health;
    }

    /// <summary>
    /// Что изменилось с прошлой проверки. Плечо без предыдущего результата считается рабочим: первая же
    /// проверка нового выхода, показавшая сбой, — новость для оператора, а первая удачная — нет. Постоянное
    /// состояние (рабочее или упавшее на обеих проверках) переходов не даёт, иначе журнал пополнялся бы на каждом тике.
    /// </summary>
    public static IReadOnlyList<XCoreExitTransition> Transitions(
        IReadOnlyList<XCoreExitHealth> previous, IReadOnlyList<XCoreExitHealth> current)
    {
        var before = previous.GroupBy(h => h.ServerId, StringComparer.Ordinal)
            .ToDictionary(g => g.Key, g => g.First().Ok, StringComparer.Ordinal);

        return
        [
            .. current
                .Where(c => before.GetValueOrDefault(c.ServerId, true) != c.Ok)
                .Select(c => new XCoreExitTransition(c.ServerId, c.Ok, c.Error)),
        ];
    }
}
