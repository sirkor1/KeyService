using System.Text;
using AmneziaKeyService.Infrastructure.Install;
using AmneziaKeyService.Infrastructure.Monitoring;
using AmneziaKeyService.Infrastructure.Scripts;
using AmneziaKeyService.Infrastructure.Services;

// Проверяет разбор вывода wg и арифметику счётчиков без обращения к серверам.
//
// Зачем отдельно: обе вещи ошибаются молча. Съехавший на одно поле парсер
// вернёт правдоподобные числа не из тех колонок, а неверная обработка сброса
// счётчиков даст не исключение, а тихо неправильный трафик — который заметят
// не раньше, чем по нему кого-нибудь отключат за перебор квоты.
//
// Здесь же — проверка редактирования секретов: строка интерфейса из wg dump
// содержит приватный ключ сервера, и она не должна пережить путь в лог.

var failures = new List<string>();
var checks = 0;

void Check(string name, bool ok, string? detail = null)
{
    checks++;
    Console.WriteLine($"  [{(ok ? "OK  " : "ПРОВАЛ")}] {name}{(detail is null ? "" : $" — {detail}")}");
    if (!ok) failures.Add(name);
}

Console.OutputEncoding = Encoding.UTF8;

// ── Разбор wg show dump ──────────────────────────────────────────────────────
// Образец соответствует реальному формату: первая строка описывает интерфейс
// (4 поля), остальные — peer-ы (8 полей), разделитель — табуляция.

// Ровно 44 символа с завершающим '=': столько занимает base64 32-байтного
// ключа X25519. Редактор опознаёт секрет именно по этой длине, и ключ короче
// сквозь него пройдёт — но такого ключа не бывает.
const string ServerPrivateKey = "cE5vAqRtYuIoPaSdFgHjKlZxCvBnMqWeRtYuIoPaSd0=";

const string PeerConnected  = "kJ8zQwErTyUiOpAsDfGhJkLzXcVbNmQwErTyUiOpAs0=";
const string PeerSilent     = "aB1cD2eF3gH4iJ5kL6mN7oP8qR9sT0uV1wX2yZ3aB4c=";
const string PeerNoHandshake = "zY9xW8vU7tS6rQ5pO4nM3lK2jI1hG0fE9dC8bA7zY6x=";

var dump = string.Join('\n',
    // Интерфейс: приватный ключ, публичный ключ, порт, fwmark.
    $"{ServerPrivateKey}\tkJ8zQwErTyUiOpAsDfGhJkLzXcVbNmQwErTyUiOpAs0=\t42174\toff",
    // Peer: pubkey, psk, endpoint, allowed-ips, handshake, rx, tx, keepalive.
    $"{PeerConnected}\tpSk1234567890AbCdEfGhIjKlMnOpQrStUvWxYz9876=\t203.0.113.7:51820\t10.8.1.2/32\t1753900000\t1048576\t2097152\t25",
    $"{PeerSilent}\tpSk1234567890AbCdEfGhIjKlMnOpQrStUvWxYz9876=\t(none)\t10.8.1.3/32\t0\t0\t0\toff",
    $"{PeerNoHandshake}\t(none)\t198.51.100.4:41000\t10.8.1.4/32\t1753900500\t512\t1024\toff",
    // Хвостовая пустая строка: команда всегда заканчивает переводом строки.
    "");

var peers = WgDumpParser.Parse(dump);

Console.WriteLine("Разбор wg show dump");

Check("Строка интерфейса отброшена", peers.Count == 3, $"peer-ов разобрано: {peers.Count}");

Check("Приватный ключ сервера не попал в результат",
    peers.TrueForAll(p => p.PublicKey != ServerPrivateKey));

var connected = peers.Find(p => p.PublicKey == PeerConnected);

Check("Peer найден по публичному ключу", connected is not null);
Check("Счётчик приёма из своей колонки", connected?.RxBytes == 1048576, $"{connected?.RxBytes}");
Check("Счётчик передачи из своей колонки", connected?.TxBytes == 2097152, $"{connected?.TxBytes}");
Check("Endpoint разобран", connected?.Endpoint == "203.0.113.7:51820", connected?.Endpoint);
Check("Туннельный адрес разобран", connected?.AllowedIps == "10.8.1.2/32", connected?.AllowedIps);

Check("Момент хэндшейка переведён из unix-времени",
    connected?.LatestHandshake == DateTimeOffset.FromUnixTimeSeconds(1753900000).UtcDateTime,
    connected?.LatestHandshake?.ToString("O"));

var silent = peers.Find(p => p.PublicKey == PeerSilent);

Check("Нулевой хэндшейк читается как «не было», а не как 1970 год",
    silent?.LatestHandshake is null);

Check("(none) в endpoint даёт null, а не строку «(none)»", silent?.Endpoint is null);

var noPsk = peers.Find(p => p.PublicKey == PeerNoHandshake);

Check("Peer без preshared-key разобран целиком",
    noPsk is { RxBytes: 512, TxBytes: 1024 });

Check("Пустой ввод не роняет разбор", WgDumpParser.Parse("").Count == 0);
Check("Null не роняет разбор", WgDumpParser.Parse(null).Count == 0);

Check("Вывод без peer-ов даёт пустой список",
    WgDumpParser.Parse($"{ServerPrivateKey}\tpub\t42174\toff\n").Count == 0);

Check("Мусорная строка пропускается, а не ломает разбор",
    WgDumpParser.Parse("что-то не то\n" + dump).Count == 3);

// ── Арифметика счётчиков ─────────────────────────────────────────────────────
// Счётчики wg монотонны с момента старта контейнера и обнуляются при рестарте.

Console.WriteLine();
Console.WriteLine("Приращение счётчиков");

Check("Обычный рост даёт разность", UsageMath.Delta(1500, 1000) == 500);
Check("Первый опрос даёт всё показание", UsageMath.Delta(1500, 0) == 1500);
Check("Без движения приращение нулевое", UsageMath.Delta(1500, 1500) == 0);

Check("Рестарт контейнера: показание меньше прежнего — берём его целиком",
    UsageMath.Delta(300, 5000) == 300);

Check("Рестарт с нулевым показанием даёт нулевое приращение",
    UsageMath.Delta(0, 5000) == 0);

Check("Отрицательное показание не даёт отрицательного приращения",
    UsageMath.Delta(-1, 1000) == 0);

Check("Приращение около границы long не переполняется",
    UsageMath.Delta(long.MaxValue, long.MaxValue - 10) == 10);

// ── Редактирование секретов ──────────────────────────────────────────────────
// Вывод wg попадает в лог целиком только по ошибке, но именно от таких ошибок
// и защищает обёртка стока — проверяем, что редактор её отрабатывает.

Console.WriteLine();
Console.WriteLine("Редактирование секретов");

var redactedDump = SecretRedactor.Redact(dump);

Check("Приватный ключ сервера вырезан из вывода wg",
    !redactedDump.Contains(ServerPrivateKey));

Check("Публичные ключи peer-ов тоже вырезаны",
    !redactedDump.Contains(PeerConnected) && !redactedDump.Contains(PeerSilent));

Check("Счётчики после редактирования остаются читаемыми",
    redactedDump.Contains("1048576") && redactedDump.Contains("2097152"));

const string Pem = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXk\n-----END OPENSSH PRIVATE KEY-----";

Check("PEM-блок вырезан целиком", !SecretRedactor.Redact($"ключ узла: {Pem}").Contains("b3BlbnNzaC1rZXk"));

Check("PresharedKey в строке конфига вырезан",
    !SecretRedactor.Redact("PresharedKey = pSk1234567890AbCdEfGhIjKlMnOpQrStUvWxYz9876=")
        .Contains("pSk1234567890"));

// ── Скрипты установки в сборке ───────────────────────────────────────────────
// Проверка появилась после того, как маски EmbeddedResource в csproj покрывали
// только *.conf и *.json: скрипты установки и Dockerfile-ы в сборку не попадали,
// и установка падала на первом же чтении — но лишь на живом узле, потому что
// до чтения дело доходит только после успешного SSH-подключения.

Console.WriteLine();
Console.WriteLine("Скрипты установки встроены в сборку");

var scripts = new ScriptRegistry();

Console.WriteLine();
Console.WriteLine("Package-manager lock probe contract");

Check("Exit code 0 means the package manager is ready",
    PackageManagerProbe.FromExitStatus(0) == PackageManagerProbeState.Ready);
Check("Exit code 1 means the package manager is busy",
    PackageManagerProbe.FromExitStatus(1) == PackageManagerProbeState.Busy);
Check("Probe errors are not treated as busy retries",
    PackageManagerProbe.FromExitStatus(2) == PackageManagerProbeState.Error &&
    PackageManagerProbe.FromExitStatus(255) == PackageManagerProbeState.Error);

var busyScript = scripts.Read("shared/check_server_is_busy.sh");
Check("The script maps an occupied fuser lock to exit code 1",
    busyScript.Contains("0) exit 1", StringComparison.Ordinal));
Check("The script maps a free fuser lock to exit code 0",
    busyScript.Contains("1) exit 0", StringComparison.Ordinal));
Check("The script reserves exit code 2 for probe errors",
    busyScript.Contains("exit 2", StringComparison.Ordinal));

string[] required =
[
    "shared/check_user_in_sudo.sh",
    "shared/check_server_is_busy.sh",
    "shared/check_connection.sh",
    "shared/install_docker.sh",
    "shared/prepare_host.sh",
    "shared/remove_container.sh",
    "shared/build_container.sh",
    "shared/setup_host_firewall.sh",
];

// Каждый протокол приносит один и тот же набор из четырёх файлов.
string[] protocolFolders = ["awg", "awg_legacy", "wireguard", "xray"];
string[] perProtocol = ["Dockerfile", "run_container.sh", "configure_container.sh", "start.sh"];

var allScripts = required
    .Concat(protocolFolders.SelectMany(f => perProtocol.Select(n => $"{f}/{n}")))
    .ToArray();

var missing = new List<string>();

foreach (var path in allScripts)
{
    try
    {
        if (scripts.Read(path).Length == 0) missing.Add($"{path} (пусто)");
    }
    catch (InvalidOperationException)
    {
        missing.Add(path);
    }
}

Check($"Все {allScripts.Length} скриптов установки читаются",
    missing.Count == 0,
    missing.Count == 0 ? null : $"нет: {string.Join(", ", missing)}");

// Клиентские шаблоны — отдельно: они читаются на выдаче ключа, а не установке.
foreach (var template in new[]
         {
             "awg/template.conf", "awg_legacy/template.conf",
             "wireguard/template.conf", "xray/template.json",
         })
{
    bool ok;
    try { ok = scripts.Read(template).Length > 0; } catch (InvalidOperationException) { ok = false; }
    Check($"Шаблон {template} читается", ok);
}

// ── Итог ─────────────────────────────────────────────────────────────────────

Console.WriteLine();
Console.WriteLine(failures.Count == 0
    ? $"Все проверки пройдены: {checks}."
    : $"Провалено {failures.Count} из {checks}: {string.Join(", ", failures)}");

return failures.Count == 0 ? 0 : 1;
