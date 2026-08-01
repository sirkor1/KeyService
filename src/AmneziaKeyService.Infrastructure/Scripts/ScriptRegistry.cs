using System.Collections.Concurrent;
using System.Reflection;
using System.Text.RegularExpressions;

namespace AmneziaKeyService.Infrastructure.Scripts;

/// <summary>
/// Доступ к шаблонам конфигов, встроенным в сборку.
///
/// Путь задаётся как в исходном дереве amnezia-client: "awg/template.conf".
/// Содержимое кешируется — ресурсы неизменны в пределах процесса.
/// </summary>
public class ScriptRegistry
{
    private const string ResourcePrefix = "AmneziaKeyService.Infrastructure.ServerScripts.";

    private static readonly Assembly Assembly = typeof(ScriptRegistry).Assembly;
    private readonly ConcurrentDictionary<string, string> _cache = new(StringComparer.Ordinal);

    /// <summary>Читает шаблон. Отсутствие ресурса — ошибка сборки, а не среды.</summary>
    public string Read(string relativePath)
        => _cache.GetOrAdd(relativePath, static path =>
        {
            var resourceName = ResourcePrefix + path.Replace('/', '.').Replace('\\', '.');

            using var stream = Assembly.GetManifestResourceStream(resourceName)
                ?? throw new InvalidOperationException(
                    $"Шаблон '{path}' не встроен в сборку (ожидался ресурс '{resourceName}'). " +
                    "Проверьте EmbeddedResource в AmneziaKeyService.Infrastructure.csproj.");

            using var reader = new StreamReader(stream);
            // \r убирается так же, как в scripts_registry.cpp: конфиги уезжают
            // на Linux, а парсер WireGuard на \r\n спотыкается.
            return reader.ReadToEnd().Replace("\r", string.Empty);
        });
}

/// <summary>
/// Подстановка $VAR в шаблоны.
///
/// Одним проходом по regex-альтернативе из известных ключей, длинные первыми.
/// Последовательный Replace здесь опасен вдвойне: $WIREGUARD_SUBNET_IP является
/// префиксом $WIREGUARD_SUBNET_IP_CIDR, а в скриптах установки встречаются
/// настоящие shell-переменные ($CUR_USER, $pm), которые трогать нельзя.
/// </summary>
public static class ScriptTemplateRenderer
{
    public static string Render(string template, IReadOnlyDictionary<string, string> vars)
    {
        if (vars.Count == 0) return template;

        var alternation = string.Join(
            '|',
            vars.Keys.OrderByDescending(k => k.Length).Select(Regex.Escape));

        // \b на конце: $JC не должен совпасть с началом $JCMAX.
        var pattern = new Regex($@"\$({alternation})\b", RegexOptions.None, TimeSpan.FromSeconds(2));

        return pattern.Replace(template, match => vars[match.Groups[1].Value]);
    }

    /// <summary>
    /// Проверяет, что в отрендеренном тексте не осталось наших плейсхолдеров.
    ///
    /// Оригинальный XrayConfigurator делает такую же проверку перед отправкой
    /// конфига клиенту: незамещённый $XRAY_PUBLIC_KEY даёт валидный по виду
    /// конфиг, который молча не подключается.
    /// </summary>
    public static void EnsureNoPlaceholdersLeft(string rendered, params string[] required)
    {
        var missing = required.Where(name => rendered.Contains($"${name}", StringComparison.Ordinal)).ToList();

        if (missing.Count > 0)
            throw new InvalidOperationException(
                $"В шаблоне остались незаполненные плейсхолдеры: {string.Join(", ", missing)}.");
    }
}
