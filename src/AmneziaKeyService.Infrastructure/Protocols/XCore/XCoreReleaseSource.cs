using System.Net;
using System.Text.Json;

namespace AmneziaKeyService.Infrastructure.Protocols.XCore;

/// <summary>
/// Откуда worker узнаёт последний релиз российских списков. Отдельный интерфейс, чтобы обновление проверялось
/// без сети: тег определяется здесь, а скачивает файлы уже узел.
/// </summary>
public interface IXCoreReleaseSource
{
    /// <exception cref="XCoreGeoException">Репозиторий недоступен или ответил не тем. Текст безопасен для показа.</exception>
    Task<string> GetLatestTagAsync(string repo, CancellationToken ct = default);
}

/// <summary>
/// Последний релиз по API GitHub. Запрос идёт из worker, а не с узла: узел в РФ мог бы не дотянуться до
/// api.github.com, и решение «есть ли новее» не должно зависеть от канала каждого входа.
/// </summary>
public sealed class GitHubReleaseSource : IXCoreReleaseSource
{
    private readonly HttpClient _http;

    public GitHubReleaseSource(HttpClient http)
    {
        _http = http;
    }

    public async Task<string> GetLatestTagAsync(string repo, CancellationToken ct = default)
    {
        if (!XCoreRfLists.IsSafeRepo(repo))
            throw new XCoreGeoException("Настройка XCore:RfListsRepo не в формате «владелец/репозиторий».");

        using var request = new HttpRequestMessage(HttpMethod.Get, XCoreRfLists.LatestReleaseApiUrl(repo));
        // GitHub отклоняет запросы без User-Agent.
        request.Headers.UserAgent.ParseAdd("AmneziaKeyService");
        request.Headers.Accept.ParseAdd("application/vnd.github+json");

        try
        {
            using var response = await _http.SendAsync(request, ct);
            if (response.StatusCode != HttpStatusCode.OK)
                throw new XCoreGeoException($"GitHub ответил кодом {(int)response.StatusCode} на запрос последнего релиза.");

            using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync(ct));
            var tag = doc.RootElement.ValueKind == JsonValueKind.Object
                && doc.RootElement.TryGetProperty("tag_name", out var name) && name.ValueKind == JsonValueKind.String
                    ? name.GetString()
                    : null;
            return XCoreRfLists.IsSafeTag(tag)
                ? tag!
                : throw new XCoreGeoException("GitHub не вернул корректный тег последнего релиза.");
        }
        catch (Exception ex) when (ex is HttpRequestException or JsonException or TaskCanceledException && !ct.IsCancellationRequested)
        {
            throw new XCoreGeoException("Не удалось запросить последний релиз списков на GitHub.", ex);
        }
    }
}
