using AmneziaKeyService.Core.Exceptions;
using AmneziaKeyService.Core.Interfaces;

namespace AmneziaKeyService.Infrastructure.Protocols;

/// <summary>
/// Резолвит конфигуратор по виду протокола.
///
/// Фасад поверх набора реализаций, а не keyed DI напрямую: так место отказа
/// при неизвестном протоколе одно и с понятным сообщением.
/// </summary>
public class ProtocolRegistry : IProtocolRegistry
{
    private readonly Dictionary<string, IProtocolConfigurator> _configurators;

    public ProtocolRegistry(IEnumerable<IProtocolConfigurator> configurators)
    {
        _configurators = configurators.ToDictionary(c => c.Kind, StringComparer.Ordinal);
    }

    public bool IsSupported(string kind) => _configurators.ContainsKey(kind);

    public IProtocolConfigurator GetConfigurator(string kind)
        => _configurators.TryGetValue(kind, out var configurator)
            ? configurator
            : throw new NotFoundException($"Протокол '{kind}' не поддерживается.");
}
