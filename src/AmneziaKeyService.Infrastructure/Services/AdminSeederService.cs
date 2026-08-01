using AmneziaKeyService.Core.Interfaces;
using AmneziaKeyService.Core.Models;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace AmneziaKeyService.Infrastructure.Services;

/// <summary>
/// Гарантирует существование владельца панели.
///
/// Сознательно не миграция: миграция отрабатывает однократно, а проверка
/// «владелец есть» нужна при каждом старте — иначе удаление единственной
/// админской учётки навсегда закрывает вход в панель без прямого доступа к базе.
/// </summary>
public class AdminSeederService : IHostedService
{
    private readonly IUserRepository _users;
    private readonly AdminOptions _opts;
    private readonly ILogger<AdminSeederService> _logger;

    public AdminSeederService(
        IUserRepository users,
        IOptions<AdminOptions> opts,
        ILogger<AdminSeederService> logger)
    {
        _users  = users;
        _opts   = opts.Value;
        _logger = logger;
    }

    public async Task StartAsync(CancellationToken ct)
    {
        var owner = await _users.FindByRoleAsync(UserRoles.Owner, ct);

        if (owner is not null)
        {
            if (_opts.ResetPasswordOnStartup && !string.IsNullOrWhiteSpace(_opts.Password))
            {
                owner.PasswordHash = BCrypt.Net.BCrypt.HashPassword(_opts.Password);
                owner.Status       = UserStatuses.Active;
                await _users.UpdateAsync(owner, ct);

                _logger.LogWarning(
                    "Пароль владельца '{Username}' сброшен из конфигурации (Admin:ResetPasswordOnStartup). " +
                    "Снимите этот флаг после входа.", owner.Username);
            }
            return;
        }

        if (string.IsNullOrWhiteSpace(_opts.Password))
            throw new InvalidOperationException(
                "В базе нет владельца панели, а Admin:Password не задан. " +
                "Укажите ADMIN__USERNAME и ADMIN__PASSWORD, иначе войти в панель будет невозможно.");

        // Логин может быть уже занят обычным пользователем — тогда повышаем его,
        // а не падаем на уникальном индексе username.
        var existing = await _users.FindByUsernameAsync(_opts.Username, ct);

        if (existing is not null)
        {
            existing.Role         = UserRoles.Owner;
            existing.Status       = UserStatuses.Active;
            existing.PasswordHash = BCrypt.Net.BCrypt.HashPassword(_opts.Password);
            existing.DisplayName ??= _opts.DisplayName;
            await _users.UpdateAsync(existing, ct);

            _logger.LogWarning(
                "Существующий пользователь '{Username}' повышен до владельца панели.", _opts.Username);
            return;
        }

        await _users.CreateAsync(new User
        {
            Username     = _opts.Username,
            PasswordHash = BCrypt.Net.BCrypt.HashPassword(_opts.Password),
            Role         = UserRoles.Owner,
            Status       = UserStatuses.Active,
            DisplayName  = _opts.DisplayName ?? "Владелец"
        }, ct);

        _logger.LogInformation("Создан владелец панели '{Username}'.", _opts.Username);
    }

    public Task StopAsync(CancellationToken ct) => Task.CompletedTask;
}
