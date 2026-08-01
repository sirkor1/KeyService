using System.ComponentModel.DataAnnotations;

namespace AmneziaKeyService.Core.DTOs;

/// <summary>
/// Регистрация конечного VPN-пользователя через HTTP.
///
/// PassCode обязателен: без него эндпоинт открыт наружу и любой желающий
/// получал токен, удовлетворяющий всем [Authorize]-маршрутам, включая CRUD серверов.
/// Роль создаваемого пользователя всегда client — см. AuthService.RegisterAsync.
/// </summary>
public record RegisterRequest(
    [Required, MinLength(3)] string Username,
    [Required, MinLength(6)] string Password,
    [Required] string PassCode
);
