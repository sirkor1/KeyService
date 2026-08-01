using System.ComponentModel.DataAnnotations;

namespace AmneziaKeyService.Core.DTOs;

public record LoginRequest(
    [Required] string Username,
    [Required] string Password
);
