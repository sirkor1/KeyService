namespace AmneziaKeyService.Core.Models;

/// <summary>Имена cookie, которыми пользуется админ-панель.</summary>
public static class AuthCookies
{
    /// <summary>
    /// JWT доступа. httpOnly: JS его не читает, поэтому XSS не может украсть токен.
    /// SameSite=Strict закрывает CSRF — панель и API живут на одном origin за nginx.
    /// </summary>
    public const string AccessToken = "panel_token";
    public const string RefreshToken = "panel_refresh";
}

/// <summary>Имена политик CORS.</summary>
public static class CorsPolicies
{
    /// <summary>Dev-режим: Vite на localhost:5173 обращается к API напрямую.</summary>
    public const string Panel = "panel";
}
