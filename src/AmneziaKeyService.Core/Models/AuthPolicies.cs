namespace AmneziaKeyService.Core.Models;

/// <summary>Имена политик авторизации. Регистрируются в Program.cs.</summary>
public static class AuthPolicies
{
    /// <summary>Чтение любых данных панели.</summary>
    public const string PanelRead = "PanelRead";

    /// <summary>Мутации данных панели: выдача и отзыв ключей, инвайт-коды.</summary>
    public const string PanelWrite = "PanelWrite";

    /// <summary>Администрирование: серверы, пользователи, настройки.</summary>
    public const string PanelAdmin = "PanelAdmin";

    /// <summary>Операции, доступные только владельцу.</summary>
    public const string PanelOwner = "PanelOwner";
}
