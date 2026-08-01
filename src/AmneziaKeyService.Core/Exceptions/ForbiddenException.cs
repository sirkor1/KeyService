namespace AmneziaKeyService.Core.Exceptions;

/// <summary>Операция аутентифицирована, но запрещена правилами доступа.</summary>
public class ForbiddenException : Exception
{
    public ForbiddenException() { }
}
