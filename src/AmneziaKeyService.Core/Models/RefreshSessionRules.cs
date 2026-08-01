namespace AmneziaKeyService.Core.Models;

/// <summary>Pure classification of a presented refresh-session record.</summary>
public static class RefreshSessionRules
{
    public static RefreshSessionPresentation Classify(RefreshSession? session, DateTime now)
    {
        if (session is null || session.ActivatedAt is null || session.RevokedAt is not null || session.ExpiresAt <= now)
            return RefreshSessionPresentation.Invalid;

        // A consumed predecessor is proof of refresh-token replay, even though it is no longer current.
        return session.RotatedAt is null
            ? RefreshSessionPresentation.Current
            : RefreshSessionPresentation.ReuseDetected;
    }
}

public enum RefreshSessionPresentation { Invalid, Current, ReuseDetected }
