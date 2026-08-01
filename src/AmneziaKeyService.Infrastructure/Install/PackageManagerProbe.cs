namespace AmneziaKeyService.Infrastructure.Install;

/// <summary>Normalized result of a package-manager lock probe.</summary>
public enum PackageManagerProbeState
{
    Ready,
    Busy,
    Error,
}

/// <summary>
/// Contract of <c>check_server_is_busy.sh</c>: 0 is ready, 1 is busy and any
/// other exit status is a probe error.
/// </summary>
public static class PackageManagerProbe
{
    public static PackageManagerProbeState FromExitStatus(int exitStatus) => exitStatus switch
    {
        0 => PackageManagerProbeState.Ready,
        1 => PackageManagerProbeState.Busy,
        _ => PackageManagerProbeState.Error,
    };
}
