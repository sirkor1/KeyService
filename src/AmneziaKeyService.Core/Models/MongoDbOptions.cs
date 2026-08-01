namespace AmneziaKeyService.Core.Models;

public class MongoDbOptions
{
    public string ConnectionString { get; set; } = "mongodb://localhost:27017";
    public string DatabaseName { get; set; } = "amnezia_vpn";

    public string UsersCollection { get; set; } = "users";
    public string ClientsCollection { get; set; } = "clients";
    public string ServerConfigCollection { get; set; } = "server_config";
    public string PassCodesCollection { get; set; } = "passcodes";
    public string RefreshSessionsCollection { get; set; } = "refresh_sessions";

    // ── Коллекции панели ──────────────────────────────────────────────────────

    public string AuditLogCollection { get; set; } = "audit_log";
    public string PanelSettingsCollection { get; set; } = "panel_settings";
    public string InstallJobsCollection { get; set; } = "install_jobs";
    public string InstallJobLogsCollection { get; set; } = "install_job_logs";

    // ── Суточные срезы (фаза 5) ───────────────────────────────────────────────

    public string KeyUsageDailyCollection { get; set; } = "key_usage_daily";
    public string ServerUsageDailyCollection { get; set; } = "server_usage_daily";
    public string ServerHealthDailyCollection { get; set; } = "server_health_daily";

    // ── Шина доменных событий ─────────────────────────────────────────────────

    public string DomainEventsCollection { get; set; } = "domain_events";

    /// <summary>Именованные аренды: партиции и таймерные воркеры.</summary>
    public string LeasesCollection { get; set; } = "leases";
}
