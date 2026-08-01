using System.Text;
using System.Threading.RateLimiting;
using AmneziaKeyService.Api.Infrastructure;
using AmneziaKeyService.Core.Interfaces;
using AmneziaKeyService.Core.Models;
using AmneziaKeyService.Infrastructure.DependencyInjection;
using AmneziaKeyService.Infrastructure.Install;
using AmneziaKeyService.Infrastructure.Logging;
using AmneziaKeyService.Infrastructure.Migrations;
using AmneziaKeyService.Infrastructure.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi;
using Microsoft.OpenApi.Models;

var builder = WebApplication.CreateBuilder(args);

builder.Host.UseAmneziaLogging("api");

// ── Options ──────────────────────────────────────────────────────────────────
builder.Services.Configure<JwtOptions>(builder.Configuration.GetSection("Jwt"));

// ── Композиция ───────────────────────────────────────────────────────────────
// Разложена по слоям доступа в Infrastructure/DependencyInjection: процессов
// теперь три, и список регистраций у них общий, а различия проходят
// по границам методов.
builder.Services.AddAmneziaData(builder.Configuration);
builder.Services.AddAmneziaMigrations();
builder.Services.AddAmneziaProtocols();

// SSH в api остаётся только ради синхронной диагностики мастера установки:
// POST /api/servers/test-connection и POST /api/servers/{id}/refresh
// (IServerParamsService, IInstallService.TestConnectionAsync) отвечают
// пользователю здесь и сейчас, отдельного события под них не заводили.
// Выдача и отзыв ключей ушли в worker на доменных событиях — сборка vpn://
// и клиентского файла (IVpnConfigReader) узла не требует и приходит
// из AddAmneziaProtocols.
builder.Services.AddAmneziaNodeAccess();

// Установку api больше не исполняет — только создаёт задачу и публикует
// событие. Работу делает worker.
builder.Services.AddScoped<IInstallService, InstallService>();

builder.Services.AddScoped<AuthService>();

// ── JWT Authentication ────────────────────────────────────────────────────────
var jwtSecret = builder.Configuration["Jwt:Secret"]
    ?? throw new InvalidOperationException("Jwt:Secret не задан в конфиге.");

ValidateJwtSecret(jwtSecret);
ValidateJwtLifetimes(builder.Configuration.GetSection("Jwt").Get<JwtOptions>() ?? new JwtOptions());

builder.Services
    .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(opts =>
    {
        opts.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer           = true,
            ValidateAudience         = true,
            ValidateLifetime         = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer              = builder.Configuration["Jwt:Issuer"],
            ValidAudience            = builder.Configuration["Jwt:Audience"],
            IssuerSigningKey         = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSecret))
        };

        // Панель хранит токен в httpOnly-куке: JS его не видит, поэтому заголовок
        // Authorization не выставляется. Bearer при этом продолжает работать
        // для Telegram-бота, Swagger и прочих существующих потребителей.
        opts.Events = new JwtBearerEvents
        {
            OnMessageReceived = ctx =>
            {
                if (string.IsNullOrEmpty(ctx.Token) &&
                    ctx.Request.Cookies.TryGetValue(AuthCookies.AccessToken, out var cookieToken))
                {
                    ctx.Token = cookieToken;
                }
                return Task.CompletedTask;
            },
            OnTokenValidated = async ctx =>
            {
                // Existing client/API Bearer tokens stay stateless. A panel token without sid predates
                // server-side revocation and is deliberately rejected at this security cutover.
                var role = ctx.Principal is null ? null : PanelAccessClaims.FindRole(ctx.Principal);
                if (ctx.Principal?.FindFirst("sid") is null)
                {
                    if (role is not null && UserRoles.PanelRead.Contains(role))
                        ctx.Fail("Legacy panel JWTs must be replaced by a new session.");
                    return;
                }
                var auth = ctx.HttpContext.RequestServices.GetRequiredService<AuthService>();
                if (!await auth.IsPanelAccessValidAsync(ctx.Principal, ctx.HttpContext.RequestAborted))
                    ctx.Fail("Panel session has been revoked or its privileges changed.");
            }
        };
    });

// ── Authorization ─────────────────────────────────────────────────────────────
builder.Services
    .AddAuthorizationBuilder()
    .AddPolicy(AuthPolicies.PanelRead,  p => p.RequireRole(UserRoles.PanelRead))
    .AddPolicy(AuthPolicies.PanelWrite, p => p.RequireRole(UserRoles.PanelWrite))
    .AddPolicy(AuthPolicies.PanelAdmin, p => p.RequireRole(UserRoles.PanelAdmin))
    .AddPolicy(AuthPolicies.PanelOwner, p => p.RequireRole(UserRoles.Owner));

// ── Rate limiting ─────────────────────────────────────────────────────────────
builder.Services.AddRateLimiter(opts =>
{
    opts.RejectionStatusCode = StatusCodes.Status429TooManyRequests;

    opts.AddPolicy(RateLimitPolicies.Auth, ctx =>
        RateLimitPartition.GetFixedWindowLimiter(
            partitionKey: ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            factory: _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = 10,
                Window      = TimeSpan.FromMinutes(1),
                QueueLimit  = 0
            }));
    opts.AddPolicy(RateLimitPolicies.Refresh, ctx =>
        RateLimitPartition.GetFixedWindowLimiter(
            partitionKey: ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            factory: _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = 30,
                Window = TimeSpan.FromMinutes(1),
                QueueLimit = 0
            }));
});

// ── CORS (только для dev: в проде SPA и API за одним nginx) ───────────────────
var corsOrigins = builder.Configuration.GetSection("Cors:Origins").Get<string[]>() ?? [];
if (corsOrigins.Length > 0)
{
    builder.Services.AddCors(opts =>
        opts.AddPolicy(CorsPolicies.Panel, p => p
            .WithOrigins(corsOrigins)
            .AllowCredentials()      // нужен для httpOnly-куки
            .AllowAnyHeader()
            .AllowAnyMethod()));
}

// ── Hosted services ───────────────────────────────────────────────────────────
// Схему правит только worker: три раннера миграций на одной базе дали бы гонку
// на _migrations. HTTP не поднимается, пока схема не готова.
builder.Services.AddHostedService<MongoSchemaGate>();

builder.Services.AddExceptionHandler<GlobalExceptionHandler>();
builder.Services.AddProblemDetails();
builder.Services.AddControllers();

// ── Swagger ───────────────────────────────────────────────────────────────────
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo
    {
        Title       = "AmneziaKeyService",
        Version     = "v1",
        Description = "Генерация и выдача ключей AmneziaWG в формате AmneziaVPN (vpn://)."
    });

    c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Name         = "Authorization",
        Type         = SecuritySchemeType.Http,
        Scheme       = "bearer",
        BearerFormat = "JWT",
        In           = ParameterLocation.Header
    });

    c.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference { Type = ReferenceType.SecurityScheme, Id = "Bearer" }
            },
            new List<string>()
        }
    });
});

// ─────────────────────────────────────────────────────────────────────────────
var app = builder.Build();

// nginx терминирует TLS — без этого ASP.NET видит http и адрес контейнера,
// из-за чего Secure-куки не выставляются, а в логах вместо клиента стоит прокси.
app.UseForwardedHeaders(new ForwardedHeadersOptions
{
    ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto
});

app.UseExceptionHandler();

// Swagger только в разработке: в проде это карта всех эндпоинтов панели.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

if (corsOrigins.Length > 0)
    app.UseCors(CorsPolicies.Panel);

app.UseRateLimiter();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();

// ─────────────────────────────────────────────────────────────────────────────

/// <summary>
/// Отказывается стартовать со слабым JWT-секретом.
///
/// HMAC-SHA256 берёт ключ короче 256 бит как есть, поэтому короткая или
/// дефолтная строка из appsettings.json означает, что токен владельца
/// подделывается кем угодно, кто видел репозиторий.
/// </summary>
static void ValidateJwtSecret(string secret)
{
    const string placeholder = "CHANGE_ME_USE_32+_CHARS_RANDOM_KEY";

    if (secret == placeholder)
        throw new InvalidOperationException(
            "Jwt:Secret оставлен со значением-заглушкой. Задайте случайный секрет " +
            "через переменную окружения Jwt__Secret.");

    if (Encoding.UTF8.GetByteCount(secret) < 32)
        throw new InvalidOperationException(
            $"Jwt:Secret короче 32 байт ({Encoding.UTF8.GetByteCount(secret)}). " +
            "HMAC-SHA256 требует ключ не меньше длины хэша.");
}

static void ValidateJwtLifetimes(JwtOptions options)
{
    if (options.ExpiryMinutes is < 1 or > 1440)
        throw new InvalidOperationException("Jwt:ExpiryMinutes must be between 1 and 1440.");
    if (options.PanelAccessExpiryMinutes is < 1 or > 60)
        throw new InvalidOperationException("Jwt:PanelAccessExpiryMinutes must be between 1 and 60.");
    if (options.RefreshTokenDays is < 1 or > 90)
        throw new InvalidOperationException("Jwt:RefreshTokenDays must be between 1 and 90.");
}
