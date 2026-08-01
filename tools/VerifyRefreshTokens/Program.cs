using AmneziaKeyService.Core.Models;
using System.Security.Claims;

var first = RefreshTokenCrypto.Create();
var second = RefreshTokenCrypto.Create();
var hash = RefreshTokenCrypto.Hash(first);
var active = new RefreshSession { ActivatedAt = DateTime.UtcNow, ExpiresAt = DateTime.UtcNow.AddDays(1) };
var rotated = new RefreshSession { ActivatedAt = DateTime.UtcNow, RotatedAt = DateTime.UtcNow, ExpiresAt = DateTime.UtcNow.AddDays(1) };
var revoked = new RefreshSession { ActivatedAt = DateTime.UtcNow, RevokedAt = DateTime.UtcNow, ExpiresAt = DateTime.UtcNow.AddDays(1) };
var mappedClaims = new ClaimsPrincipal(new ClaimsIdentity([new Claim(ClaimTypes.NameIdentifier, "mapped-user"), new Claim(ClaimTypes.Role, UserRoles.Admin)]));
var standardClaims = new ClaimsPrincipal(new ClaimsIdentity([new Claim("sub", "standard-user"), new Claim("role", UserRoles.Operator)]));

var checks = new (bool Passed, string Name)[]
{
    (first != second && Convert.FromBase64String(first).Length == 32, "CSPRNG produces independent 256-bit opaque tokens"),
    (!hash.Contains(first, StringComparison.Ordinal) && hash.Length == 64, "database representation is a fixed-length SHA-256 hash"),
    (RefreshTokenCrypto.Matches(first, hash) && !RefreshTokenCrypto.Matches(second, hash), "hash comparison accepts only its source token"),
    (RefreshSessionRules.Classify(active, DateTime.UtcNow) == RefreshSessionPresentation.Current, "only activated, unrotated and unrevoked record is current"),
    (RefreshSessionRules.Classify(rotated, DateTime.UtcNow) == RefreshSessionPresentation.ReuseDetected, "replayed rotated token revokes its whole family"),
    (RefreshSessionRules.Classify(revoked, DateTime.UtcNow) == RefreshSessionPresentation.Invalid, "revoked token remains invalid without creating a child"),
    (PanelAccessClaims.FindUserId(mappedClaims) == "mapped-user" && PanelAccessClaims.FindRole(mappedClaims) == UserRoles.Admin, "mapped JWT subject and role claims are accepted"),
    (PanelAccessClaims.FindUserId(standardClaims) == "standard-user" && PanelAccessClaims.FindRole(standardClaims) == UserRoles.Operator, "standard JWT subject and role claims are accepted"),
};

foreach (var check in checks) Console.WriteLine($"{(check.Passed ? "PASS" : "FAIL")}: {check.Name}");
return checks.All(x => x.Passed) ? 0 : 1;
