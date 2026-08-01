[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$connectionString = $env:MONGODB_CONNECTION_STRING

if ([string]::IsNullOrWhiteSpace($connectionString)) {
    throw 'MONGODB_CONNECTION_STRING must be supplied through the environment.'
}

try {
    $uri = [Uri]$connectionString
}
catch {
    throw 'MONGODB_CONNECTION_STRING is not a valid URI.'
}

if ($uri.Scheme -ne 'mongodb' -or [string]::IsNullOrWhiteSpace($uri.UserInfo)) {
    throw 'MONGODB_CONNECTION_STRING must be a credentialed mongodb URI.'
}

$expectedUser = [Uri]::UnescapeDataString($uri.UserInfo.Split(':', 2)[0])
$authSource = $null
foreach ($pair in $uri.Query.TrimStart('?').Split('&', [StringSplitOptions]::RemoveEmptyEntries)) {
    $separator = $pair.IndexOf('=')
    if ($separator -gt 0 -and $pair.Substring(0, $separator) -eq 'authSource') {
        $authSource = [Uri]::UnescapeDataString($pair.Substring($separator + 1))
        break
    }
}

if ([string]::IsNullOrWhiteSpace($expectedUser) -or [string]::IsNullOrWhiteSpace($authSource)) {
    throw 'MONGODB_CONNECTION_STRING must include a username and authSource.'
}

$env:MONGO_PROBE_USERNAME = $expectedUser
$env:MONGO_PROBE_AUTH_SOURCE = $authSource
$probeScript = 'const info=db.runCommand({connectionStatus:1}).authInfo;const users=info.authenticatedUsers||[];if(users.length!==1||users[0].user!==process.env.MONGO_PROBE_USERNAME||users[0].db!==process.env.MONGO_PROBE_AUTH_SOURCE)quit(2);quit(0);'
$probeBase64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($probeScript))
$shellCommand = "echo $probeBase64 | base64 -d > /tmp/mongo-uri-probe.js && mongosh --quiet `"`$MONGODB_CONNECTION_STRING`" --file /tmp/mongo-uri-probe.js; exitCode=`$?; rm -f /tmp/mongo-uri-probe.js; exit `$exitCode"

$exitCode = 1
try {
    & docker compose exec -T `
        -e MONGODB_CONNECTION_STRING `
        -e MONGO_PROBE_USERNAME `
        -e MONGO_PROBE_AUTH_SOURCE `
        mongo /bin/sh -c $shellCommand 2>$null | Out-Null
    $exitCode = $LASTEXITCODE
}
catch { }
finally {
    Remove-Item Env:MONGO_PROBE_USERNAME -ErrorAction SilentlyContinue
    Remove-Item Env:MONGO_PROBE_AUTH_SOURCE -ErrorAction SilentlyContinue
}

if ($exitCode -ne 0) {
    throw 'MongoDB application URI authentication probe failed.'
}

Write-Host 'MongoDB application URI probe passed.'
