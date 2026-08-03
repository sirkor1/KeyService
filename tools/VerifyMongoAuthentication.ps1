[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$probeId = [Guid]::NewGuid().ToString('N')
$containerName = "amnezia-mongo-auth-$probeId"
$volumeName = "amnezia-mongo-auth-$probeId"
$zeroUserContainerName = "amnezia-mongo-zero-users-$probeId"
$zeroUserVolumeName = "amnezia-mongo-zero-users-$probeId"
$databaseName = "auth_probe_$probeId"
$rootUser = 'root_probe'
$rootPassword = "Root$probeId"
$appUser = 'app_probe'
$appPassword = "App password?%/$probeId"
$scriptPath = Join-Path $PSScriptRoot '..\docker\mongo-init\01-create-app-user.sh'
$scriptPath = [IO.Path]::GetFullPath($scriptPath)
$escapedAppPassword = [Uri]::EscapeDataString($appPassword)
$appUri = "mongodb://${appUser}:${escapedAppPassword}@127.0.0.1:27017/${databaseName}?authSource=${databaseName}"

function Invoke-Docker {
    param(
        [string[]] $DockerArguments,
        [string] $Step = 'Docker operation'
    )

    & docker @DockerArguments
    if ($LASTEXITCODE -ne 0) {
        throw "$Step failed."
    }
}

function Test-MongoReady {
    param([string] $TargetContainer = $containerName)

    for ($attempt = 0; $attempt -lt 30; $attempt++) {
        $isReady = $false
        try {
            & docker exec $TargetContainer mongosh --quiet --username $rootUser --password $rootPassword --authenticationDatabase admin --eval 'quit(db.adminCommand({ ping: 1 }).ok ? 0 : 2)' 2>$null | Out-Null
            $isReady = $LASTEXITCODE -eq 0
        }
        catch { }
        if ($isReady) {
            return
        }
        Start-Sleep -Seconds 1
    }

    throw 'Temporary authenticated MongoDB did not become ready.'
}

try {
    Invoke-Docker -DockerArguments @('volume', 'create', $volumeName)
    Invoke-Docker -DockerArguments @(
        'run', '-d', '--name', $containerName,
        '-e', "MONGO_INITDB_ROOT_USERNAME=$rootUser",
        '-e', "MONGO_INITDB_ROOT_PASSWORD=$rootPassword",
        '-e', "MONGO_INITDB_DATABASE=$databaseName",
        '-e', "MONGO_APP_USERNAME=$appUser",
        '-e', "MONGO_APP_PASSWORD=$appPassword",
        '-v', "$volumeName`:/data/db",
        '-v', "$scriptPath`:/docker-entrypoint-initdb.d/01-create-app-user.sh:ro",
        'mongo:8', 'mongod', '--auth', '--bind_ip_all')

    Test-MongoReady

    $unauthenticatedRejected = $false
    try {
        & docker exec $containerName mongosh --quiet "mongodb://127.0.0.1:27017/$databaseName" --eval 'db.auth_probe.findOne()' 2>$null | Out-Null
        $unauthenticatedRejected = $LASTEXITCODE -ne 0
    }
    catch {
        $unauthenticatedRejected = $true
    }
    if (-not $unauthenticatedRejected) {
        throw 'Unauthenticated MongoDB query unexpectedly succeeded.'
    }

    $probeScript = @'
const collection = db.getCollection('auth_probe');
collection.insertOne({ value: 1 });
if (collection.countDocuments({ value: 1 }) !== 1) quit(2);
collection.createIndex({ value: 1 }, { unique: true });
collection.dropIndex({ value: 1 });
db.getCollection('_migrations').insertOne({ _id: 'auth_probe' });
db.getCollection('_migrations').updateOne({ _id: 'auth_probe' }, { $set: { appliedAt: new Date() } });
db.getCollection('_migrations').createIndex({ appliedAt: 1 });
quit(0);
'@
    Invoke-Docker -DockerArguments @('exec', $containerName, 'mongosh', '--quiet', $appUri, '--eval', $probeScript)

    # Regression case: a failed entrypoint can leave WiredTiger files but no
    # users. Bootstrap must retain that volume, use the localhost exception to
    # create only the root account, then run the normal idempotent app hook.
    Invoke-Docker -DockerArguments @('volume', 'create', $zeroUserVolumeName)
    Invoke-Docker -Step 'Zero-user MongoDB start' -DockerArguments @(
        'run', '-d', '--name', $zeroUserContainerName,
        '-v', "$zeroUserVolumeName`:/data/db",
        'mongo:8', 'mongod', '--bind_ip_all')
    for ($attempt = 0; $attempt -lt 30; $attempt++) {
        & docker exec $zeroUserContainerName mongosh --quiet --eval 'quit(db.adminCommand({ ping: 1 }).ok ? 0 : 2)' 2>$null | Out-Null
        if ($LASTEXITCODE -eq 0) { break }
        Start-Sleep -Seconds 1
    }
    if ($LASTEXITCODE -ne 0) { throw 'Temporary unauthenticated MongoDB did not become ready.' }
    Invoke-Docker -DockerArguments @('exec', $zeroUserContainerName, 'mongosh', '--quiet', '--eval', "db.getSiblingDB('$databaseName').zero_user_marker.insertOne({ value: 1 }); quit(0);")
    Invoke-Docker -DockerArguments @('rm', '-f', $zeroUserContainerName)

    Invoke-Docker -DockerArguments @(
        'run', '-d', '--name', $zeroUserContainerName,
        '-e', "MONGO_INITDB_ROOT_USERNAME=$rootUser",
        '-e', "MONGO_INITDB_ROOT_PASSWORD=$rootPassword",
        '-e', "MONGO_INITDB_DATABASE=$databaseName",
        '-e', "MONGO_APP_USERNAME=$appUser",
        '-e', "MONGO_APP_PASSWORD=$appPassword",
        '-v', "$zeroUserVolumeName`:/data/db",
        '-v', "$scriptPath`:/docker-entrypoint-initdb.d/01-create-app-user.sh:ro",
        'mongo:8', 'mongod', '--auth', '--bind_ip_all')
    $reachedFinalMongod = $false
    for ($attempt = 0; $attempt -lt 30; $attempt++) {
        $pidOneCommand = $null
        $pidProbeExitCode = 1
        try {
            $pidOneCommand = @(& docker exec $zeroUserContainerName cat /proc/1/comm 2>$null)
            $pidProbeExitCode = $LASTEXITCODE
        }
        catch { }
        if ($pidProbeExitCode -eq 0 -and ([string] $pidOneCommand[0]).Trim() -eq 'mongod') {
            $reachedFinalMongod = $true
            break
        }
        Start-Sleep -Seconds 1
    }
    if (-not $reachedFinalMongod) { throw 'Recovery MongoDB did not reach final mongod.' }
    $rootAuthenticationWorked = $false
    try {
        & docker exec $zeroUserContainerName mongosh --quiet --username $rootUser --password $rootPassword --authenticationDatabase admin --eval 'quit(0)' 2>$null | Out-Null
        $rootAuthenticationWorked = $LASTEXITCODE -eq 0
    }
    catch { }
    if ($rootAuthenticationWorked) { throw 'Root authentication unexpectedly worked before localhost recovery.' }

$createRootScript = @'
db.createUser({
  user: process.env.MONGO_INITDB_ROOT_USERNAME,
  pwd: process.env.MONGO_INITDB_ROOT_PASSWORD,
  roles: [{ role: "root", db: "admin" }]
});
quit(0);
'@
    $createRootScriptBase64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($createRootScript))
    Invoke-Docker -Step 'Localhost root recovery' -DockerArguments @(
        'exec', '-e', "RECOVERY_JS_BASE64=$createRootScriptBase64", $zeroUserContainerName,
        'sh', '-c',
        'temporary=$(mktemp /tmp/amnezia-root-recovery.XXXXXX.js); trap ''rm -f -- "$temporary"'' EXIT; printf ''%s'' "$RECOVERY_JS_BASE64" | base64 -d > "$temporary"; mongosh --quiet --host 127.0.0.1 admin "$temporary"')
    Test-MongoReady -TargetContainer $zeroUserContainerName
    Invoke-Docker -Step 'Idempotent application-user hook' -DockerArguments @('exec', $zeroUserContainerName, '/docker-entrypoint-initdb.d/01-create-app-user.sh')
    Invoke-Docker -Step 'Recovered application authentication' -DockerArguments @('exec', $zeroUserContainerName, 'mongosh', '--quiet', $appUri, '--eval', 'quit(db.adminCommand({ ping: 1 }).ok ? 0 : 2)')

    Invoke-Docker -Step 'Recovered sentinel verification' -DockerArguments @(
        'exec', $zeroUserContainerName, 'mongosh', '--quiet', $appUri, '--eval',
        'quit(db.zero_user_marker.countDocuments() === 1 ? 0 : 2)')

    # Steady state keeps only the application URI. Recreate the container
    # without any MONGO_INITDB/MONGO_APP bootstrap variables and verify that
    # both authentication and the pre-recovery sentinel still work.
    Invoke-Docker -Step 'Recovery container removal' -DockerArguments @('rm', '-f', $zeroUserContainerName)
    Invoke-Docker -Step 'Steady-state MongoDB start' -DockerArguments @(
        'run', '-d', '--name', $zeroUserContainerName,
        '-e', "MONGODB_CONNECTION_STRING=$appUri",
        '-v', "$zeroUserVolumeName`:/data/db",
        'mongo:8', 'mongod', '--auth', '--bind_ip_all')

    $steadyMongoReady = $false
    for ($attempt = 0; $attempt -lt 30; $attempt++) {
        try {
            & docker exec $zeroUserContainerName mongosh --quiet $appUri --eval 'quit(db.adminCommand({ ping: 1 }).ok ? 0 : 2)' 2>$null | Out-Null
            if ($LASTEXITCODE -eq 0) {
                $steadyMongoReady = $true
                break
            }
        }
        catch { }
        Start-Sleep -Seconds 1
    }
    if (-not $steadyMongoReady) { throw 'Steady-state MongoDB did not accept the application URI.' }

    Invoke-Docker -Step 'Steady-state sentinel verification' -DockerArguments @(
        'exec', $zeroUserContainerName, 'mongosh', '--quiet', $appUri, '--eval',
        'quit(db.zero_user_marker.countDocuments() === 1 ? 0 : 2)')
    $steadyEnvironment = @(& docker inspect --format '{{range .Config.Env}}{{println .}}{{end}}' $zeroUserContainerName)
    if ($LASTEXITCODE -ne 0) { throw 'Could not inspect steady-state MongoDB environment.' }
    if ($steadyEnvironment | Where-Object { $_ -match '^(MONGO_INITDB_ROOT_PASSWORD|MONGO_APP_PASSWORD)=' }) {
        throw 'Steady-state MongoDB still contains a bootstrap password variable.'
    }

    Write-Host 'MongoDB authentication probe passed: fresh auth, zero-user recovery, data retention, and steady-state secret removal succeeded.'
}
finally {
    try { & docker rm -f $containerName 2>$null | Out-Null } catch { }
    try { & docker volume rm $volumeName 2>$null | Out-Null } catch { }
    try { & docker rm -f $zeroUserContainerName 2>$null | Out-Null } catch { }
    try { & docker volume rm $zeroUserVolumeName 2>$null | Out-Null } catch { }
}
