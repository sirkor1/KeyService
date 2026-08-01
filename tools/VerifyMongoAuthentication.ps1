[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$probeId = [Guid]::NewGuid().ToString('N')
$containerName = "amnezia-mongo-auth-$probeId"
$volumeName = "amnezia-mongo-auth-$probeId"
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
    param([string[]] $DockerArguments)

    & docker @DockerArguments
    if ($LASTEXITCODE -ne 0) {
        throw 'Docker command failed.'
    }
}

function Test-MongoReady {
    for ($attempt = 0; $attempt -lt 30; $attempt++) {
        $isReady = $false
        try {
            & docker exec $containerName mongosh --quiet --username $rootUser --password $rootPassword --authenticationDatabase admin --eval 'quit(db.adminCommand({ ping: 1 }).ok ? 0 : 2)' 2>$null | Out-Null
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

    Write-Host 'MongoDB authentication probe passed: unauthenticated access was denied and app credentials performed CRUD and migration DDL.'
}
finally {
    try { & docker rm -f $containerName 2>$null | Out-Null } catch { }
    try { & docker volume rm $volumeName 2>$null | Out-Null } catch { }
}
