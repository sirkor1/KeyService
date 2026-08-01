#requires -Version 5.1
<#
.SYNOPSIS
Bootstraps one empty production VPS from Windows without copying secrets into
the repository, the release archive, command line arguments, or local files.

.DESCRIPTION
The script first verifies the server's ED25519 SSH fingerprint that was copied
from the VPS provider.  Only then does it prompt for secrets and send them as
base64-encoded records over the already verified SSH session's standard input.

deploy/production/bootstrap-vps.sh is the remote half of this protocol.  It
must consume records in the form NAME=BASE64_UTF8_VALUE from stdin.  The
archive contains only the explicitly listed non-secret files in
deploy/production/bootstrap-manifest.txt. The remote bootstrap helper is
also explicitly listed there but uploaded separately, so that helper can
verify the ZIP has exactly the expected release entries.

Never use -ValidateOnly to infer that a VPS is reachable: it deliberately
makes no network connections and never prompts for secrets.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string] $HostAddress,

    [Parameter(Mandatory)]
    [string] $ExpectedSshHostKeyFingerprint,

    [Parameter(Mandatory)]
    [string] $GitHubOwner,

    # The GitHub account that owns the classic PAT used by `docker login`.
    # It is often the same as GitHubOwner, but must be a human account when
    # GitHubOwner is an organization.
    [string] $GhcrUsername,

    [Parameter(Mandatory)]
    [string] $ImageTag,

    [Parameter(Mandatory)]
    [string] $AcmeEmail,

    [ValidateRange(1, 65535)]
    [int] $SshPort = 22,

    [ValidatePattern('^[a-z_][a-z0-9_-]*$')]
    [string] $RootUser = 'root',

    [ValidatePattern('^[a-z_][a-z0-9_-]*$')]
    [string] $DeployUser = 'deploy',

    [ValidatePattern('^[A-Za-z0-9._-]{3,64}$')]
    [string] $AdminUsername = 'admin',

    [string] $DeployPath = '/opt/amnezia-key-service',

    [string] $RootSshIdentityPath,

    [Alias('ActionsPrivateKeyPath')]
    [string] $ActionsKeyPath,

    [switch] $PublicGhcr,

    [switch] $Resume,

    [switch] $ValidateOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Fail([string] $Message) {
    throw "bootstrap-production.ps1: $Message"
}

function Get-RequiredCommand([string] $Name) {
    $command = @(Get-Command -Name $Name -CommandType Application -ErrorAction SilentlyContinue)[0]
    if ($null -eq $command) {
        Fail "Required executable '$Name' was not found in PATH. Install Git and the Windows OpenSSH client, then retry."
    }
    return $command.Source
}

function Test-PublicIpv4([string] $Address) {
    $parsed = $null
    if (-not [System.Net.IPAddress]::TryParse($Address, [ref] $parsed) -or
        $parsed.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) {
        return $false
    }

    $octets = $parsed.GetAddressBytes()
    $a = [int] $octets[0]
    $b = [int] $octets[1]

    # RFC1918, loopback, link-local, CGNAT, documentation/test, multicast and
    # other non-routable ranges are never valid public VPS addresses.
    if ($a -eq 0 -or $a -eq 10 -or $a -eq 127 -or $a -ge 224) { return $false }
    if ($a -eq 100 -and $b -ge 64 -and $b -le 127) { return $false }
    if ($a -eq 169 -and $b -eq 254) { return $false }
    if ($a -eq 172 -and $b -ge 16 -and $b -le 31) { return $false }
    if ($a -eq 192 -and ($b -eq 0 -or $b -eq 2 -or $b -eq 168)) { return $false }
    if ($a -eq 198 -and ($b -eq 18 -or $b -eq 19 -or $b -eq 51)) { return $false }
    if ($a -eq 203 -and $b -eq 0) { return $false }
    if ($a -ge 240) { return $false }
    return $true
}

function Get-Plaintext([Security.SecureString] $SecureValue) {
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureValue)
    try {
        return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
    }
    finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    }
}

function Read-ConfirmedSecret([string] $Label, [int] $MinimumLength) {
    $first = Get-Plaintext (Read-Host -Prompt $Label -AsSecureString)
    $second = Get-Plaintext (Read-Host -Prompt "Repeat $Label" -AsSecureString)
    try {
        if ([string]::IsNullOrWhiteSpace($first) -or $first.Length -lt $MinimumLength) {
            Fail "$Label must contain at least $MinimumLength characters."
        }
        if ($first.IndexOfAny([char[]]"`r`n`0") -ge 0) {
            Fail "$Label must not contain line breaks or NUL characters."
        }
        if (-not [string]::Equals($first, $second, [StringComparison]::Ordinal)) {
            Fail "$Label values do not match."
        }
        return $first
    }
    finally {
        $second = $null
    }
}

function ConvertTo-Base64Utf8([string] $Value) {
    return [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($Value))
}

function ConvertTo-PosixSingleQuoted([string] $Value) {
    # Every value passed to the remote shell is validated first. Quote it as
    # well: notably, RFC-valid local parts of an email address can contain an
    # apostrophe, which must never become shell syntax.
    $singleQuote = [string] [char] 39
    $doubleQuote = [string] [char] 34
    $embeddedQuote = $singleQuote + $doubleQuote + $singleQuote + $doubleQuote + $singleQuote
    return $singleQuote + $Value.Replace($singleQuote, $embeddedQuote) + $singleQuote
}

function Assert-NativeSuccess([string] $Program) {
    if ($LASTEXITCODE -ne 0) {
        Fail "$Program failed with exit code $LASTEXITCODE."
    }
}

function Set-PrivateKeyAcl([string] $Path) {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    & icacls.exe $Path /inheritance:r | Out-Null
    Assert-NativeSuccess 'icacls'
    & icacls.exe $Path /grant:r "${identity}:(R)" 'SYSTEM:(F)' 'Administrators:(F)' | Out-Null
    Assert-NativeSuccess 'icacls'
}

function Ensure-ActionsKey([string] $PrivateKeyPath, [string] $SshKeygen, [switch] $RequireExisting) {
    $keyDirectory = Split-Path -Parent $PrivateKeyPath
    if ([string]::IsNullOrWhiteSpace($keyDirectory)) {
        Fail 'ActionsKeyPath must include a directory.'
    }
    New-Item -ItemType Directory -Path $keyDirectory -Force | Out-Null

    $publicKeyPath = "$PrivateKeyPath.pub"
    if (-not (Test-Path -LiteralPath $PrivateKeyPath -PathType Leaf)) {
        if ($RequireExisting) {
            Fail 'Resume requires the existing GitHub Actions private key; it will not generate a replacement key.'
        }
        Write-Host 'Generating a dedicated, passphrase-free ED25519 key for the GitHub Actions deploy identity...'
        & $SshKeygen -q -t ed25519 -a 64 -N '' -C 'amnezia-production-github-actions' -f $PrivateKeyPath
        Assert-NativeSuccess 'ssh-keygen'
    }
    Set-PrivateKeyAcl $PrivateKeyPath

    if (-not (Test-Path -LiteralPath $publicKeyPath -PathType Leaf)) {
        if ($RequireExisting) {
            Fail 'Resume requires the existing GitHub Actions public key file; it will not derive a replacement key.'
        }
        $publicKey = & $SshKeygen -y -f $PrivateKeyPath
        Assert-NativeSuccess 'ssh-keygen'
        [IO.File]::WriteAllText($publicKeyPath, (($publicKey -join "`n").Trim() + "`n"), [Text.Encoding]::ASCII)
    }
    $publicKeyText = [IO.File]::ReadAllText($publicKeyPath, [Text.Encoding]::ASCII).Trim()
    if ($publicKeyText -notmatch '^ssh-ed25519\s+[A-Za-z0-9+/]+={0,2}(\s+.*)?$') {
        Fail 'Actions public key is not a valid SSH ED25519 public key.'
    }

    $derivedPublicKey = ((& $SshKeygen -y -f $PrivateKeyPath) -join "`n").Trim()
    Assert-NativeSuccess 'ssh-keygen'
    $derivedParts = $derivedPublicKey -split '\s+', 3
    $storedParts = $publicKeyText -split '\s+', 3
    if ($derivedParts.Count -lt 2 -or $storedParts.Count -lt 2 -or
        $derivedParts[0] -cne $storedParts[0] -or $derivedParts[1] -cne $storedParts[1]) {
        Fail 'Actions public key does not match its private key.'
    }
    return @{ Private = $PrivateKeyPath; Public = $publicKeyPath; PublicText = $publicKeyText }
}

function Get-ManifestFiles([string] $RepositoryRoot, [string] $ManifestPath, [string] $Git) {
    if (-not (Test-Path -LiteralPath $ManifestPath -PathType Leaf)) {
        Fail "Missing bootstrap manifest: $ManifestPath"
    }
    $files = @()
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    foreach ($rawLine in [IO.File]::ReadAllLines($ManifestPath, [Text.Encoding]::UTF8)) {
        $entry = $rawLine.Trim()
        if ([string]::IsNullOrWhiteSpace($entry) -or $entry.StartsWith('#')) { continue }
        if ($entry.StartsWith('/') -or $entry.StartsWith('\\') -or $entry -match '(^|[\\/])\.\.([\\/]|$)') {
            Fail "Unsafe path in bootstrap manifest: $entry"
        }
        if (-not $seen.Add($entry)) {
            Fail "Duplicate path in bootstrap manifest: $entry"
        }
        $source = Join-Path $RepositoryRoot ($entry -replace '/', [IO.Path]::DirectorySeparatorChar)
        if (-not (Test-Path -LiteralPath $source -PathType Leaf)) {
            Fail "Manifest file is missing: $entry"
        }
        # Images are tagged with HEAD. Every uploaded release descriptor (the
        # root bootstrap helper included) must be a tracked, clean version of
        # that same commit rather than an accidental local edit.
        $null = & $Git -C $RepositoryRoot ls-files --error-unmatch -- $entry 2>$null
        if ($LASTEXITCODE -ne 0) {
            Fail "Manifest file is not tracked by Git: $entry"
        }
        $null = & $Git -C $RepositoryRoot diff --quiet --no-ext-diff HEAD -- $entry
        if ($LASTEXITCODE -eq 1) {
            Fail "Manifest file differs from HEAD; commit or discard the local change before bootstrap: $entry"
        }
        if ($LASTEXITCODE -ne 0) {
            Fail "Could not verify Git cleanliness for manifest file: $entry"
        }
        $files += [PSCustomObject]@{ Relative = $entry; Source = (Resolve-Path -LiteralPath $source).Path }
    }
    if ($files.Count -eq 0) { Fail 'Bootstrap manifest has no files.' }
    return $files
}

function New-BootstrapReleaseArchive([object[]] $Files) {
    $temporaryRoot = Join-Path ([IO.Path]::GetTempPath()) ("amnezia-production-bootstrap-" + [Guid]::NewGuid().ToString('N'))
    $archive = Join-Path $temporaryRoot 'release.zip'
    $bootstrapHelper = $null
    New-Item -ItemType Directory -Path $temporaryRoot -Force | Out-Null
    Add-Type -AssemblyName System.IO.Compression
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $zip = [IO.Compression.ZipFile]::Open($archive, [IO.Compression.ZipArchiveMode]::Create)
    try {
        foreach ($file in $Files) {
            if ($file.Relative -eq 'deploy/production/bootstrap-vps.sh') {
                $bootstrapHelper = $file.Source
                continue
            }
            [IO.Compression.ZipFileExtensions]::CreateEntryFromFile(
                $zip,
                $file.Source,
                $file.Relative,
                [IO.Compression.CompressionLevel]::Optimal) | Out-Null
        }
    }
    finally {
        $zip.Dispose()
    }
    if ($null -eq $bootstrapHelper) {
        Remove-Item -LiteralPath $temporaryRoot -Recurse -Force -ErrorAction SilentlyContinue
        Fail 'The manifest must explicitly include deploy/production/bootstrap-vps.sh.'
    }
    return @{ Root = $temporaryRoot; Archive = $archive; BootstrapHelper = $bootstrapHelper }
}

if (-not (Test-PublicIpv4 $HostAddress)) {
    Fail 'HostAddress must be a globally routable public IPv4 address.'
}
if ($ExpectedSshHostKeyFingerprint -notmatch '^SHA256:[A-Za-z0-9+/]{43}$') {
    Fail 'ExpectedSshHostKeyFingerprint must be an ED25519 SHA256 fingerprint, e.g. SHA256:abc...'
}
if ($GitHubOwner -cnotmatch '^[a-z0-9](?:[a-z0-9-]{0,37}[a-z0-9])?$') {
    Fail 'GitHubOwner must be a lowercase GitHub user or organization name.'
}
if ([string]::IsNullOrWhiteSpace($GhcrUsername)) {
    $GhcrUsername = $GitHubOwner
}
if ($GhcrUsername -cnotmatch '^[a-z0-9](?:[a-z0-9-]{0,37}[a-z0-9])?$') {
    Fail 'GhcrUsername must be the lowercase GitHub username that owns the GHCR PAT.'
}
if ($ImageTag -notmatch '^sha-[0-9a-f]{40}$') {
    Fail 'ImageTag must be sha- followed by the 40 lowercase hexadecimal commit SHA.'
}
if ($AcmeEmail -notmatch '^[^\s@]+@[^\s@]+\.[^\s@]+$') {
    Fail "AcmeEmail must be a valid email address for Let's Encrypt expiry notices."
}
if ($DeployPath -notmatch '^/opt/[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*$' -or $DeployPath.Contains('..')) {
    Fail 'DeployPath must be an absolute, traversal-free path below /opt.'
}
if ($RootUser -eq $DeployUser) {
    Fail 'RootUser and DeployUser must be different accounts.'
}

$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$git = Get-RequiredCommand 'git'
$ssh = Get-RequiredCommand 'ssh'
$scp = Get-RequiredCommand 'scp'
$sshKeyscan = Get-RequiredCommand 'ssh-keyscan'
$sshKeygen = Get-RequiredCommand 'ssh-keygen'

if ($RootSshIdentityPath) {
    if (-not (Test-Path -LiteralPath $RootSshIdentityPath -PathType Leaf)) {
        Fail 'RootSshIdentityPath does not point to an existing private key file.'
    }
    $RootSshIdentityPath = (Resolve-Path -LiteralPath $RootSshIdentityPath).Path
}

$gitHeadOutput = & $git -C $repositoryRoot rev-parse HEAD
Assert-NativeSuccess 'git rev-parse'
$gitHead = (($gitHeadOutput | Select-Object -First 1).ToString()).Trim().ToLowerInvariant()
if ($gitHead -notmatch '^[0-9a-f]{40}$') { Fail 'git rev-parse HEAD did not return a full commit SHA.' }
if ($ImageTag -cne "sha-$gitHead") {
    Fail "ImageTag must equal sha-$gitHead, the currently checked-out commit."
}

$manifestPath = Join-Path $PSScriptRoot 'production/bootstrap-manifest.txt'
$manifestFiles = Get-ManifestFiles $repositoryRoot $manifestPath $git
if (-not $ActionsKeyPath) {
    $ActionsKeyPath = Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'AmneziaKeyService\keys\production-actions-ed25519'
}
$actionsKey = Ensure-ActionsKey ([IO.Path]::GetFullPath($ActionsKeyPath)) $sshKeygen -RequireExisting:$Resume

Write-Host "Validated local release $ImageTag and $($manifestFiles.Count) explicit non-secret bootstrap files."
Write-Host "GitHub Actions deploy public key: $($actionsKey.Public)"

if ($ValidateOnly) {
    Write-Host 'ValidateOnly completed: no network operation and no secret prompt was performed.'
    Write-Host 'After a real bootstrap, create GitHub Environment production with:'
    Write-Host "  secret PRODUCTION_SSH_HOST = $HostAddress"
    Write-Host "  secret PRODUCTION_SSH_USER = $DeployUser"
    Write-Host "  secret PRODUCTION_SSH_PRIVATE_KEY = contents of $($actionsKey.Private)"
    Write-Host '  secret PRODUCTION_SSH_KNOWN_HOSTS = verified ssh-keyscan output printed by the real bootstrap'
    Write-Host "  variable PRODUCTION_SSH_PORT = $SshPort"
    Write-Host "  variable PRODUCTION_DEPLOY_PATH = $DeployPath"
    Write-Host '  variable PRODUCTION_PROXY_MODE = nginx'
    exit 0
}

$temporaryRoot = $null
$packageRoot = $null
try {
    $temporaryRoot = Join-Path ([IO.Path]::GetTempPath()) ("amnezia-production-ssh-" + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $temporaryRoot -Force | Out-Null
    $knownHosts = Join-Path $temporaryRoot 'known_hosts'

    Write-Host "Fetching the ED25519 host key from $HostAddress`:$SshPort for fingerprint verification..."
    & $sshKeyscan -T 10 -t ed25519 -p $SshPort -H $HostAddress 2>$null | Set-Content -LiteralPath $knownHosts -Encoding ascii
    Assert-NativeSuccess 'ssh-keyscan'
    if (-not (Test-Path -LiteralPath $knownHosts) -or (Get-Item -LiteralPath $knownHosts).Length -eq 0) {
        Fail 'ssh-keyscan returned no ED25519 host key.'
    }

    $fingerprintLines = & $sshKeygen -lf $knownHosts -E sha256
    Assert-NativeSuccess 'ssh-keygen'
    $actualFingerprints = @($fingerprintLines | ForEach-Object {
        if ($_ -match '\b(SHA256:[A-Za-z0-9+/]{43})\b') { $Matches[1] }
    } | Where-Object { $_ })
    if ($actualFingerprints.Count -ne 1 -or $actualFingerprints[0] -cne $ExpectedSshHostKeyFingerprint) {
        Fail 'The scanned SSH ED25519 fingerprint does not exactly match ExpectedSshHostKeyFingerprint. Nothing was uploaded.'
    }
    Write-Host 'SSH ED25519 host fingerprint verified.'

    $sshOptions = @('-o', 'IdentitiesOnly=yes', '-o', 'StrictHostKeyChecking=yes', '-o', "UserKnownHostsFile=$knownHosts", '-p', "$SshPort")
    $scpOptions = @('-o', 'IdentitiesOnly=yes', '-o', 'StrictHostKeyChecking=yes', '-o', "UserKnownHostsFile=$knownHosts", '-P', "$SshPort")
    if ($RootSshIdentityPath) {
        $sshOptions += @('-i', $RootSshIdentityPath)
        $scpOptions += @('-i', $RootSshIdentityPath)
    }
    $remote = "$RootUser@$HostAddress"
    $remoteIncoming = "/tmp/amnezia-bootstrap-$($ImageTag.Substring(4))"
    & $ssh @sshOptions $remote "umask 077; mkdir -p '$remoteIncoming'"
    Assert-NativeSuccess 'ssh'

    $package = New-BootstrapReleaseArchive $manifestFiles
    # The release ZIP is intentionally created only after the host key has been checked.
    $packageRoot = $package.Root
    & $scp @scpOptions $package.Archive "${remote}:$remoteIncoming/release.zip"
    Assert-NativeSuccess 'scp release archive'
    & $scp @scpOptions $package.BootstrapHelper "${remote}:$remoteIncoming/bootstrap-vps.sh"
    Assert-NativeSuccess 'scp bootstrap helper'

    $payloadLines = New-Object System.Collections.Generic.List[string]
    # An interrupted bootstrap validates this complete record set. A completed
    # installation ignores stdin and performs only its read-only health check.
    $mongoRootPassword = Read-ConfirmedSecret 'MongoDB root password' 24
    $mongoAppPassword = Read-ConfirmedSecret 'MongoDB application password' 24
    if ([string]::Equals($mongoRootPassword, $mongoAppPassword, [StringComparison]::Ordinal)) {
        Fail 'MongoDB root and application passwords must be different.'
    }
    $adminPassword = Read-ConfirmedSecret 'Panel administrator password' 12
    $telegramToken = Read-ConfirmedSecret 'Telegram bot token' 20
    if ($telegramToken -notmatch '^[0-9]{5,}:[A-Za-z0-9_-]{10,}$') {
        Fail 'Telegram bot token has an unexpected format.'
    }

    $payloadLines.Add("MONGO_ROOT_PASSWORD=$(ConvertTo-Base64Utf8 $mongoRootPassword)")
    $payloadLines.Add("MONGO_APP_PASSWORD=$(ConvertTo-Base64Utf8 $mongoAppPassword)")
    $payloadLines.Add("ADMIN_PASSWORD=$(ConvertTo-Base64Utf8 $adminPassword)")
    $payloadLines.Add("TELEGRAM_BOT_TOKEN=$(ConvertTo-Base64Utf8 $telegramToken)")
    # This key is public, but the remote script intentionally receives it via
    # the same base64 line parser as the sensitive values.
    $payloadLines.Add("ACTIONS_PUBLIC_KEY=$(ConvertTo-Base64Utf8 $actionsKey.PublicText)")
    if (-not $PublicGhcr) {
        $ghcrPat = Read-ConfirmedSecret 'GitHub Container Registry PAT (read:packages)' 1
        $payloadLines.Add("GHCR_PAT=$(ConvertTo-Base64Utf8 $ghcrPat)")
    }

    $publicImagesFlag = if ($PublicGhcr) { '1' } else { '0' }
    $resumeFlag = if ($Resume) { '1' } else { '0' }
    $quotedHelper = ConvertTo-PosixSingleQuoted "$remoteIncoming/bootstrap-vps.sh"
    $quotedArchive = ConvertTo-PosixSingleQuoted "$remoteIncoming/release.zip"
    $remoteCommand = "set -Eeuo pipefail; umask 077; chmod 700 $quotedHelper; exec bash $quotedHelper $quotedArchive $(ConvertTo-PosixSingleQuoted $HostAddress) $(ConvertTo-PosixSingleQuoted $GitHubOwner) $(ConvertTo-PosixSingleQuoted $DeployUser) $(ConvertTo-PosixSingleQuoted $DeployPath) $(ConvertTo-PosixSingleQuoted $ImageTag) $(ConvertTo-PosixSingleQuoted $AcmeEmail) $publicImagesFlag $resumeFlag $SshPort $(ConvertTo-PosixSingleQuoted $AdminUsername) $(ConvertTo-PosixSingleQuoted $GhcrUsername)"

    # Do not put payloadLines in a file, process arguments, environment variable,
    # transcript, exception, or output.  SSH receives it only through stdin.
    $payloadLines | & $ssh @sshOptions $remote $remoteCommand
    Assert-NativeSuccess 'ssh bootstrap'

    # The VPS has just installed this exact public key with no-pty and
    # no-forwarding restrictions. Verify that GitHub Actions will be able to
    # run its non-interactive deployment command before asking the operator to
    # save this private key in the production environment.
    Write-Host 'Verifying the GitHub Actions deploy-key login...'
    $actionsSshOptions = @('-i', $actionsKey.Private, '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes', '-o', 'StrictHostKeyChecking=yes', '-o', "UserKnownHostsFile=$knownHosts", '-p', "$SshPort")
    & $ssh @actionsSshOptions "$DeployUser@$HostAddress" 'true'
    Assert-NativeSuccess 'GitHub Actions deploy-key SSH verification'

    Write-Host ''
    Write-Host 'Production bootstrap completed. Add these safe values to GitHub Environment production:'
    Write-Host "  PRODUCTION_SSH_HOST (secret): $HostAddress"
    Write-Host "  PRODUCTION_SSH_USER (secret): $DeployUser"
    Write-Host "  PRODUCTION_SSH_PRIVATE_KEY (secret): contents of $($actionsKey.Private)"
    Write-Host '  PRODUCTION_SSH_KNOWN_HOSTS (secret):'
    Get-Content -LiteralPath $knownHosts
    Write-Host "  PRODUCTION_SSH_PORT (variable): $SshPort"
    Write-Host "  PRODUCTION_DEPLOY_PATH (variable): $DeployPath"
    Write-Host '  PRODUCTION_PROXY_MODE (variable): nginx'
}
finally {
    if ($packageRoot -and (Test-Path -LiteralPath $packageRoot)) {
        Remove-Item -LiteralPath $packageRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
    if ($temporaryRoot -and (Test-Path -LiteralPath $temporaryRoot)) {
        Remove-Item -LiteralPath $temporaryRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}
