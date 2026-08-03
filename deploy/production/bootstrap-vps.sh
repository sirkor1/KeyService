#!/usr/bin/env bash
# Initial production bootstrap. This file is uploaded and invoked by
# deploy/bootstrap-production.ps1 only after that script has verified the SSH
# host fingerprint. It deliberately accepts configuration only as validated
# non-secret arguments and receives secrets as base64 records on stdin.
#
# Do not run this script by pasting passwords into a terminal. Its stdin format
# is documented in deploy/production/README.md and is intended for the local
# PowerShell bootstrapper.
set -Eeuo pipefail
IFS=$'\n\t'
umask 077

readonly BOOTSTRAP_VERSION='1'
readonly PROJECT_NAME='amnezia-key-service'
readonly MONGO_DATABASE='amnezia_vpn'
readonly MONGO_ROOT_USER='amnezia_root'
readonly MONGO_APP_USER='amnezia_app'

if (( $# != 13 )); then
  printf 'bootstrap: expected exactly 13 positional arguments.\n' >&2
  exit 2
fi

release_archive=${1:?missing release archive path}
public_ipv4=${2:?missing public IPv4}
github_owner=${3:?missing GitHub owner}
deploy_user=${4:?missing deployment user}
deploy_path=${5:?missing deployment path}
image_tag=${6:?missing immutable image tag}
acme_email=${7:?missing ACME email}
public_images=${8:?missing public-images flag}
telegram_mode=${9:?missing Telegram mode}
resume=${10:?missing resume flag}
ssh_port=${11:?missing SSH port}
admin_username=${12:?missing administrator username}
ghcr_username=${13:?missing GitHub Container Registry username}

fresh_env=''
work_dir=''
release_dir=''
env_file=''
progress_file=''
complete_marker=''
incoming_dir=''

fail() {
  printf 'bootstrap: %s\n' "$*" >&2
  exit 1
}

cleanup() {
  # The fresh environment contains MongoDB bootstrap passwords. /dev/shm is
  # memory-backed on Ubuntu, but unlink it regardless of the outcome.
  if [[ -n "$fresh_env" && -e "$fresh_env" ]]; then
    rm -f -- "$fresh_env"
  fi
  if [[ -n "$work_dir" && -d "$work_dir" ]]; then
    rm -rf -- "$work_dir"
  fi
  if [[ "$incoming_dir" =~ ^/tmp/amnezia-bootstrap-[0-9a-f]{32}$ ]]; then
    rm -f -- "$incoming_dir/release.zip" "$incoming_dir/bootstrap-vps.sh"
    rmdir -- "$incoming_dir" 2>/dev/null || true
  fi
  unset MONGO_ROOT_PASSWORD MONGO_APP_PASSWORD ADMIN_PASSWORD TELEGRAM_BOT_TOKEN GHCR_PAT
}
trap cleanup EXIT

require_root() {
  [[ "$(id -u)" == '0' ]] || fail 'this script must run as root.'
}

validate_arguments() {
  [[ "$public_ipv4" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || fail 'public IPv4 is invalid.'
  local octet first second third
  local -a octets
  IFS='.' read -r -a octets <<< "$public_ipv4"
  for octet in "${octets[@]}"; do
    [[ "$octet" =~ ^[0-9]+$ ]] && ((10#$octet <= 255)) || fail 'public IPv4 is invalid.'
  done
  first=$((10#${octets[0]}))
  second=$((10#${octets[1]}))
  third=$((10#${octets[2]}))
  ((first != 0 && first != 10 && first != 127 && first < 224)) || fail 'public IPv4 must be globally routable.'
  ((first != 169 || second != 254)) || fail 'public IPv4 must be globally routable.'
  ((first != 172 || second < 16 || second > 31)) || fail 'public IPv4 must be globally routable.'
  ((first != 192 || second != 0 || (third != 0 && third != 2))) || fail 'public IPv4 must be globally routable.'
  ((first != 192 || second != 168)) || fail 'public IPv4 must be globally routable.'
  ((first != 100 || second < 64 || second > 127)) || fail 'public IPv4 must be globally routable.'
  ((first != 198 || (second != 18 && second != 19))) || fail 'public IPv4 must be globally routable.'
  ((first != 198 || second != 51 || third != 100)) || fail 'public IPv4 must be globally routable.'
  ((first != 203 || second != 0 || third != 113)) || fail 'public IPv4 must be globally routable.'
  [[ "$github_owner" =~ ^[a-z0-9]([a-z0-9-]{0,37}[a-z0-9])?$ ]] || fail 'GitHub owner must be a valid lowercase GitHub user or organization name.'
  [[ "$deploy_user" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]] || fail 'deployment user is invalid.'
  [[ "$deploy_path" =~ ^/opt/[A-Za-z0-9._/-]+$ && "$deploy_path" != *'..'* && "$deploy_path" != *'//'* ]] || fail 'deployment path must be a canonical path below /opt.'
  [[ "$image_tag" =~ ^sha-[0-9a-f]{40}$ ]] || fail 'image tag must be sha- followed by a 40-character lowercase commit SHA.'
  [[ "$acme_email" =~ ^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$ ]] || fail 'ACME email is invalid.'
  [[ "$public_images" == '0' || "$public_images" == '1' ]] || fail 'public-images flag must be 0 or 1.'
  [[ "$telegram_mode" == 'telegram-enabled' || "$telegram_mode" == 'no-telegram' ]] || fail 'Telegram mode must be telegram-enabled or no-telegram.'
  [[ "$resume" == '0' || "$resume" == '1' ]] || fail 'resume flag must be 0 or 1.'
  [[ "$ssh_port" =~ ^[0-9]{1,5}$ ]] && ((10#$ssh_port >= 1 && 10#$ssh_port <= 65535)) || fail 'SSH port is invalid.'
  [[ "$admin_username" =~ ^[A-Za-z0-9._-]{3,64}$ ]] || fail 'administrator username is invalid.'
  [[ "$ghcr_username" =~ ^[a-z0-9]([a-z0-9-]{0,37}[a-z0-9])?$ ]] || fail 'GitHub Container Registry username is invalid.'
  [[ "$release_archive" =~ ^/tmp/amnezia-bootstrap-[0-9a-f]{32}/release\.zip$ ]] || fail 'release archive path is invalid.'
  incoming_dir=${release_archive%/release.zip}
  [[ -f "$release_archive" ]] || fail 'release archive is missing.'
}

require_printable_single_line() {
  local label=$1 value=$2
  local LC_ALL=C
  # Bash strings cannot contain NUL at all. Reject line breaks explicitly so
  # that a decoded value can never alter the temporary Compose env-file.
  [[ "$value" != *$'\n'* && "$value" != *$'\r'* ]] || fail "$label must not contain CR or LF."
  [[ "$value" =~ ^[[:print:]]+$ ]] || fail "$label must contain printable ASCII characters only."
}

decode_record() {
  local encoded=$1
  [[ "$encoded" =~ ^[A-Za-z0-9+/]*={0,2}$ ]] || fail 'secret input is not valid base64.'
  printf '%s' "$encoded" | base64 --decode
}

read_secret_records() {
  local name encoded value
  local got_root=0 got_app=0 got_admin=0 got_telegram=0 got_ghcr=0 got_actions_key=0

  while IFS='=' read -r name encoded; do
    [[ -n "$name" ]] || continue
    # PowerShell may write native-process stdin with CRLF. `read` removes the
    # LF but leaves that one record terminator CR; remove exactly that suffix
    # before strict base64 validation, without accepting CR elsewhere.
    if [[ "$encoded" == *$'\r' ]]; then
      encoded=${encoded%$'\r'}
    fi
    value=$(decode_record "$encoded") || fail 'cannot decode secret input.'
    case "$name" in
      MONGO_ROOT_PASSWORD) MONGO_ROOT_PASSWORD=$value; got_root=1 ;;
      MONGO_APP_PASSWORD) MONGO_APP_PASSWORD=$value; got_app=1 ;;
      ADMIN_PASSWORD) ADMIN_PASSWORD=$value; got_admin=1 ;;
      TELEGRAM_BOT_TOKEN)
        [[ "$telegram_mode" == 'telegram-enabled' ]] || fail 'Telegram token record is forbidden when Telegram is disabled.'
        TELEGRAM_BOT_TOKEN=$value
        got_telegram=1
        ;;
      GHCR_PAT) GHCR_PAT=$value; got_ghcr=1 ;;
      ACTIONS_PUBLIC_KEY) ACTIONS_PUBLIC_KEY=$value; got_actions_key=1 ;;
      *) fail 'secret input contains an unknown record name.' ;;
    esac
    unset value
  done

  if [[ "$telegram_mode" == 'telegram-enabled' ]]; then
    ((got_root && got_app && got_admin && got_telegram && got_actions_key)) || fail 'secret input is incomplete.'
  else
    ((got_root && got_app && got_admin && got_actions_key && ! got_telegram)) || fail 'secret input is incomplete.'
    TELEGRAM_BOT_TOKEN=''
  fi
  ((public_images == 1 || got_ghcr == 1)) || fail 'private GHCR images require a GHCR_PAT record.'
  [[ ${#MONGO_ROOT_PASSWORD} -ge 24 ]] || fail 'MongoDB root password must contain at least 24 characters.'
  [[ ${#MONGO_APP_PASSWORD} -ge 24 ]] || fail 'MongoDB application password must contain at least 24 characters.'
  [[ "$MONGO_ROOT_PASSWORD" != "$MONGO_APP_PASSWORD" ]] || fail 'MongoDB root and application passwords must differ.'
  require_printable_single_line 'MongoDB root password' "$MONGO_ROOT_PASSWORD"
  require_printable_single_line 'MongoDB application password' "$MONGO_APP_PASSWORD"
  require_printable_single_line 'administrator password' "$ADMIN_PASSWORD"
  if [[ "$telegram_mode" == 'telegram-enabled' ]]; then
    require_printable_single_line 'Telegram bot token' "$TELEGRAM_BOT_TOKEN"
  fi
  [[ "$ACTIONS_PUBLIC_KEY" =~ ^ssh-ed25519[[:space:]][A-Za-z0-9+/=]+([[:space:]][^[:space:]]+)?$ ]] || fail 'GitHub Actions public key must be an ED25519 OpenSSH key.'
  if ((public_images == 0)); then
    require_printable_single_line 'GHCR token' "$GHCR_PAT"
    [[ "$GHCR_PAT" =~ ^(ghp_[A-Za-z0-9]{36,}|[A-Fa-f0-9]{40})$ ]] || \
      fail 'private GHCR images require a classic GitHub PAT (ghp_ token or legacy 40-character hexadecimal token).'
  fi
}

assert_ubuntu() {
  [[ -r /etc/os-release ]] || fail 'cannot identify operating system.'
  # shellcheck disable=SC1091
  . /etc/os-release
  [[ "${ID:-}" == 'ubuntu' ]] || fail 'only Ubuntu is supported by this bootstrap.'
  [[ "${VERSION_ID:-}" == '24.04' ]] || fail 'this bootstrap requires Ubuntu 24.04 LTS.'
}

install_os_packages() {
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  apt-get install -y ca-certificates curl gnupg unzip nginx ufw fail2ban snapd openssl iproute2
  systemctl enable --now fail2ban
}

install_docker() {
  install -m 0755 -d /etc/apt/keyrings
  if [[ ! -s /etc/apt/keyrings/docker.asc ]]; then
    curl --fail --silent --show-error --location https://download.docker.com/linux/ubuntu/gpg \
      -o /etc/apt/keyrings/docker.asc
    chmod a+r /etc/apt/keyrings/docker.asc
  fi

  local architecture codename
  architecture=$(dpkg --print-architecture)
  # shellcheck disable=SC1091
  . /etc/os-release
  codename=$VERSION_CODENAME
  printf 'deb [arch=%s signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu %s stable\n' \
    "$architecture" "$codename" > /etc/apt/sources.list.d/docker.list
  apt-get update
  apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
  systemctl enable --now docker
  docker compose version >/dev/null

  # docker-compose host override uses the !override tag introduced in v2.24.4.
  local compose_version
  compose_version=$(docker compose version --short | sed 's/^v//')
  dpkg --compare-versions "$compose_version" ge '2.24.4' || fail 'Docker Compose 2.24.4 or newer is required.'
}

wait_for_snapd() {
  # apt can replace snapd while this bootstrap is running.  Wait for both the
  # socket and the initial snap state before issuing changes; otherwise the
  # first snap command can race snapd's post-upgrade restart/rollback.
  local deadline
  systemctl enable --now snapd.socket
  deadline=$((SECONDS + 120))
  while ((SECONDS < deadline)); do
    if systemctl is-active --quiet snapd.socket && \
      timeout 5 snap wait system seed.loaded >/dev/null 2>&1; then
      return 0
    fi
    sleep 2
  done
  fail 'snapd did not become ready within 120 seconds.'
}

run_snap_change() {
  # A snapd package upgrade can finish just before its daemon has restarted.
  # Retry the complete change a few times, but surface a persistent install or
  # refresh failure instead of treating it as optional.
  local attempt
  for attempt in {1..3}; do
    wait_for_snapd
    if snap "$@"; then
      return 0
    fi
    if ((attempt < 3)); then
      printf 'bootstrap: snap command failed; waiting before retry %d/3.\n' "$((attempt + 1))" >&2
      sleep 2
    fi
  done
  fail 'snap command failed after 3 attempts.'
}

install_certbot() {
  wait_for_snapd
  if ! snap list core >/dev/null 2>&1; then
    run_snap_change install core
  fi
  wait_for_snapd

  if ! snap list certbot >/dev/null 2>&1; then
    run_snap_change install --classic certbot
  fi
  ln -sfn /snap/bin/certbot /usr/local/bin/certbot

  local certbot_version
  certbot_version=$(/snap/bin/certbot --version | sed -nE 's/^certbot ([0-9][0-9A-Za-z.~-]*).*$/\1/p')
  [[ -n "$certbot_version" ]] || fail 'cannot determine Certbot version.'
  dpkg --compare-versions "$certbot_version" ge '5.4' || fail 'IP certificates require Certbot 5.4 or newer.'
}

verify_release_bundle() {
  local expected actual archive_entries
  local -a expected_files=(
    'docker-compose.yml'
    'docker-compose.mongo-auth.yml'
    'docker-compose.mongo-auth.fresh.yml'
    'docker/mongo-init/01-create-app-user.sh'
    'deploy/production/docker-compose.images.yml'
    'deploy/production/deploy.sh'
    'deploy/nginx/docker-compose.host-nginx.yml'
    'deploy/nginx/amnezia.bootstrap-ip-http.conf.example'
    'deploy/nginx/amnezia.ip.conf.example'
  )

  # Validate names before extraction to prevent a zip-slip path from touching
  # anything outside a fresh /tmp directory. The Windows bootstrapper creates
  # exactly these file entries, with no directory or wildcard entries.
  expected=$(printf '%s\n' "${expected_files[@]}" | LC_ALL=C sort)
  archive_entries=$(unzip -Z1 "$release_archive" | LC_ALL=C sort)
  [[ "$archive_entries" == "$expected" ]] || fail 'release archive entries do not match the explicit bootstrap manifest.'

  work_dir=$(mktemp -d /tmp/amnezia-release.XXXXXX)
  unzip -qq "$release_archive" -d "$work_dir/release"
  find "$work_dir/release" -type l -print -quit | grep -q . && fail 'release archive must not contain symlinks.'
  actual=$(cd "$work_dir/release" && find . -type f -printf '%P\n' | LC_ALL=C sort)
  [[ "$actual" == "$expected" ]] || fail 'release archive does not match the explicit bootstrap manifest.'
  for expected in "${expected_files[@]}"; do
    [[ -s "$work_dir/release/$expected" ]] || fail "release archive contains an empty required file: $expected"
  done
}

ensure_deploy_account() {
  if ! id "$deploy_user" >/dev/null 2>&1; then
    useradd --create-home --shell /bin/bash "$deploy_user"
  fi
  usermod -aG docker "$deploy_user"
  install -d -m 0700 -o "$deploy_user" -g "$deploy_user" "/home/$deploy_user/.ssh"
  local authorized_keys="/home/$deploy_user/.ssh/authorized_keys"
  if [[ -L "$authorized_keys" || ( -e "$authorized_keys" && ! -f "$authorized_keys" ) ]]; then
    fail 'deployment authorized_keys path must be a regular file.'
  fi
  if [[ ! -e "$authorized_keys" ]]; then
    install -m 0600 -o "$deploy_user" -g "$deploy_user" /dev/null "$authorized_keys"
  fi

  # This is the dedicated GitHub Actions key. The deploy account is in the
  # docker group (therefore root-equivalent); keep the three forwarding
  # features disabled for this particular key.
  local restricted_key
  restricted_key="no-port-forwarding,no-agent-forwarding,no-X11-forwarding,no-pty $ACTIONS_PUBLIC_KEY"
  if ! grep -Fqx -- "$restricted_key" "$authorized_keys"; then
    printf '%s\n' "$restricted_key" >> "$authorized_keys"
  fi
  chown "$deploy_user:$deploy_user" "$authorized_keys"
  chmod 0600 "$authorized_keys"
}

configure_firewall() {
  ufw default deny incoming
  ufw default allow outgoing
  ufw allow "${ssh_port}/tcp" comment 'SSH administration and GitHub Actions'
  ufw allow 80/tcp comment 'ACME HTTP-01 only'
  ufw allow 443/tcp comment 'Amnezia panel HTTPS'
  ufw --force enable
}

install_release_files() {
  release_dir="$deploy_path/release"
  env_file="$deploy_path/.env"
  progress_file="$deploy_path/.bootstrap-progress"
  complete_marker="$deploy_path/.bootstrap-complete"

  install -d -m 0750 -o "$deploy_user" -g "$deploy_user" "$deploy_path" "$deploy_path/incoming"
  install -d -m 0750 -o root -g "$deploy_user" "$release_dir"

  local source target parent
  while IFS= read -r source; do
    target="$release_dir/$source"
    parent=$(dirname "$target")
    install -d -m 0750 -o root -g "$deploy_user" "$parent"
    if [[ "$source" == 'docker/mongo-init/01-create-app-user.sh' ]]; then
      # The official mongo:8 entrypoint drops to the unprivileged `mongodb`
      # user before it sources initdb shell hooks.  This hook contains no
      # secrets (they come only from the container environment), so it must be
      # readable and executable by that user rather than limited to deploy.
      install -m 0555 -o root -g root "$work_dir/release/$source" "$target"
    elif [[ "$source" == 'deploy/production/deploy.sh' ]]; then
      install -m 0750 -o root -g "$deploy_user" "$work_dir/release/$source" "$target"
    else
      install -m 0640 -o root -g "$deploy_user" "$work_dir/release/$source" "$target"
    fi
  done < <(cd "$work_dir/release" && find . -type f -printf '%P\n' | LC_ALL=C sort)
}

dotenv_single_quote() {
  local value=$1
  value=${value//\'/\'\\\'}
  printf "'%s'" "$value"
}

write_env_line_to() {
  local destination=$1 key=$2 value=$3
  printf '%s=' "$key" >> "$destination"
  dotenv_single_quote "$value" >> "$destination"
  printf '\n' >> "$destination"
}

write_env_line() {
  write_env_line_to "$env_file" "$1" "$2"
}

uri_encode() {
  local raw=$1 char hex encoded='' index
  LC_ALL=C
  for ((index = 0; index < ${#raw}; index++)); do
    char=${raw:index:1}
    case "$char" in
      [a-zA-Z0-9.~_-]) encoded+=$char ;;
      *) printf -v hex '%02X' "'$char"; encoded+="%$hex" ;;
    esac
  done
  printf '%s' "$encoded"
}

create_steady_env_if_absent() {
  if [[ -f "$env_file" ]]; then
    if ((resume == 0)); then
      fail "refusing to overwrite existing $env_file; use -Resume only for a prior interrupted bootstrap."
    fi
    if grep -Eq '^(MONGO_ROOT_(USERNAME|PASSWORD)|MONGO_APP_(USERNAME|PASSWORD))=' "$env_file"; then
      fail 'existing .env stores raw Mongo bootstrap credentials; resolve this manually before resuming.'
    fi
    return 0
  fi

  local temporary jwt_secret data_protection_key mongo_password_encoded
  temporary=$(mktemp "${deploy_path}/.env.XXXXXX")
  chmod 0600 "$temporary"
  chown "$deploy_user:$deploy_user" "$temporary"
  env_file=$temporary
  jwt_secret=$(openssl rand -base64 48 | tr -d '\n')
  data_protection_key=$(openssl rand -base64 32 | tr -d '\n')
  mongo_password_encoded=$(uri_encode "$MONGO_APP_PASSWORD")

  write_env_line 'COMPOSE_PROJECT_NAME' "$PROJECT_NAME"
  write_env_line 'JWT_SECRET' "$jwt_secret"
  write_env_line 'DATA_PROTECTION_KEY' "$data_protection_key"
  write_env_line 'ADMIN_USERNAME' "$admin_username"
  write_env_line 'ADMIN_PASSWORD' "$ADMIN_PASSWORD"
  write_env_line 'TELEGRAM_BOT_TOKEN' "$TELEGRAM_BOT_TOKEN"
  write_env_line 'MONGODB_CONNECTION_STRING' "mongodb://${MONGO_APP_USER}:${mongo_password_encoded}@mongo:27017/${MONGO_DATABASE}?authSource=${MONGO_DATABASE}"
  write_env_line 'GHCR_IMAGE_PREFIX' "ghcr.io/${github_owner}/amnezia-key-service"
  write_env_line 'SEQ_ADMIN_PASSWORD_HASH' ''
  write_env_line 'SEQ_API_KEY' ''
  mv -f -- "$temporary" "$deploy_path/.env"
  env_file="$deploy_path/.env"
  chmod 0600 "$env_file"
  chown "$deploy_user:$deploy_user" "$env_file"
  unset jwt_secret data_protection_key mongo_password_encoded
}

assert_resume_app_password_matches_env() {
  # A partially completed bootstrap has already persisted an application URI.
  # Recreating the fresh Mongo volume with a different password would create a
  # user that cannot authenticate with that URI, so fail before changing Mongo.
  [[ -f "$env_file" ]] || return 0

  local persisted_uri expected_uri encoded_password
  persisted_uri=$(sed -nE "s/^MONGODB_CONNECTION_STRING='([^']*)'$/\1/p" "$env_file")
  [[ -n "$persisted_uri" ]] || fail 'cannot read the persisted MongoDB application URI while resuming.'
  encoded_password=$(uri_encode "$MONGO_APP_PASSWORD")
  expected_uri="mongodb://${MONGO_APP_USER}:${encoded_password}@mongo:27017/${MONGO_DATABASE}?authSource=${MONGO_DATABASE}"
  [[ "$persisted_uri" == "$expected_uri" ]] || fail 'the supplied MongoDB application password does not match the interrupted bootstrap; no database change was made.'
  unset persisted_uri expected_uri encoded_password
}

write_progress() {
  local phase=$1
  local temp
  temp=$(mktemp "${deploy_path}/.bootstrap-progress.XXXXXX")
  chmod 0600 "$temp"
  cat > "$temp" <<EOF
bootstrapVersion=${BOOTSTRAP_VERSION}
phase=${phase}
imageTag=${image_tag}
publicIpv4=${public_ipv4}
proxyMode=nginx
EOF
  mv -f -- "$temp" "$progress_file"
}

read_phase() {
  if [[ -f "$progress_file" ]]; then
    sed -nE 's/^phase=([A-Za-z0-9_-]+)$/\1/p' "$progress_file" | head -n1
  fi
}

run_as_deploy() {
  runuser -u "$deploy_user" -- env "HOME=/home/$deploy_user" "$@"
}

compose_base() {
  docker compose --project-name "$PROJECT_NAME" --env-file "$env_file" \
    -f "$release_dir/docker-compose.yml" \
    -f "$release_dir/docker-compose.mongo-auth.yml" "$@"
}

wait_for_mongo_health() {
  local mongo_id status attempt
  for attempt in {1..45}; do
    mongo_id=$(run_as_deploy "$(command -v docker)" compose --project-name "$PROJECT_NAME" --env-file "$env_file" \
      -f "$release_dir/docker-compose.yml" -f "$release_dir/docker-compose.mongo-auth.yml" ps -q mongo)
    if [[ -n "$mongo_id" ]]; then
      status=$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "$mongo_id")
      [[ "$status" == 'healthy' ]] && return 0
    fi
    sleep 2
  done
  diagnose_mongo_health_failure
  fail 'MongoDB did not become healthy.'
}

diagnose_mongo_health_failure() {
  # Do not inspect container environment or print healthcheck output: both can
  # contain the application URI. MongoDB's own recent startup logs identify
  # init-hook and storage failures without exposing bootstrap passwords.
  local mongo_id state health restart_count
  mongo_id=$(run_as_deploy "$(command -v docker)" compose --project-name "$PROJECT_NAME" --env-file "$env_file" \
    -f "$release_dir/docker-compose.yml" -f "$release_dir/docker-compose.mongo-auth.yml" ps -aq mongo 2>/dev/null || true)
  if [[ -z "$mongo_id" ]]; then
    printf 'bootstrap: MongoDB diagnostics: no container was created.\n' >&2
    return 0
  fi

  state=$(docker inspect --format '{{.State.Status}}' "$mongo_id" 2>/dev/null || printf 'unknown')
  health=$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "$mongo_id" 2>/dev/null || printf 'unknown')
  restart_count=$(docker inspect --format '{{.RestartCount}}' "$mongo_id" 2>/dev/null || printf 'unknown')
  printf 'bootstrap: MongoDB diagnostics: state=%s health=%s restarts=%s. Recent MongoDB logs follow (connection URIs are redacted):\n' \
    "$state" "$health" "$restart_count" >&2
  docker logs --tail 80 "$mongo_id" 2>&1 | \
    sed -E 's#mongodb(\+srv)?://[^[:space:]"'"'"']+#mongodb\1://[redacted]#g' >&2 || true
}

wait_for_mongo_root_auth() {
  # Only used to recover the known fresh-starting phase. The password expands
  # inside the transient Mongo container and never appears in host arguments,
  # diagnostics, or the steady-state environment.
  local mongo_id pid1_command attempt
  for attempt in {1..45}; do
    # Label lookup avoids giving deploy_user access to the root-only fresh env
    # merely to ask Compose for an already-created container ID.
    mongo_id=$(docker ps -aq --filter "label=com.docker.compose.project=${PROJECT_NAME}" \
      --filter 'label=com.docker.compose.service=mongo' | head -n1)
    pid1_command=$(docker exec "$mongo_id" sh -c 'cat /proc/1/comm' 2>/dev/null || true)
    if [[ -n "$mongo_id" && "$pid1_command" == 'mongod' ]] && docker exec "$mongo_id" sh -c \
      'mongosh --quiet --username "$MONGO_INITDB_ROOT_USERNAME" --password "$MONGO_INITDB_ROOT_PASSWORD" --authenticationDatabase admin --eval "quit(db.adminCommand({ ping: 1 }).ok ? 0 : 2)"' \
      >/dev/null 2>&1; then
      printf '%s' "$mongo_id"
      return 0
    fi
    sleep 2
  done
  diagnose_mongo_health_failure
  fail 'MongoDB fresh-start recovery could not authenticate the bootstrap root user; the existing volume was left unchanged.'
}

wait_for_runtime_services() {
  # The static web page alone can be available while the API is blocked by the
  # schema gate or the bot/worker is crashing. These services have no HTTP
  # health endpoint yet, so require a stable first start for each process.
  local service service_id state restart_count attempt all_running
  local -a services=(web api worker bot)
  local -a compose=(
    "$(command -v docker)" compose --project-name "$PROJECT_NAME" --env-file "$env_file"
    -f "$release_dir/docker-compose.yml"
    -f "$release_dir/docker-compose.mongo-auth.yml"
  )

  for attempt in {1..45}; do
    all_running=1
    for service in "${services[@]}"; do
      service_id=$(run_as_deploy "${compose[@]}" ps -q "$service" 2>/dev/null || true)
      if [[ -z "$service_id" ]]; then
        all_running=0
        break
      fi
      state=$(docker inspect --format '{{.State.Status}}' "$service_id" 2>/dev/null || true)
      restart_count=$(docker inspect --format '{{.RestartCount}}' "$service_id" 2>/dev/null || true)
      if [[ "$state" != 'running' || "$restart_count" != '0' ]]; then
        all_running=0
        break
      fi
    done
    ((all_running == 1)) && return 0
    sleep 2
  done
  fail 'one or more runtime containers are not stably running; inspect docker compose logs before continuing.'
}

bootstrap_mongo_if_needed() {
  local phase volume_name recovering_fresh_start=0 mongo_id
  phase=$(read_phase)
  volume_name="${PROJECT_NAME}_mongo_data"

  if [[ "$phase" == 'mongo-steady' || "$phase" == 'applications-started' || "$phase" == 'complete' ]]; then
    wait_for_mongo_health
    return 0
  fi

  if [[ -z "$phase" ]]; then
    if docker volume inspect "$volume_name" >/dev/null 2>&1; then
      fail "existing MongoDB volume $volume_name has no bootstrap marker; refusing to guess its credentials or modify it."
    fi
    write_progress 'mongo-fresh-starting'
  elif ((resume == 0)); then
    fail 'an interrupted bootstrap was found; rerun with -Resume after confirming the same Mongo passwords.'
  elif [[ "$phase" == 'mongo-fresh-starting' ]] && docker volume inspect "$volume_name" >/dev/null 2>&1; then
    # A failed first init can leave a non-empty volume (the official entrypoint
    # creates the root user before it sources application hooks). Recovery is
    # gated by authenticating that known root user; it never removes or
    # recreates the volume.
    recovering_fresh_start=1
  fi

  if ((resume == 1)); then
    assert_resume_app_password_matches_env
  fi

  # The raw credentials exist only in this tmpfs file and the initial Mongo
  # container. Run this one command as root so the 0600 file stays root-owned:
  # deploy_user is in the root-equivalent docker group, but must not gain a
  # separate filesystem read path to these raw values. Do not make the file
  # group- or world-readable. The following steady-state recreation removes
  # those container environment variables again.
  fresh_env=$(mktemp /dev/shm/amnezia-mongo-bootstrap.XXXXXX)
  chmod 0600 "$fresh_env"
  cat "$env_file" > "$fresh_env"
  write_env_line_to "$fresh_env" 'MONGO_ROOT_USERNAME' "$MONGO_ROOT_USER"
  write_env_line_to "$fresh_env" 'MONGO_ROOT_PASSWORD' "$MONGO_ROOT_PASSWORD"
  write_env_line_to "$fresh_env" 'MONGO_APP_USERNAME' "$MONGO_APP_USER"
  write_env_line_to "$fresh_env" 'MONGO_APP_PASSWORD' "$MONGO_APP_PASSWORD"
  write_env_line_to "$fresh_env" 'MONGO_DATABASE_NAME' "$MONGO_DATABASE"

  if ((recovering_fresh_start)); then
    # A previous failed init can leave a stopped container whose environment
    # still contains the old one-time values. Recreate only that container so
    # the root-auth gate below verifies exactly this invocation's credentials;
    # named volumes are never removed by --force-recreate.
    docker compose --project-name "$PROJECT_NAME" --env-file "$fresh_env" \
      -f "$release_dir/docker-compose.yml" \
      -f "$release_dir/docker-compose.mongo-auth.yml" \
      -f "$release_dir/docker-compose.mongo-auth.fresh.yml" up -d --force-recreate mongo
  else
    docker compose --project-name "$PROJECT_NAME" --env-file "$fresh_env" \
      -f "$release_dir/docker-compose.yml" \
      -f "$release_dir/docker-compose.mongo-auth.yml" \
      -f "$release_dir/docker-compose.mongo-auth.fresh.yml" up -d mongo
  fi
  # Compose has read the one-time credentials. Remove the source immediately;
  # cleanup still handles failures and signal-driven interruption before here.
  rm -f -- "$fresh_env"
  fresh_env=''

  if ((recovering_fresh_start)); then
    # Run the repair only once PID 1 is the final mongod rather than the image
    # entrypoint's temporary init server. The script is idempotent and changes
    # only the known application account; a root-auth failure stops without
    # changing database data.
    mongo_id=$(wait_for_mongo_root_auth)
    docker exec "$mongo_id" /docker-entrypoint-initdb.d/01-create-app-user.sh
  fi
  wait_for_mongo_health
  write_progress 'mongo-fresh-created'

  # Recreate the database service without fresh overlay, so neither root nor
  # app bootstrap password remains in docker inspect for the active container.
  run_as_deploy "$(command -v docker)" compose --project-name "$PROJECT_NAME" --env-file "$env_file" \
    -f "$release_dir/docker-compose.yml" \
    -f "$release_dir/docker-compose.mongo-auth.yml" up -d --force-recreate mongo
  wait_for_mongo_health
  write_progress 'mongo-steady'
}

configure_nginx_bootstrap_site() {
  install -d -m 0755 /var/www/certbot
  local candidate=/etc/nginx/sites-available/amnezia-key.bootstrap
  sed "s/PUBLIC_IPV4/${public_ipv4}/g" "$release_dir/deploy/nginx/amnezia.bootstrap-ip-http.conf.example" > "$candidate"
  activate_nginx_candidate "$candidate"
  # The stock Ubuntu site may continue to answer unknown Host headers, but it
  # does not expose the panel. Remove just this known default after our site
  # has passed nginx -t; no recursive deletion is used.
  rm -f /etc/nginx/sites-enabled/default
  systemctl enable --now nginx
  systemctl reload nginx
}

activate_nginx_candidate() {
  local candidate=$1 destination=/etc/nginx/sites-available/amnezia-key enabled=/etc/nginx/sites-enabled/amnezia-key
  local backup previous_link='' had_destination=0 had_link=0
  backup=$(mktemp /etc/nginx/amnezia-key.backup.XXXXXX)
  if [[ -e "$destination" ]]; then
    cp -a -- "$destination" "$backup"
    had_destination=1
  fi
  if [[ -L "$enabled" ]]; then
    previous_link=$(readlink "$enabled")
    had_link=1
  fi

  install -m 0644 "$candidate" "$destination"
  ln -sfn /etc/nginx/sites-available/amnezia-key "$enabled"
  if ! nginx -t; then
    if ((had_destination)); then
      cp -a -- "$backup" "$destination"
    else
      rm -f -- "$destination"
    fi
    if ((had_link)); then
      ln -sfn "$previous_link" "$enabled"
    else
      rm -f -- "$enabled"
    fi
    rm -f -- "$backup"
    fail 'candidate Nginx configuration failed validation; previous site was restored.'
  fi
  rm -f -- "$backup"
}

issue_ip_certificate() {
  # A staging issuance first verifies the public routing without consuming a
  # production rate-limit slot. IP certificates are intentionally short-lived;
  # leave the HTTP-01 location available in the final config for renewal.
  if [[ ! -f /etc/letsencrypt/live/amnezia-ip/fullchain.pem ]]; then
    /snap/bin/certbot certonly --non-interactive --webroot -w /var/www/certbot \
      --ip-address "$public_ipv4" --preferred-profile shortlived --cert-name amnezia-ip-staging --staging \
      --email "$acme_email" --agree-tos --no-eff-email
    /snap/bin/certbot certonly --non-interactive --webroot -w /var/www/certbot \
      --ip-address "$public_ipv4" --preferred-profile shortlived --cert-name amnezia-ip \
      --email "$acme_email" --agree-tos --no-eff-email
  fi

  local candidate=/etc/nginx/sites-available/amnezia-key.tls
  sed "s/PUBLIC_IPV4/${public_ipv4}/g" "$release_dir/deploy/nginx/amnezia.ip.conf.example" > "$candidate"
  activate_nginx_candidate "$candidate"
  systemctl reload nginx

  install -d -m 0755 /etc/letsencrypt/renewal-hooks/deploy
  cat > /etc/letsencrypt/renewal-hooks/deploy/reload-nginx <<'EOF'
#!/bin/sh
systemctl reload nginx
EOF
  chmod 0755 /etc/letsencrypt/renewal-hooks/deploy/reload-nginx
  systemctl enable --now snap.certbot.renew.timer
  /snap/bin/certbot renew --dry-run
}

login_ghcr() {
  if ((public_images == 1)); then
    return 0
  fi
  printf '%s' "$GHCR_PAT" | runuser -u "$deploy_user" -- env "HOME=/home/$deploy_user" \
    docker login ghcr.io --username "$ghcr_username" --password-stdin >/dev/null
  unset GHCR_PAT
}

start_application() {
  local -a compose=(
    docker compose --project-name "$PROJECT_NAME" --env-file "$env_file"
    -f "$release_dir/docker-compose.yml"
    -f "$release_dir/docker-compose.mongo-auth.yml"
    -f "$release_dir/deploy/production/docker-compose.images.yml"
    -f "$release_dir/deploy/nginx/docker-compose.host-nginx.yml"
  )

  run_as_deploy env "IMAGE_TAG=$image_tag" "${compose[@]}" config --quiet
  run_as_deploy env "IMAGE_TAG=$image_tag" "${compose[@]}" pull web api worker bot
  run_as_deploy env "IMAGE_TAG=$image_tag" "${compose[@]}" up -d --no-build --remove-orphans

  local attempt
  for attempt in {1..45}; do
    if curl --fail --silent --show-error --max-time 5 http://127.0.0.1:8081/ -o /dev/null; then
      wait_for_runtime_services
      write_progress 'applications-started'
      return 0
    fi
    sleep 2
  done
  fail 'the web container did not become reachable on loopback.'
}

remove_admin_seed_password_after_owner_exists() {
  # The owner is seeded by worker. Removing this one-time value protects it at
  # rest; never remove it until a matching owner document actually exists.
  local mongo_id owner_count temporary_env attempt
  mongo_id=$(run_as_deploy docker compose --project-name "$PROJECT_NAME" --env-file "$env_file" \
    -f "$release_dir/docker-compose.yml" -f "$release_dir/docker-compose.mongo-auth.yml" ps -q mongo)
  [[ -n "$mongo_id" ]] || fail 'MongoDB container is unavailable while checking owner seed.'
  owner_count=0
  for attempt in {1..30}; do
    owner_count=$(docker exec "$mongo_id" sh -c \
      'mongosh --quiet "$MONGODB_CONNECTION_STRING" --eval "$1"' sh \
      "db.getSiblingDB('${MONGO_DATABASE}').users.countDocuments({role:'owner'})") || owner_count=0
    [[ "$owner_count" =~ ^[1-9][0-9]*$ ]] && break
    sleep 2
  done
  [[ "$owner_count" =~ ^[1-9][0-9]*$ ]] || fail 'worker has not created an owner account; ADMIN_PASSWORD remains in .env for recovery.'

  temporary_env=$(mktemp "${deploy_path}/.env.XXXXXX")
  chmod 0600 "$temporary_env"
  chown "$deploy_user:$deploy_user" "$temporary_env"
  grep -v '^ADMIN_PASSWORD=' "$env_file" > "$temporary_env"
  mv -f -- "$temporary_env" "$env_file"
}

assert_runtime_hardening() {
  # No direct service binding may escape the loopback-only host-Nginx overlay.
  local listening
  listening=$(ss -ltnH '( sport = :8080 or sport = :8081 or sport = :8082 or sport = :27017 or sport = :5341 )' || true)
  if grep -Eq '(^|[[:space:]])(0\.0\.0\.0|\[::\]|::):' <<< "$listening"; then
    fail 'a private service port is listening on a public interface.'
  fi
  curl --fail --silent --show-error --max-time 10 "https://${public_ipv4}/" -o /dev/null
}

mark_complete() {
  local temporary
  temporary=$(mktemp "${deploy_path}/.bootstrap-complete.XXXXXX")
  chmod 0600 "$temporary"
  cat > "$temporary" <<EOF
bootstrapVersion=${BOOTSTRAP_VERSION}
completedAt=$(date -u +%FT%TZ)
imageTag=${image_tag}
publicIpv4=${public_ipv4}
proxyMode=nginx
EOF
  mv -f -- "$temporary" "$complete_marker"
  rm -f -- "$progress_file"
}

main() {
  require_root
  validate_arguments
  assert_ubuntu
  release_dir="$deploy_path/release"
  env_file="$deploy_path/.env"
  progress_file="$deploy_path/.bootstrap-progress"
  complete_marker="$deploy_path/.bootstrap-complete"

  # Never treat an arbitrary old deployment as a fresh machine. A finished
  # marker is harmless to rerun only with explicit -Resume, which becomes a
  # health check and does not rewrite .env, keys, volumes, or certificates.
  if [[ -e "$deploy_path" && ! -f "$deploy_path/.bootstrap-complete" && ! -f "$deploy_path/.bootstrap-progress" && $resume -eq 0 ]]; then
    fail "deployment path already exists without a bootstrap marker: $deploy_path"
  fi
  if [[ -f "$deploy_path/.bootstrap-complete" && $resume -eq 0 ]]; then
    fail 'bootstrap is already complete; use -Resume only to perform health checks.'
  fi

  if [[ -f "$complete_marker" ]]; then
    [[ -f "$env_file" ]] || fail 'completed bootstrap has no .env file; refusing to repair it during a health-only run.'
    [[ -f "$release_dir/docker-compose.yml" && -f "$release_dir/docker-compose.mongo-auth.yml" ]] || \
      fail 'completed bootstrap release descriptors are missing; refusing to replace them during a health-only run.'
    wait_for_mongo_health
    wait_for_runtime_services
    assert_runtime_hardening
    printf 'bootstrap: existing installation is healthy; no secrets or persistent files were changed.\n'
    return 0
  fi

  read_secret_records
  install_os_packages
  verify_release_bundle
  install_docker
  install_certbot
  ensure_deploy_account
  configure_firewall
  install_release_files
  create_steady_env_if_absent

  bootstrap_mongo_if_needed
  configure_nginx_bootstrap_site
  issue_ip_certificate
  login_ghcr
  start_application
  remove_admin_seed_password_after_owner_exists
  assert_runtime_hardening
  mark_complete
  printf 'bootstrap: production stack is ready for https://%s/\n' "$public_ipv4"
}

main "$@"
