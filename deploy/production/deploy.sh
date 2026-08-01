#!/usr/bin/env bash
# Executed on the VPS by .github/workflows/deploy-production.yml.
# Application secrets are deliberately never accepted as arguments and must
# already exist in $DEPLOY_PATH/.env with mode 0600.
set -Eeuo pipefail
IFS=$'\n\t'

deploy_path=${1:?missing deploy path}
image_tag=${2:?missing image tag}
incoming_path=${3:?missing incoming release path}
proxy_mode=${4:?missing proxy mode}

case "$deploy_path" in
  /opt/*) ;;
  *) echo 'Deployment directory must be below /opt.' >&2; exit 64 ;;
esac

if [[ ! "$image_tag" =~ ^sha-[0-9a-f]{40}$ ]]; then
  echo 'Image tag must be an immutable sha-<40 lowercase hex> tag.' >&2
  exit 64
fi

case "$incoming_path" in
  "$deploy_path"/incoming/"$image_tag") ;;
  *) echo 'Incoming release path does not match the deployment directory and tag.' >&2; exit 64 ;;
esac

case "$proxy_mode" in
  nginx) proxy_overlay=deploy/nginx/docker-compose.host-nginx.yml ;;
  traefik) proxy_overlay=deploy/traefik/docker-compose.traefik.yml ;;
  *) echo 'Proxy mode must be nginx or traefik.' >&2; exit 64 ;;
esac

env_file="$deploy_path/.env"
if [[ ! -f "$env_file" ]]; then
  echo "Missing $env_file. Provision the VPS and its secrets before deploying." >&2
  exit 66
fi

for file in docker-compose.yml docker-compose.mongo-auth.yml; do
  [[ -f "$incoming_path/$file" ]] || { echo "Missing $file in release." >&2; exit 66; }
done
[[ -f "$incoming_path/deploy/docker-compose.images.yml" ]] || { echo 'Missing image override in release.' >&2; exit 66; }
[[ -f "$incoming_path/$proxy_overlay" ]] || { echo "Missing $proxy_overlay in release." >&2; exit 66; }

install -d -m 0750 "$deploy_path/deploy/nginx" "$deploy_path/deploy/traefik"
install -m 0644 "$incoming_path/docker-compose.yml" "$deploy_path/docker-compose.yml"
install -m 0644 "$incoming_path/docker-compose.mongo-auth.yml" "$deploy_path/docker-compose.mongo-auth.yml"
install -m 0644 "$incoming_path/deploy/docker-compose.images.yml" "$deploy_path/deploy/docker-compose.images.yml"
install -m 0644 "$incoming_path/deploy/nginx/docker-compose.host-nginx.yml" "$deploy_path/deploy/nginx/docker-compose.host-nginx.yml"
install -m 0644 "$incoming_path/deploy/traefik/docker-compose.traefik.yml" "$deploy_path/deploy/traefik/docker-compose.traefik.yml"

cd "$deploy_path"
export IMAGE_TAG="$image_tag"
compose=(docker compose --env-file "$env_file" -f docker-compose.yml -f docker-compose.mongo-auth.yml -f deploy/docker-compose.images.yml -f "$proxy_overlay")

"${compose[@]}" config --quiet
services=(web api worker bot)
if [[ "$proxy_mode" == traefik ]]; then
  services+=(traefik)
fi
"${compose[@]}" pull "${services[@]}"
"${compose[@]}" up -d --no-build --remove-orphans
"${compose[@]}" ps

# Docker considers a process started before an application is actually ready.
# The web container is the externally exposed entry point, so require it to
# serve its static page before reporting a successful deployment.
for attempt in {1..30}; do
  if "${compose[@]}" exec -T web wget -q --spider http://127.0.0.1/; then
    echo "Deployment of $image_tag is serving traffic."
    exit 0
  fi
  sleep 2
done

echo 'Web container did not become ready; inspect docker compose logs on the VPS.' >&2
"${compose[@]}" ps >&2 || true
exit 1
