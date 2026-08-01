# Production-развёртывание AmneziaKeyService

Эта инструкция разворачивает панель на отдельном VPS с Ubuntu 24.04 LTS. CI/CD выполняется в **GitHub Actions**: GitHub-hosted runner получает исходный код, собирает четыре неизменяемых образа в GHCR, а затем по SSH передаёт на VPS только compose-дескрипторы и запускает выбранный тег образов. Runtime-секреты остаются только на VPS, а исходный код на VPS при обычном deploy не копируется.

Рекомендуемый вариант — **Nginx на хосте**. Traefik ниже является полноценной альтернативой, если хочется держать TLS и обратный прокси в Docker. Нельзя включать оба варианта одновременно: оба занимают порты 80 и 443.

> Для нового пустого VPS с Ubuntu 24.04 и публичным IPv4 рекомендуемый путь —
> [Windows bootstrap](deploy/production/README.md). Он проверяет SSH
> fingerprint, устанавливает пакеты и Docker, настраивает MongoDB, Nginx,
> IP-сертификат и первый запуск. После него вручную добавьте только
> SSH-параметры в GitHub Environment `production`; runtime-секреты приложения
> в GitHub не передаются. Этот раздел ниже сохраняется как подробная
> справка для доменного варианта, диагностики, backup и эксплуатации.

## 1. Целевая схема и сетевые границы

```
Интернет ── 443 ──► Nginx на VPS ──► web :8081 (loopback)
                                   └──► api :8080 (loopback, /api/*)

GitHub Actions ── SSH ──► deploy@VPS ──► Docker Compose ──► GHCR
                                                     ├── worker
                                                     ├── bot ──► Telegram (исходящий HTTPS)
                                                     ├── mongo (только сеть Compose)
                                                     └── seq   (127.0.0.1:8082)
```

| Порт | Кто слушает | Доступ |
| --- | --- | --- |
| `22/tcp` | SSH | Только администратор и GitHub Actions; дополнительно ограничьте cloud firewall по IP, если это возможно. |
| `80/tcp` | Nginx или Traefik | Редирект на HTTPS и Let's Encrypt HTTP-01. Во временном IP-first bootstrap до выпуска сертификата Nginx отдаёт только HTTP-01, на всё остальное отвечает `404`. |
| `443/tcp` | Nginx или Traefik | Единственный публичный вход в панель и `/api/*`. |
| `8080/tcp` | API | Только `127.0.0.1` в варианте Nginx; не открывать наружу. |
| `8081/tcp` | Web | Только `127.0.0.1` в варианте Nginx; не открывать наружу. |
| `8082/tcp` | Seq | Только `127.0.0.1`, доступ через SSH-туннель. |
| `27017`, `5341` | MongoDB, Seq ingestion | Только внутренняя сеть Docker, host-порты отсутствуют. |

Порты AmneziaWG принадлежат управляемым VPN-узлам, а не VPS панели. С панели к ним нужен исходящий SSH; от них к панели входящие соединения не требуются.

## 2. Предварительные условия

- Для публикации с доменом DNS-запись `A` (и, при наличии IPv6, `AAAA`) для `panel.example.com` указывает на VPS до выпуска сертификата. Для временного **IP-first** домен не нужен: достаточно публичного IPv4 VPS, достижимого по `80/tcp` и `443/tcp`. IP-first конфигурация ниже намеренно не обслуживает IPv6.
- VPS: Ubuntu 24.04 LTS, не менее 2 vCPU, 4 GB RAM, 40 GB SSD. Для небольшого стенда допустимы 2 GB RAM и swap, но MongoDB, Seq и сбор логов будут тесниться.
- Доступ root или пользователь с `sudo` на VPS.
- Репозиторий на GitHub и основная ветка `main`.
- Для закрытого GHCR-пакета — classic PAT GitHub с областью `read:packages` **только на VPS**. Это не секрет GitHub Actions.

Сначала обновите ОС и поставьте базовые пакеты:

```bash
sudo apt-get update
sudo apt-get upgrade -y
sudo apt-get install -y ca-certificates curl gnupg jq git ufw fail2ban unattended-upgrades snapd
```

Установите Docker из [официального репозитория Docker](https://docs.docker.com/engine/install/ubuntu/), а не из старого пакета `docker.io` Ubuntu:

```bash
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg

echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo \"$VERSION_CODENAME\") stable" \
  | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
sudo systemctl enable --now docker
docker --version
docker compose version
```

В проекте применяются compose-теги `!override`; требуется Docker Compose **v2.24.4 или новее**. Проверяйте это до первого запуска.

## 3. Отдельный пользователь развёртывания и SSH

Создайте отдельного пользователя. Участник группы `docker` фактически имеет root-эквивалентные права, поэтому ключ этого пользователя, GitHub Environment и доступ к репозиторию защищайте как root-доступ.

```bash
sudo adduser --disabled-password --gecos "" deploy
sudo usermod -aG docker deploy
sudo install -d -m 0755 -o root -g root /opt
sudo install -d -m 0700 -o deploy -g deploy /home/deploy/.ssh
sudoedit /home/deploy/.ssh/authorized_keys
sudo chown deploy:deploy /home/deploy/.ssh/authorized_keys
sudo chmod 600 /home/deploy/.ssh/authorized_keys
```

Создайте отдельную пару ED25519 для GitHub Actions на безопасной администраторской машине. Не используйте личный SSH-ключ:

```bash
ssh-keygen -t ed25519 -a 64 -f ./amnezia-production-deploy -C "github-actions-amnezia-production"
```

Содержимое `amnezia-production-deploy.pub` добавьте в `authorized_keys` пользователя `deploy`. Включите ключевой вход и запретите root/пароли только после того, как в отдельном терминале проверите вход новым ключом:

```text
# /etc/ssh/sshd_config.d/10-amnezia-production.conf
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
AllowUsers <ваш_администратор> deploy
```

```bash
sudo sshd -t
sudo systemctl reload ssh
ssh -i ./amnezia-production-deploy deploy@<VPS_IPV4_OR_DNS> 'id && docker version --format "{{.Server.Version}}"'
```

Не меняйте SSH-порт в рамках первого развёртывания. Если позже меняете его, сначала откройте новый порт в firewall и cloud firewall, проверьте новую сессию, и только затем закрывайте старый.

## 4. Firewall, DNS и защита хоста

Сначала в панели провайдера VPS разрешите `22`, `80`, `443`; затем настройте UFW:

```bash
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 22/tcp
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw enable
sudo ufw status verbose
sudo systemctl enable --now fail2ban
```

Docker публикует порты через собственные iptables-правила и часть таких правил может обойти обычные правила UFW. Поэтому безопасность здесь не строится на одном UFW: production-overlays вообще не публикуют MongoDB/Seq, а `8080` и `8081` либо привязаны к loopback (Nginx), либо отключены (Traefik). После запуска всегда проверьте:

```bash
sudo ss -lntp
docker ps --format 'table {{.Names}}\t{{.Ports}}'
```

На публичном интерфейсе должны оставаться только SSH, 80 и 443. Не публикуйте MongoDB, Seq, API или панель напрямую «на время диагностики».

## 5. GitHub: CI, GHCR и защищённый production Environment

В репозитории уже подготовлены workflow-файлы:

- `.github/workflows/ci.yml` — backend, Mongo integration, frontend и контейнерные проверки;
- `.github/workflows/publish-ghcr.yml` — публикация `api`, `worker`, `bot`, `web` в GHCR с неизменяемым тегом `sha-<commit>`;
- `.github/workflows/deploy-production.yml` — одобренное развёртывание и ручной rollback по SHA.

Поток выпуска: merge/push в `main` → CI → `Publish container images` → GitHub Environment `production` ждёт approval → VPS скачивает ровно `sha-<commit>` и выполняет `docker compose up --no-build`. Публикация не передаёт runtime-секреты в GitHub.

В **Settings → Environments → New environment** создайте `production`, добавьте required reviewers и при необходимости ограничьте, какие ветки могут деплоить. Не ставьте приложения и пароли из `.env` в GitHub Secrets.

Секреты Environment `production`:

| Имя | Значение |
| --- | --- |
| `PRODUCTION_SSH_HOST` | `panel.example.com` или публичный IPv4 VPS; для IP-first используйте именно IPv4. |
| `PRODUCTION_SSH_USER` | `deploy`. |
| `PRODUCTION_SSH_PRIVATE_KEY` | содержимое приватного `amnezia-production-deploy` без изменений. |
| `PRODUCTION_SSH_KNOWN_HOSTS` | проверенная строка `known_hosts` VPS. |

Переменные Environment `production`:

| Имя | Значение |
| --- | --- |
| `PRODUCTION_DEPLOY_PATH` | `/opt/amnezia-key-service` |
| `PRODUCTION_SSH_PORT` | `22` |
| `PRODUCTION_PROXY_MODE` | `nginx` (рекомендуется) или `traefik`; ровно одно значение. |

Получить строку known-hosts можно так, но отпечаток нужно сверить с консолью провайдера или уже доверенным каналом перед сохранением:

```bash
ssh-keyscan -p 22 -H panel.example.com
```

Workflow публикации использует автоматически выданный `GITHUB_TOKEN` с `packages: write`; отдельный токен для публикации не нужен. После первой публикации проверьте в **Packages**: пакет должен принадлежать нужному owner и иметь доступ репозитория. Для private package на VPS создайте classic PAT с `read:packages`, войдите под пользователем `deploy`, затем удалите токен из терминала/history:

```bash
sudo -iu deploy
read -rsp 'GHCR read:packages token: ' GHCR_TOKEN; echo
printf '%s' "$GHCR_TOKEN" | docker login ghcr.io -u <github-owner> --password-stdin
unset GHCR_TOKEN
```

При публичных images этот login не нужен, но закрытый registry предпочтительнее для панели управления VPN. Документация GitHub: [публикация Docker images](https://docs.github.com/en/actions/tutorials/publish-packages/publish-docker-images), [Environments и approvals](https://docs.github.com/en/actions/reference/workflows-and-actions/deployments-and-environments), [права GitHub Packages](https://docs.github.com/en/packages/working-with-a-github-packages-registry).

## 6. Каталог на VPS и runtime `.env`

Для первого bootstrap можно один раз клонировать репозиторий в каталог развёртывания. В дальнейшем GitHub Actions передаёт лишь compose-файлы и не требует `git pull` или сборки на VPS. Bootstrap выполняйте из того же commit, что и GHCR-тег: после clone проверьте `git rev-parse HEAD`, а в `IMAGE_TAG` используйте `sha-<этот-же-SHA>`.

```bash
sudo -iu deploy git clone --depth 1 https://github.com/<github-owner>/<repository>.git /opt/amnezia-key-service
cd /opt/amnezia-key-service
```

Для private repository используйте read-only GitHub deploy key либо скопируйте только перечисленные ниже файлы защищённым `scp`. Не передавайте runtime `.env` через Git, Actions, мессенджер или issue.

Создайте файл, доступный только пользователю `deploy`:

```bash
sudo -iu deploy
cd /opt/amnezia-key-service
umask 077
cp .env.example .env
chmod 600 .env
```

Секреты генерируйте на VPS или в менеджере секретов. Команды ниже показывают значения, поэтому не сохраняйте вывод в публичной истории/скриншотах:

```bash
openssl rand -base64 48  # JWT_SECRET
openssl rand -base64 32  # DATA_PROTECTION_KEY
openssl rand -base64 32  # ADMIN_PASSWORD
openssl rand -hex 32     # MONGO_ROOT_PASSWORD или MONGO_APP_PASSWORD
docker run --rm -it datalust/seq:2024 config hash  # SEQ_ADMIN_PASSWORD_HASH
```

Заполните `.env`. Для сгенерированных base64/hex-значений оба варианта корректны: `JWT_SECRET=значение` и `JWT_SECRET="значение"`; в примере ниже используются двойные кавычки. Однако Compose выполняет `$VARIABLE`-интерполяцию в некавыченных и двойных кавычках. Поэтому литеральное значение с `$`, в частности Seq password hash, заключайте в **одинарные** кавычки. Не используйте в значениях переводы строк. Сгенерированный hex-пароль MongoDB не требует percent-encoding; еси задаёте иной пароль, percent-encode его для URI.

```dotenv
JWT_SECRET="ВСТАВЬТЕ_СГЕНЕРИРОВАННЫЙ_JWT"
DATA_PROTECTION_KEY="ВСТАВЬТЕ_СГЕНЕРИРОВАННЫЙ_КЛЮЧ_32_БАЙТА"
ADMIN_USERNAME="admin"
ADMIN_PASSWORD="ВСТАВЬТЕ_СГЕНЕРИРОВАННЫЙ_ПАРОЛЬ"
TELEGRAM_BOT_TOKEN="123456:ВСТАВЬТЕ_ТОКЕН_BOTFATHER"

# Тег задаёт Actions/deploy.sh; эту строку в .env не добавляйте.
GHCR_IMAGE_PREFIX="ghcr.io/<github-owner-в-нижнем-регистре>/amnezia-key-service"

# Только для первого запуска пустого mongo_data.
MONGO_ROOT_USERNAME="amnezia_root"
MONGO_ROOT_PASSWORD="64_СИМВОЛА_HEX"
MONGO_APP_USERNAME="amnezia_app"
MONGO_APP_PASSWORD="64_СИМВОЛА_HEX"
MONGO_DATABASE_NAME="amnezia_vpn"
MONGODB_CONNECTION_STRING="mongodb://amnezia_app:64_СИМВОЛА_HEX@mongo:27017/amnezia_vpn?authSource=amnezia_vpn"

SEQ_ADMIN_PASSWORD_HASH='ВЫВОД_КОМАНДЫ_seq_config_hash_СО_ЗНАКАМИ_$'
SEQ_API_KEY=""
```

`DATA_PROTECTION_KEY` нельзя менять или терять после появления SSH-учётных данных и ключей в MongoDB: старые зашифрованные данные перестанут читаться. Базу секретов и файл `.env` храните раздельно в защищённом password manager / vault.

## 7. Первый запуск MongoDB с authentication

Ниже предполагается **новый пустой volume**. Это рекомендуемый production-путь. `docker-compose.mongo-auth.fresh.yml` запускает init-hook только при пустом `/data/db`; не добавляйте его к существующему volume — он не создаст пользователей задним числом и может создать ложное ощущение защиты.

Сначала дождитесь успешного `Publish container images` для нужного коммита. Подставьте его immutable tag в текущую shell-сессию:

```bash
cd /opt/amnezia-key-service
export IMAGE_TAG="sha-<40-символьный-SHA-коммита>"

compose=(docker compose --env-file .env \
  -f docker-compose.yml \
  -f docker-compose.mongo-auth.yml \
  -f docker-compose.mongo-auth.fresh.yml \
  -f deploy/production/docker-compose.images.yml \
  -f deploy/nginx/docker-compose.host-nginx.yml)

"${compose[@]}" config --quiet
"${compose[@]}" pull web api worker bot
"${compose[@]}" up -d --no-build
"${compose[@]}" ps
"${compose[@]}" logs --tail=100 mongo worker api bot
```

Для Traefik замените последнюю строку массива на `-f deploy/traefik/docker-compose.traefik.yml`, а `PANEL_DOMAIN` и `ACME_EMAIL` добавьте в `.env`. Не добавляйте оба proxy-overlays.

После успешного bootstrap сразу перейдите в steady-state: удалите из `.env` или очистите `MONGO_ROOT_USERNAME`, `MONGO_ROOT_PASSWORD`, `MONGO_APP_USERNAME`, `MONGO_APP_PASSWORD`; остаётся только `MONGODB_CONNECTION_STRING`. Затем пересоздайте сервисы без fresh-overlay:

```bash
compose=(docker compose --env-file .env \
  -f docker-compose.yml \
  -f docker-compose.mongo-auth.yml \
  -f deploy/production/docker-compose.images.yml \
  -f deploy/nginx/docker-compose.host-nginx.yml)
"${compose[@]}" config --quiet
"${compose[@]}" up -d --no-build
```

Убедитесь, что MongoDB `healthy`, worker применил миграции, а API не сообщает `MongoSchemaGate`. Для уже существующей незащищённой базы сначала остановите `api worker bot`, сделайте и проверьте backup, интерактивно создайте root и application-user с `readWrite` только на `amnezia_vpn`, проверьте application URI, и лишь затем включайте `docker-compose.mongo-auth.yml`. Не удаляйте existing `mongo_data` и не используйте fresh-overlay в этом сценарии. Откат с `--auth` без заранее проверенного backup — не процедура миграции.

## 8. TLS и reverse proxy

### 8.1 Временный IP-first: Nginx с публичным IPv4, без домена

Этот режим нужен только как переходный: панель доступна по
`https://<PUBLIC_IPV4>/`, но сертификат для IP-адреса короткоживущий — до
**160 часов** (примерно 6 дней 16 часов). Он требует регулярного успешного
renewal. По умолчанию не используйте ни plain HTTP, ни self-signed
сертификат: HTTP легко перехватывается, а self-signed заставляет обходить
защиту браузера и усложняет проверку, что вы подключились к своему VPS.

IP-first поддерживается только host Nginx. Не выбирайте Traefik до появления
домена. В GitHub Environment `production` укажите:

| Параметр | Значение для IP-first |
| --- | --- |
| secret `PRODUCTION_SSH_HOST` | Публичный IPv4 VPS, например `203.0.113.10` |
| variable `PRODUCTION_PROXY_MODE` | `nginx` |

`PRODUCTION_SSH_HOST` нужен только workflow для SSH; это не меняет URL панели.
В VPS `.env` не нужны `PANEL_DOMAIN` и `ACME_EMAIL` — они относятся к Traefik.
Проверьте, что cloud firewall и UFW уже разрешают `80/tcp` и `443/tcp`, а
`8080`, `8081`, `8082` не видны снаружи.

Установите Nginx, Certbot и webroot (если это ещё не сделано):

```bash
sudo apt-get install -y nginx
sudo snap install core
sudo snap refresh core
sudo snap install --classic certbot
sudo ln -sf /snap/bin/certbot /usr/bin/certbot
sudo install -d -m 0755 /var/www/certbot
certbot --version     # требуется Certbot 5.4.0 или новее
```

Если версия ниже `5.4.0`, сначала обновите snap (`sudo snap refresh certbot`) и
проверьте версию снова. Подставьте фактический IPv4 вместо `PUBLIC_IPV4` только
в файлах Nginx и командах ниже. Не добавляйте этот IP в `server_name` обычного
доменного конфига.

Сначала включите HTTP bootstrap. В нём открыт **только**
`/.well-known/acme-challenge/`; все остальные HTTP-запросы получают `404` и не
попадают в панель:

```bash
sudo cp deploy/nginx/amnezia.bootstrap-ip-http.conf.example /etc/nginx/sites-available/amnezia-key
sudoedit /etc/nginx/sites-available/amnezia-key   # заменить PUBLIC_IPV4
sudo rm -f /etc/nginx/sites-enabled/default
sudo ln -s /etc/nginx/sites-available/amnezia-key /etc/nginx/sites-enabled/amnezia-key
sudo nginx -t && sudo systemctl reload nginx

curl -sS -o /dev/null -w '%{http_code}\n' http://PUBLIC_IPV4/  # должно быть 404
```

Сначала проверьте выпуск через staging CA. Для staging задано отдельное имя
lineage: его нельзя использовать для production, иначе renewal может остаться
привязанным к тестовому CA.

```bash
sudo certbot certonly --staging --preferred-profile shortlived \
  --webroot -w /var/www/certbot \
  --ip-address PUBLIC_IPV4 \
  --cert-name amnezia-ip-staging \
  -m ops@example.com --agree-tos --no-eff-email

sudo certbot certificates --cert-name amnezia-ip-staging
sudo certbot delete --cert-name amnezia-ip-staging
```

Только после успешного staging-выпуска получите production-сертификат. Имя
`amnezia-ip` фиксировано: финальный Nginx всегда читает
`/etc/letsencrypt/live/amnezia-ip/`.

```bash
sudo certbot certonly --preferred-profile shortlived \
  --webroot -w /var/www/certbot \
  --ip-address PUBLIC_IPV4 \
  --cert-name amnezia-ip \
  -m ops@example.com --agree-tos --no-eff-email

sudo certbot certificates --cert-name amnezia-ip
```

Замените bootstrap финальным конфигом. После этого HTTP перенаправляется на
HTTPS, но Nginx по-прежнему никогда не проксирует панель или API по HTTP:

```bash
sudo cp deploy/nginx/amnezia.ip.conf.example /etc/nginx/sites-available/amnezia-key
sudoedit /etc/nginx/sites-available/amnezia-key   # заменить PUBLIC_IPV4
sudo nginx -t && sudo systemctl reload nginx
```

Включите renewal и deploy hook. Для short-lived IP-сертификата контролируйте
таймер ежедневно: запас в несколько дней, а не десятков дней, является нормой.

```bash
sudo install -d -m 0755 /etc/letsencrypt/renewal-hooks/deploy
printf '%s\n' '#!/bin/sh' 'systemctl reload nginx' \
  | sudo tee /etc/letsencrypt/renewal-hooks/deploy/reload-nginx >/dev/null
sudo chmod 0755 /etc/letsencrypt/renewal-hooks/deploy/reload-nginx
sudo systemctl enable --now snap.certbot.renew.timer
sudo certbot renew --dry-run
systemctl list-timers snap.certbot.renew.timer
sudo certbot certificates --cert-name amnezia-ip
```

В мониторинг добавьте проверку даты окончания сертификата минимум раз в сутки;
также просматривайте `sudo journalctl -u snap.certbot.renew.service --since '24 hours' --no-pager`. При сбое renewal исправляйте его немедленно, до истечения примерно 6 дней.

Smoke test после deploy:

```bash
curl --fail --show-error --silent https://PUBLIC_IPV4/ -o /dev/null
test "$(curl -sS -o /dev/null -w '%{http_code}' http://PUBLIC_IPV4/)" = 301
openssl s_client -connect PUBLIC_IPV4:443 </dev/null 2>/dev/null \
  | openssl x509 -noout -enddate -ext subjectAltName
sudo ss -lntp
```

Последняя команда не должна показывать на внешнем интерфейсе `8080`, `8081`,
`8082`, `27017` или `5341`. В браузере открывайте только
`https://PUBLIC_IPV4/`; предупреждения о сертификате быть не должно.

### Переход с IP-first на домен

Когда появится домен, создайте A/AAAA-записи, дождитесь распространения DNS и
выпустите обычный доменный сертификат по разделу 8.2. Замените IP-конфиг на
доменный только после успешного выпуска и проверки `https://panel.example.com/`.
`PRODUCTION_SSH_HOST` можно оставить IPv4 (это только SSH) или заменить на DNS.
После переключения Nginx и проверки нового TLS удалите уже ненужную короткую
IP-lineage: `sudo certbot delete --cert-name amnezia-ip`. Не переключайтесь на
Traefik одновременно с host Nginx: сначала остановите и отключите старый
listener.

### 8.2 Nginx с доменом

Файлы для Nginx находятся в `deploy/nginx/`:

- `docker-compose.host-nginx.yml` — web/API привязаны только к `127.0.0.1`;
- `amnezia.bootstrap-http.conf.example` — временный HTTP-сайт для первого сертификата;
- `amnezia.conf.example` — финальный TLS-сайт с `/api/jobs/*` без буферизации.

Установите Nginx и Certbot:

```bash
sudo apt-get install -y nginx
sudo snap install core
sudo snap refresh core
sudo snap install --classic certbot
sudo ln -sf /snap/bin/certbot /usr/bin/certbot
sudo install -d -m 0755 /var/www/certbot
```

Скопируйте bootstrap-конфиг, замените `panel.example.com` на фактический домен, отключите стандартный site и проверьте Nginx:

```bash
sudo cp deploy/nginx/amnezia.bootstrap-http.conf.example /etc/nginx/sites-available/amnezia-key
sudoedit /etc/nginx/sites-available/amnezia-key
sudo rm -f /etc/nginx/sites-enabled/default
sudo ln -s /etc/nginx/sites-available/amnezia-key /etc/nginx/sites-enabled/amnezia-key
sudo nginx -t && sudo systemctl reload nginx

sudo certbot certonly --webroot -w /var/www/certbot \
  -d panel.example.com -m ops@example.com --agree-tos --no-eff-email
```

Установите финальный конфиг, снова замените домен и перезагрузите:

```bash
sudo cp deploy/nginx/amnezia.conf.example /etc/nginx/sites-available/amnezia-key
sudoedit /etc/nginx/sites-available/amnezia-key
sudo nginx -t && sudo systemctl reload nginx
sudo systemctl enable --now snap.certbot.renew.timer
sudo certbot renew --dry-run
```

Конфиг уже добавляет HSTS без `includeSubDomains`; добавляйте этот флаг только когда все нынешние и будущие поддомены гарантированно работают по HTTPS. Nginx — единственный публичный прокси; API должен оставаться привязанным к loopback. Подробнее: [Certbot](https://certbot.eff.org/instructions?ws=nginx&os=snap).

## 9. Альтернатива: Traefik в Docker

Не ставьте host Nginx и не запускайте Nginx-overlay. Добавьте в `.env`:

```dotenv
PANEL_DOMAIN="panel.example.com"
ACME_EMAIL="ops@example.com"
```

Запустите тот же production compose с `deploy/traefik/docker-compose.traefik.yml`. Traefik сам занимает 80/443, принудительно перенаправляет HTTP в HTTPS и хранит ACME certificates в Docker volume. Dashboard отключён, а к Docker API подключается только read-only socket mount. Это всё равно чувствительная привилегия Docker: не добавляйте на этот VPS недоверенные контейнеры и при росте инфраструктуры вынесите доступ к socket в Docker socket proxy.

Проверка сертификата и роутеров:

```bash
docker compose --env-file .env \
  -f docker-compose.yml \
  -f docker-compose.mongo-auth.yml \
  -f deploy/production/docker-compose.images.yml \
  -f deploy/traefik/docker-compose.traefik.yml ps

curl -fsSI https://panel.example.com/
```

## 10. Обычный deploy, rollback и миграции

После первого bootstrap ручной `docker compose build` на VPS не нужен. При каждом успешном publish GitHub Actions загружает base-, Mongo auth-, image- и оба proxy-overlays вместе с `deploy.sh`. Скрипт проверяет `PRODUCTION_PROXY_MODE`, включает ровно один proxy-overlay и выполняет `pull`, `config --quiet` и `up -d --no-build`.

Проверяйте завершившийся deployment в **Actions → Deploy production**, затем:

```bash
sudo -iu deploy
cd /opt/amnezia-key-service
docker compose --env-file .env \
  -f docker-compose.yml \
  -f docker-compose.mongo-auth.yml \
  -f deploy/production/docker-compose.images.yml \
  -f deploy/nginx/docker-compose.host-nginx.yml ps
curl -fsSI https://panel.example.com/
```

Для отката откройте **Actions → Deploy production → Run workflow**, введите прежний существующий `sha-<40-символьный commit SHA>` в `image_tag` и тот же commit SHA в `source_ref`, затем пройдите approval. Workflow специально сверяет эти два значения до SSH-подключения. Не используйте `latest`: он изменяемый. Сначала сделайте backup, если новый worker мог применить миграцию. Откат контейнеров не всегда откатывает схему MongoDB; для несовместимой миграции нужны протестированные backup и restore procedure.

## 11. Backup, восстановление и наблюдаемость

До обновлений с миграциями и минимум ежедневно снимайте dump MongoDB. При standalone MongoDB для консистентного приложения остановите writers на время backup:

```bash
sudo -iu deploy
cd /opt/amnezia-key-service
backup_dir="$HOME/backups/mongo-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$backup_dir"

api_id=$(docker compose --env-file .env -f docker-compose.yml -f docker-compose.mongo-auth.yml ps -q api)
worker_id=$(docker compose --env-file .env -f docker-compose.yml -f docker-compose.mongo-auth.yml ps -q worker)
bot_id=$(docker compose --env-file .env -f docker-compose.yml -f docker-compose.mongo-auth.yml ps -q bot)
test -n "$api_id" && test -n "$worker_id" && test -n "$bot_id"
docker compose --env-file .env -f docker-compose.yml -f docker-compose.mongo-auth.yml stop api worker bot
mongo_id=$(docker compose --env-file .env -f docker-compose.yml -f docker-compose.mongo-auth.yml ps -q mongo)
docker compose --env-file .env -f docker-compose.yml -f docker-compose.mongo-auth.yml exec -T mongo \
  sh -c 'mongodump --uri="$MONGODB_CONNECTION_STRING" --archive=/tmp/mongo.archive.gz --gzip'
docker cp "$mongo_id:/tmp/mongo.archive.gz" "$backup_dir/mongo.archive.gz"
sha256sum "$backup_dir/mongo.archive.gz" > "$backup_dir/mongo.archive.gz.sha256"
test -s "$backup_dir/mongo.archive.gz"
docker start "$api_id" "$worker_id" "$bot_id"
unset api_id worker_id bot_id mongo_id
```

Не оставляйте единственный backup на том же VPS. Зашифруйте и передавайте копию в отдельное хранилище с версионированием. Периодически проверяйте восстановление на отдельном тестовом VPS/volume: `mongorestore --drop --archive=... --gzip`. Restore в production без отдельной change procedure перезаписывает данные.

`seq_data` содержит эксплуатационные логи. Его также нужно сохранять согласно retention-политике, но не путайте логи с backup MongoDB. Ограничьте Docker-логи ротацией на уровне Docker daemon и следите за местом: `docker system df`, `df -h`, `docker compose logs --since=1h`.

Seq намеренно не публикуется. Открывайте его так:

```bash
ssh -N -L 8082:127.0.0.1:8082 deploy@panel.example.com
```

После этого UI доступен только на `http://localhost:8082`. Задайте пароль до работы с UI; затем создайте Seq API key, внесите его в `SEQ_API_KEY` в `.env` и повторите deploy текущего SHA, чтобы сервисы подхватили его.

Базовая диагностика:

```bash
cd /opt/amnezia-key-service
docker compose logs --tail=200 worker api bot
docker compose ps
docker inspect --format '{{.State.Health.Status}}' $(docker compose ps -q mongo)
sudo journalctl -u nginx -n 100 --no-pager   # только Nginx-вариант
```

Если панель показывает 502, сначала проверьте `web`, затем `api`, потом логи worker/MongoDB. Если GitHub Actions не может подключиться, не ослабляйте `StrictHostKeyChecking`: проверьте `PRODUCTION_SSH_KNOWN_HOSTS`, DNS, cloud firewall и ключ пользователя `deploy`. Если `docker compose pull` получает `denied`, повторите GHCR login на VPS именно под `deploy` и проверьте package access.

## 12. Эксплуатационные рекомендации

- Включите GitHub branch protection для `main`, обязательный CI и required reviewers для `production`.
- Следите за обновлениями Ubuntu, Docker, MongoDB, Seq, Nginx/Traefik и образов приложения; сначала применяйте их на staging-копии с restore backup.
- Не меняйте `DATA_PROTECTION_KEY` и не удаляйте Docker volumes во время «очистки» без проверенного restore.
- Снимайте snapshot VPS только как дополнительный слой, а не вместо логического Mongo backup.
- Ограничьте SSH в cloud firewall известными IP/VPN, включите 2FA для GitHub и храните PAT/SSH-ключи в password manager.
- Периодически запускайте manual deploy старого SHA на staging и restore drill: это проверяет не только backup, но и реальную возможность отката.
