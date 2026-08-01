# Windows bootstrap production-VPS

`deploy/bootstrap-production.ps1` подготавливает **один новый пустой VPS с
Ubuntu 24.04 LTS** для IP-first запуска панели. Скрипт запускается на
локальном Windows-компьютере: входить на VPS и вручную устанавливать Docker,
Nginx, MongoDB или Certbot не нужно.

Скрипт рассчитан на host Nginx и публичный IPv4 без домена. Он не является
инструментом миграции существующей инсталляции: если на VPS уже есть
неизвестный каталог развёртывания или Mongo volume, запуск намеренно
останавливается.

## Быстрый старт

Перед запуском нужны:

- Windows PowerShell **5.1+**;
- `git` и Windows OpenSSH Client (`ssh`, `scp`, `ssh-keyscan`, `ssh-keygen`) в
  `PATH`;
- пустой VPS с Ubuntu 24.04 LTS, доступный по публичному IPv4 на SSH-порту;
- доступ root по SSH: лучше по отдельному ключу, допустим и пароль;
- репозиторий в GitHub и успешная публикация образов в GHCR для текущего
  коммита;
- email для уведомлений Let's Encrypt;
- отпечаток **ED25519 SHA256**, взятый из панели провайдера VPS. Не получайте
  его командой `ssh-keyscan`: скрипт сам сверит результат `ssh-keyscan` с
  независимым значением, чтобы обнаружить подмену сервера.

Откройте PowerShell в корне checkout. Тег обязан соответствовать именно
текущему commit и иметь вид `sha-<40-символьный-SHA>`:

```powershell
$sha = (git rev-parse HEAD).Trim().ToLower()
$imageTag = "sha-$sha"
```

Пример с ключом root (рекомендуется):

```powershell
.\deploy\bootstrap-production.ps1 `
  -HostAddress '203.0.113.10' `
  -ExpectedSshHostKeyFingerprint 'SHA256:ВСТАВЬТЕ_ОТПЕЧАТОК_ИЗ_ПАНЕЛИ_ПРОВАЙДЕРА' `
  -GitHubOwner 'your-organization' `
  -GhcrUsername 'your-personal-github-login' `
  -ImageTag $imageTag `
  -AcmeEmail 'ops@example.com' `
  -RootSshIdentityPath "$env:USERPROFILE\.ssh\vps-root-ed25519"
```

Если root пока принимает пароль, опустите `-RootSshIdentityPath`: OpenSSH
запросит пароль при подключении. Не передавайте пароль ключом параметра или
через переменные окружения.

```powershell
.\deploy\bootstrap-production.ps1 `
  -HostAddress '203.0.113.10' `
  -ExpectedSshHostKeyFingerprint 'SHA256:ВСТАВЬТЕ_ОТПЕЧАТОК_ИЗ_ПАНЕЛИ_ПРОВАЙДЕРА' `
  -GitHubOwner 'your-github-owner' `
  -ImageTag $imageTag `
  -AcmeEmail 'ops@example.com'
```

`GitHubOwner` должен быть в нижнем регистре. `GhcrUsername` по умолчанию
равен `GitHubOwner`. Но если `GitHubOwner` — организация, а GHCR-package
закрыт, обязательно передайте `-GhcrUsername` с lowercase login человека,
которому принадлежит classic PAT с `read:packages`. Этот параметр нужен только
для `docker login`, а префикс образов всё равно остаётся организационным.
Для нестандартного SSH-порта добавьте `-SshPort 2222`; для другого имени
администратора панели — `-AdminUsername admin`.

### Интерактивные секреты

### Bootstrap stdin protocol

`bootstrap-vps.sh` is invoked only by `bootstrap-production.ps1`. Its standard
input is newline-delimited `NAME=BASE64_UTF8_VALUE` records. Do not run the
remote helper manually and do not paste passwords into a terminal.

При обычном режиме точный набор записей: `MONGO_ROOT_PASSWORD`,
`MONGO_APP_PASSWORD`, `ADMIN_PASSWORD`, `TELEGRAM_BOT_TOKEN`,
`ACTIONS_PUBLIC_KEY` и, для закрытого GHCR, `GHCR_PAT`. С `-NoTelegram`
запись `TELEGRAM_BOT_TOKEN` не передаётся; удалённый скрипт отвергает её,
чтобы режимы нельзя было случайно смешать.

Скрипт не читает `.env` и не создаёт файл с введёнными секретами на Windows.
Он дважды запросит, без отображения на экране:

- пароль root MongoDB (минимум 24 символа);
- пароль прикладного пользователя MongoDB (минимум 24 символа, другой);
- пароль первого администратора панели;
- токен Telegram-бота, кроме запуска с `-NoTelegram`;
- classic GitHub PAT с `read:packages`, только если GHCR-пакет закрыт.

То есть оба пароля MongoDB задаёте вы в ходе запуска. До первого старта они
живут только во временном файле `/dev/shm` на VPS, а затем удаляются. В
постоянном `/opt/amnezia-key-service/.env` остаётся лишь URL подключения
прикладного пользователя с percent-encoded паролем, но не raw Mongo
credentials. Приватный GHCR PAT передаётся на VPS один раз в stdin `docker
login` и не добавляется ни в GitHub, ни в `.env`.

### Полезные режимы

- `-PublicGhcr` — укажите, только если package GHCR действительно публичный:
  PAT тогда не запрашивается.
- `-NoTelegram` — не запрашивает и не передаёт токен Telegram; постоянный
  `.env` получает `TELEGRAM_BOT_TOKEN=''`, а контейнер `bot` запускается в
  отключённом runtime без polling. Позднее включение Telegram требует
  отдельного изменения `.env` и deploy. Добавьте `-NoTelegram` к обычной
  команде bootstrap, если Telegram пока не нужен.
- `-Resume` — продолжает **тот же** прерванный bootstrap: секреты будут
  запрошены повторно и должны быть прежними. Для уже завершённого VPS это
  health-only проверка без перезаписи `.env`, ключей, volume или сертификата.
  PowerShell всё ещё локально запросит секреты до SSH-подключения, но удалённый
  скрипт их не читает и ничего не меняет. Для `-Resume` должна уже существовать
  пара ключей Actions по пути `-ActionsKeyPath` (по умолчанию —
  `%LOCALAPPDATA%\AmneziaKeyService\keys\production-actions-ed25519`): новый
  ключ в этом режиме не создаётся.
- `-ValidateOnly` — проверяет текущий Git SHA, формат параметров и manifest,
  создаёт (если отсутствует) отдельный ключ GitHub Actions, но не подключается
  к VPS и не спрашивает секреты. Например:

```powershell
.\deploy\bootstrap-production.ps1 `
  -HostAddress '203.0.113.10' `
  -ExpectedSshHostKeyFingerprint 'SHA256:ВСТАВЬТЕ_ОТПЕЧАТОК' `
  -GitHubOwner 'your-github-owner' `
  -ImageTag $imageTag `
  -AcmeEmail 'ops@example.com' `
  -ValidateOnly
```

По умолчанию ключ Actions создаётся в
`%LOCALAPPDATA%\AmneziaKeyService\keys\production-actions-ed25519`; путь можно
сменить `-ActionsKeyPath`. Храните приватный ключ как секрет: Windows ACL
скрипт ограничивает автоматически.

## Что делает bootstrap

После точной проверки ED25519 fingerprint скрипт передаёт только явный набор
несекретных release-файлов и затем автоматически:

- устанавливает необходимые пакеты Ubuntu, Docker Engine/Compose, Nginx,
  Certbot, UFW и fail2ban;
- создаёт пользователя `deploy`, выдаёт ему доступ к Docker и добавляет
  отдельный ключ GitHub Actions с отключёнными forwarding-функциями;
- открывает только SSH, `80/tcp` и `443/tcp` в UFW;
- создаёт защищённый `.env`, инициализирует пустой MongoDB с authentication и
  переводит его в steady-state без bootstrap-паролей в контейнере;
- логинится в GHCR от имени `deploy`, выпускает short-lived IP-сертификат
  Let's Encrypt, настраивает Nginx и renewal;
- скачивает immutable образы, запускает сервисы и проверяет, что внутренние
  порты не слушают публичный интерфейс.

По завершении панель доступна по `https://<VPS_IP>/`. IP-сертификаты
short-lived: контролируйте renewal и срок действия сертификата. Для домена и
дальнейшей эксплуатации используйте [полную инструкцию](../../DEPLOYMENT.md).

## Что остаётся сделать вручную в GitHub

После успешного запуска скрипт выводит проверенную строку `known_hosts` и
путь к созданному ключу. В GitHub откройте **Settings → Environments → New
environment**, создайте `production`, включите required reviewers и добавьте:

| Тип | Имя | Значение |
| --- | --- | --- |
| Secret | `PRODUCTION_SSH_HOST` | публичный IPv4 VPS |
| Secret | `PRODUCTION_SSH_USER` | `deploy` |
| Secret | `PRODUCTION_SSH_PRIVATE_KEY` | содержимое созданного приватного ключа Actions |
| Secret | `PRODUCTION_SSH_KNOWN_HOSTS` | строка, выведенная bootstrap-скриптом после проверки fingerprint |
| Variable | `PRODUCTION_SSH_PORT` | `22` или заданный SSH-порт |
| Variable | `PRODUCTION_DEPLOY_PATH` | `/opt/amnezia-key-service` |
| Variable | `PRODUCTION_PROXY_MODE` | `nginx` |

Это остаётся ручной операцией намеренно: GitHub Environment защищает доступ
к production и approval, а приложение не передаёт свои runtime-секреты в
GitHub. Не добавляйте туда MongoDB-пароли, токен Telegram, `.env` или GHCR
PAT. После заполнения Environment используйте workflow **Actions → Deploy
production**; для rollback указывайте существующий immutable `sha-<SHA>` и
тот же commit в `source_ref`.
