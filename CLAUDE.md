# AmneziaKeyService

Сервис выдачи VPN-ключей AmneziaVPN с Telegram-ботом и веб-панелью
администратора.

## Что это делает

Панель и бот управляют парком VPN-узлов: разворачивают на них контейнеры
Amnezia по SSH, выдают клиентам ключи и отзывают их. Клиент получает
ссылку `vpn://…`, которую вставляет в приложение AmneziaVPN.

Два способа получить ключ:

- **Telegram-бот** — конечный пользователь вводит пригласительный код,
  выбирает узел, получает ссылку. Работал до появления панели и должен
  продолжать работать при любых изменениях.
- **Панель** — администратор добавляет узлы, выдаёт именные ключи
  с ограничением срока и трафика, отзывает их, смотрит журнал.

Протоколы: AmneziaWG (текущая и legacy-версии), обычный WireGuard,
VLESS Reality на Xray-core.

## Устройство

Три процесса поверх двух общих библиотек:

```
src/AmneziaKeyService.Core            модели, DTO, интерфейсы — без зависимостей
src/AmneziaKeyService.Infrastructure  MongoDB, SSH, протоколы, установка, композиция
src/AmneziaKeyService.Api             ASP.NET Core: контроллеры и авторизация
src/AmneziaKeyService.Worker          миграции, сидирование владельца, воркеры эксплуатации
src/AmneziaKeyService.Bot             Telegram-бот
tools/VerifyVpnUri                    офлайн-проверка формата vpn://
tools/VerifyMonitoring                офлайн-проверка разбора wg dump и редактирования секретов
tools/VerifyRouterMonitoring          состояния роутеров, профиль, права API; --mongo добавляет интеграционные проверки
tools/VerifyUserManagement            офлайн-проверка правил управления пользователями и legacy passcode BSON
tools/VerifyPanelSettings             офлайн-проверка границ настроек панели
tools/VerifyRefreshTokens             офлайн-проверка hash/rotation/reuse refresh-сессий
tools/VerifyEvents                    проверка шины событий, требует живую MongoDB
tools/VerifyLegacyMigration           проверка зачистки legacy server_config, требует живую MongoDB
tools/VerifyMongoAuthentication.ps1   disposable-проверка MongoDB auth, CRUD и migration DDL
tools/VerifyMongoApplicationUri.ps1   проверка реальной credentialed MongoDB URI перед cutover
web/admin                             панель на Vite + React + TypeScript
```

Состав процессов задаётся не копипастой в трёх `Program.cs`, а расширениями
из `Infrastructure/DependencyInjection/`: `AddAmneziaData`,
`AddAmneziaProtocols`, `AddAmneziaNodeAccess`. Последнее — граница доступа
к узлам: кто его не вызвал, тот не может открыть SSH, потому что
в его контейнере нет `ISshSessionFactory`.

Ключевые узлы Infrastructure:

| Каталог | Назначение |
|---|---|
| `Protocols/` | абстракция протоколов: конфигураторы (выдача ключей) и инсталляторы (развёртывание) |
| `Install/` | оркестратор шести шагов установки, очередь и фоновый воркер |
| `Monitoring/` | четыре фоновых воркера: трафик, здоровье узлов, сроки и квоты, сверка peer-ов |
| `Ssh/` | `ISshSession` — единственная точка работы с узлами по SSH |
| `Migrations/` | миграции схемы MongoDB, применяются при старте |
| `ServerScripts/` | скрипты Amnezia, встроенные в сборку как ресурсы |

## Команды

Бэкенд:

```bash
dotnet build AmneziaKeyService.sln
```

```bash
dotnet run --project src/AmneziaKeyService.Api
```

```bash
dotnet run --project src/AmneziaKeyService.Worker
```

```bash
dotnet run --project src/AmneziaKeyService.Bot
```

Локально api и бот ждут миграций от воркера — поднимайте воркер первым.

Офлайн-проверки (не входят в solution, запускать отдельно). Формат `vpn://`:

```bash
dotnet run --project tools/VerifyVpnUri
```

Разбор `wg show dump`, арифметика счётчиков и редактирование секретов:

```bash
dotnet run --project tools/VerifyMonitoring
```

Правила управления пользователями и обратная совместимость BSON пригласительных
кодов, границы настроек панели, а также hash/rotation/reuse refresh-токенов:

```bash
dotnet run --project tools/VerifyUserManagement
dotnet run --project tools/VerifyPanelSettings
dotnet run --project tools/VerifyRefreshTokens
```

Шина доменных событий. **Требует живую MongoDB** — работает на временной базе
и удаляет её за собой; адрес меняется через `--mongo=` или `MONGO_URL`:

```bash
dotnet run --project tools/VerifyEvents
```

Миграция `012_drop_legacy` (плоские поля узла и plaintext `sshPassword`) на
временной MongoDB:

```bash
dotnet run --project tools/VerifyLegacyMigration
```

Фронтенд (нужен Node 22+; локально его может не быть — см. ниже):

```bash
cd web/admin && npm ci && npm run dev
```

```bash
cd web/admin && npm run lint && npm run build
```

Статическая проверка общих инвариантов доступности (диалог, клавиатурные
строки таблиц, focus-visible и live-статусы):

```bash
cd web/admin && npm run verify:a11y
```

Без Node фронтенд собирается через Docker:

```bash
docker run --rm -v "$PWD/web/admin:/app" -w /app node:22-alpine sh -c "npm ci && npm run lint && npm run build"
```

Весь стек:

```bash
docker compose up -d --build
```

## Конфигурация

Обязательные переменные — без них сервис не стартует:

| Переменная | Назначение |
|---|---|
| `Jwt__Secret` | подпись JWT, минимум 32 байта |
| `SECURITY__DATAPROTECTIONKEY` | шифрование секретов в базе, ровно 32 байта в base64 |
| `ADMIN__USERNAME`, `ADMIN__PASSWORD` | владелец панели, создаётся при первом запуске |

Необязательные: `TelegramBot__Token`, `MongoDb__ConnectionString`,
`Cors__Origins` (только для dev-сервера Vite), `Seq__ServerUrl` и `Seq__ApiKey`
(пустой URL отключает сток логов), секция `Polling` (интервалы фоновых воркеров;
`Polling__Enabled=false` выключает все четыре — так они и настроены локально).
Секция `Notifications` управляет массовыми Telegram-рассылками: включением,
размером пачки, числом сообщений в секунду, повторами и TTL аренды доставки.

### MongoDB authentication

Обычный `docker-compose.yml` намеренно остаётся без MongoDB authentication для
локальной разработки и существующего тома. Защищённый запуск — только явный
override `docker-compose.mongo-auth.yml`; без внешней
`MONGODB_CONNECTION_STRING` (с credentials и `authSource`) Compose остановится
до изменения контейнера. Для известного пустого тома к нему добавляется
`docker-compose.mongo-auth.fresh.yml`: официальный init-hook создаёт отдельного
пользователя `readWrite` только в рабочей БД. Bootstrap root не остаётся в
steady-state контейнере. Для существующего тома не подключать fresh override:
сначала backup, отдельные admin и app users, проверка URI и лишь затем `--auth`.
Полная процедура и rollback — в `DEPLOYMENT.md`; автоматическая проверка на
одноразовом контейнере — `tools/VerifyMongoAuthentication.ps1`. Для реального
existing volume до cutover есть `tools/VerifyMongoApplicationUri.ps1`: он
проверяет SCRAM и точного app user, не выводя credentialed URI.

**Потеря `SECURITY__DATAPROTECTIONKEY` необратима** — зашифрованные SSH-пароли
и приватные ключи станут нечитаемыми.

## Порты

- `8080` — API, опубликован (на него смотрит хостовой nginx из текущего развёртывания)
- `8081` — контейнер панели; занимать `80` нельзя, там уже слушает nginx хоста
- `8082` — интерфейс Seq, **только на `127.0.0.1`**: у него нет пароля
  до первой настройки. Доступ через SSH-туннель либо nginx с basic-auth
- `5341` — приём логов Seq, наружу не публикуется вовсе
- `5116` — API при локальном `dotnet run`
- `5173` — dev-сервер Vite, проксирует `/api` на 5116

## Правила, которые легко нарушить

**Скрипты и шаблоны из `amnezia-client` копируются дословно.** Клиент
AmneziaVPN разбирает конфиги по тем же файлам; расхождение в один пробел
даёт успешный импорт и несостоявшийся хэндшейк без диагностики. Не
переписывать на C# — рендерить подстановкой `$VAR`. См.
`ServerScripts/UPSTREAM.md`.

**Всё из `ServerScripts/` должно попадать в сборку.** `ScriptRegistry` читает
эти файлы как embedded-ресурсы, и отсутствующий скрипт обнаруживается только
при установке на живой узел. Маска в `.csproj` берёт каталог целиком —
не заменять её перечислением расширений. Проверяется в `tools/VerifyMonitoring`.

**Не добавлять `set -e` в скрипты установки.** Upstream выполняет каждую
логическую строку отдельным SSH-exec и рассчитывает, что падение одной
команды не прерывает остальные; `install_docker.sh` на этом построен.

**Текст SSH-команд не должен попадать в HTTP-ответы.** В командах
`docker exec` лежат приватные ключи и PSK. `SshCommandException` несёт
только метку операции; подробности идут в лог через `SecretRedactor`.

**Свойство с именем `Id` во вложенном BSON-документе.** Драйвер MongoDB
по соглашению мапит его в `_id`, игнорируя `[BsonElement("id")]`. Для
вложенных классов обязателен `[BsonNoId]` — иначе значение теряется при
чтении и перегенерируется при записи.

**`$ne` не работает в `partialFilterExpression`.** Использовать `$in`
с перечислением (требует MongoDB 6.0+).

**Telegram-бот — синглтон `IHostedService`.** Scoped-сервисы он берёт
через `IServiceScopeFactory`, а не из конструктора.

**Событие, тянущее за собой видимое оператору состояние, обязано убирать
за собой.** `IDomainEventHandler.OnFailedAsync` вызывают и диспетчер, и жнец
при окончательном провале. Без него задача установки, чей исполнитель умер,
осталась бы «выполняется» навсегда: сам оркестратор её уже не пометит.

**Политику повторов события объявляет обработчик, а не общий механизм.**
`IDomainEventHandler.Policy` — единственное место, где записано, идемпотентна
ли операция. Вернуть в очередь оборванную установку значит запустить её поверх
наполовину настроенного узла; не вернуть отзыв ключа значит оставить доступ
работающим. Общий диспетчер этого различить не может.

**Две операции над одним узлом не должны идти одновременно.** `wg syncconf`
поверх правящегося конфига теряет peer-ов. Событие с `PartitionKey` берёт
аренду партиции; если её не дали — возвращается в очередь **не сжигая попытку**,
иначе загруженный узел исчерпал бы попытки события, которое не начинали.

**Миграции применяет только воркер.** Три раннера на одной базе дали бы гонку:
проверка «уже применена» и запись факта применения не атомарны между собой.
Api и бот дожидаются через `MongoSchemaGate` и не поднимаются, пока схема
не готова. Плата — порядок запуска: не поднялся воркер, не поднимется и панель.

**Дизайн-система `web/admin/src/styles/ds/` не редактируется.** Это
дословная копия. Своя вёрстка — в CSS-модулях поверх её токенов.
Правило oxlint запрещает сырые `px` и hex в строковых литералах, поэтому
в TSX нет инлайновых стилей, а внесистемные величины вынесены
в `--panel-*` (`styles/tokens.css`).

**Логи уезжают наружу — секреты вырезает сток, а не автор кода.**
`SecretRedactingSink` оборачивает и консоль, и Seq: чистит строковые свойства
события и текст шаблона. Второе нужно из-за интерполяции — `LogDebug($"…{x}")`
не создаёт свойств вовсе. Не обходить обёртку и не логировать сырой вывод
`wg show dump`: его первая строка — приватный ключ сервера.

**Счётчики трафика монотонны только в пределах жизни контейнера.** При рестарте
они обнуляются, поэтому накопление считается приращениями через
`UsageMath.Delta`, а не присваиванием. Сырые показания хранятся в `usage.rxRaw`
и `usage.txRaw` именно для этого сравнения.

**`wg show all` не парсить.** Только `show <iface> dump`: первый рассчитан
на чтение человеком и менялся между версиями.

**Миграции применяются при старте и записываются в `_migrations`.**
Новая правка схемы — новая миграция, а не изменение существующей: применённые
повторно не запускаются. Имена индексов не задавать явно, если индекс уже
мог быть создан прежним кодом с автоименем — иначе `IndexOptionsConflict`.

## Совместимость

Схема MongoDB эволюционирует **на месте**: те же коллекции, те же `_id`.
На `VpnClient.serverId` ссылается каждый выданный ботом ключ, пересоздание
документов осиротило бы их все.

Сигнатуры `IVpnConfigService.GetOrCreateConfigAsync` и `CreateNewConfigAsync`
менять нельзя — на них завязаны бот и `/api/vpn/*`.

## Окружение разработки

Windows, PowerShell 5.1 как основная оболочка. Два подводных камня, на
которые уже наступали:

- `.ps1` читается в ANSI — кириллица в литералах скриптов ломается.
  Вспомогательные скрипты писать латиницей.
- Имена переменных **регистронезависимы**: `$t` затирает `$T`.

MongoDB локально — 6.0.5 на `localhost:27017`, база `amnezia_vpn`.

## Документы

- `Plan.md` — план работ и текущая точка
- `DEPLOYMENT.md` — production-развёртывание на VPS через GitHub Actions и GHCR
- `README.md` — краткое описание API
- `ROUTER_MONITORING.md` — наблюдение за роутерами, Telegram, настройка TP-Link и проверки
- `src/AmneziaKeyService.Infrastructure/ServerScripts/UPSTREAM.md` — происхождение скриптов
