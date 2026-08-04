# AmneziaKeyService

Сервис для автоматической генерации VPN-ключей AmneziaWG и выдачи конфигов в формате AmneziaVPN (`vpn://`).

## Требования

- [.NET 10 SDK](https://dotnet.microsoft.com/download/dotnet/10.0) (RC или Preview)
- MongoDB 6+
- AmneziaWG-сервер (уже настроен с Docker-контейнером `amnezia-awg`)

## Быстрый старт

### 1. Создайте владельца и добавьте сервер через API

Сначала запустите worker: только он применяет миграции. Затем создайте
владельца из `ADMIN__USERNAME`/`ADMIN__PASSWORD` и добавьте сервер через
`POST /api/servers` или мастер панели. Этот путь записывает современный
`server_config` и шифрует SSH-пароль либо приватный ключ до сохранения в MongoDB.
Не создавайте документ узла напрямую через `mongosh`: плоская legacy-схема
больше не поддерживается.

### 2. Настройте appsettings.json

```json
{
  "MongoDb": {
    "ConnectionString": "mongodb://localhost:27017"
  },
  "Jwt": {
    "Secret": "минимум-32-символа-случайная-строка"
  }
}
```

Используйте `appsettings.Development.json` или переменные среды для секретов:
```bash
export Jwt__Secret="your-random-secret-here"
```

### 3. Запустите сервис

```bash
cd src/AmneziaKeyService.Api
dotnet run
```

Swagger UI: http://localhost:5000/swagger

## API

### `POST /api/auth/register`
Регистрация нового VPN-пользователя.
```json
{ "username": "alice", "password": "securepassword" }
```
Ответ: `{ "token": "eyJ..." }`

### `POST /api/auth/login`
Аутентификация.
```json
{ "username": "alice", "password": "securepassword" }
```

### `GET /api/vpn/config`
_(требует Bearer JWT)_

Если у пользователя на этом узле уже есть активный ключ — отдаёт готовый
VPN-конфиг сразу, `200`:
```json
{
  "vpnUri": "vpn://eJy...",
  "clientIp": "10.8.1.2",
  "clientPubKey": "abc123..."
}
```

Если ключа ещё нет, выдача синхронно по HTTP не делается — она идёт по SSH
в фоновом процессе (worker) и не укладывается в один запрос. Ответ — `202`
с идентификаторами заявки:
```json
{ "eventId": "665f...", "keyId": "665f..." }
```

Порядок для клиента: опрашивать `GET /api/events/{eventId}`, пока статус
не станет терминальным (`succeeded`/`failed`/`canceled`); по `succeeded`
повторить запрос `GET /api/vpn/config` — сработает быстрый путь выше.

`vpnUri` можно вставить в AmneziaVPN (Добавить → Вставить ссылку) или сгенерировать QR-код.

### Массовые уведомления Telegram

Раздел панели «Рассылки» доступен владельцу и администратору. API не отправляет
сообщения внутри HTTP-запроса: он создаёт кампанию и устойчивую очередь
получателей в MongoDB, которую с ограничением скорости разбирает процесс бота.

- `GET /api/notifications/audience` — число активных пользователей с Telegram;
- `GET /api/notifications` — история и прогресс кампаний;
- `POST /api/notifications` — создать и сразу запустить кампанию;
- `POST /api/notifications/{id}/cancel` — остановить ещё не выполненные доставки.

Текст отправляется без parse mode и ограничен 4096 символами. По умолчанию
диспетчер отправляет не более 20 сообщений в секунду, повторяет временные
ошибки и учитывает Telegram `retry_after`.

## Формат `vpn://`

Совместим с [exportController.cpp](../amnezia-client-dev/client/ui/controllers/exportController.cpp):
1. JSON → UTF-8 bytes
2. qCompress: 4 байта big-endian (размер оригинала) + zlib RFC 1950
3. Base64 URL-safe без padding
4. Префикс `vpn://`

## Структура проекта

```
AmneziaKeyService/
├── src/
│   ├── AmneziaKeyService.Core/          # Модели, DTO, интерфейсы
│   ├── AmneziaKeyService.Infrastructure/ # Репозитории, SSH, шифрование
│   └── AmneziaKeyService.Api/           # ASP.NET Core Web API
└── global.json                           # Требует .NET 10 SDK
```

## MongoDB-схема

### Коллекция `server_config`
Один документ с параметрами AWG-сервера (SSH-кредиты, пути к ключам, параметры обфускации Jc/S1-S4/H1-H4).
При первом запросе `/api/vpn/config` сервис подключается по SSH, читает `awg0.conf` и кэширует параметры обратно в MongoDB.

### Коллекция `clients`
Один документ на пользователя: `username`, `passwordHash` (BCrypt), `assignedIp`, `clientPrivKey`, `clientPubKey`, `pskKey`, `vpnConfigJson`.
