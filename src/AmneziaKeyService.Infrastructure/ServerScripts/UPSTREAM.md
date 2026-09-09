# Шаблоны конфигов из amnezia-client

Файлы скопированы **дословно** из `amnezia-client/client/server_scripts/`
и подключены как `EmbeddedResource` (см. `.csproj`).

| Файл | Источник |
|---|---|
| `awg/template.conf` | `server_scripts/awg/template.conf` — AmneziaWG актуальной версии (контейнер `amnezia-awg2`) |
| `awg_legacy/template.conf` | `server_scripts/awg_legacy/template.conf` — AmneziaWG legacy (контейнер `amnezia-awg`) |
| `wireguard/template.conf` | `server_scripts/wireguard/template.conf` — обычный WireGuard |
| `xray/template.json` | `server_scripts/xray/template.json` — клиент VLESS Reality |

Локальная копия upstream: `D:\Amnezia\amnezia-client-dev`.

## AWG 3

`awg3/{Dockerfile,configure_container.sh,run_container.sh,start.sh,template.conf}`
скопированы без изменений из официального релиза **AmneziaVPN 5.0.2.1**, commit
`327e5985df0ef16ea03058b611e171b1d3bc0420`, каталога `client/server_scripts/awg/`.
Источник: https://github.com/amnezia-vpn/amnezia-client/tree/327e5985df0ef16ea03058b611e171b1d3bc0420/client/server_scripts/awg

Этот релиз обозначает новое семейство как `protocol_version = "3.1"`.
Значения параметров взяты из `core/installers/awgInstaller.cpp` и
`core/utils/constants/protocolConstants.h` того же релиза.
Прежний каталог `awg/` оставлен для AWG 2.0.

На сервере новая версия использует отдельное имя `amnezia-awg3`,
но в экспортируемом клиентском JSON тип контейнера — `amnezia-awg2`:
именно его знает upstream-клиент, версия задаётся внутри `awg`.
Dockerfile upstream сохранён дословно, но при загрузке инсталлятор заменяет
его `FROM` на проверенный образ
`amneziavpn/amneziawg-go@sha256:cbafc02b8373a83f428272db6d8001b37bc02e6211cbd8c0cb4e2e3759b12b72`.
Образ проверен 2026-09-08: `amneziawg-tools v3.1.20260812`, новые параметры
принимаются через `awg setconf` в одноразовом контейнере. Установка считается
успешной только после проверки работающего интерфейса AWG.
Полный handshake проверяется на тестовом VPN-узле.

## Почему дословно

Клиент AmneziaVPN разбирает конфиг по этим же шаблонам. Любое расхождение —
лишний пробел в `.conf`, изменённый порядок ключей в `last_config` — приводит
к тому, что импорт проходит, а хэндшейк не устанавливается, причём без
внятной диагностики. Поэтому шаблоны не переписываются на C#, а рендерятся
подстановкой `$VAR`, как в оригинале.

При обновлении upstream: сверить файлы заново и прогнать проверку формата
(`tools/verify-vpn-uri`), а не править шаблоны руками.

## Подстановка переменных

Токены соответствуют `ServerController::genVarsForScript` в
`client/core/controllers/serverController.cpp`. Подстановка выполняется
`ScriptTemplateRenderer` одним проходом по regex-альтернативе из известных
ключей (длинные первыми) — так чужие shell-переменные вида `$CUR_USER`
не затрагиваются, а префиксы не конфликтуют.

## Скрипты установки

Здесь только шаблоны клиентских конфигов. Скрипты развёртывания контейнеров
(`Dockerfile`, `configure_container.sh`, `run_container.sh`, `start.sh`,
общие `install_docker.sh`, `prepare_host.sh` и прочие) добавляются вместе
с оркестрацией установки.
