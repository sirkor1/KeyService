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
