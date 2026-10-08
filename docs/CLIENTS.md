# Подключение клиентов

Клиент ходит в Aegis с **виртуальным ключом** (`aegis vkey issue`), а не с ключом провайдера. Ключ провайдера хранится только в gateway. Менять нужно две вещи: адрес API (`base URL`) и ключ.

Aegis принимает виртуальный ключ в любом из привычных мест: `x-api-key`, `Authorization: Bearer`, `api-key` (Azure-клиенты), `x-goog-api-key` и параметр `?key=` (Gemini). Заголовки клиента, кроме нужных протоколу (`anthropic-version`, `anthropic-beta`, `openai-beta`, `content-type`, `accept`, `user-agent`), провайдеру не передаются.

> Важно. Названия переменных и настроек клиентов зависят от их версии: сверяйтесь с документацией клиента. Шестнадцать клиентов проверены настоящими бинарниками против Aegis и **подставного провайдера** (см. ниже); остальные — только тестами на уровне формата запросов и ответов. Против настоящего провайдера проверены 15 из 16 (см. ниже «Проверено с настоящими моделями»); Gemini CLI нет: нужен родной ключ Gemini. Если у клиента что-то не работает, пришлите `X-Aegis-Request-Id` и текст ошибки.

## Проверено настоящими клиентами

`scripts/clients.sh` запускает настоящий клиент в режиме без интерфейса, направляет его в Aegis, а Aegis — в подставной провайдер, который отвечает текстом и двумя вызовами инструмента (один безобидный, второй уносит секрет на внешний адрес). Проверяется всё, что видит клиент и провайдер: значения замаскированы в каждом запросе и в истории, ключ провайдера подменён, безобидная команда выполнилась с настоящим значением, а её вывод в следующем запросе снова замаскирован, вызов с секретом заменён объяснением, аудит и журнал без значений.

| Клиент (версия) | Протокол | Что пришлось учесть |
|---|---|---|
| Claude Code 2.1.292 | Anthropic, поток | Шлёт `POST /v1/messages?beta=true`: строка запроса теперь доходит до провайдера (до проверки терялась). В режиме `--bare` использует только `ANTHROPIC_API_KEY` и `ANTHROPIC_BASE_URL` |
| Codex CLI 0.160.1 | OpenAI Responses, поток | Шлёт инструмент `web_search`: Aegis его отклоняет, отключите: `web_search = "disabled"` в `config.toml` или `-c web_search=disabled`. Команды идут инструментом `exec_command` с полем `cmd` (добавлен в таблицу инструментов) |
| Qwen Code 0.25.0 | OpenAI Chat, поток | `@имя` в тексте запроса клиент считает ссылкой на файл и переписывает текст (пароль `a@b` превращается в `a @b`): это делает клиент, не Aegis. Остальное работает |
| Gemini CLI 0.63.0 | Gemini, SSE | В `~/.gemini/settings.json` нужен `security.auth.selectedType = "gemini-api-key"`; адрес — `GOOGLE_GEMINI_BASE_URL` |
| OpenCode 1.18.35 | OpenAI Chat, поток | Свой провайдер в `opencode.json`: `npm: "@ai-sdk/openai-compatible"`, `options.baseURL` и `options.apiKey` |
| Aider 0.86.2 | OpenAI Chat, поток | `OPENAI_API_BASE`, `OPENAI_API_KEY`, `--model openai/<имя>`. Вызовов инструментов нет: маскируются запрос и содержимое файлов, добавленных в чат |
| Continue CLI 1.5.47 | OpenAI Chat, поток | `~/.continue/config.yaml`: модель с `provider: openai`, `apiBase`, `apiKey`; инструмент `Bash` |
| Cline CLI 3.0.69 | OpenAI Chat, поток | `cline auth openai -k <ключ> -m <модель> -b <адрес>/v1`. Команды идут инструментом `run_commands` со списком `commands`, задачу завершает `submit_and_exit` |
| Hermes Agent 0.19.0 | OpenAI Chat, поток | `~/.hermes/config.yaml`: `model.provider: custom`, `default`, `base_url`, `api_key`, `context_length`; запуск `hermes -z "…" --yolo`. Команды идут инструментом `terminal`, браузер — `browser_navigate`, код — `execute_code` (его Aegis считает неизвестным и не подставляет в него значения) |
| OpenClaw 2026.6.35 | OpenAI Chat, поток | `~/.openclaw/openclaw.json`: `models.providers.<имя>` с `baseUrl`, `apiKey`, `api: "openai-completions"` и списком `models`; модель — в `agents.defaults.model.primary` (`имя/id`) и в `agents.defaults.models`; запуск `openclaw agent --local`. Команды идут инструментом `exec`, сообщения в каналы — `message` (Aegis считает его выходом в сеть) |
| Crush 0.97.1 | OpenAI Chat, поток | `~/.config/crush/crush.json`: провайдер `type: "openai-compat"`, `base_url`, `api_key`, `models`; запуск `crush run`. Команды — `bash`, файлы — `view`, `edit`, `write`, `multiedit` |
| Kilo Code CLI 7.8.8 | OpenAI Chat, поток | Как у OpenCode: `kilo.json` (или `opencode.json`) с `@ai-sdk/openai-compatible`; запуск `kilo run -m имя/модель` |
| Pi 0.73.1 | OpenAI Chat, поток | `~/.pi/agent/models.json`: провайдер с `baseUrl`, `api: "openai-completions"`, `apiKey`, `models`; запуск `pi --provider … --model … -p` |
| Goose 1.53.0 | OpenAI Chat, поток | `GOOSE_PROVIDER=openai`, `OPENAI_HOST=http://адрес`, `OPENAI_BASE_PATH=v1/chat/completions`, `OPENAI_API_KEY`, `GOOSE_MODEL`; запуск `goose run --with-builtin developer -t`. Клиент отбрасывает текст, пришедший после вызова инструмента, поэтому объяснение отказа Aegis в потоке стоит перед оставшимися вызовами |
| GitHub Copilot CLI 1.0.93 | OpenAI Chat, поток | Режим «своя модель», вход в GitHub не нужен: `COPILOT_PROVIDER_BASE_URL`, `COPILOT_PROVIDER_TYPE=openai`, `COPILOT_PROVIDER_API_KEY`, `COPILOT_PROVIDER_WIRE_API=completions`, `COPILOT_MODEL`, `COPILOT_OFFLINE=true` (отключает телеметрию и обращения к GitHub) |
| Mistral Vibe 2.26.0 | OpenAI Chat, поток | `~/.vibe/config.toml`: `[[providers]]` с `api_base`, `api_key_env_var`, `api_style = "openai"`, `backend = "generic"`, `[[models]]` и `active_model`; запуск `vibe --trust --auto-approve -p` |

Для Claude Code есть и файловый сценарий (`scripts/client-claude-files.sh`, сценарий из концепции): клиент читает конфиг, модель правит этот файл с секретом в тексте правки и другой файл так же. Правка файла, откуда прочитан секрет, проходит, и на диске оказывается настоящий пароль без маркеров; правка другого файла отклонена, файл не изменился, а в истории её нет. (В режиме `--bare` у клиента есть инструмент `Edit`, но нет `Write`.)

Проверка нашла четыре ошибки Aegis, которых тесты на синтетических запросах не видели: потерянная строка запроса (`?beta=true`), конфигурация только с `openai_base_url` без префикса пути не создавала провайдера, неизвестные имена инструментов (`exec_command` у Codex и `run_commands` со списком команд у Cline считались неизвестными и поэтому блокировали и безобидные команды) и пояснение об отказе, приклеенное к хосту в потоке (`prod-db01.corp.local[Aegis]`), из-за чего хост не распознавался при возврате истории.

## Проверено с настоящими моделями

`scripts/client-real.sh` запускает клиентов против **настоящего провайдера** через Aegis (по умолчанию OpenRouter: Chat Completions, Responses и совместимый с Anthropic вход). Между Aegis и провайдером стоит прозрачный прокси `scripts/real_tap.py`: он записывает тела запросов, которые провайдер получил на самом деле, и никогда не пишет ключи.

```
REAL_KEY=sk-or-... bash scripts/client-real.sh all                 # сценарий «команда»
REAL_SCENARIO=files REAL_KEY=... bash scripts/client-real.sh all   # сценарий «правка файла с паролем»
REAL_MODEL=openai/gpt-5-mini REAL_KEY=... bash scripts/client-real.sh codex hermes
```

Жёсткие проверки: все ответы 200, провайдер получил ключ Aegis, ни хоста, ни пароля нет ни в одном запросе провайдеру и ни в аудите, на диске нет маркеров. Мягкие (выводятся, но не проваливают): модель вызвала инструмент, настоящий хост вернулся пользователю, файл изменён.

Результат (`gpt-4o-mini`, для Claude Code `claude-haiku-4.5`): Claude Code, Codex, Qwen Code, OpenCode, Aider, Continue, Cline, Hermes Agent, OpenClaw, Crush, Kilo Code, Pi, Goose, Copilot CLI и Mistral Vibe проходят оба сценария. Codex с `gpt-5-mini` (рассуждение): зашифрованный элемент `reasoning` уходит провайдеру и принимается. Слабая модель иногда записывает в файл только добавленную строку вместо всего содержимого или не правит файл вовсе: это поведение модели, и сценарий отмечает его, не считая провалом. Тест нашёл две реальные дыры детектора паролей (строки с номерами и JSON-строки с `\n`), они исправлены.

### Качество подстановки с настоящими моделями

Клиенты только вызывают инструменты; как модель обращается с псевдонимами в тексте, проверяет `scripts/real_quality.py`: 12 задач (повторить данные, написать скрипт, сделать таблицу, перевести, вернуть JSON, объяснить лог, собрать строку подключения, поправить код…) идут через Aegis к настоящей модели, а прозрачный прокси фиксирует, что получил провайдер.

```
REAL_KEY=sk-or-... python3 scripts/real_quality.py --model openai/gpt-4o-mini --model deepseek/deepseek-chat --stream --repeat 2
REAL_KEY=sk-or-... python3 scripts/real_quality.py --protocol anthropic --model anthropic/claude-haiku-4.5 --stream
REAL_KEY=sk-or-... python3 scripts/real_quality.py --protocol responses --model openai/gpt-5-mini --stream
```

Четыре величины на модель: утечка провайдеру (должна быть 0), ответы с остатком псевдонима у пользователя (должно быть 0), настоящие значения, вернувшиеся в ответ, и ошибки. На пяти моделях по Chat Completions (gpt-4o-mini, gemini-2.5-flash-lite, deepseek-chat, mistral-nemo, llama-3.1-8b), в потоке, по два повтора, а также по Anthropic Messages (claude-haiku-4.5) и Responses (gpt-4o-mini, gpt-5-mini): утечек 0. Остатки псевдонима у пользователя бывают у слабых моделей: в последнем полном прогоне (36 ответов на модель, в потоке, два повтора) gemini-2.5-flash-lite оставила псевдоним или слово «aegis.invalid» в 3–4 ответах, deepseek-chat в 0–1 (в основном модель сама упоминает домен псевдонима в пояснении или искажает хвост псевдонима хоста; искажённый хвост после этого прогона поправлен, повторный замер не сделан); gpt-5-mini один раз вычислила адрес сети из псевдонима IP, значения, которого в запросе не было. Возвращено значений: 40–42 из 42 у четырёх моделей и 23 из 42 у llama-3.1-8b (она часто отказывается повторять данные или не включает их в ответ: это выбор модели, не подстановка). Что остаётся по замыслу: пароль в тексте не возвращается (виден маркер с подсказкой); модель, которая записала псевдоним задом наперёд или придумала свой маркер, восстановить нельзя.

## Что подключается

| Клиент | Протокол | Как подключить |
|---|---|---|
| **Claude Code** | Anthropic | `ANTHROPIC_BASE_URL`, `ANTHROPIC_API_KEY` или `ANTHROPIC_AUTH_TOKEN` |
| **Codex CLI**, OpenAI Agents SDK | OpenAI Responses | `~/.codex/config.toml`, `wire_api = "responses"` |
| **Gemini CLI**, SDK Google GenAI | Gemini | `GOOGLE_GEMINI_BASE_URL`, `GEMINI_API_KEY` |
| **Cline, Roo Code, Kilo Code** (CLI Kilo проверен) | Anthropic или OpenAI Chat | Провайдер «Anthropic» с адресом или «OpenAI Compatible» |
| **Continue** | OpenAI Chat, Completions, Embeddings, Anthropic | `config.yaml`: `provider`, `apiBase`, `apiKey` |
| **Aider** | OpenAI Chat, Anthropic | `OPENAI_API_BASE` / `ANTHROPIC_API_BASE` и ключи |
| **OpenCode, Crush, Goose, Pi, Mistral Vibe** | OpenAI Chat, Responses, Anthropic | Настройка провайдера с `baseURL` |
| **Hermes Agent, OpenClaw** | OpenAI Chat | Свой адрес в конфигурации (см. таблицу проверенных) |
| **GitHub Copilot CLI** | OpenAI Chat | Режим своей модели `COPILOT_PROVIDER_*` |
| **Qwen Code**, **Kimi CLI** | OpenAI Chat, Anthropic | `OPENAI_BASE_URL`, `OPENAI_API_KEY` (Qwen Code); тип провайдера и адрес в конфиге (Kimi CLI) |
| **Zed** | OpenAI Chat, Anthropic | `language_models`: `api_url` |
| **VS Code Copilot Chat (BYOK)**, **JetBrains AI Assistant** | OpenAI Chat | Свой OpenAI-совместимый эндпоинт. Встроенные подсказки кода идут через серверы вендора и не проходят |
| **Open WebUI, LibreChat, LobeChat, Dify, Cherry Studio** | OpenAI Chat, Anthropic | `OPENAI_API_BASE_URL` и ключ |
| **Tabby**, автодополнение в Continue | OpenAI Completions | `/v1/completions` с `prompt` и `suffix` (fill-in-the-middle) |
| Индексация кода (Cline, Roo, Continue) | OpenAI Embeddings | `/v1/embeddings`: тексты маскируются, векторы возвращаются как есть |
| SDK OpenAI, Anthropic, Google GenAI, LangChain, LlamaIndex, LiteLLM-клиенты | любой | `base_url` |

### Claude Code

```
export ANTHROPIC_BASE_URL=https://ai-gateway.company.ru
export ANTHROPIC_API_KEY=aegis-vk-...
```

`POST /v1/messages` с потоком и без, `count_tokens`, `GET /v1/models`. Блоки thinking и их подписи не изменяются, `cache_control` сохраняется.

### Codex CLI

```toml
model_provider = "aegis"

[model_providers.aegis]
name = "Aegis"
base_url = "https://ai-gateway.company.ru/v1"
env_key = "AEGIS_API_KEY"
wire_api = "responses"
```

Responses работает только без состояния: `previous_response_id`, `item_reference` и `store: true` отклоняются, а если `store` не указан, Aegis выставляет `store: false`. Сжатие тела запроса (`Content-Encoding`) не поддерживается: отключите его, иначе Aegis ответит 415, так как сжатое тело проверить нельзя.

### Gemini CLI и SDK Google GenAI

```
export GOOGLE_GEMINI_BASE_URL=https://ai-gateway.company.ru
export GEMINI_API_KEY=aegis-vk-...
```

Поддерживаются `generateContent`, `streamGenerateContent` (SSE и JSON-массив), `countTokens`, `embedContent`. Серверные инструменты Gemini (`googleSearch`, `codeExecution`, `urlContext`, `retrieval`) и `cachedContent` отклоняются. Подписи рассуждений (`thoughtSignature`) и части `thought` не изменяются. Vertex AI (OAuth, пути `projects/…/locations/…`) не поддерживается.

### OpenAI-совместимые клиенты (Cline, Aider, Continue, Qwen Code, OpenCode, Open WebUI…)

Базовый адрес: `https://ai-gateway.company.ru/v1`, ключ — виртуальный. Модель указывается так, как её называет провайдер за Aegis (`gpt-…`, `deepseek-chat`, `qwen3-coder-plus`, `kimi-k2`, `glm-4.6`).

## Соль псевдонимов и разговор

Если клиент умеет добавлять заголовок, передавайте `X-Aegis-Conversation: <идентификатор сессии>`. Без него соль берётся из хеша первого пользовательского сообщения целиком.

## Что не проходит через Aegis

- **Cursor, Windsurf, Trae, Kiro**: запросы идут через серверы вендора, даже с собственным ключом. Направить их в gateway нельзя.
- **GitHub Copilot** (встроенные подсказки), **Amazon Q**, **JetBrains AI** (облако вендора): то же. Исключение: **Copilot CLI** в режиме своей модели (`COPILOT_PROVIDER_*`) проходит через Aegis.
- **Cursor CLI**, **Amp**, **Augment (Auggie)**, **Warp**: свой адрес модели не принимают, проверить нечего.
- Не проверены настоящим бинарником: **Droid** (Factory: без входа в аккаунт не подхватил свои модели из `~/.factory/settings.json`), **iFlow CLI** (отмечен устаревшим, до провайдера не дошёл ни один запрос), **Kimi CLI** (старый пакет не поддерживается, новый ставится скриптом с сайта вендора). Для них остаются тесты формата запросов.
- Нативные протоколы **AWS Bedrock** и **Google Vertex AI**: не поддерживаются (этап 3).

Для всего этого действует только блокировка на периметре (`deploy/egress`) и настройки самого вендора (запрет отправки кода, политики организации).

## Если запрос отклонён

Клиент видит сообщение вида `Aegis: …` с правилом и `Request ID` в формате своего протокола (Anthropic, OpenAI или Google). Отказ вызова инструмента приходит текстом в ответе модели, а не ошибкой HTTP: агент видит причину и может предложить другое действие.

## Вход по токену OIDC

Если в gateway включён `oidc` ([ADMIN](ADMIN.md)), клиент может передавать вместо виртуального ключа JWT вашего провайдера удостоверений. Токены живут недолго, поэтому клиент должен получать их заново: у Claude Code для этого есть `apiKeyHelper` в настройках (команда печатает свежий токен), у остальных — переменная окружения, которую обновляет скрипт входа. Gateway проверяет подпись, издателя, получателя и срок; группы из токена выбирают маршрут (`routes`) и правила политики.
