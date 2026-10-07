# Подключение клиентов

Клиент ходит в Aegis с **виртуальным ключом** (`aegis vkey issue`), а не с ключом провайдера. Ключ провайдера хранится только в gateway. Менять нужно две вещи: адрес API (`base URL`) и ключ.

Aegis принимает виртуальный ключ в любом из привычных мест: `x-api-key`, `Authorization: Bearer`, `api-key` (Azure-клиенты), `x-goog-api-key` и параметр `?key=` (Gemini). Заголовки клиента, кроме нужных протоколу (`anthropic-version`, `anthropic-beta`, `openai-beta`, `content-type`, `accept`, `user-agent`), провайдеру не передаются.

> Важно. Названия переменных и настроек клиентов зависят от их версии: сверяйтесь с документацией клиента. Aegis проверен тестами на уровне формата запросов и ответов для каждого протокола, но **ни один из перечисленных клиентов не запускался**: см. [STATUS.md](STATUS.md). Если у клиента что-то не работает, пришлите `X-Aegis-Request-Id` и текст ошибки.

## Что подключается

| Клиент | Протокол | Как подключить |
|---|---|---|
| **Claude Code** | Anthropic | `ANTHROPIC_BASE_URL`, `ANTHROPIC_API_KEY` или `ANTHROPIC_AUTH_TOKEN` |
| **Codex CLI**, OpenAI Agents SDK | OpenAI Responses | `~/.codex/config.toml`, `wire_api = "responses"` |
| **Gemini CLI**, SDK Google GenAI | Gemini | `GOOGLE_GEMINI_BASE_URL`, `GEMINI_API_KEY` |
| **Cline, Roo Code, Kilo Code** | Anthropic или OpenAI Chat | Провайдер «Anthropic» с адресом или «OpenAI Compatible» |
| **Continue** | OpenAI Chat, Completions, Embeddings, Anthropic | `config.yaml`: `provider`, `apiBase`, `apiKey` |
| **Aider** | OpenAI Chat, Anthropic | `OPENAI_API_BASE` / `ANTHROPIC_API_BASE` и ключи |
| **OpenCode, Crush, Goose** | OpenAI Chat, Responses, Anthropic | Настройка провайдера с `baseURL` |
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
- **GitHub Copilot** (встроенные подсказки), **Amazon Q**, **JetBrains AI** (облако вендора): то же.
- Нативные протоколы **AWS Bedrock** и **Google Vertex AI**: не поддерживаются (этап 3).

Для всего этого действует только блокировка на периметре (`deploy/egress`) и настройки самого вендора (запрет отправки кода, политики организации).

## Если запрос отклонён

Клиент видит сообщение вида `Aegis: …` с правилом и `Request ID` в формате своего протокола (Anthropic, OpenAI или Google). Отказ вызова инструмента приходит текстом в ответе модели, а не ошибкой HTTP: агент видит причину и может предложить другое действие.
