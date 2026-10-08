# Провайдеры моделей

Aegis работает с тремя семействами протоколов. В одном экземпляре — по одному провайдеру на семейство: нужно два OpenAI-совместимых провайдера — запускайте два экземпляра (динамическая маршрутизация запланирована на этап 3).

| Семейство | Эндпоинты | Настройка |
|---|---|---|
| Anthropic Messages | `/v1/messages`, `/v1/messages/count_tokens` | `anthropic_base_url`, ключ `AEGIS_ANTHROPIC_KEY` |
| OpenAI-совместимые | `/v1/chat/completions`, `/v1/responses`, `/v1/completions`, `/v1/embeddings`, `/v1/models` | `openai_base_url`, ключ `AEGIS_OPENAI_KEY` |
| Google Gemini | `/v1beta/models/<модель>:generateContent`, `:streamGenerateContent`, `:countTokens`, `:embedContent`, `:batchEmbedContents` | `gemini_base_url`, ключ `AEGIS_GEMINI_KEY` |

Эндпоинт, для которого провайдер не настроен, отвечает 404 в формате протокола. Всё остальное (Files, Batches, Assistants, кэшированный контекст Gemini) не поддерживается и отклоняется.

## Параметры подключения

| Параметр | По умолчанию | Назначение |
|---|---|---|
| `anthropic_base_url` | — | Адрес провайдера Anthropic Messages. Путь `/v1/messages` добавляется к нему |
| `anthropic_auth` | `x-api-key` | `x-api-key` или `bearer` (у Kimi, GLM, DeepSeek и других для совместимых с Anthropic адресов) |
| `openai_base_url` | — | Адрес OpenAI-совместимого провайдера |
| `openai_api_prefix` | `/v1` | Путь между адресом и `/chat/completions`. Пустая строка: без префикса |
| `openai_auth` | `bearer` | `bearer`, `api-key` (Azure OpenAI) или `none` (локальные модели без ключа) |
| `gemini_base_url` | — | Адрес Gemini API. Ключ уходит в `x-goog-api-key` |

Ключ провайдера хранится только в окружении gateway (в файле `ИМЯ_FILE` или в выводе команды `ИМЯ_COMMAND`, см. [ADMIN](ADMIN.md)). Клиенты работают с виртуальным ключом, ключ провайдера им не выдаётся и в запросе к провайдеру подставляется заново. Ключ клиента из заголовка и из параметра `?key=` провайдеру не передаётся.

## Облачные провайдеры

Адреса и пути взяты из документации вендоров на момент написания и меняются: сверяйте перед внедрением. Aegis проверен на уровне формата запросов и путей, но не против живых сервисов.

| Провайдер | Протокол | `*_base_url` | `openai_api_prefix` | Заметки |
|---|---|---|---|---|
| Anthropic | Anthropic | `https://api.anthropic.com` | — | |
| OpenAI | OpenAI | `https://api.openai.com` | `/v1` | Responses без состояния (`store: false`) |
| Azure OpenAI (v1 API) | OpenAI | `https://<ресурс>.openai.azure.com/openai` | `/v1` | `openai_auth: "api-key"` |
| Google Gemini | Gemini | `https://generativelanguage.googleapis.com` | — | Vertex AI (OAuth, другие пути) не поддерживается |
| DeepSeek | OpenAI | `https://api.deepseek.com` | `/v1` или пусто | Поле `reasoning_content`, см. ниже |
| DeepSeek | Anthropic | `https://api.deepseek.com/anthropic` | — | Для Claude Code |
| Alibaba Qwen (Model Studio) | OpenAI | `https://dashscope.aliyuncs.com/compatible-mode` | `/v1` | Международный: `dashscope-intl.aliyuncs.com`. `enable_search` отклоняется |
| Alibaba Qwen | Anthropic | `https://dashscope.aliyuncs.com/apps/anthropic` | — | |
| Moonshot Kimi | OpenAI | `https://api.moonshot.cn` | `/v1` | Международный: `api.moonshot.ai`. Встроенный `$web_search` отклоняется |
| Moonshot Kimi | Anthropic | `https://api.moonshot.cn/anthropic` | — | `anthropic_auth: "bearer"` |
| Zhipu GLM (BigModel) | OpenAI | `https://open.bigmodel.cn/api/paas` | `/v4` | Международный Z.ai: `https://api.z.ai/api/paas`. Инструменты `web_search`, `retrieval` отклоняются |
| Zhipu GLM | Anthropic | `https://open.bigmodel.cn/api/anthropic` | — | `anthropic_auth: "bearer"` |
| MiniMax | OpenAI / Anthropic | `https://api.minimax.io` / `https://api.minimax.io/anthropic` | `/v1` | |
| Volcengine Ark (Doubao) | OpenAI | `https://ark.cn-beijing.volces.com/api` | `/v3` | |
| Baidu Qianfan | OpenAI | `https://qianfan.baidubce.com` | `/v2` | |
| Tencent Hunyuan | OpenAI | `https://api.hunyuan.cloud.tencent.com` | `/v1` | |
| SiliconFlow | OpenAI | `https://api.siliconflow.cn` | `/v1` | |
| OpenRouter, Together, Groq, Fireworks | OpenAI | адрес вендора | `/v1` или `/api/v1` | |

Пример (DeepSeek через Claude Code и OpenAI-клиенты одновременно):

```json
{
  "anthropic_base_url": "https://api.deepseek.com/anthropic",
  "anthropic_auth": "bearer",
  "openai_base_url": "https://api.deepseek.com"
}
```

## Локальные модели

Qwen, DeepSeek, GLM, Kimi, Llama, Mistral и другие открытые модели на vLLM, SGLang, llama.cpp, Ollama или LM Studio подключаются как OpenAI-совместимый провайдер без ключа:

```json
{ "openai_base_url": "http://vllm.internal:8000", "openai_auth": "none" }
```

Для Ollama: `"openai_base_url": "http://ollama.internal:11434"`. Нативный API Ollama (`/api/chat`) не поддерживается, используйте `/v1`.

Локальная модель не снимает необходимость в Aegis: он по-прежнему ведёт аудит, ограничивает вызовы инструментов (правило трёх условий, отказ подстановки секрета в сетевую команду) и не пускает секреты в журналы и кэши сервера инференса. Маскирование при этом можно ослабить политикой.

## Китайские облачные модели: что учесть

- **Юрисдикция.** Запрос уходит на серверы вендора в КНР (или в международные регионы вендора). Псевдонимизация не делает данные обезличенными (см. [COMPLIANCE.md](COMPLIANCE.md)); трансграничная передача и доступ органов юрисдикции остаются вопросом для юристов компании. Aegis юридических выводов не делает.
- **Отдельный экземпляр и бандл.** Для таких провайдеров держите отдельный экземпляр gateway со строгой политикой: `block_request` для классов `CORP`, `INFRA` и `PII`, а не маскирование; узкий круг виртуальных ключей.
- **Самостоятельный хостинг** открытых весов тех же моделей (vLLM, SGLang, Ollama в вашем контуре) убирает вопрос юрисдикции и сохраняет качество модели.
- **Встроенный поиск и retrieval** (`enable_search` у Qwen, `$web_search` у Kimi, `web_search`/`retrieval` у GLM) выполняются на стороне провайдера и обходят gateway: такие запросы отклоняются. Если поиск нужен, подключайте его как обычный инструмент клиента, чтобы он шёл через Aegis.
- **`reasoning_content`** (DeepSeek, Qwen, Kimi) — рассуждение самой модели. Aegis не изменяет его в ответе, поэтому в нём видны псевдонимы, а не настоящие значения. В следующем запросе клиент возвращает его в историю (DeepSeek требует этого для вызовов инструментов); там оно проверяется как обычный текст.
- **Параллельные вызовы инструментов** без поля `index` (часть эндпоинтов GLM, Qwen и vLLM-парсеров) разбираются по `id`: каждый новый `id` — отдельный вызов.

Вендорские расширения запросов (`enable_thinking`, `thinking: {type: enabled}`, `top_k` и т. п.) передаются как есть; строки в них проверяются так же, как все остальные.
