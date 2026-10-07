# Подключение клиентов

Клиенты ходят в Aegis с **виртуальным ключом** (`aegis vkey issue`), а не с ключом провайдера. Ключ провайдера хранится только в gateway.

Подробности настроек зависят от версии клиента: сверяйтесь с его документацией. Ниже — общий принцип и то, что проверено на стороне Aegis.

## Claude Code (Anthropic Messages)

```
export ANTHROPIC_BASE_URL=https://ai-gateway.company.ru
export ANTHROPIC_API_KEY=aegis-vk-...
```

Aegis принимает `POST /v1/messages` с потоком и без. Блоки thinking и их подписи не изменяются. Ключи кэша промптов (`cache_control`) сохраняются.

## Codex и другие клиенты OpenAI (Responses, Chat Completions)

Базовый адрес — `https://ai-gateway.company.ru/v1`, ключ — виртуальный. Пример для Codex (`~/.codex/config.toml`):

```toml
model_provider = "aegis"

[model_providers.aegis]
name = "Aegis"
base_url = "https://ai-gateway.company.ru/v1"
env_key = "AEGIS_API_KEY"
wire_api = "responses"
```

Aegis работает с Responses только без состояния: запрос с `previous_response_id` отклоняется, а если `store` не указан, Aegis сам выставляет `store: false`.

## Разговор и соль псевдонимов

Если клиент умеет добавлять заголовок, передавайте `X-Aegis-Conversation: <идентификатор сессии>`. Без него соль берётся из хеша первого пользовательского сообщения целиком.

## Что не проходит через Aegis

Cursor и GitHub Copilot используют серверы вендоров. Направить их в gateway нельзя; ограничивайте их на периметре (`deploy/egress`) и настройками самого вендора (запрет отправки кода, политики организации).

## Если запрос отклонён

Клиент видит сообщение вида `Aegis: …` с правилом и `Request ID`. Отказ вызова инструмента приходит текстом в ответе модели, а не ошибкой HTTP: агент видит причину и может предложить другое действие.
