# Aegis — руководство администратора

Документ описывает то, что реализовано в репозитории сейчас. Статус по плану работ — в [STATUS.md](STATUS.md).

## 1. Состав

| Бинарник | Назначение |
|---|---|
| `aegis-gateway` | Прокси между клиентами и провайдерами: Anthropic Messages, OpenAI Chat Completions, OpenAI Responses (без состояния) |
| `aegis` | Администрирование: ключи подписи, сборка и проверка бандла политики, тесты политики, виртуальные ключи, отчёты по аудиту |
| `aegis-bench` | Измерения качества: ложные срабатывания, полнота, задержка |

## 2. Запуск

```
aegis-gateway /etc/aegis/gateway.json
```

Секреты берутся из окружения или из файла (`ИМЯ_FILE`), не из конфигурации:

| Переменная | Назначение |
|---|---|
| `AEGIS_K_TENANT` | Ключ тенанта `K_t`, не короче 16 байт. Из него считаются псевдонимы |
| `AEGIS_K_AUDIT` | Ключ аудита, не короче 16 байт. Должен отличаться от `K_t` |
| `AEGIS_PROVIDER_KEY` | Ключ Anthropic. Клиентам не выдаётся |
| `AEGIS_OPENAI_KEY` | Ключ OpenAI-совместимого провайдера (нужен, если задан `openai_base_url`) |

Без ключей процесс не стартует. Если бандл настроен, но действительного бандла нет, процесс отвечает 503 и `readyz` не готов (fail-closed).

### Конфигурация (`gateway.json`)

| Ключ | Значение |
|---|---|
| `listen`, `admin_listen` | Адреса основного и служебного портов. Служебный порт (`/healthz`, `/readyz`, `/metrics`) не должен быть доступен клиентам |
| `upstream_base_url` | Провайдер Anthropic |
| `openai_base_url` | OpenAI-совместимый провайдер; включает `/v1/chat/completions` и `/v1/responses` |
| `tenant` | Идентификатор тенанта |
| `bundle` | `source` (путь или URL), `cache_path`, `trusted_keys` (hex открытых ключей), `reload_seconds` (1–30) |
| `audit_path`, `audit_required`, `audit_queue` | Файл аудита JSONL (по умолчанию stdout), остановка трафика при переполнении очереди, размер очереди |
| `internal_zones`, `company_ranges`, `service_account_patterns`, `employees`, `terms`, `virtual_keys` | Те же настройки без бандла. С бандлом их задаёт политика |

## 3. Политика и бандл

Политика — YAML, строгая схема: неизвестное поле или значение — ошибка, а не молчаливый пропуск.

```yaml
version: 1
tenant: acme
zones: { internal: [corp.local, company.ru], company_ranges: ["10.50.0.0/16"] }
detectors:
  service_account_patterns: ['\bacme_[a-z]+_svc\b']
  custom:
    - id: acme-token
      type: SECRET
      regex: 'ACME-TKN-([A-Z0-9]{12})'
      group: 1
      examples: { matches: ["ACME-TKN-AB12CD34EF56"], non_matches: ["ACME-TKN-x"] }
dictionary:
  employees: [{ first: Иван, last: Петров }]
  terms: [{ form: InternalPaymentSystem, type: SYSTEM }]
trifecta: { mode: enforce, allow_destinations: ["docs.python.org"] }
defaults:
  ingress: { SECRET: mask, INFRA: mask, PII: mask, CORP: mask }
  secret_attributes: [kind, has]
rules:
  - { id: R-020, when: { type: SECRET, kind: pem }, ingress: block_request }
  - { id: R-112, when: { sink: [shell_network, network] }, restore: { SECRET: deny, INFRA: internal_only } }
```

Порядок работы:

```
aegis keys generate --out signing.key                    # один раз; закрытый ключ хранить офлайн
aegis policy test policy.yaml tests.yaml                 # схема, примеры детекторов, тесты политики
aegis vkey issue --principal u:ivanov --file vkeys.json  # ключ печатается один раз, в файл идёт только хеш
aegis bundle build --policy policy.yaml --tests tests.yaml --key signing.key \
    --version 2026.10.07-1 --valid-days 90 --vkeys vkeys.json -o bundle.json
aegis bundle verify bundle.json --trusted <публичный ключ>
```

Сборка останавливается, если не проходят схема, примеры собственных детекторов или тесты политики. Бандл без тестов собирается только с явным `--no-tests`.

Gateway проверяет подпись, срок действия и политику, затем подменяет движок без перезапуска (не позже `reload_seconds` после публикации). Неверный бандл ничего не меняет, ошибка видна в `aegis_bundle_errors_total`. Последний действительный бандл копируется в `cache_path` и используется при перезапуске, если источник недоступен. Когда срок действия истёк, трафик останавливается (503), поэтому новый бандл надо публиковать заранее: метрика `aegis_bundle_expires_in_seconds`.

**Отзыв виртуального ключа:** `aegis vkey revoke --principal ... --file vkeys.json`, затем собрать и опубликовать новый бандл.

**Ротация ключей.** `K_t`: псевдонимы всех разговоров меняются сразу. Состояния нет, поэтому ничего не ломается: следующий запрос перемаскирует весь контекст новыми псевдонимами, но кэш промптов провайдера для идущих разговоров сбрасывается. Ротацию лучше делать в нерабочее время; ответ, который уже получен от провайдера в момент ротации, с новым ключом не подставится. `K_audit`: после замены записи аудита, сделанные до ротации, нельзя связать с новыми значениями (crypto-shredding); старый ключ после ротации уничтожается.

## 4. Аудит и отчёты

Каждый запрос пишет событие JSONL: тип и вид сущностей, хеши (HMAC на `K_audit`), счётчики, решения по инструментам, сработавшие правила, состояние правила трёх условий. Значений и псевдонимов в аудите нет.

```
aegis report audit.jsonl                                  # сводка
aegis report audit.jsonl --since 2026-10-07T00:00:00Z     # период
aegis report audit.jsonl --conversation <хеш разговора>   # одна задача агента
```

## 5. Метрики (служебный порт, `/metrics`)

`aegis_requests_total{decision}`, `aegis_entities_total{class}`, `aegis_denied_total{rule,sink}`, `aegis_stage_ms{stage}` (parse, detect, transform), `aegis_detect_blocks_total{result}`, `aegis_pseudonym_collisions_total`, `aegis_bundle_applied_total`, `aegis_bundle_errors_total{reason}`, `aegis_bundle_info{version,signer}`, `aegis_bundle_expires_in_seconds`, `aegis_audit_overflow_total`.

Значений, путей и текста запросов в метриках нет.

## 6. Заголовки

| Заголовок | Направление | Назначение |
|---|---|---|
| `x-api-key` или `Authorization: Bearer` | запрос | Виртуальный ключ |
| `X-Aegis-Conversation` | запрос, необязательный | Якорь соли псевдонимов |
| `X-Aegis-Request-Id`, `X-Aegis-Summary` | ответ | Идентификатор и счётчики по классам |

Заголовки `X-Aegis-*` и виртуальный ключ провайдеру не передаются.

## 7. Ограничения

- Только режим без состояния: `previous_response_id`, `item_reference`, `store: true`, Assistants, Files и Batches отклоняются.
- Серверные инструменты провайдера (web search, code execution, MCP connector) отключены.
- Изображения и PDF заменяются текстовым уведомлением.
- Cursor и GitHub Copilot ходят через серверы вендоров и в gateway не направляются; для них действует только блокировка на периметре (`deploy/egress`).
- Образ контейнера и Helm-чарт не собирались и не рендерились в среде разработки: проверьте их в вашем кластере.
