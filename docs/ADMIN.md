# Aegis — руководство администратора

Документ описывает то, что реализовано в репозитории сейчас. Статус по плану работ — в [STATUS.md](STATUS.md).

## 1. Состав

| Бинарник | Назначение |
|---|---|
| `aegis-gateway` | Прокси между клиентами и провайдерами: Anthropic Messages, OpenAI (Chat Completions, Responses без состояния, Completions, Embeddings), Google Gemini |
| `aegis` | Администрирование: ключи подписи, сборка и проверка бандла политики, тесты политики, виртуальные ключи, отчёты по аудиту, `aegis scan` (что было бы замаскировано в ваших файлах) |
| `aegis-bench` | Измерения: ложные срабатывания, полнота, задержка преобразования, нагрузка по HTTP (`load`) |

## 2. Запуск

```
aegis-gateway /etc/aegis/gateway.json
```

Секреты берутся из окружения или из файла (`ИМЯ_FILE`), не из конфигурации:

| Переменная | Назначение |
|---|---|
| `AEGIS_K_TENANT` | Ключ тенанта `K_t`, не короче 16 байт. Из него считаются псевдонимы |
| `AEGIS_K_AUDIT` | Ключ аудита, не короче 16 байт. Должен отличаться от `K_t` |
| `AEGIS_ANTHROPIC_KEY` | Ключ провайдера Anthropic (прежнее имя `AEGIS_PROVIDER_KEY` тоже работает). Нужен, если задан `anthropic_base_url` |
| `AEGIS_OPENAI_KEY` | Ключ OpenAI-совместимого провайдера. Нужен, если задан `openai_base_url` и `openai_auth` не `none` |
| `AEGIS_GEMINI_KEY` | Ключ Gemini. Нужен, если задан `gemini_base_url` |

Ключи провайдеров клиентам не выдаются. Без `K_t`, `K_audit` и ключа каждого настроенного провайдера процесс не стартует. Если бандл настроен, но действительного бандла нет, процесс отвечает 503 и `readyz` не готов (fail-closed).

### Конфигурация (`gateway.json`)

| Ключ | Значение |
|---|---|
| `listen`, `admin_listen` | Адреса основного и служебного портов. Служебный порт (`/healthz`, `/readyz`, `/metrics`) не должен быть доступен клиентам |
| `anthropic_base_url` (прежнее имя `upstream_base_url`), `anthropic_auth` | Провайдер Anthropic Messages и способ передачи ключа |
| `openai_base_url`, `openai_api_prefix`, `openai_auth` | OpenAI-совместимый провайдер: Chat Completions, Responses, Completions, Embeddings |
| `gemini_base_url` | Google Gemini API |
| `model_aliases` | Псевдонимы моделей: `{"claude-default": "claude-sonnet-..."}`. Клиент просит стабильное имя, провайдеру уходит настоящее; смена модели не требует правки клиентов. Работает для всех протоколов, у Gemini имя заменяется в пути |
| `detect_cache_mb`, `detect_budget_ms` | Память кэша обнаружения (1024 МБ, вытеснение LRU, на диск не пишется) и время на проверку одного блока (2000 мс). Блок, который не успели проверить, или проверка которого упала, заменяется на `[Aegis: блок не проверен и удалён]`, запрос не отклоняется; событие аудита получает `detector_faults`, метрика `aegis_detector_faults_total{kind}` растёт |
| `max_concurrent_requests` | Запросов одновременно (по умолчанию 1000, потоки считаются на всё время потока). Лишний запрос получает 503 с `Retry-After: 1` до чтения тела |
| `upstream_connect_timeout_secs`, `upstream_read_timeout_secs` | Ожидание соединения с провайдером (10) и молчания провайдера до ответа и между кусками потока (300). По истечении — 502 |
| `tenant` | Идентификатор тенанта |
| `bundle` | `source` (путь или URL), `cache_path`, `trusted_keys` (hex открытых ключей), `reload_seconds` (1–30) |
| `audit_path`, `audit_required`, `audit_queue` | Файл аудита JSONL (по умолчанию stdout), остановка трафика при переполнении очереди, размер очереди |
| `internal_zones`, `company_ranges`, `service_account_patterns`, `employees`, `terms`, `virtual_keys` | Те же настройки без бандла. С бандлом их задаёт политика |

Нужен хотя бы один провайдер. Подробности, адреса и примеры для DeepSeek, Qwen, Kimi, GLM, Azure, Ollama и других — в [PROVIDERS.md](PROVIDERS.md). Файл примера — [examples/gateway.json](../examples/gateway.json).

### Проверка конфигурации перед запуском

```
aegis-gateway check /etc/aegis/gateway.json
```

Команда ничего не запускает и не открывает порты надолго. Она проверяет: разбор конфигурации; ключи `K_t` и `K_audit` (длина, различие); провайдеров и их ключи; бандл (загрузка, подпись, срок: предупреждение, если до конца меньше 14 дней или взят кэш); запись в файл аудита; свободны ли порты. Выводит `ok`, `warn` или `FAIL` по каждому пункту, значения ключей и пароли в адресах не печатает. Код выхода 0, если нет `FAIL`, иначе 1. Подходит как шаг CI, `initContainer` или проверка перед перезапуском. Предупреждения: открытый наружу порт без TLS, служебный порт на всех интерфейсах.

### Проверка до внедрения

```
aegis scan path/to/repo --zone corp.local          # что будет замаскировано: файл, строка, тип, правило; значения не выводятся
aegis scan config.env --mask                       # тот же файл с подставленными псевдонимами
aegis scan . --policy policy.yaml --fail-on-findings   # в CI или pre-commit
```

Команда использует те же детекторы и правила, что и gateway, работает локально и без ключей.

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

`aegis_requests_total{decision}` (`allow`, `rejected`, `overloaded`, `upstream_error`, `fail_closed`), `aegis_entities_total{class}`, `aegis_denied_total{rule,sink}`, `aegis_stage_ms{stage}` (parse, detect, transform), `aegis_detect_blocks_total{result}`, `aegis_pseudonym_collisions_total`, `aegis_bundle_applied_total`, `aegis_bundle_errors_total{reason}`, `aegis_bundle_info{version,signer}`, `aegis_bundle_expires_in_seconds`, `aegis_audit_overflow_total`.

Значений, путей и текста запросов в метриках нет.

## 6. Заголовки

| Заголовок | Направление | Назначение |
|---|---|---|
| `x-api-key`, `Authorization: Bearer`, `api-key`, `x-goog-api-key` или `?key=` | запрос | Виртуальный ключ (принимается любой из способов) |
| `X-Aegis-Conversation` | запрос, необязательный | Якорь соли псевдонимов |
| `X-Aegis-Request-Id`, `X-Aegis-Summary` | ответ | Идентификатор и счётчики по классам |

Заголовки `X-Aegis-*` и виртуальный ключ провайдеру не передаются.

## 7. Ограничения

- Только режим без состояния: `previous_response_id`, `item_reference`, `store: true`, Assistants, Files и Batches отклоняются.
- Серверные инструменты провайдера (web search, code execution, MCP connector, `enable_search` у Qwen, `$web_search` у Kimi, `retrieval` у GLM, `googleSearch` у Gemini) отключены.
- Сжатые тела запросов (`Content-Encoding`) отклоняются: 415.
- Gateway слушает обычный HTTP: TLS завершайте на балансировщике или ингрессе, основной порт не выставляйте наружу без него. Собственного TLS нет.
- Один провайдер на семейство протоколов в одном экземпляре.
- Изображения и PDF заменяются текстовым уведомлением.
- Cursor, Windsurf и встроенные подсказки GitHub Copilot ходят через серверы вендоров и в gateway не направляются; для них действует только блокировка на периметре (`deploy/egress`). Полный список клиентов — в [CLIENTS.md](CLIENTS.md).
- Образ контейнера собран и запущен, Helm-чарт отрендерен (`helm lint`, `helm template`), но в кластере манифесты не применялись: проверьте NetworkPolicy, пробы и egress у себя.

## 8. Проверка установки

В репозитории есть сценарии, которые можно запустить на своей машине или в CI:

| Сценарий | Что проверяет |
|---|---|
| `scripts/demo.sh` | Клиент, Aegis и «провайдер», который печатает полученное: что видит провайдер, что возвращается клиенту |
| `scripts/smoke.sh` | Настоящие бинарники: бандл, ключи, горячая замена, повреждённый бандл, аудит без значений, SIGTERM во время потока |
| `scripts/clients.sh` | Настоящие Claude Code, Codex, Qwen Code, Gemini CLI, OpenCode, Aider, Continue и Cline против Aegis и подставного провайдера (нужны Node.js и npm; Aider ставится через `uv`). Не установленный клиент пропускается |
| `scripts/client-claude-files.sh` | Сценарий из концепции с настоящим Claude Code: секрет возвращается в файл, откуда он прочитан, и не попадает в другой файл |
| `scripts/trace.sh` | Какие требования спецификации покрыты тестами |
| `aegis-bench load --dir <исходники>` | Добавка ко времени до первого байта, поток запросов, одновременные потоки |
| `aegis-bench fp`, `recall`, `perf` | Ложные срабатывания, полнота, задержка преобразования |

Подставные провайдеры (`scripts/mock_anthropic.py`, `mock_openai.py`, `mock_gemini.py`) пригодны и для проверки вашего клиента: они записывают каждый запрос в файл.
