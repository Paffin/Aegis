# Журнал изменений

Формат: [Keep a Changelog](https://keepachangelog.com/ru/1.1.0/), версии по [SemVer](https://semver.org/lang/ru/). Пока `0.x`, совместимость между версиями не гарантируется.

## [Не выпущено]

### Добавлено
- Протокол **Google Gemini**: `generateContent`, `streamGenerateContent` (SSE и JSON-массив), `countTokens`, `embedContent`; `camelCase` и `snake_case`; подписи рассуждений не изменяются.
- Протоколы **OpenAI Completions** (автодополнение, fill-in-the-middle) и **OpenAI Embeddings** (индексация кода).
- Провайдеры независимы и необязательны: Anthropic, OpenAI-совместимый, Gemini. Способы авторизации `x-api-key`, `bearer`, `api-key` (Azure), `x-goog-api-key`, `none` (локальные модели); `openai_api_prefix` для вендоров без `/v1` (Zhipu, Volcengine, Qianfan).
- Виртуальный ключ принимается из `x-api-key`, `Authorization`, `api-key`, `x-goog-api-key` и `?key=`; ключ из запроса провайдеру не передаётся.
- Китайские модели: отказ встроенного поиска (`enable_search`, `$web_search`, `web_search`, `retrieval`), параллельные вызовы без `index`, `reasoning_content`.
- `aegis scan`: что будет замаскировано в файлах, без вывода значений; `--mask`, `--json`, `--fail-on-findings`.
- `scripts/demo.sh`, каталог `examples/`, `docs/PROVIDERS.md`, переписанный `docs/CLIENTS.md`.

### Изменено
- `upstream_base_url` → `anthropic_base_url` (прежнее имя читается), `AEGIS_PROVIDER_KEY` → `AEGIS_ANTHROPIC_KEY` (прежнее имя читается). Хотя бы один провайдер обязателен.
- Сжатые тела запросов отклоняются (415): их нельзя проверить.

## [0.1.0] — первая рабочая версия

### Добавлено
- Ядро: обнаружение (секреты, инфраструктура, ПДн, словари, свои детекторы), псевдонимы без хранилища (HMAC, Crypto-PAn для IPv4, 3fff::/20 для IPv6), подстановка по месту назначения, shell-лексер, правило трёх условий.
- Gateway: Anthropic Messages, OpenAI Chat и Responses (без состояния), потоки с окном удержания, подписанный бандл политики (Ed25519) с горячей заменой, аудит без значений, метрики Prometheus, fail-closed, усиление процесса.
- Строгий разбор JSON и проверка всех строк запроса (защита от расхождения разборщиков и полей вне схемы).
- CLI `aegis`: ключи, бандлы, тесты политики, виртуальные ключи, отчёты.
- `aegis-bench`: ложные срабатывания, полнота, задержка; гейты в CI.
- Документация: концепция, спецификация, план, администрирование, модель угроз, обработка данных; Dockerfile, Helm-чарт, systemd, egress.
