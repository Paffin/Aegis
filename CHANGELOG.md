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

- Набор эксфильтрации (QA-08): более 1300 сценариев, `tests/exfil.rs`. Property-тесты ядра (INV-1, INV-3, INV-4, устойчивость) и фаззинг запросов и потоков (`tests/fuzz.rs`, proptest; `PROPTEST_CASES=40000` для долгого прогона).

- `aegis-bench load`: нагрузочный стенд по настоящему HTTP (добавка ко времени до первого байта, поток запросов, одновременные потоки); в CI.
- В CI: сборка образа, запуск его read-only без привилегий, `helm lint` и `helm template`.

- `scripts/clients.sh`: настоящие Claude Code, Codex CLI, Qwen Code и Gemini CLI против Aegis и подставного провайдера (`mock_anthropic.py`, `mock_openai.py`, `mock_gemini.py`); в CI.
- Имена инструментов других агентов (`exec_command` у Codex, `run_shell_command`, `write_file`, `web_fetch`… у Gemini CLI и Qwen Code, `bash`, `edit`… у OpenCode).

### Исправлено
- Строка запроса (`/v1/messages?beta=true` у Claude Code) терялась по дороге к провайдеру.
- Конфигурация только с `openai_base_url` без `openai_api_prefix` не создавала провайдера (находка Codex).
- Пояснение об отказе вызова приклеивалось к хосту в потоке (`prod-db01.corp.local[Aegis]`), и хост не распознавался при возврате истории; теперь оно начинается с новой строки, а хост перед `[Aegis` распознаётся.
- Значение в URL markdown-картинки, ссылки, `<img>` или автоссылки на чужой адрес подставлялось в текст ответа и уходило при отображении (RST-11).
- Не находился пароль в незакрытой кавычке и фраза-пароль с пробелами; пароли в командной строке (`curl -u`, `sshpass -p`, `redis-cli -a`, `mysql -p`).
- Маркер Aegis после ключевого слова принимался за значение; хост после `@` и пользователь с базой в строке подключения с маркером вместо пароля не находились в истории.
- Блоки `thinking`, `reasoning` с лишними полями проходили без проверки; теперь неприкосновенны только запечатанные поля.

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
