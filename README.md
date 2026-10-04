# siggen — генератор SIEM-правил для Wazuh/OSSEC

Detection-as-Code ассистент: по строке лога предлагает декодер и правило, но отдаёт их
только после проверок.

**Главный инвариант проекта: модель предлагает — движок проверяет.**
Человекопонятный, но нерабочий результат — основная проблема LLM-генерации правил, поэтому
идентификаторы, XML и вердикт о пригодности формирует наш код, а работоспособность
подтверждает `wazuh-logtest`/`ossec-logtest`, а не текст модели.

## Что это даёт

**SOC / инженеру детекций:** конвейер «строка лога → декодер и правило → статические
проверки → прогон через движок → артефакты для PR», с negative-фикстурой на каждое правило
и реестром занятых ID.

**CISO:** прослеживаемость (модель, версия и хэш промпта, строка-основание, статус ревью),
честный статус проверки вместо обещаний и отчёт, который можно приложить к ревью.
Подробный план развития — [`docs/ROADMAP.md`](docs/ROADMAP.md).

## Быстрый старт

Нужен только Python 3.10+ и `pydantic`. Пакет работает без установки:

```bash
python -m siggen gen --log samples/positive.log --negative samples/negative.log
```

Либо обычная установка:

```bash
python -m pip install -e ".[dev]"     # ядро + pytest
python -m pip install -e ".[gigachat]"  # реальная модель
python -m pip install -e ".[ui]"        # веб-интерфейс
```

По умолчанию используется провайдер `fake` — детерминированная заглушка, которая понимает
демонстрационные шаблоны (`login_failed`, `Failed password for`) и не ходит в сеть.
Для реальных логов включите GigaChat:

```bash
cp .env.example .env    # заполнить GIGACHAT_CREDENTIALS
python -m siggen gen --provider gigachat --log /path/to/log.line --negative /path/to/noise.line
```

## Команды

```bash
# Сгенерировать и проверить артефакт
python -m siggen gen --log samples/positive.log --negative samples/negative.log \
    --engine wazuh --out out --registry registry/rules.json

# Перепроверить ранее сгенерированный артефакт (например, после обновления рулсета)
python -m siggen validate --path out/wazuh-100100

# Для CI: недоступность движка считать провалом, а не «не проверено»
python -m siggen gen ... --require-engine

# Движок не в PATH, а в контейнере лаборатории:
python -m siggen gen ... --logtest "docker compose exec -T wazuh-manager /var/ossec/bin/wazuh-logtest"
```

Коды возврата: `0` — артефакт прошёл проверки, `1` — не прошёл, `2` — ошибка ввода
или конфигурации. Код `1` делает команду пригодной для CI-gate.

Веб-интерфейс: `streamlit run siggen/ui/app.py`.

## Что именно проверяется

| Проверка | Уровень | Смысл |
|---|---|---|
| `decoder_wellformed`, `rule_wellformed` | ошибка | XML разбирается, корневой тег верный |
| `rule_id_in_range`, `rule_id_unique` | ошибка | ID в разрешённом диапазоне и не занят |
| `decoded_as_matches_decoder` | ошибка | правило ссылается на существующий декодер |
| `order_fields_allowed` | ошибка | в `<order>` только поля, известные движку |
| `order_matches_regex_groups` | ошибка | число групп захвата = числу полей `<order>` |
| `regex_compiles` | ошибка | регулярное выражение компилируется |
| `decoder_offset_allowed` | ошибка | допустимый `offset` |
| `mitre_in_allowlist` | ошибка | техника ATT&CK есть в справочнике, а не выдумана |
| `no_broad_suppression`, `no_active_response`, `level_not_zero` | ошибка | правило не подавляет всё подряд и не блокирует хосты |
| `negative_fixture_present`, `groups_present`, `no_duplicate`, `no_source_ip_whitelist` | предупреждение | требует явного решения человека |

Плюс прогон фикстур через движок: `positive` обязана сматчиться, `negative` — нет.
Если движок недоступен, статус честно `skipped` («не проверено»), а флаг `--require-engine`
превращает это в провал.

## Прогон через настоящий движок

Лаборатория описана в [`docker-compose.yml`](docker-compose.yml) (файл не поднимался
автоматически — сверьте образ и пути со своей версией Wazuh). Движок должен быть доступен
там, где запущен `siggen`. Два способа:

**1. `wazuh-logtest` в PATH** — ничего дополнительно указывать не нужно.

**2. Движок внутри контейнера** — передайте команду целиком:

```bash
python -m siggen gen \
  --log samples/positive.log --negative samples/negative.log \
  --logtest "docker compose exec -T wazuh-manager /var/ossec/bin/wazuh-logtest"
```

То же самое можно задать переменной окружения `SIGGEN_LOGTEST` (см. `.env.example`).

> **Осторожно, PowerShell.** В аргументах командной строки PowerShell съедает вложенные
> кавычки, поэтому путь с пробелами через `--logtest` передать не получится. Такие пути
> задавайте переменной окружения — она передаётся дословно:
>
> ```powershell
> $env:SIGGEN_LOGTEST = '"C:\Program Files\wazuh\bin\wazuh-logtest.exe"'
> python -m siggen gen ...
> ```

Проверка того, что правило действительно срабатывает, вынесена в отдельные тесты
(пропускаются, пока лаборатория не поднята):

```bash
SIGGEN_LAB=1 \
SIGGEN_LOGTEST="docker compose exec -T wazuh-manager /var/ossec/bin/wazuh-logtest" \
  python -m pytest -m integration -v
```

Порядок развёртывания примера правил на стенде — в docstring
[`tests/test_integration_engine.py`](tests/test_integration_engine.py).

## Данные и секреты

- Секреты — только через переменные окружения (`.env` в `.gitignore`), см. `.env.example`.
- Проверка TLS включена всегда; отключение — явный флаг с предупреждением в лог.
- **Движок не отправляет логи в модель.** Сейчас в модель попадает одна строка-образец,
  которую вы передаёте руками. Маскирование и режимы работы с данными описаны в
  [`docs/SECURITY.md`](docs/SECURITY.md).
- Содержимое лога для модели — недоверенные данные: в промпте оно отделено маркерами,
  и модели явно запрещено следовать инструкциям из лога.

## Ограничения текущего MVP

Это минимальная рабочая версия, а не продукт. Честный список:

- **Реальный `wazuh-logtest` не прогонялся**: демон Docker не был запущен, стенд не поднимался.
  Связка «внешняя команда движка → коды возврата → вердикт» проверена end-to-end (`--logtest`,
  `SIGGEN_LOGTEST` и тестовый двойник), но соответствие нашего XML и regex-якорей требованиям
  настоящего движка нужно подтвердить в лаборатории: см. `tests/test_integration_engine.py`.
  При первом запуске ожидайте правок в `siggen/engine.py`.
- Провайдер GigaChat написан, но автотестами не покрыт (в CI не ходим в сеть).
- Веб-интерфейс автотестами не покрыт.
- Обрабатывается одна строка-образец за прогон: нет корпуса логов, кластеризации
  и анализа покрытия (Фаза 4 в `docs/ROADMAP.md`).
- Нет Sigma как входного формата и нет бэкендов Splunk/Elastic (Фаза 3).
- Compliance-маппинг (PCI DSS, ISO 27001, ФСТЭК) не реализован (Фаза 5).
- `FakeProvider` знает два демонстрационных шаблона — это заглушка для тестов, не детектор.
- `rule_id_min`/`rule_id_max` по умолчанию (100100–120000) нужно сверить с диапазоном
  пользовательских правил вашего менеджера.

## Структура

```
siggen/
  cli.py          команды gen / validate
  pipeline.py     оркестрация, реестр ID, отчёт
  models.py       контракты: кандидат от модели → проверенный артефакт
  providers.py    LlmProvider: fake и gigachat
  prompts.py      загрузка версионированных промптов
  emit.py         сборка XML (наш код, не модель)
  validation.py   статические проверки и политика проекта
  engine.py       прогон через wazuh-logtest/ossec-logtest
  data.py         allowlist-ы полей и техник ATT&CK
  ui/app.py       Streamlit
prompts/detection.md    промпт с версией (хэш попадает в provenance)
samples/                демонстрационные строки логов
examples/               пример результата прогона
tests/                  тесты (без сети и без токена)
docs/                   ROADMAP, ARCHITECTURE, SECURITY
```

## Разработка

```bash
python -m pytest
```

Тесты не требуют ни сети, ни токена, ни установленного движка: модель подменяется
`FakeProvider`, `wazuh-logtest` — тестовым двойником в `tests/fixtures/fake_logtest.py`.

## История

Первая версия проекта была демонстрацией «LLM пишет XML OSSEC-декодера»
(видео: https://github.com/M0nteCarl0/Gigachat-SIEM-rules-generator-/assets/5123250/30e9e4d0-aeff-4f86-b8c8-d5133eb9fec5).
Она заменена этим конвейером: идентификаторы, XML и вердикт формирует код, а не модель.
