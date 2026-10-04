# Архитектура

Целевая архитектура Detection-as-Code ассистента. Отражает состояние **после** Фаз 1–3 из [`ROADMAP.md`](./ROADMAP.md);
текущее состояние репозитория описано в разделе «Отображение на существующий код».

---

## 1. Принципы

1. **LLM предлагает — движок проверяет.** Модель не является источником правды ни для синтаксиса, ни для семантики правила.
2. **Structured output вместо парсинга текста.** Модель возвращает JSON по схеме; XML/DSL собирает наш сериализатор. Это убирает целый класс ошибок «модель забыла закрыть тег».
3. **Детерминизм.** Один вход + один промпт + один провайдер = один артефакт. Всё, что влияет на результат, фиксируется в `Provenance`.
4. **Один источник правды для детекции — Sigma.** Платформенные форматы — производные.
5. **Fail loudly.** Неотмапленное поле, неизвестный декодер, коллизия ID — это ошибка сборки, а не warning.
6. **Ничего не пишем в прод-менеджер.** Результат — артефакты в git и pull request.

---

## 2. Компоненты

| Компонент | Ответственность | Технологии |
|---|---|---|
| `siggen.cli` | пользовательские команды: analyze / generate / validate / export / report | `typer` или `argparse` |
| `siggen.ingest` | чтение корпуса логов (файлы, директории, rsyslog/journald дампы, Wazuh API, OpenSearch) | `pathlib`, `httpx` |
| `siggen.coverage` | прогон корпуса через движок, кластеризация неразобранных строк, рейтинг слепых зон | `wazuh-logtest`, шаблонный кластеризатор |
| `siggen.providers` | доступ к LLM за единым интерфейсом | `gigachat`, `FakeProvider` |
| `siggen.prompts` | версионированные промпты и JSON-схемы ответа | файлы `prompts/**`, `jinja2` |
| `siggen.emit` | сериализация модели детекции в целевой формат | собственный Wazuh/OSSEC XML, pySigma-бэкенды Splunk/Elastic |
| `siggen.validate` | статические проверки и прогон движком | `defusedxml`, `lxml`, `wazuh-logtest`, `wazuh-analysisd -t` |
| `siggen.registry` | реестр правил: ID, владелец, статус, версия, платформа | YAML/SQLite |
| `siggen.report` | отчёты для SOC и CISO | Markdown → HTML/PDF/XLSX |
| `siggen.ui` | Streamlit-приложение | `streamlit` |

---

## 3. Поток данных

```
                  ┌──────────────────────────────────────────────────────┐
   источники      │                    siggen pipeline                    │
   логов          │                                                       │
 ┌──────────┐     │  ┌─────────┐   ┌──────────┐   ┌───────────────┐        │
 │ файлы /  │────►│  │ ingest  │──►│ coverage │──►│  candidates   │        │
 │ дампы    │     │  │         │   │ (logtest │   │ (непокрытые   │        │
 ├──────────┤     │  └─────────┘   │  без ПР) │   │  кластеры)    │        │
 │ Wazuh API│────►│                └──────────┘   └───────┬───────┘        │
 ├──────────┤     │                                       │               │
 │OpenSearch│────►│                                       ▼               │
 └──────────┘     │                            ┌────────────────────┐     │
                  │                            │  LLM (structured   │     │
 ┌──────────┐     │                            │  output: Sigma /   │     │
 │ Sigma    │────►│                            │  эскиз декодера)   │     │
 │ (вручную)│     │                            └─────────┬──────────┘     │
 └──────────┘     │                                      │                │
                  │                                      ▼                │
                  │   ┌──────────────┐   ┌────────────────────────────┐   │
                  │   │ дедупликация │◄──│  emit: Wazuh/OSSEC XML,    │   │
                  │   │ с рулсетом   │   │  Splunk/Elastic (pySigma)  │   │
                  │   └──────┬───────┘   └────────────┬───────────────┘   │
                  │          │                        │                   │
                  │          ▼                        ▼                   │
                  │   ┌──────────────────────────────────────────────┐    │
                  │   │  validate: схема XML · коллизии ID · if_sid  │    │
                  │   │  · positive/negative фикстуры · logtest      │    │
                  │   └───────────────────┬──────────────────────────┘    │
                  │                       │                               │
                  └───────────────────────┼───────────────────────────────┘
                                          ▼
                         ┌──────────────────────────────────┐
                         │  артефакты: правила + фикстуры   │
                         │  + provenance + отчёт            │
                         └───────────┬──────────────────────┘
                                     ▼
                    git / pull request ──► ревью ──► деплой правил
                                     └──────► отчёты SOC/CISO
```

---

## 4. Модель данных

Эскиз контрактов (Pydantic v2). Имена полей — ориентир, не финальная спецификация.

> Состояние MVP: реализованы `DetectionCandidate`, `DecoderDraft`, `RuleDraft`, `CheckResult`,
> `ValidationResult`, `Provenance`, `ArtifactBundle`, `PipelineResult` — см. `siggen/models.py`.
> `LogSample`, `CoverageReport`, `LogCluster` и `RuleArtifact` ещё не реализованы: они относятся
> к Фазе 4 (работа с корпусом логов) и Фазе 3 (Sigma как источник).

```python
from datetime import datetime
from typing import Literal, Sequence
from pydantic import BaseModel, Field

Engine = Literal["wazuh", "ossec", "splunk", "elastic"]


class LogSample(BaseModel):
    """Строка лога, пригодная для прогона через движок."""
    raw: str
    source: str                 # файл/API/поток
    location: str | None = None # для <location>, если требуется
    observed_at: datetime | None = None
    labels: dict[str, str] = {}


class CoverageReport(BaseModel):
    """Результат прогона корпуса: что уже разбирается, что нет."""
    total_lines: int
    decoded_lines: int
    undecoded_clusters: list["LogCluster"]
    per_source: dict[str, float]     # доля разобранных строк по источнику


class LogCluster(BaseModel):
    """Кластер похожих неразобранных строк — единица работы для генерации."""
    template: str
    count: int
    examples: Sequence[LogSample]
    decoder_hint: str | None = None


class DetectionCandidate(BaseModel):
    """То, что модель предлагает. Ещё не правило."""
    sigma_yaml: str | None = None        # предпочтительный вход
    decoder_draft: str | None = None     # если нужен новый декодер
    logsource: dict[str, str]
    mitre_techniques: list[str] = []     # ["T1078"]
    evidence: Sequence[LogSample]        # на чём основано предложение
    confidence: float = Field(ge=0.0, le=1.0)
    rationale: str


class RuleArtifact(BaseModel):
    """Готовый артефакт под конкретный движок."""
    engine: Engine
    rule_id: int
    level: int
    description: str
    body: str                       # XML или DSL
    groups: list[str] = []
    compliance: dict[str, list[str]] = {}   # {"pci_dss": ["10.2.5"], "nist_800_53": ["AU.9"]}
    mitre_techniques: list[str] = []


class ValidationResult(BaseModel):
    rule_id: int
    engine: Engine
    static_checks: dict[str, bool]     # schema, id_range, refs, escaping
    positive_fixtures: tuple[int, int] # (успешно, всего)
    negative_fixtures: tuple[int, int]
    logtest_exit_code: int | None = None
    logtest_phase3: dict | None = None  # matched rule, level, groups, compliance
    passed: bool
    failures: list[str] = []


class Provenance(BaseModel):
    """Прослеживаемость — требование и SOC, и CISO."""
    model: str
    provider: str
    prompt_name: str
    prompt_version: str
    prompt_hash: str
    corpus_hash: str
    sigma_uuid: str | None = None
    generated_at: datetime
    generated_by: str
    reviewed_by: str | None = None
    review_state: Literal["draft", "tested", "reviewed", "prod", "deprecated"] = "draft"
```

**Реестр ID.** Отдельный файл (например, `registry/rules.yaml` или SQLite) хранит соответствие
`sigma_uuid → rule_id` по каждому движку, с резервированием диапазона под пользовательские правила
и проверкой отсутствия коллизий с существующим рулсетом. Диапазон пользовательских ID фиксируется конфигом
и сверяется с фактическим рулсетом целевого менеджера, а не берётся «на память».

---

## 5. Провайдер LLM

```python
from typing import Protocol

class LlmProvider(Protocol):
    name: str

    def complete_structured(
        self,
        system_prompt: str,
        user_payload: dict,
        response_schema: dict,
        *,
        temperature: float = 0.0,
    ) -> dict:
        """Возвращает объект, соответствующий response_schema. Ошибку — исключением."""
```

Реализации:
- `GigaChatProvider` — облачный или on-prem endpoint; `verify_ssl_certs=True` по умолчанию;
- `FakeProvider` — детерминированные ответы из `tests/fixtures/llm/*.json`; используется в CI, чтобы тесты не требовали ни сети, ни токена;
- опционально `RecordReplayProvider` — запись реальных ответов для регрессионных тестов.

Требования к провайдеру: таймауты, retry с backoff, учёт usage/tokens, жёсткий лимит на размер входа,
запрет логировать сырые промпты и секреты (см. `SECURITY.md`).

---

## 6. Валидация

Два независимых уровня. Второй обязателен, первый — дешёвый фильтр.

**Статические проверки** (без движка, быстрые):
- well-formedness и соответствие схеме (`defusedxml`, DTD/entities отключены);
- диапазон и уникальность `rule_id`, отсутствие коллизий с существующим рулсетом;
- ссылки `<if_sid>`, `<if_group>`, `<parent>` на существующие правила/декодеры;
- корректность escaping в `<regex>`/`<field>`;
- политика: правило с `active-response` требует ручного ревью и отдельной метки.

**Прогон движком** (источник правды):
```
wazuh-analysisd -t                                        # конфигурация валидна
wazuh-logtest -U "<rule_id>:<level>:<decoder>"            # exit 0 → правило матчится
```
Плюс разбор вывода фаз 1/2/3: какое правило сматчилось, уровень, группы, compliance-маппинг.
Для интеграции без shell — Wazuh Server API `logtest` (JWT, `PUT` для проверки строки, `DELETE` для снятия сессии).
Для OSSEC — `ossec-logtest` через тот же интерфейс runner-а.

Команда движка берётся либо из `PATH`, либо задаётся явно (`--logtest`, `SIGGEN_LOGTEST`):
в лаборатории `wazuh-logtest` живёт внутри контейнера, и без этого его не вызвать. Реализация —
`LogtestRunner.from_settings` в `siggen/engine.py`; разбор командной строки не считает обратный
слэш экранированием, иначе пути Windows разваливаются.

Фикстуры каждого правила:
```
rules/100042/
├── rule.xml
├── positive/*.log     # должно сматчиться, ожидаемый rule_id и level
├── negative/*.log     # не должно сматчиться
└── provenance.json
```

Правило считается готовым только при `positive = all passed` и `negative = 0 matches`.

---

## 7. Экспортёры

| Движок | Путь | Проверка |
|---|---|---|
| Wazuh | собственный XML-эмиттер (`<rule>`, `<decoder>`, `<if_sid>`, `<field>`, `<mitre>`, compliance-группы) | `wazuh-logtest` |
| OSSEC | тот же эмиттер, отличия формата — в конфиге | `ossec-logtest` |
| Splunk | pySigma-бэкенд | unit-тесты + опционально живая инсталляция |
| Elastic | pySigma-бэкенд | unit-тесты + опционально живая инсталляция |

Особенности Wazuh/OSSEC, которые эмиттер обязан учитывать:
- модель «базовое правило + `<field>`/`<if_sid>`», а не декларативное условие Sigma;
- отсутствие общей OR-логики → одна Sigma раскладывается в несколько правил (DNF), связь хранится в реестре;
- корреляции выражаются композицией (`<if_matched_sid>` + `frequency`/`timeframe`), а не напрямую;
- поля маппятся явно; неотмапленное поле = ошибка (иначе правило компилируется и молча никогда не срабатывает).

---

## 8. Развёртывание

```
docker-compose.yml
├── wazuh-manager        # изолированный инстанс только для валидации
├── siggen-validator     # runner: кладёт кандидатов как local_rules.xml, гоняет logtest
├── siggen-cli           # CLI
└── siggen-ui (опц.)     # Streamlit
```

Правила:
- валидационный менеджер не имеет доступа к продакшн-инфраструктуре и не пишет в прод-рулсет;
- секреты (токен GigaChat, креды Wazuh API) — только через переменные окружения/секрет-хранилище;
- для on-prem LLM конфигурация не отличается, меняется только endpoint;
- артефакты прогона (отчёты, фикстуры, provenance) сохраняются как build artifacts CI.

---

## 9. Тестируемость

| Уровень | Что проверяет |
|---|---|
| Unit | контракты, сериализация XML, маппинг полей, дедупликация, кластеризация |
| Golden/snapshot | промпт + `FakeProvider` → стабильный артефакт (ловит регрессии промптов) |
| Integration | `docker-compose` + `wazuh-logtest` на фикстурах (тег `integration`, отдельный job в CI) |
| Contract | JSON-схема ответа модели; обновление схемы без миграции ломает тест |

`FakeProvider` обязателен: без него нельзя ни запускать CI без токена, ни воспроизводить баги.

---

## 10. ADR (краткие решения)

| # | Решение | Обоснование | Альтернатива |
|---|---|---|---|
| A1 | XML собирает наш сериализатор, а не модель | убирает битый XML и упрощает тесты | «модель возвращает XML» — текущее состояние, отклонено |
| A2 | Sigma как вход, платформенные форматы как выход | один источник правды, отраслевой стандарт | собственный промежуточный DSL |
| A3 | Wazuh — основной движок валидации, OSSEC — через тот же runner | классический OSSEC-репозиторий замер на 3.7.0, у Wazuh есть `wazuh-logtest` | OSSEC-only |
| A4 | Собственный XML-эмиттер для Wazuh/OSSEC | официального pySigma-бэкенда для Wazuh/OSSEC нет | ждать upstream-бэкенда |
| A5 | Неотмапленное поле — ошибка | отсекает класс правил, которые никогда не сработают | warning и «починим потом» |
| A6 | Провайдер LLM за интерфейсом | тесты без сети, возможность смены модели | прямые вызовы SDK (текущее состояние) |
| A7 | Промпты — файлы с версией | ревью промпта как кода, воспроизводимость | строки внутри модулей |
| A8 | Артефакты только через git + PR | аудит и прослеживаемость | прямая запись в прод |

---

## 11. Отображение на существующий код

| Сейчас | Куда переходит |
|---|---|
| `cli_version.py` (не компилируется) | `siggen/cli.py` |
| `siem_rules_generator.py` (Streamlit, `while True`) | `siggen/ui/app.py`, логика — в `siggen` |
| Промпт-константа в двух файлах | `prompts/*.md` + `siggen/prompts` |
| Прямой `GigaChat(...)` в модуле | `siggen/providers/gigachat.py` за `LlmProvider` |
| Нет валидации | `siggen/validate` + `docker-compose` с Wazuh |
| `requirements.txt` (112 пакетов) | `pyproject.toml` + lock (`uv`) |

---

## 12. Как расширять

- **Новый движок:** реализовать `Emitter` (модель → формат) и `EngineRunner` (фикстуры → результат). Если для платформы существует pySigma-бэкенд — предпочесть его вместо своего эмиттера.
- **Новый источник логов:** реализовать `LogSource` с методом `iter_samples()`.
- **Новая модель:** реализовать `LlmProvider`; регрессионные тесты прогоняются на `RecordReplayProvider` с сохранёнными ответами.
- **Новое compliance-требование:** добавить запись в `config/compliance.yaml`, код не меняется.
