"""Интеграционный прогон через настоящий движок Wazuh/OSSEC.

По умолчанию тесты пропускаются: нужна поднятая лаборатория и развёрнутый на ней
пример правил. Порядок включения:

1. поднять лабораторию:      docker compose up -d
2. положить пример правил в лабораторный рулсет:
     docker compose cp examples/myapp-login-failed/local_rules.xml \\
       wazuh-manager:/var/ossec/etc/rules/local_rules.xml
3. проверить конфигурацию:   docker compose exec wazuh-manager /var/ossec/bin/wazuh-analysisd -t
4. прогнать тесты (вариант без локального бинаря — через команду движка):
     SIGGEN_LAB=1 \\
     SIGGEN_LOGTEST="docker compose exec -T wazuh-manager /var/ossec/bin/wazuh-logtest" \\
       python -m pytest -m integration -v

Именно этот прогон превращает вердикт «не проверено» в «проверено».
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from siggen.config import Settings
from siggen.engine import LogtestRunner
from siggen.pipeline import load_candidate, rule_id_from_xml

pytestmark = pytest.mark.integration

REPO_ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = REPO_ROOT / "examples" / "myapp-login-failed"
LAB_ENABLED = os.getenv("SIGGEN_LAB") == "1"


@pytest.mark.skipif(
    not LAB_ENABLED,
    reason=(
        "лаборатория не включена: задайте SIGGEN_LAB=1 и SIGGEN_LOGTEST после "
        "развёртывания examples/myapp-login-failed/local_rules.xml (см. docstring)"
    ),
)
def test_real_engine_accepts_example_rule() -> None:
    """Пример правила должен сматчиться на positive и не сматчиться на negative."""
    settings = Settings.from_env(engine="wazuh")
    runner = LogtestRunner.from_settings(settings)
    if not runner.available:
        pytest.skip(
            "движок недоступен: поднимите лабораторию и задайте SIGGEN_LOGTEST "
            "или добавьте wazuh-logtest в PATH"
        )

    candidate = load_candidate(EXAMPLE)
    rule_xml = (EXAMPLE / "rule.xml").read_text(encoding="utf-8")
    rule_id = rule_id_from_xml(rule_xml, settings.max_xml_bytes)
    positive = (EXAMPLE / "positive.log").read_text(encoding="utf-8").strip()
    negative = (EXAMPLE / "negative.log").read_text(encoding="utf-8").strip()

    outcome = runner.verify(
        positive=positive,
        negative=negative,
        rule_id=rule_id,
        level=candidate.rule.level,
        decoder=candidate.decoder.name,
    )

    assert outcome.status == "passed", (
        "движок не подтвердил правило.\n"
        f"статус: {outcome.status}\n"
        f"детали: {outcome.detail}\n"
        "проверьте, что правила развёрнуты и имя декодера совпадает с "
        f"{candidate.decoder.name!r}\n"
        f"вывод движка:\n{outcome.raw}"
    )


@pytest.mark.skipif(
    not LAB_ENABLED,
    reason="лаборатория не включена: SIGGEN_LAB=1",
)
def test_lab_engine_is_reachable() -> None:
    """Явная проверка доступности движка: без неё интеграционные тесты бессмысленны."""
    runner = LogtestRunner.from_settings(Settings.from_env(engine="wazuh"))
    assert runner.available, (
        "движок не найден. Задайте SIGGEN_LOGTEST, например: "
        "docker compose exec -T wazuh-manager /var/ossec/bin/wazuh-logtest"
    )
