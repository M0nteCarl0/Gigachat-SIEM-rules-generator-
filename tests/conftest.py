"""Общие фикстуры для тестов."""

from __future__ import annotations

import copy
import sys
from pathlib import Path

import pytest

from siggen.config import Settings
from siggen.providers import FakeProvider

FIXTURES = Path(__file__).resolve().parent / "fixtures"
REPO_ROOT = Path(__file__).resolve().parents[1]
POSITIVE = (REPO_ROOT / "samples" / "positive.log").read_text(encoding="utf-8").strip()
NEGATIVE = (REPO_ROOT / "samples" / "negative.log").read_text(encoding="utf-8").strip()


class StubProvider:
    """Провайдер, возвращающий заранее заданный ответ: для негативных сценариев."""

    name = "stub"
    model = "stub"

    def __init__(self, payload: dict) -> None:
        self.payload = payload

    def complete_structured(self, **_kwargs: object) -> dict:
        return copy.deepcopy(self.payload)


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return Settings(
        engine="wazuh",
        provider="fake",
        rule_id_min=100_100,
        rule_id_max=100_200,
        registry_path=tmp_path / "registry.json",
    )


@pytest.fixture
def fake_binary() -> list[str]:
    """Команда тестового двойника wazuh-logtest."""
    return [sys.executable, str(FIXTURES / "fake_logtest.py")]


@pytest.fixture
def candidate_payload() -> dict:
    """Валидный кандидат из FakeProvider — база для негативных проверок."""
    payload = FakeProvider().complete_structured(
        system_prompt="", user_payload={"log_sample": POSITIVE}, response_schema={}
    )
    return copy.deepcopy(payload)
