"""Прогон через движок: коды возврата, фикстуры, честный статус «не проверено»."""

from __future__ import annotations

import shutil

import pytest

from siggen.engine import LogtestRunner

from conftest import NEGATIVE, POSITIVE

RULE_ID = 100_100
LEVEL = 10
DECODER = "myapp-login"


def _runner(fake_binary: list[str], *extra: str) -> LogtestRunner:
    return LogtestRunner("wazuh", binary=[*fake_binary, *extra], timeout=30)


def test_positive_fixture_matches(fake_binary: list[str]) -> None:
    outcome = _runner(fake_binary).test_line(POSITIVE, RULE_ID, LEVEL, DECODER)
    assert outcome.status == "passed"
    assert "100100:10:myapp-login" in outcome.detail


def test_negative_fixture_does_not_match(fake_binary: list[str]) -> None:
    outcome = _runner(fake_binary).test_line(NEGATIVE, RULE_ID, LEVEL, DECODER)
    assert outcome.status == "failed"


def test_verify_passes_when_positive_matches_and_negative_does_not(
    fake_binary: list[str],
) -> None:
    outcome = _runner(fake_binary).verify(
        positive=POSITIVE, negative=NEGATIVE, rule_id=RULE_ID, level=LEVEL, decoder=DECODER
    )
    assert outcome.status == "passed"


def test_verify_fails_on_false_positive(fake_binary: list[str]) -> None:
    """Negative-фикстура, которая всё равно матчится, — это ложное срабатывание."""
    outcome = _runner(fake_binary).verify(
        positive=POSITIVE, negative=POSITIVE, rule_id=RULE_ID, level=LEVEL, decoder=DECODER
    )
    assert outcome.status == "failed"
    assert "ложное срабатывание" in outcome.detail


def test_verify_fails_when_positive_does_not_match(fake_binary: list[str]) -> None:
    outcome = _runner(fake_binary).verify(
        positive=NEGATIVE, negative=NEGATIVE, rule_id=RULE_ID, level=LEVEL, decoder=DECODER
    )
    assert outcome.status == "failed"


def test_unsupported_option_is_skipped_not_failed(fake_binary: list[str]) -> None:
    """Движок без поддержки -U: честнее сказать «не проверено», чем «провал»."""
    outcome = _runner(fake_binary, "--unsupported").test_line(POSITIVE, RULE_ID, LEVEL, DECODER)
    assert outcome.status == "skipped"
    assert "не поддерживает" in outcome.detail


def test_missing_binary_is_skipped(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(shutil, "which", lambda _name: None)
    runner = LogtestRunner("wazuh")
    assert runner.available is False
    outcome = runner.test_line(POSITIVE, RULE_ID, LEVEL, DECODER)
    assert outcome.status == "skipped"
    assert "не найден в PATH" in outcome.detail


def test_verify_skips_negative_when_engine_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(shutil, "which", lambda _name: None)
    outcome = LogtestRunner("wazuh").verify(
        positive=POSITIVE, negative=NEGATIVE, rule_id=RULE_ID, level=LEVEL, decoder=DECODER
    )
    assert outcome.status == "skipped"
