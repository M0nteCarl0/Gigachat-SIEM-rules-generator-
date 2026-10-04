"""Конфигурация и промпты: секреты, версионирование, подстановки."""

from __future__ import annotations

import logging
from pathlib import Path

import pytest

from siggen.config import Settings
from siggen.models import ConfigurationError
from siggen.prompts import load_prompt


def test_default_prompt_is_loaded_and_versioned() -> None:
    prompt = load_prompt()
    assert prompt.name == "detection"
    assert prompt.version == "1"
    assert len(prompt.sha256) == 64


def test_prompt_without_version_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "p.md"
    path.write_text("просто текст без заголовка", encoding="utf-8")
    with pytest.raises(ConfigurationError, match="version"):
        load_prompt(path)


def test_prompt_missing_file_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(ConfigurationError, match="не найден"):
        load_prompt(tmp_path / "absent.md")


def test_render_requires_all_placeholders() -> None:
    prompt = load_prompt()
    with pytest.raises(ConfigurationError, match="не заполнены"):
        prompt.render(engine="wazuh", allowed_fields="srcip", techniques="-")


def test_render_rejects_unknown_placeholders() -> None:
    prompt = load_prompt()
    with pytest.raises(ConfigurationError, match="лишние"):
        prompt.render(
            engine="wazuh", allowed_fields="srcip", techniques="-", log_sample="x", extra="y"
        )


def test_render_leaves_no_placeholders() -> None:
    rendered = load_prompt().render(
        engine="wazuh",
        allowed_fields="srcuser, srcip",
        techniques="- T1110: Brute Force",
        log_sample="line",
    )
    assert "{{" not in rendered
    assert "T1110" in rendered


def test_settings_from_env_reads_values(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SIGGEN_ENGINE", "ossec")
    monkeypatch.setenv("SIGGEN_RULE_ID_MIN", "200000")
    monkeypatch.setenv("SIGGEN_RULE_ID_MAX", "200500")
    monkeypatch.setenv("SIGGEN_PROVIDER", "fake")
    settings = Settings.from_env()
    assert settings.engine == "ossec"
    assert settings.rule_id_min == 200_000
    assert settings.rule_id_max == 200_500


def test_overrides_win_over_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SIGGEN_ENGINE", "ossec")
    monkeypatch.delenv("SIGGEN_PROVIDER", raising=False)
    assert Settings.from_env(engine="wazuh").engine == "wazuh"


def test_bad_rule_id_range_is_rejected() -> None:
    with pytest.raises(ValueError, match="rule_id_min"):
        Settings(rule_id_min=100, rule_id_max=100)


def test_disabled_tls_verification_warns(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.WARNING, logger="siggen.config"):
        Settings(gigachat_verify_ssl=False)
    assert any("TLS" in record.message for record in caplog.records)


def test_tls_verification_is_on_by_default() -> None:
    assert Settings().gigachat_verify_ssl is True


def test_credentials_are_not_stored_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GIGACHAT_CREDENTIALS", raising=False)
    assert Settings.from_env().gigachat_credentials is None
