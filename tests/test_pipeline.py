"""Пайплайн целиком: от строки лога до проверенного артефакта."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from siggen.config import Settings
from siggen.engine import LogtestRunner
from siggen.pipeline import (
    GenerateOptions,
    Registry,
    first_meaningful_line,
    generate,
    load_candidate,
    rule_id_from_xml,
)
from siggen.prompts import load_prompt
from siggen.providers import FakeProvider

from conftest import NEGATIVE, POSITIVE, StubProvider


def _generate(settings: Settings, tmp_path: Path, *, provider=None, negative=NEGATIVE,
              runner=None, write: bool = True):
    out_dir = tmp_path / "out"
    options = GenerateOptions(out_dir=out_dir, write_artifacts=write)
    return generate(
        log_input=POSITIVE,
        negative_input=negative,
        settings=settings,
        provider=provider or FakeProvider(),
        prompt=load_prompt(),
        registry=Registry(settings.registry_path),
        runner=runner,
        options=options,
    )


def test_first_meaningful_line_skips_blank_and_comment() -> None:
    assert first_meaningful_line("\n# comment\n\nreal line\n") == "real line"


def test_first_meaningful_line_rejects_empty_input() -> None:
    with pytest.raises(Exception, match="непустой"):
        first_meaningful_line("   \n\n")


def test_generate_produces_validated_artifact(settings: Settings, tmp_path: Path) -> None:
    result = _generate(settings, tmp_path)

    assert result.ok is True
    assert result.bundle.rule_id == 100_100
    # Движок не установлен в CI — статус должен быть честным.
    assert result.bundle.validation.engine_status == "skipped"

    directory = tmp_path / "out" / "wazuh-100100"
    for name in (
        "candidate.json",
        "decoder.xml",
        "rule.xml",
        "local_rules.xml",
        "positive.log",
        "negative.log",
        "provenance.json",
        "validation.json",
    ):
        assert (directory / name).is_file(), f"нет артефакта {name}"
    assert (tmp_path / "out" / "report.md").is_file()
    assert "ГОТОВО К РЕВЬЮ" in result.report_markdown


def test_registry_records_allocated_id(settings: Settings, tmp_path: Path) -> None:
    _generate(settings, tmp_path)
    registry = json.loads(settings.registry_path.read_text(encoding="utf-8"))
    rules = registry["engines"]["wazuh"]["rules"]
    assert [rule["rule_id"] for rule in rules] == [100_100]
    assert rules[0]["fingerprint"]


def test_second_run_gets_next_id_and_reports_duplicate(
    settings: Settings, tmp_path: Path
) -> None:
    _generate(settings, tmp_path)
    second = _generate(settings, tmp_path)

    assert second.bundle.rule_id == 100_101
    assert any("тем же отпечатком" in message for message in second.messages)
    # Дубликат — предупреждение, а не провал.
    assert second.ok is True


def test_prompt_metadata_is_recorded_in_provenance(settings: Settings, tmp_path: Path) -> None:
    result = _generate(settings, tmp_path)
    provenance = result.bundle.provenance
    assert provenance.prompt_name == "detection"
    assert provenance.prompt_hash == load_prompt().sha256
    assert provenance.provider == "fake"
    assert provenance.log_sample == POSITIVE


def test_engine_passed_when_runner_available(
    settings: Settings, tmp_path: Path, fake_binary: list[str]
) -> None:
    runner = LogtestRunner("wazuh", binary=fake_binary)
    result = _generate(settings, tmp_path, runner=runner)
    assert result.bundle.validation.engine_status == "passed"
    assert result.ok is True


def test_engine_failure_blocks_artifact(
    settings: Settings, tmp_path: Path, fake_binary: list[str]
) -> None:
    """Движок отверг правило — артефакт не готов, ID не закрепляется."""
    runner = LogtestRunner("wazuh", binary=fake_binary)
    result = _generate(settings, tmp_path, runner=runner, negative=POSITIVE)

    assert result.ok is False
    assert result.bundle.validation.engine_status == "failed"
    assert settings.registry_path.is_file() is False
    assert any("ID не закреплён" in message for message in result.messages)


def test_require_engine_turns_skip_into_failure(
    settings: Settings, tmp_path: Path
) -> None:
    strict = Settings(
        engine=settings.engine,
        rule_id_min=settings.rule_id_min,
        rule_id_max=settings.rule_id_max,
        registry_path=settings.registry_path,
        require_engine=True,
    )
    result = _generate(strict, tmp_path)
    assert result.ok is False
    assert result.bundle.validation.engine_status == "failed"
    assert "require-engine" in result.bundle.validation.engine_detail


def test_mitre_outside_allowlist_fails_the_run(settings: Settings, tmp_path: Path,
                                               candidate_payload: dict) -> None:
    candidate_payload["rule"]["mitre"] = ["T9999"]
    result = _generate(settings, tmp_path, provider=StubProvider(candidate_payload))
    assert result.ok is False
    assert any(not c.passed and c.name == "mitre_in_allowlist"
               for c in result.bundle.validation.checks)


def test_broken_model_output_raises_provider_error(settings: Settings, tmp_path: Path) -> None:
    bad = {"rule": {"level": 10}, "confidence": 2.0}
    with pytest.raises(Exception, match="не соответствует контракту"):
        _generate(settings, tmp_path, provider=StubProvider(bad))


def test_artifact_dir_can_be_reloaded(settings: Settings, tmp_path: Path) -> None:
    """Артефакт самодостаточен: по каталогу восстанавливаются кандидат и ID."""
    _generate(settings, tmp_path)
    directory = tmp_path / "out" / "wazuh-100100"

    candidate = load_candidate(directory)
    assert candidate.decoder.name == "myapp-login"
    assert rule_id_from_xml((directory / "rule.xml").read_text(encoding="utf-8"), 4096) == 100_100


def test_registry_rejects_broken_json(settings: Settings, tmp_path: Path) -> None:
    settings.registry_path.write_text("{not json", encoding="utf-8")
    with pytest.raises(Exception, match="повреждён"):
        Registry(settings.registry_path)


def test_registry_rejects_exhausted_range(settings: Settings) -> None:
    narrow = Settings(
        engine="wazuh",
        rule_id_min=100_100,
        rule_id_max=100_101,
        registry_path=settings.registry_path,
    )
    registry = Registry(narrow.registry_path)
    registry.record(
        engine="wazuh", rule_id=100_100, fingerprint="f", description="d", artifact_dir=None
    )
    with pytest.raises(Exception, match="исчерпан"):
        registry.next_id("wazuh", narrow)
