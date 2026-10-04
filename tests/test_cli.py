"""CLI: коды возврата, пригодные для CI-gate."""

from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

from siggen.cli import EXIT_OK, EXIT_USAGE, EXIT_VALIDATION_FAILED, main

from conftest import POSITIVE

REPO_ROOT = Path(__file__).resolve().parents[1]
SAMPLES = REPO_ROOT / "samples"


@pytest.fixture(autouse=True)
def _no_engine(monkeypatch: pytest.MonkeyPatch) -> None:
    """Тесты не должны зависеть от того, установлен ли wazuh-logtest на машине."""
    monkeypatch.setattr(
        "siggen.engine.LogtestRunner.detect", staticmethod(lambda _engine: None)
    )


def _gen_args(tmp_path: Path, *extra: str) -> list[str]:
    return [
        "gen",
        "--log", str(SAMPLES / "positive.log"),
        "--negative", str(SAMPLES / "negative.log"),
        "--out", str(tmp_path / "out"),
        "--registry", str(tmp_path / "registry.json"),
        *extra,
    ]


def test_gen_returns_success(tmp_path: Path) -> None:
    assert main(_gen_args(tmp_path)) == EXIT_OK
    assert (tmp_path / "out" / "report.md").is_file()


def test_gen_reports_unverified_engine(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    main(_gen_args(tmp_path))
    output = capsys.readouterr().out
    assert "skipped" in output
    assert "ГОТОВО К РЕВЬЮ" in output


def test_gen_with_require_engine_fails_when_engine_missing(tmp_path: Path) -> None:
    assert main(_gen_args(tmp_path, "--require-engine")) == EXIT_VALIDATION_FAILED


def test_gen_reports_missing_file_as_usage_error(tmp_path: Path) -> None:
    args = ["gen", "--log", str(tmp_path / "nope.log"), "--out", str(tmp_path / "out"),
            "--registry", str(tmp_path / "registry.json")]
    assert main(args) == EXIT_USAGE


def test_gen_reports_unknown_log_pattern_as_usage_error(tmp_path: Path) -> None:
    odd = tmp_path / "odd.log"
    odd.write_text("kernel: something unrelated happened\n", encoding="utf-8")
    args = ["gen", "--log", str(odd), "--out", str(tmp_path / "out"),
            "--registry", str(tmp_path / "registry.json")]
    assert main(args) == EXIT_USAGE


def test_gen_reads_stdin(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("sys.stdin", io.StringIO(POSITIVE + "\n"))
    args = ["gen", "--log", "-", "--out", str(tmp_path / "out"),
            "--registry", str(tmp_path / "registry.json")]
    assert main(args) == EXIT_OK


def test_gen_json_output_is_machine_readable(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    assert main(_gen_args(tmp_path, "--json")) == EXIT_OK
    payload = json.loads(capsys.readouterr().out)
    assert payload["ok"] is True
    assert payload["bundle"]["rule_id"] == 100_100
    assert payload["bundle"]["validation"]["engine_status"] == "skipped"


def test_validate_rechecks_existing_artifact(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    main(_gen_args(tmp_path))
    capsys.readouterr()
    directory = tmp_path / "out" / "wazuh-100100"

    exit_code = main(["validate", "--path", str(directory),
                      "--registry", str(tmp_path / "registry.json")])
    assert exit_code == EXIT_OK
    # Перепроверка обновляет сохранённый вердикт.
    saved = json.loads((directory / "validation.json").read_text(encoding="utf-8"))
    assert saved["rule_id"] == 100_100


def test_validate_with_require_engine_fails(tmp_path: Path) -> None:
    main(_gen_args(tmp_path))
    directory = tmp_path / "out" / "wazuh-100100"
    assert main(["validate", "--path", str(directory), "--require-engine",
                 "--registry", str(tmp_path / "registry.json")]) == EXIT_VALIDATION_FAILED


def test_validate_reports_missing_directory(tmp_path: Path) -> None:
    assert main(["validate", "--path", str(tmp_path / "absent")]) == EXIT_USAGE


# --- движок, доступный по явной команде ----------------------------------------


def _logtest_command(fake_binary: list[str]) -> str:
    """Кавычки обязательны: путь к интерпретатору содержит пробелы."""
    return " ".join(f'"{part}"' for part in fake_binary)


def test_logtest_option_runs_engine_check(
    tmp_path: Path, fake_binary: list[str], capsys: pytest.CaptureFixture
) -> None:
    """С --logtest прогон через движок становится частью вердикта, а не skip."""
    exit_code = main(
        _gen_args(tmp_path, "--logtest", _logtest_command(fake_binary), "--require-engine")
    )
    assert exit_code == EXIT_OK
    assert "passed" in capsys.readouterr().out


def test_logtest_option_blocks_false_positive(
    tmp_path: Path, fake_binary: list[str]
) -> None:
    """Negative-пример совпадает с positive: движок отвергает правило, релиз блокируется."""
    noisy = tmp_path / "noise.log"
    noisy.write_text(POSITIVE + "\n", encoding="utf-8")
    args = [
        "gen",
        "--log", str(SAMPLES / "positive.log"),
        "--negative", str(noisy),
        "--out", str(tmp_path / "out"),
        "--registry", str(tmp_path / "registry.json"),
        "--logtest", _logtest_command(fake_binary),
    ]
    assert main(args) == EXIT_VALIDATION_FAILED
