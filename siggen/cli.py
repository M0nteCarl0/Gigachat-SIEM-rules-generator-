"""Командный интерфейс.

Коды возврата: 0 — артефакт прошёл проверки, 1 — проверки не пройдены,
2 — ошибка конфигурации или ввода. Код 1 делает команду пригодной для CI-gate.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

from . import __version__
from .config import Settings
from .engine import LogtestRunner
from .models import ConfigurationError, ProviderError, ValidationResult
from .pipeline import (
    GenerateOptions,
    PipelineResult,
    Registry,
    generate,
    load_candidate,
    rule_id_from_xml,
)
from .prompts import load_prompt
from .providers import build_provider
from .validation import static_checks

EXIT_OK = 0
EXIT_VALIDATION_FAILED = 1
EXIT_USAGE = 2

log = logging.getLogger("siggen")


def _read_input(value: str | None, max_bytes: int) -> str | None:
    """Читает строку лога из файла, из stdin ('-') или возвращает None."""
    if value is None:
        return None
    if value == "-":
        return sys.stdin.read()
    path = Path(value)
    if not path.is_file():
        raise ConfigurationError(f"файл не найден: {path}")
    if path.stat().st_size > max_bytes:
        raise ConfigurationError(
            f"{path} превышает лимит {max_bytes} байт: передавайте образец, а не весь корпус"
        )
    return path.read_text(encoding="utf-8")


def _print_result(result: PipelineResult) -> None:
    bundle = result.bundle
    validation = bundle.validation
    failed = [c for c in validation.checks if not c.passed and c.severity == "error"]
    warned = [c for c in validation.checks if not c.passed and c.severity == "warning"]

    print(f"Правило:      {bundle.engine}/{bundle.rule_id} (level={bundle.candidate.rule.level})")
    print(f"Описание:     {bundle.candidate.rule.description}")
    print(f"Итог:         {'ГОТОВО К РЕВЬЮ' if result.ok else 'НЕ ГОТОВО'}")
    print(f"Проверки:     {len(validation.checks) - len(failed) - len(warned)} ok, "
          f"{len(failed)} fail, {len(warned)} warn")
    for check in failed:
        print(f"  [fail] {check.name}: {check.detail}")
    for check in warned:
        print(f"  [warn] {check.name}: {check.detail}")
    print(f"Движок:       {validation.engine_status} — {validation.engine_detail}")
    if validation.requires_manual_review:
        print("Ручное ревью: " + "; ".join(validation.requires_manual_review))
    for message in result.messages:
        print(f"Примечание:   {message}")
    if bundle.directory:
        print(f"Артефакты:    {bundle.directory}")


def _add_common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--engine", choices=["wazuh", "ossec"], default=None,
                        help="целевой движок (по умолчанию из SIGGEN_ENGINE или wazuh)")
    parser.add_argument("--registry", default=None, help="путь к реестру ID")
    parser.add_argument("--require-engine", action="store_true",
                        help="недоступность движка валидации считать провалом (для CI)")
    parser.add_argument("--json", action="store_true", dest="as_json",
                        help="вывести результат в JSON")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="siggen",
        description="Генератор SIEM-правил для Wazuh/OSSEC: LLM предлагает, движок проверяет",
    )
    parser.add_argument("--version", action="version", version=f"siggen {__version__}")
    parser.add_argument("--verbose", action="store_true", help="подробный лог")
    sub = parser.add_subparsers(dest="command", required=True)

    gen = sub.add_parser("gen", help="сгенерировать и проверить артефакт по строке лога")
    _add_common(gen)
    gen.add_argument("--log", default="-", help="файл со строкой лога, '-' — stdin")
    gen.add_argument("--negative", default=None, help="файл с negative-примером (шум)")
    gen.add_argument("--provider", choices=["fake", "gigachat"], default=None)
    gen.add_argument("--out", default="out", help="каталог для артефактов")

    validate = sub.add_parser("validate", help="перепроверить ранее сгенерированный артефакт")
    _add_common(validate)
    validate.add_argument("--path", required=True, help="каталог артефакта (например out/wazuh-100100)")
    return parser


def _settings(args: argparse.Namespace) -> Settings:
    overrides: dict[str, object] = {
        "engine": args.engine,
        "registry_path": Path(args.registry) if args.registry else None,
        "require_engine": True if args.require_engine else None,
    }
    provider = getattr(args, "provider", None)
    if provider:
        overrides["provider"] = provider
    return Settings.from_env(**overrides)


def cmd_gen(args: argparse.Namespace) -> int:
    settings = _settings(args)
    prompt = load_prompt()
    provider = build_provider(settings)
    registry = Registry(settings.registry_path)

    log_input = _read_input(args.log, settings.max_log_bytes)
    negative_input = _read_input(args.negative, settings.max_log_bytes)
    if log_input is None:
        raise ConfigurationError("не передан образец лога: --log <файл> или --log -")

    result = generate(
        log_input=log_input,
        negative_input=negative_input,
        settings=settings,
        provider=provider,
        prompt=prompt,
        registry=registry,
        options=GenerateOptions(out_dir=Path(args.out), write_artifacts=True),
    )

    if args.as_json:
        print(result.model_dump_json(indent=2))
    else:
        _print_result(result)
        print(f"Отчёт:        {Path(args.out) / 'report.md'}")
    return EXIT_OK if result.ok else EXIT_VALIDATION_FAILED


def cmd_validate(args: argparse.Namespace) -> int:
    directory = Path(args.path)
    if not directory.is_dir():
        raise ConfigurationError(f"каталог не найден: {directory}")

    provenance_path = directory / "provenance.json"
    provenance = (
        json.loads(provenance_path.read_text(encoding="utf-8"))
        if provenance_path.is_file()
        else {}
    )
    engine = args.engine or provenance.get("engine") or "wazuh"
    settings = Settings.from_env(engine=engine, registry_path=Path(args.registry) if args.registry else None,
                                 require_engine=True if args.require_engine else None)

    candidate = load_candidate(directory)
    rule_xml = (directory / "rule.xml").read_text(encoding="utf-8")
    decoder_xml = (directory / "decoder.xml").read_text(encoding="utf-8")
    positive = _read_input(str(directory / "positive.log"), settings.max_log_bytes) or ""
    negative_path = directory / "negative.log"
    negative = negative_path.read_text(encoding="utf-8") if negative_path.is_file() else None

    rule_id = rule_id_from_xml(rule_xml, settings.max_xml_bytes)
    registry = Registry(settings.registry_path)
    used = {k: v for k, v in registry.used_ids(settings.engine).items() if k != rule_id}

    checks, review = static_checks(
        candidate=candidate,
        decoder_xml=decoder_xml,
        rule_xml=rule_xml,
        rule_id=rule_id,
        settings=settings,
        used_ids=used,
        duplicate_of=None,
        has_negative_sample=negative is not None,
    )

    runner = LogtestRunner(settings.engine, timeout=settings.engine_timeout)
    outcome = runner.verify(
        positive=positive,
        negative=negative,
        rule_id=rule_id,
        level=candidate.rule.level,
        decoder=candidate.decoder.name,
    )
    status = outcome.status
    detail = outcome.detail
    if status == "skipped" and settings.require_engine:
        status, detail = "failed", f"{detail} (--require-engine)"

    result = ValidationResult(
        rule_id=rule_id,
        engine=settings.engine,
        checks=checks,
        engine_status=status,  # type: ignore[arg-type]
        engine_detail=detail,
        engine_raw=outcome.raw,
        requires_manual_review=review,
    )
    (directory / "validation.json").write_text(
        result.model_dump_json(indent=2) + "\n", encoding="utf-8"
    )

    if args.as_json:
        print(result.model_dump_json(indent=2))
    else:
        failed = [c for c in checks if not c.passed and c.severity == "error"]
        warned = [c for c in checks if not c.passed and c.severity == "warning"]
        print(f"Артефакт:  {directory} ({engine}/{rule_id})")
        print(f"Итог:      {'ПРОВЕРКА ПРОЙДЕНА' if result.passed else 'ПРОВЕРКА НЕ ПРОЙДЕНА'}")
        print(f"Проверки:  {len(checks) - len(failed) - len(warned)} ok, {len(failed)} fail, "
              f"{len(warned)} warn")
        for check in failed:
            print(f"  [fail] {check.name}: {check.detail}")
        print(f"Движок:    {status} — {detail}")
    return EXIT_OK if result.passed else EXIT_VALIDATION_FAILED


def _configure_stdio() -> None:
    """Переводит stdout/stderr в UTF-8.

    Без этого на Windows-консолях с кодировкой cp1252/cp866 русский текст
    в справке и в отчёте роняет процесс с UnicodeEncodeError.
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:  # pragma: no cover - не-TextIOWrapper (например, в тестах)
            continue
        try:
            reconfigure(encoding="utf-8", errors="replace")
        except (ValueError, OSError):  # pragma: no cover - зависит от окружения
            log.debug("не удалось переключить %r на UTF-8", stream)


def main(argv: list[str] | None = None) -> int:
    _configure_stdio()
    parser = build_parser()
    args = parser.parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="%(levelname)s %(name)s: %(message)s",
    )
    try:
        if args.command == "gen":
            return cmd_gen(args)
        if args.command == "validate":
            return cmd_validate(args)
        parser.error(f"неизвестная команда: {args.command}")
        return EXIT_USAGE
    except (ConfigurationError, ProviderError) as exc:
        print(f"Ошибка: {exc}", file=sys.stderr)
        return EXIT_USAGE
    except KeyboardInterrupt:  # pragma: no cover
        print("Прервано пользователем", file=sys.stderr)
        return EXIT_USAGE


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
