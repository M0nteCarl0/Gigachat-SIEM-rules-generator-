"""Оркестрация: строка лога → кандидат → артефакт → валидация → отчёт.

Здесь сходятся все части и применяется главный инвариант проекта:
артефакт получает идентификатор, XML и вердикт только после статических
проверок и (когда доступен) прогона через движок.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from .config import Settings
from .data import MITRE_TECHNIQUES, OSSEC_ORDER_FIELDS
from .emit import render_decoder, render_rule, render_ruleset
from .engine import LogtestRunner
from .models import (
    ArtifactBundle,
    ConfigurationError,
    DetectionCandidate,
    PipelineResult,
    Provenance,
    ProviderError,
    ValidationResult,
    utcnow,
)
from .prompts import PromptTemplate
from .providers import LlmProvider
from .validation import parse_xml_safe, static_checks

log = logging.getLogger(__name__)


# --- реестр идентификаторов -----------------------------------------------------


class Registry:
    """Учёт выделенных ID и отпечатков правил.

    Идентификаторы выделяет наша система, а не модель: иначе два прогона
    займут один номер, и менеджер откажется грузить рулсет.
    """

    VERSION = 1

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._data: dict[str, Any] = {"version": self.VERSION, "engines": {}}
        if self.path.is_file():
            try:
                loaded = json.loads(self.path.read_text(encoding="utf-8"))
            except json.JSONDecodeError as exc:
                raise ConfigurationError(f"реестр {self.path} повреждён: {exc}") from exc
            if not isinstance(loaded, dict) or "engines" not in loaded:
                raise ConfigurationError(f"реестр {self.path} имеет неожиданный формат")
            self._data = loaded

    def _rules(self, engine: str) -> list[dict[str, Any]]:
        engines = self._data.setdefault("engines", {})
        entry = engines.setdefault(engine, {"rules": []})
        return entry.setdefault("rules", [])

    def used_ids(self, engine: str) -> dict[int, str]:
        return {
            int(rule["rule_id"]): str(rule.get("description", ""))
            for rule in self._rules(engine)
        }

    def next_id(self, engine: str, settings: Settings) -> int:
        """Первый свободный ID в разрешённом диапазоне."""
        used = set(self.used_ids(engine))
        candidate = settings.rule_id_min
        while candidate in used:
            candidate += 1
            if candidate >= settings.rule_id_max:
                raise ConfigurationError(
                    f"диапазон ID [{settings.rule_id_min}; {settings.rule_id_max}) исчерпан"
                )
        return candidate

    def find_by_fingerprint(self, engine: str, fingerprint: str) -> int | None:
        for rule in self._rules(engine):
            if rule.get("fingerprint") == fingerprint:
                return int(rule["rule_id"])
        return None

    def record(
        self,
        *,
        engine: str,
        rule_id: int,
        fingerprint: str,
        description: str,
        artifact_dir: str | None,
    ) -> None:
        # Путь пишем через прямой слэш: реестр лежит в git и переносится между ОС.
        normalized = Path(artifact_dir).as_posix() if artifact_dir else None
        self._rules(engine).append(
            {
                "rule_id": rule_id,
                "fingerprint": fingerprint,
                "description": description,
                "artifact_dir": normalized,
                "created_at": utcnow().isoformat(),
            }
        )

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(
            json.dumps(self._data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )


# --- вспомогательное ------------------------------------------------------------


def first_meaningful_line(raw: str) -> str:
    """Берёт первую непустую строку: остальной корпус — задача следующих фаз."""
    for line in raw.splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            return stripped
    raise ConfigurationError("на входе нет ни одной непустой строки лога")


def _prompt_values(sample: str, settings: Settings) -> dict[str, str]:
    return {
        "engine": settings.engine,
        "allowed_fields": ", ".join(sorted(OSSEC_ORDER_FIELDS)),
        "techniques": "\n".join(
            f"- {code}: {name}" for code, name in sorted(MITRE_TECHNIQUES.items())
        ),
        "log_sample": sample,
    }


def render_report(result: PipelineResult) -> str:
    """Формирует отчёт в markdown: его прикладывают к PR и отдают на ревью."""
    bundle = result.bundle
    validation = bundle.validation
    verdict = "ГОТОВО К РЕВЬЮ" if result.ok else "НЕ ГОТОВО"

    lines: list[str] = [
        "# Отчёт генератора детекций",
        "",
        f"- Итог: **{verdict}**",
        f"- Движок: `{bundle.engine}`",
        f"- Правило: `{bundle.rule_id}`, уровень `{bundle.candidate.rule.level}`",
        f"- Описание: {bundle.candidate.rule.description}",
        f"- Уверенность модели: {bundle.candidate.confidence}",
        f"- Провайдер: `{bundle.provenance.provider}` ({bundle.provenance.model})",
        (
            f"- Промпт: `{bundle.provenance.prompt_name}` v{bundle.provenance.prompt_version} "
            f"sha256 `{bundle.provenance.prompt_hash[:12]}…`"
        ),
        "",
        "## Проверки",
        "",
        "| Проверка | Статус | Уровень | Детали |",
        "|---|---|---|---|",
    ]
    for check in validation.checks:
        status = "ok" if check.passed else "fail"
        lines.append(
            f"| `{check.name}` | {status} | {check.severity} | {check.detail} |"
        )
    lines += [
        "",
        "## Прогон через движок",
        "",
        f"- Статус: `{validation.engine_status}`",
        f"- Детали: {validation.engine_detail or '—'}",
    ]
    if validation.engine_raw:
        lines += ["", "```", validation.engine_raw.strip()[:4000], "```"]

    lines += ["", "## Требует ручного ревью", ""]
    lines += (
        [f"- {item}" for item in validation.requires_manual_review]
        if validation.requires_manual_review
        else ["- нет"]
    )

    lines += ["", "## Сообщения", ""]
    lines += [f"- {message}" for message in result.messages] if result.messages else ["- нет"]

    lines += [
        "",
        "## Обоснование модели",
        "",
        bundle.candidate.rationale or "—",
        "",
    ]
    return "\n".join(lines)


def _write_artifacts(directory: Path, bundle: ArtifactBundle, positive: str, negative: str | None) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "candidate.json").write_text(
        bundle.candidate.model_dump_json(indent=2) + "\n", encoding="utf-8"
    )
    (directory / "decoder.xml").write_text(
        bundle.decoder_xml
        + "\n<!-- Сгенерировано siggen, требует ревью перед деплоем -->\n",
        encoding="utf-8",
    )
    (directory / "rule.xml").write_text(bundle.rule_xml, encoding="utf-8")
    (directory / "local_rules.xml").write_text(
        render_ruleset(bundle.decoder_xml, bundle.rule_xml), encoding="utf-8"
    )
    (directory / "positive.log").write_text(positive + "\n", encoding="utf-8")
    if negative:
        (directory / "negative.log").write_text(negative + "\n", encoding="utf-8")
    (directory / "provenance.json").write_text(
        bundle.provenance.model_dump_json(indent=2) + "\n", encoding="utf-8"
    )
    (directory / "validation.json").write_text(
        bundle.validation.model_dump_json(indent=2) + "\n", encoding="utf-8"
    )


# --- основной сценарий ----------------------------------------------------------

@dataclass
class GenerateOptions:
    """Параметры одного прогона генерации."""

    out_dir: Path | None = None
    write_artifacts: bool = True


def generate(
    *,
    log_input: str,
    negative_input: str | None,
    settings: Settings,
    provider: LlmProvider,
    prompt: PromptTemplate,
    registry: Registry,
    runner: LogtestRunner | None = None,
    options: GenerateOptions | None = None,
) -> PipelineResult:
    """Полный проход: от строки лога до проверенного артефакта."""
    options = options or GenerateOptions()
    messages: list[str] = []

    sample = first_meaningful_line(log_input)
    negative = first_meaningful_line(negative_input) if negative_input else None

    if len(sample.encode("utf-8")) > settings.max_log_bytes:
        raise ConfigurationError(
            f"строка лога превышает лимит {settings.max_log_bytes} байт"
        )

    # 1. Предложение модели. Ответ — недоверенный ввод, поэтому проверяем схемой.
    system_prompt = prompt.render(**_prompt_values(sample, settings))
    raw_candidate = provider.complete_structured(
        system_prompt=system_prompt,
        user_payload={"log_sample": sample, "engine": settings.engine},
        response_schema=DetectionCandidate.model_json_schema(),
    )
    try:
        candidate = DetectionCandidate.model_validate(raw_candidate)
    except ValidationError as exc:
        raise ProviderError(f"ответ модели не соответствует контракту: {exc}") from exc

    # 2. Идентификатор и проверка на дубликат.
    rule_id = registry.next_id(settings.engine, settings)
    fingerprint = candidate.fingerprint()
    duplicate_of = registry.find_by_fingerprint(settings.engine, fingerprint)
    if duplicate_of is not None:
        messages.append(
            f"найден артефакт с тем же отпечатком: id={duplicate_of} "
            "(возможно, детекция уже описана)"
        )

    # 3. Сборка XML нашим кодом.
    decoder_xml = render_decoder(candidate.decoder)
    rule_xml = render_rule(settings.engine, rule_id, candidate.rule)

    # 4. Статические проверки и политика проекта.
    checks, review = static_checks(
        candidate=candidate,
        decoder_xml=decoder_xml,
        rule_xml=rule_xml,
        rule_id=rule_id,
        settings=settings,
        used_ids=registry.used_ids(settings.engine),
        duplicate_of=duplicate_of,
        has_negative_sample=negative is not None,
    )

    # 5. Прогон через движок.
    runner = runner or LogtestRunner(settings.engine, timeout=settings.engine_timeout)
    outcome = runner.verify(
        positive=sample,
        negative=negative,
        rule_id=rule_id,
        level=candidate.rule.level,
        decoder=candidate.decoder.name,
    )
    if outcome.status == "skipped" and settings.require_engine:
        outcome_status = "failed"
        engine_detail = f"{outcome.detail} (--require-engine: недоступность движка = провал)"
    else:
        outcome_status = outcome.status
        engine_detail = outcome.detail

    validation = ValidationResult(
        rule_id=rule_id,
        engine=settings.engine,
        checks=checks,
        engine_status=outcome_status,  # type: ignore[arg-type]
        engine_detail=engine_detail,
        engine_raw=outcome.raw,
        requires_manual_review=review,
    )

    provenance = Provenance(
        provider=provider.name,
        model=provider.model,
        prompt_name=prompt.name,
        prompt_version=prompt.version,
        prompt_hash=prompt.sha256,
        engine=settings.engine,
        log_sample=sample,
        confidence=candidate.confidence,
        rationale=candidate.rationale,
    )

    bundle = ArtifactBundle(
        engine=settings.engine,
        rule_id=rule_id,
        decoder_xml=decoder_xml,
        rule_xml=rule_xml,
        positive_sample=sample,
        negative_sample=negative,
        candidate=candidate,
        provenance=provenance,
        validation=validation,
    )

    if options.write_artifacts and options.out_dir is not None:
        directory = options.out_dir / f"{settings.engine}-{rule_id}"
        bundle.directory = str(directory)
        _write_artifacts(directory, bundle, sample, negative)
        if validation.passed:
            registry.record(
                engine=settings.engine,
                rule_id=rule_id,
                fingerprint=fingerprint,
                description=candidate.rule.description,
                artifact_dir=str(directory),
            )
            registry.save()
        else:
            messages.append(
                "артефакт не прошёл проверки: ID не закреплён в реестре, "
                "файлы сохранены для разбора"
            )

    result = PipelineResult(
        ok=validation.passed, bundle=bundle, report_markdown="", messages=messages
    )
    result.report_markdown = render_report(result)

    if options.write_artifacts and options.out_dir is not None:
        (options.out_dir / "report.md").write_text(result.report_markdown, encoding="utf-8")

    return result


def load_candidate(directory: Path) -> DetectionCandidate:
    """Читает сохранённый кандидат: артефакт должен быть самодостаточным."""
    path = directory / "candidate.json"
    if not path.is_file():
        raise ConfigurationError(f"в {directory} нет candidate.json")
    return DetectionCandidate.model_validate(json.loads(path.read_text(encoding="utf-8")))


def rule_id_from_xml(rule_xml: str, max_bytes: int) -> int:
    """Достаёт id правила из rule.xml — артефакт описывает сам себя."""
    root = parse_xml_safe(rule_xml, max_bytes)
    raw = root.get("id")
    if raw is None:
        raise ConfigurationError("в rule.xml нет атрибута id")
    return int(raw)
