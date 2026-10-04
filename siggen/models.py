"""Контракты данных пайплайна.

Граница доверия проходит здесь: `DetectionCandidate` — это ещё недоверенное
предложение модели, `ArtifactBundle` — уже проверенный артефакт.

Идентификатор правила (`rule_id`) в `DetectionCandidate` отсутствует намеренно:
ID выделяет наш реестр, а не модель (docs/SECURITY.md, SEC-11).
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, Field, field_validator

from .data import MAX_RULE_LEVEL

Engine = Literal["wazuh", "ossec"]

Severity = Literal["error", "warning"]

EngineStatus = Literal["passed", "failed", "skipped"]


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class DecoderDraft(BaseModel):
    """Черновик декодера: то, что предложила модель."""

    name: str = Field(min_length=1, max_length=64)
    program_name: str | None = None
    parent: str | None = None
    prematch: str | None = None
    regex: str | None = None
    offset: str = "after_prematch"
    order: list[str] = Field(default_factory=list)

    @field_validator("name")
    @classmethod
    def _name_is_slug(cls, value: str) -> str:
        allowed = set("abcdefghijklmnopqrstuvwxyz0123456789-_")
        if not set(value.lower()) <= allowed:
            raise ValueError(
                "имя декодера может содержать только латиницу, цифры, '-' и '_'"
            )
        return value


class RuleDraft(BaseModel):
    """Черновик правила: то, что предложила модель."""

    level: int = Field(ge=0, le=MAX_RULE_LEVEL)
    description: str = Field(min_length=1, max_length=256)
    decoded_as: str | None = None
    match: str | None = None
    groups: list[str] = Field(default_factory=list)
    mitre: list[str] = Field(default_factory=list)

    @field_validator("groups")
    @classmethod
    def _groups_are_slugs(cls, value: list[str]) -> list[str]:
        for group in value:
            if not group or not group.replace("_", "").replace("-", "").isalnum():
                raise ValueError(f"некорректная группа правила: {group!r}")
        return value


class DetectionCandidate(BaseModel):
    """Предложение модели целиком."""

    decoder: DecoderDraft
    rule: RuleDraft
    logsource: dict[str, str] = Field(default_factory=dict)
    confidence: float = Field(ge=0.0, le=1.0)
    rationale: str = ""

    @field_validator("rule")
    @classmethod
    def _rule_has_matcher(cls, rule: RuleDraft) -> RuleDraft:
        if not rule.match and not rule.decoded_as:
            raise ValueError("правило должно содержать <match> или <decoded_as>")
        return rule

    def fingerprint(self) -> str:
        """Отпечаток семантики детекции: по нему ищутся дубликаты в реестре."""
        payload = "|".join(
            [
                self.decoder.name,
                self.decoder.program_name or "",
                self.decoder.prematch or "",
                self.decoder.regex or "",
                self.rule.match or "",
                self.rule.decoded_as or "",
                str(self.rule.level),
                ",".join(self.decoder.order),
                ",".join(sorted(self.rule.groups)),
            ]
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class CheckResult(BaseModel):
    """Результат одной проверки артефакта."""

    name: str
    passed: bool
    severity: Severity = "error"
    detail: str = ""


class ValidationResult(BaseModel):
    """Вердикт по артефакту."""

    rule_id: int
    engine: Engine
    checks: list[CheckResult] = Field(default_factory=list)
    engine_status: EngineStatus = "skipped"
    engine_detail: str = ""
    engine_raw: str = ""
    requires_manual_review: list[str] = Field(default_factory=list)

    @property
    def errors(self) -> list[CheckResult]:
        return [c for c in self.checks if not c.passed and c.severity == "error"]

    @property
    def warnings(self) -> list[CheckResult]:
        return [c for c in self.checks if c.severity == "warning"]

    @property
    def passed(self) -> bool:
        """Артефакт годен, если нет ошибок и движок не отверг правило."""
        return not self.errors and self.engine_status != "failed"


class Provenance(BaseModel):
    """Прослеживаемость: требование и SOC, и CISO (docs/ROADMAP.md, Фаза 5)."""

    provider: str
    model: str
    prompt_name: str
    prompt_version: str
    prompt_hash: str
    engine: Engine
    generated_at: datetime = Field(default_factory=utcnow)
    log_sample: str
    confidence: float
    rationale: str = ""


class ArtifactBundle(BaseModel):
    """Готовый к ревью набор артефактов по одному кандидату."""

    engine: Engine
    rule_id: int
    decoder_xml: str
    rule_xml: str
    positive_sample: str
    negative_sample: str | None = None
    candidate: DetectionCandidate
    provenance: Provenance
    validation: ValidationResult
    directory: str | None = None


class PipelineResult(BaseModel):
    """Результат прогона пайплайна."""

    ok: bool
    bundle: ArtifactBundle
    report_markdown: str
    messages: list[str] = Field(default_factory=list)


class ProviderError(RuntimeError):
    """Провайдер модели не смог вернуть пригодный ответ."""


class ConfigurationError(RuntimeError):
    """Неверная конфигурация или отсутствующая зависимость."""
