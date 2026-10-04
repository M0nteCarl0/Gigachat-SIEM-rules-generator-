"""Конфигурация: всё, что меняется между контурами, читается из окружения.

Секреты никогда не попадают в код или в конфигурационные файлы репозитория
(docs/SECURITY.md, SEC-4).
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from pathlib import Path

from .models import Engine

log = logging.getLogger(__name__)

_TRUTHY = {"1", "true", "yes", "on"}


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None or raw == "":
        return default
    return raw.strip().lower() in _TRUTHY


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None or raw == "":
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise ValueError(f"{name} должно быть целым числом, получено {raw!r}") from exc


@dataclass(frozen=True)
class Settings:
    """Настройки одного прогона."""

    engine: Engine = "wazuh"
    provider: str = "fake"
    rule_id_min: int = 100_100
    rule_id_max: int = 120_000
    registry_path: Path = field(default_factory=lambda: Path("registry/rules.json"))

    #: Ограничения входа: защита от случайной подачи гигабайтов логов в модель.
    max_log_bytes: int = 64 * 1024
    #: Ограничение на разбираемый XML (SEC-3).
    max_xml_bytes: int = 256 * 1024
    #: Таймаут запуска движка валидации.
    engine_timeout: float = 30.0

    # --- GigaChat ---
    gigachat_credentials: str | None = None
    gigachat_scope: str = "GIGACHAT_API_PERS"
    gigachat_model: str = "GigaChat"
    gigachat_base_url: str | None = None
    #: По умолчанию проверка TLS включена. Отключение — только явным флагом
    #: и всегда с предупреждением в лог (SEC-1).
    gigachat_verify_ssl: bool = True
    llm_temperature: float = 0.0
    llm_timeout: float = 60.0

    #: Если True, недоступность движка валидации считается провалом, а не skip.
    require_engine: bool = False

    def __post_init__(self) -> None:
        if self.rule_id_min >= self.rule_id_max:
            raise ValueError("rule_id_min должен быть меньше rule_id_max")
        if not self.gigachat_verify_ssl:
            log.warning(
                "Проверка TLS для GigaChat отключена (GIGACHAT_VERIFY_SSL=false). "
                "Это допустимо только в изолированной лаборатории: docs/SECURITY.md, SEC-1."
            )

    @classmethod
    def from_env(cls, **overrides: object) -> "Settings":
        """Собирает настройки из переменных окружения, затем применяет overrides."""
        base: dict[str, object] = {
            "engine": os.getenv("SIGGEN_ENGINE", "wazuh"),
            "provider": os.getenv("SIGGEN_PROVIDER", "fake"),
            "rule_id_min": _env_int("SIGGEN_RULE_ID_MIN", 100_100),
            "rule_id_max": _env_int("SIGGEN_RULE_ID_MAX", 120_000),
            "registry_path": Path(os.getenv("SIGGEN_REGISTRY", "registry/rules.json")),
            "require_engine": _env_bool("SIGGEN_REQUIRE_ENGINE", False),
            "gigachat_credentials": os.getenv("GIGACHAT_CREDENTIALS") or None,
            "gigachat_scope": os.getenv("GIGACHAT_SCOPE", "GIGACHAT_API_PERS"),
            "gigachat_model": os.getenv("GIGACHAT_MODEL", "GigaChat"),
            "gigachat_base_url": os.getenv("GIGACHAT_BASE_URL") or None,
            "gigachat_verify_ssl": _env_bool("GIGACHAT_VERIFY_SSL", True),
        }
        base.update({k: v for k, v in overrides.items() if v is not None})
        return cls(**base)  # type: ignore[arg-type]
