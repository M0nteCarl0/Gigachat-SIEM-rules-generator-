"""Загрузка и версионирование промптов.

Промпт — это код: он лежит в файле, имеет версию и хэш, который попадает
в provenance артефакта. Так результат генерации можно воспроизвести и отревьюить
(docs/ARCHITECTURE.md, ADR A7).
"""

from __future__ import annotations

import hashlib
import os
import re
from dataclasses import dataclass
from pathlib import Path

from .models import ConfigurationError

_PLACEHOLDER = re.compile(r"\{\{(\w+)\}\}")
_VERSION = re.compile(r"<!--\s*version:\s*([^\s>]+)\s*-->")

DEFAULT_PROMPT = Path(__file__).resolve().parent.parent / "prompts" / "detection.md"


@dataclass(frozen=True)
class PromptTemplate:
    """Промпт с версией и хэшем."""

    name: str
    version: str
    text: str
    sha256: str

    def render(self, **values: object) -> str:
        """Подставляет значения вместо {{placeholder}}.

        Разделитель {{}} выбран вместо str.format, чтобы JSON-примеры
        внутри промпта не требовали удвоения фигурных скобок.
        """
        expected = set(_PLACEHOLDER.findall(self.text))
        missing = expected - set(values)
        if missing:
            raise ConfigurationError(
                f"в промпте {self.name} не заполнены подстановки: {sorted(missing)}"
            )
        extra = set(values) - expected
        if extra:
            raise ConfigurationError(
                f"для промпта {self.name} переданы лишние подстановки: {sorted(extra)}"
            )
        return _PLACEHOLDER.sub(lambda m: str(values[m.group(1)]), self.text)


def load_prompt(path: str | os.PathLike[str] | None = None) -> PromptTemplate:
    """Читает промпт с диска. Путь по умолчанию — prompts/detection.md."""
    if path is None:
        path = os.getenv("SIGGEN_PROMPT") or DEFAULT_PROMPT
    file_path = Path(path)
    if not file_path.is_file():
        raise ConfigurationError(f"промпт не найден: {file_path}")
    text = file_path.read_text(encoding="utf-8")
    match = _VERSION.search(text)
    if match is None:
        raise ConfigurationError(
            f"в промпте {file_path} нет заголовка '<!-- version: N -->': "
            "без версии нельзя воспроизвести результат"
        )
    return PromptTemplate(
        name=file_path.stem,
        version=match.group(1),
        text=text,
        sha256=hashlib.sha256(text.encode("utf-8")).hexdigest(),
    )
