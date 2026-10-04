"""Прогон артефакта через настоящий движок анализа.

Это второй слой валидации и единственный источник правды о работоспособности
правила. Если движок недоступен, прогон честно помечается `skipped` —
«мы не проверили», а не «проверили успешно». Флагом --require-engine
недоступность превращается в провал (для CI).
"""

from __future__ import annotations

import logging
import shutil
import subprocess
from dataclasses import dataclass
from typing import Sequence

from .config import Settings
from .models import ConfigurationError, Engine, EngineStatus

log = logging.getLogger(__name__)

_BINARIES: dict[str, tuple[str, ...]] = {
    "wazuh": ("wazuh-logtest",),
    "ossec": ("ossec-logtest",),
}

#: Признаки того, что установленный движок не поддерживает режим -U.
#: В этом случае честнее сказать «не проверено», чем выдать ложный провал.
_UNSUPPORTED_OPTION = (
    "unrecognized option",
    "invalid option",
    "illegal option",
    "unknown option",
    "unrecognized argument",
)


def parse_command(value: str) -> list[str]:
    """Разбирает командную строку движка на токены.

    Кавычки группируют слова, обратный слэш экранированием не считается —
    иначе Windows-пути вида `C:\\Program Files\\...` разваливаются.
    Нужен, чтобы движок можно было взять не только из PATH, но и из контейнера:

        docker compose exec -T wazuh-manager /var/ossec/bin/wazuh-logtest
    """
    tokens: list[str] = []
    current: list[str] = []
    quote: str | None = None
    started = False

    for char in value:
        if quote is not None:
            if char == quote:
                quote = None
            else:
                current.append(char)
                started = True
        elif char in ("'", '"'):
            quote = char
            started = True
        elif char.isspace():
            if started:
                tokens.append("".join(current))
                current, started = [], False
        else:
            current.append(char)
            started = True

    if quote is not None:
        raise ConfigurationError(f"в команде движка не закрыта кавычка: {value!r}")
    if started:
        tokens.append("".join(current))
    if not tokens:
        raise ConfigurationError("команда движка пуста")
    return tokens


@dataclass(frozen=True)
class EngineOutcome:
    """Результат прогона строки (или пары строк) через движок."""

    status: EngineStatus
    detail: str
    raw: str = ""


class LogtestRunner:
    """Запускает `wazuh-logtest`/`ossec-logtest` для проверки фикстур.

    Используется документированный режим: `-U <rule_id:level:decoder>` возвращает
    код 0, если протестированная строка сматчилась под заданные критерии.
    Строка подаётся на stdin.
    """

    def __init__(
        self,
        engine: Engine = "wazuh",
        binary: Sequence[str] | None = None,
        timeout: float = 30.0,
    ) -> None:
        self.engine = engine
        self.timeout = timeout
        self._binary = list(binary) if binary else self.detect(engine)

    @classmethod
    def from_settings(cls, settings: Settings) -> "LogtestRunner":
        """Собирает runner по настройкам.

        Если задана явная команда (`--logtest`, `SIGGEN_LOGTEST`), используется она:
        так движок можно взять из контейнера, где нет локального бинаря.
        """
        if settings.logtest_command:
            return cls(
                settings.engine,
                binary=parse_command(settings.logtest_command),
                timeout=settings.engine_timeout,
            )
        return cls(settings.engine, timeout=settings.engine_timeout)

    @staticmethod
    def detect(engine: Engine) -> list[str] | None:
        """Ищет исполняемый файл движка в PATH."""
        for name in _BINARIES.get(engine, ()):  # type: ignore[arg-type]
            found = shutil.which(name)
            if found:
                return [found]
        return None

    @property
    def available(self) -> bool:
        return bool(self._binary)

    def test_line(self, line: str, rule_id: int, level: int, decoder: str) -> EngineOutcome:
        """Проверяет одну строку лога под заданные критерии правила."""
        if not self._binary:
            return EngineOutcome(
                status="skipped",
                detail=(
                    f"движок {self.engine} не найден в PATH: правило не проверено. "
                    "Поднимите лабораторию из docker-compose.yml или укажите путь к бинарю."
                ),
            )
        spec = f"{rule_id}:{level}:{decoder}"
        command = [*self._binary, "-U", spec]
        try:
            proc = subprocess.run(  # noqa: S603 - команда формируется из констант и id
                command,
                input=line if line.endswith("\n") else line + "\n",
                capture_output=True,
                text=True,
                timeout=self.timeout,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            return EngineOutcome("skipped", f"не удалось запустить движок: {exc}")

        raw = (proc.stdout or "") + (proc.stderr or "")
        if proc.returncode == 0:
            return EngineOutcome("passed", f"строка сматчилась под {spec}", raw)

        lowered = raw.lower()
        if any(marker in lowered for marker in _UNSUPPORTED_OPTION):
            return EngineOutcome(
                "skipped",
                f"движок {self.engine} не поддерживает режим -U: прогон не выполнен. "
                "Адаптируйте команду в siggen/engine.py под свой движок.",
                raw,
            )
        return EngineOutcome(
            "failed", f"строка не сматчилась под {spec} (код {proc.returncode})", raw
        )

    def verify(
        self,
        *,
        positive: str,
        negative: str | None,
        rule_id: int,
        level: int,
        decoder: str,
    ) -> EngineOutcome:
        """Проверяет положительную и отрицательную фикстуры.

        Правило годно, когда срабатывает на positive и НЕ срабатывает на negative.
        """
        pos = self.test_line(positive, rule_id, level, decoder)
        if pos.status == "failed":
            return EngineOutcome("failed", f"positive-фикстура: {pos.detail}", pos.raw)

        if negative:
            neg = self.test_line(negative, rule_id, level, decoder)
            if neg.status == "passed":
                return EngineOutcome(
                    "failed",
                    "правило сработало на negative-фикстуре: это ложное срабатывание",
                    neg.raw,
                )
            if neg.status == "skipped":
                return neg
            detail = (
                f"positive сработала, negative — нет ({pos.detail})"
                if pos.status == "passed"
                else "фикстуры не проверялись"
            )
            return EngineOutcome(pos.status, detail, pos.raw)

        return EngineOutcome(pos.status, pos.detail, pos.raw)
