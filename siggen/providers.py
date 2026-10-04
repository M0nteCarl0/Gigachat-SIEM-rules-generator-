"""Провайдеры модели за единым интерфейсом.

Смысл абстракции — не «поддержать много моделей», а иметь возможность прогонять
весь пайплайн без сети и без токена (`FakeProvider`): иначе ни CI, ни регрессионные
тесты промптов невозможны (docs/ARCHITECTURE.md, ADR A6).
"""

from __future__ import annotations

import copy
import json
import logging
import re
from typing import Any, Protocol

from .config import Settings
from .models import ConfigurationError, ProviderError

log = logging.getLogger(__name__)


class LlmProvider(Protocol):
    """Контракт провайдера: вернуть объект, соответствующий response_schema."""

    name: str
    model: str

    def complete_structured(
        self,
        *,
        system_prompt: str,
        user_payload: dict[str, Any],
        response_schema: dict[str, Any],
    ) -> dict[str, Any]: ...


# --- Детерминированный двойник -------------------------------------------------
#
# Это заглушка, а не детектор: она распознаёт несколько демонстрационных шаблонов
# и возвращает заранее описанный кандидат. Нужна для тестов, CI и демонстрации
# пайплайна без обращения к модели.

_FAKE_PATTERNS: list[tuple[str, dict[str, Any]]] = [
    (
        r"login_failed",
        {
            "decoder": {
                "name": "myapp-login",
                "program_name": r"^myapp$",
                "parent": None,
                "prematch": "login_failed ",
                "regex": r"^user=(\S+) src=(\S+) attempts=\S+$",
                "offset": "after_prematch",
                "order": ["srcuser", "srcip"],
            },
            "rule": {
                "level": 10,
                "description": "MyApp: повторный неуспешный вход для пользователя $(srcuser) с $(srcip)",
                "decoded_as": "myapp-login",
                "match": "login_failed",
                "groups": ["app_auth"],
                "mitre": ["T1110"],
            },
            "logsource": {"product": "custom_app", "service": "auth"},
            "confidence": 0.9,
            "rationale": (
                "Префикс myapp[pid] задаёт источник, 'login_failed' — признак события, "
                "user= и src= разбираются в srcuser/srcip, attempts= поглощается без захвата."
            ),
        },
    ),
    (
        r"Failed password for",
        {
            "decoder": {
                "name": "sshd-failed-password",
                "program_name": r"^sshd$",
                "parent": None,
                "prematch": "Failed password for ",
                "regex": r"^(?:invalid user )?(\S+) from (\S+) port \S+ ssh2$",
                "offset": "after_prematch",
                "order": ["srcuser", "srcip"],
            },
            "rule": {
                "level": 10,
                "description": "sshd: неуспешный вход для пользователя $(srcuser) с $(srcip)",
                "decoded_as": "sshd-failed-password",
                "match": "Failed password",
                "groups": ["app_auth", "sshd"],
                "mitre": ["T1110"],
            },
            "logsource": {"product": "linux", "service": "sshd"},
            "confidence": 0.85,
            "rationale": "Строка sshd о неуспешном входе; логин и адрес разбираются в srcuser/srcip.",
        },
    ),
]


class FakeProvider:
    """Детерминированный провайдер для тестов, CI и демонстрации."""

    name = "fake"
    model = "fake-deterministic"

    def complete_structured(
        self,
        *,
        system_prompt: str,
        user_payload: dict[str, Any],
        response_schema: dict[str, Any],
    ) -> dict[str, Any]:
        sample = str(user_payload.get("log_sample", ""))
        for pattern, payload in _FAKE_PATTERNS:
            if re.search(pattern, sample):
                log.debug("FakeProvider: совпал шаблон %s", pattern)
                return copy.deepcopy(payload)
        raise ProviderError(
            "FakeProvider — детерминированная заглушка и понимает только "
            "демонстрационные шаблоны (login_failed, 'Failed password for'). "
            "Для реального лога запустите с --provider gigachat. "
            f"Получено: {sample[:200]!r}"
        )


# --- GigaChat ------------------------------------------------------------------


class GigaChatProvider:
    """Провайдер на официальном SDK `gigachat`.

    Пакет импортируется лениво, чтобы ядро работало без него.
    Сетевой путь в CI не проверяется: тесты гоняются на FakeProvider.
    """

    name = "gigachat"

    def __init__(self, settings: Settings) -> None:
        if not settings.gigachat_credentials:
            raise ConfigurationError(
                "Не задан GIGACHAT_CREDENTIALS. Секреты передаются только через "
                "переменные окружения (docs/SECURITY.md, SEC-4)."
            )
        try:
            from gigachat import GigaChat
        except ImportError as exc:  # pragma: no cover - зависит от окружения
            raise ConfigurationError(
                "Пакет gigachat не установлен. Установите: pip install -e \".[gigachat]\""
            ) from exc

        self._settings = settings
        self.model = settings.gigachat_model
        kwargs: dict[str, Any] = {
            "credentials": settings.gigachat_credentials,
            "scope": settings.gigachat_scope,
            "model": settings.gigachat_model,
            "verify_ssl_certs": settings.gigachat_verify_ssl,
            "timeout": settings.llm_timeout,
        }
        if settings.gigachat_base_url:
            kwargs["base_url"] = settings.gigachat_base_url
        self._client = GigaChat(**kwargs)

    def complete_structured(
        self,
        *,
        system_prompt: str,
        user_payload: dict[str, Any],
        response_schema: dict[str, Any],
    ) -> dict[str, Any]:
        payload = {
            "model": self.model,
            "temperature": self._settings.llm_temperature,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": json.dumps(user_payload, ensure_ascii=False)},
            ],
        }
        try:
            response = self._client.chat(payload)
            content = response.choices[0].message.content
        except Exception as exc:  # noqa: BLE001 - наружу отдаём единый тип ошибки
            raise ProviderError(f"GigaChat не ответил: {exc}") from exc
        return _extract_json(str(content))


def _extract_json(content: str) -> dict[str, Any]:
    """Достаёт JSON из ответа модели, снимая возможные markdown-обёртки."""
    text = content.strip()
    fence = re.search(r"```(?:json)?\s*(.+?)\s*```", text, re.DOTALL)
    if fence:
        text = fence.group(1)
    start, end = text.find("{"), text.rfind("}")
    if start == -1 or end <= start:
        raise ProviderError(f"в ответе модели нет JSON-объекта: {content[:300]!r}")
    try:
        parsed = json.loads(text[start : end + 1])
    except json.JSONDecodeError as exc:
        raise ProviderError(f"ответ модели не является JSON: {exc}") from exc
    if not isinstance(parsed, dict):
        raise ProviderError("ответ модели должен быть JSON-объектом")
    return parsed


def build_provider(settings: Settings) -> LlmProvider:
    """Фабрика провайдера по настройкам."""
    if settings.provider == "fake":
        return FakeProvider()
    if settings.provider == "gigachat":
        return GigaChatProvider(settings)
    raise ConfigurationError(
        f"неизвестный провайдер {settings.provider!r}; допустимы: fake, gigachat"
    )
