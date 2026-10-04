"""Статические проверки артефакта.

Это первый, дешёвый слой валидации: он не требует движка и отсекает то,
что движок всё равно не примет, — плюс реализует политику проекта
(например, отказ от правил широкого подавления). Источником правды остаётся
прогон через `wazuh-logtest` (см. engine.py), здесь — только предполётная проверка.
"""

from __future__ import annotations

import logging
import re
import xml.etree.ElementTree as ET
from typing import Mapping

from .config import Settings
from .data import (
    BROAD_MATCH_PATTERNS,
    DECODER_OFFSETS,
    MITRE_TECHNIQUES,
    OSSEC_ORDER_FIELDS,
)
from .models import CheckResult, DetectionCandidate

log = logging.getLogger(__name__)

#: Маркеры запроса внешних сущностей: такой XML не разбираем вообще.
_FORBIDDEN_XML = re.compile(r"<!\s*(DOCTYPE|ENTITY)", re.IGNORECASE)

#: Признаки rule/decoder, которые не должны попадать в автогенерируемые правила.
_ACTIVE_RESPONSE = re.compile(r"active[-_]response", re.IGNORECASE)
_SUPPRESSION = re.compile(r"<same_source_ip\s*/?>", re.IGNORECASE)

try:  # pragma: no cover - ветка зависит от окружения
    from defusedxml.ElementTree import fromstring as _defused_fromstring

    _HAS_DEFUSEDXML = True
except ImportError:  # pragma: no cover
    _HAS_DEFUSEDXML = False

_warned_about_parser = False


def _warn_once_about_parser() -> None:
    """Предупреждает один раз за процесс, а не на каждый разбор XML."""
    global _warned_about_parser
    if _warned_about_parser:
        return
    _warned_about_parser = True
    log.warning(
        "defusedxml не установлен, используется стандартный XML-парсер "
        "с собственной защитой от DOCTYPE/ENTITY. Для эксплуатации установите "
        "defusedxml: pip install defusedxml"
    )


def parse_xml_safe(text: str, max_bytes: int) -> ET.Element:
    """Разбирает XML, отказываясь от DOCTYPE/ENTITY и слишком больших документов.

    Без defusedxml используется стандартный парсер, но с предварительным запретом
    DOCTYPE/ENTITY — этого достаточно против XXE и billion-laughs в нашем сценарии
    (docs/SECURITY.md, SEC-3).
    """
    if len(text.encode("utf-8")) > max_bytes:
        raise ValueError(f"XML превышает лимит {max_bytes} байт")
    if _FORBIDDEN_XML.search(text):
        raise ValueError("XML содержит DOCTYPE/ENTITY: разбор запрещён")
    if not _HAS_DEFUSEDXML:
        _warn_once_about_parser()
    return _defused_fromstring(text) if _HAS_DEFUSEDXML else ET.fromstring(text)


def count_capture_groups(pattern: str) -> int:
    """Считает группы захвата в regex (без объектных модулей: нужен только счёт).

    Нужен для проверки «число полей в <order> совпадает с числом групп захвата»:
    несовпадение — классическая причина отказа OSSEC принять декодер.
    """
    count = 0
    index = 0
    length = len(pattern)
    while index < length:
        char = pattern[index]
        if char == "\\":
            index += 2
            continue
        if char == "(":
            nxt = pattern[index + 1] if index + 1 < length else ""
            if nxt != "?":
                count += 1
            else:
                marker = pattern[index + 2] if index + 2 < length else ""
                if marker == "<":
                    # (?<= и (?<! — lookbehind; (?<name> — именованная группа
                    after = pattern[index + 3] if index + 3 < length else ""
                    if after not in ("=", "!"):
                        count += 1
                elif marker not in (":", "=", "!"):
                    # (?P<name> и прочие расширения-группы считаем захватом
                    count += 1
        index += 1
    return count


def _check(name: str, passed: bool, detail: str = "", severity: str = "error") -> CheckResult:
    return CheckResult(name=name, passed=passed, detail=detail, severity=severity)  # type: ignore[arg-type]


def _xml_root_ok(xml_text: str, expected: str, max_bytes: int, label: str) -> CheckResult:
    try:
        root = parse_xml_safe(xml_text, max_bytes)
    except (ValueError, ET.ParseError) as exc:
        return _check(f"{label}_wellformed", False, f"{type(exc).__name__}: {exc}")
    if root.tag != expected:
        return _check(
            f"{label}_wellformed", False, f"корневой тег {root.tag!r}, ожидался {expected!r}"
        )
    return _check(f"{label}_wellformed", True, "XML разобран, корневой тег совпадает")


def static_checks(
    *,
    candidate: DetectionCandidate,
    decoder_xml: str,
    rule_xml: str,
    rule_id: int,
    settings: Settings,
    used_ids: Mapping[int, str],
    duplicate_of: int | None,
    has_negative_sample: bool,
) -> tuple[list[CheckResult], list[str]]:
    """Прогоняет предполётные проверки.

    Возвращает список результатов и список причин для обязательного ручного ревью.
    """
    checks: list[CheckResult] = []
    review: list[str] = []

    decoder_draft = candidate.decoder
    rule_draft = candidate.rule

    checks.append(_xml_root_ok(decoder_xml, "decoder", settings.max_xml_bytes, "decoder"))
    checks.append(_xml_root_ok(rule_xml, "rule", settings.max_xml_bytes, "rule"))

    in_range = settings.rule_id_min <= rule_id < settings.rule_id_max
    checks.append(
        _check(
            "rule_id_in_range",
            in_range,
            f"id={rule_id}, допустимый диапазон [{settings.rule_id_min}; {settings.rule_id_max})",
        )
    )

    collision = used_ids.get(rule_id)
    checks.append(
        _check(
            "rule_id_unique",
            collision is None,
            "свободен" if collision is None else f"занят: {collision}",
        )
    )

    if rule_draft.decoded_as:
        matches = rule_draft.decoded_as == decoder_draft.name
        checks.append(
            _check(
                "decoded_as_matches_decoder",
                matches,
                f"decoded_as={rule_draft.decoded_as!r}, декодер={decoder_draft.name!r}",
            )
        )

    if decoder_draft.order:
        unknown = sorted(set(decoder_draft.order) - OSSEC_ORDER_FIELDS)
        checks.append(
            _check(
                "order_fields_allowed",
                not unknown,
                "все поля допустимы" if not unknown else f"недопустимые поля: {unknown}",
            )
        )

    if decoder_draft.regex:
        groups = count_capture_groups(decoder_draft.regex)
        expected = len(decoder_draft.order)
        checks.append(
            _check(
                "order_matches_regex_groups",
                groups == expected,
                f"групп захвата {groups}, полей в <order> {expected}",
            )
        )
        try:
            re.compile(decoder_draft.regex)
            checks.append(_check("regex_compiles", True, "регулярное выражение компилируется"))
        except re.error as exc:
            checks.append(_check("regex_compiles", False, f"re.error: {exc}"))

    offset_ok = decoder_draft.offset in DECODER_OFFSETS
    checks.append(
        _check(
            "decoder_offset_allowed",
            offset_ok,
            f"offset={decoder_draft.offset!r}"
            + ("" if offset_ok else f", допустимы: {sorted(DECODER_OFFSETS)}"),
        )
    )

    unknown_techniques = sorted(set(rule_draft.mitre) - set(MITRE_TECHNIQUES))
    checks.append(
        _check(
            "mitre_in_allowlist",
            not unknown_techniques,
            "техники подтверждены справочником"
            if not unknown_techniques
            else f"техники вне allowlist: {unknown_techniques}",
        )
    )

    if not rule_draft.groups:
        checks.append(_check("groups_present", False, "у правила нет <group>", severity="warning"))

    if duplicate_of is not None:
        checks.append(
            _check(
                "no_duplicate",
                False,
                f"артефакт с таким отпечатком уже есть: id={duplicate_of}",
                severity="warning",
            )
        )

    # --- политика проекта ---
    # Пустые матчеры отбрасываем: отсутствие <match> — это не «широкое правило»,
    # а правило, опирающееся только на decoded_as.
    matchers = [
        value.strip()
        for value in (rule_draft.match or "", decoder_draft.regex or "")
        if value.strip()
    ]
    broad = [value for value in matchers if value in BROAD_MATCH_PATTERNS]
    if broad:
        checks.append(
            _check(
                "no_broad_suppression",
                False,
                f"правило подавляет всё подряд: {broad}",
            )
        )
        review.append("широкий матчер — возможное подавление детекций")

    if _ACTIVE_RESPONSE.search(rule_xml) or _ACTIVE_RESPONSE.search(decoder_xml):
        checks.append(
            _check(
                "no_active_response",
                False,
                "сгенерированные правила не должны содержать active-response",
            )
        )
        review.append("active-response должен добавлять человек")

    if _SUPPRESSION.search(rule_xml) or _SUPPRESSION.search(decoder_xml):
        checks.append(
            _check(
                "no_source_ip_whitelist",
                False,
                "правило ограничивает источник (same_source_ip): сужает детекцию без анализа",
                severity="warning",
            )
        )
        review.append("ограничение по источнику требует анализа контекста")

    if rule_draft.level == 0:
        checks.append(
            _check(
                "level_not_zero",
                False,
                "уровень 0 означает «не оповещать»: такое правило не должно генерироваться",
            )
        )
        review.append("уровень 0")
    elif rule_draft.level < 3:
        checks.append(
            _check(
                "level_reasonable",
                False,
                f"уровень {rule_draft.level} слишком низкий для правила-детекции",
                severity="warning",
            )
        )

    if not has_negative_sample:
        checks.append(
            _check(
                "negative_fixture_present",
                False,
                "нет negative-примера: нечем доказать, что правило не шумит",
                severity="warning",
            )
        )
        review.append("нет negative-фикстуры")

    return checks, review
