"""Сериализация черновика модели в XML OSSEC/Wazuh.

XML собирает наш код, а не модель: так исчезает целый класс ошибок
(незакрытые теги, незаэкранированные символы) и появляется точка, где
применяются правила проекта (docs/ARCHITECTURE.md, ADR A1).
"""

from __future__ import annotations

from xml.sax.saxutils import escape, quoteattr

from .models import DecoderDraft, Engine, RuleDraft


def _attr(value: str) -> str:
    return quoteattr(value)


def render_decoder(draft: DecoderDraft) -> str:
    """Собирает <decoder> из черновика."""
    lines: list[str] = [f"<decoder name={_attr(draft.name)}>"]
    if draft.program_name:
        lines.append(f"  <program_name>{escape(draft.program_name)}</program_name>")
    if draft.parent:
        lines.append(f"  <parent>{escape(draft.parent)}</parent>")
    if draft.prematch:
        lines.append(f"  <prematch>{escape(draft.prematch)}</prematch>")
    if draft.regex:
        lines.append(
            f"  <regex offset={_attr(draft.offset)}>{escape(draft.regex)}</regex>"
        )
    if draft.order:
        lines.append(f"  <order>{escape(', '.join(draft.order))}</order>")
    lines.append("</decoder>")
    return "\n".join(lines) + "\n"


def render_rule(engine: Engine, rule_id: int, draft: RuleDraft) -> str:
    """Собирает <rule>.

    Тег <mitre> поддерживает Wazuh, но не классический OSSEC: для OSSEC он
    не выводится, техника остаётся в provenance артефакта.
    """
    lines: list[str] = [f'<rule id="{rule_id}" level="{draft.level}">']
    if draft.decoded_as:
        lines.append(f"  <decoded_as>{escape(draft.decoded_as)}</decoded_as>")
    if draft.match:
        lines.append(f"  <match>{escape(draft.match)}</match>")
    lines.append(f"  <description>{escape(draft.description)}</description>")
    if draft.groups:
        lines.append(f"  <group>{escape(','.join(draft.groups))}</group>")
    if draft.mitre and engine == "wazuh":
        lines.append("  <mitre>")
        for technique in draft.mitre:
            lines.append(f"    <id>{escape(technique)}</id>")
        lines.append("  </mitre>")
    lines.append("</rule>")
    return "\n".join(lines) + "\n"


def render_ruleset(decoder_xml: str, rule_xml: str) -> str:
    """Объединяет декодер и правило в один <group>, как ставится в local_rules.xml."""
    return (
        "<!-- Сгенерировано siggen. Требует ревью перед деплоем. -->\n"
        "<group name=\"siggen,\">\n"
        f"{decoder_xml}"
        f"{rule_xml}"
        "</group>\n"
    )
