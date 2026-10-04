"""Статические проверки: то, что отсекается до обращения к движку."""

from __future__ import annotations

import logging

import pytest

from siggen.config import Settings
from siggen.emit import render_decoder, render_rule
from siggen.models import DetectionCandidate
from siggen.validation import count_capture_groups, parse_xml_safe, static_checks


def _run(candidate: DetectionCandidate, settings: Settings, **kwargs):
    """Прогоняет статические проверки для готового кандидата."""
    kwargs.setdefault("used_ids", {})
    kwargs.setdefault("duplicate_of", None)
    kwargs.setdefault("has_negative_sample", True)
    rule_id = kwargs.pop("rule_id", settings.rule_id_min)
    return static_checks(
        candidate=candidate,
        decoder_xml=render_decoder(candidate.decoder),
        rule_xml=render_rule(settings.engine, rule_id, candidate.rule),
        rule_id=rule_id,
        settings=settings,
        **kwargs,
    )


def _failed(checks, name: str) -> bool:
    return any(c.name == name and not c.passed for c in checks)


# --- подсчёт групп захвата ------------------------------------------------------


@pytest.mark.parametrize(
    ("pattern", "expected"),
    [
        (r"^user=(\S+) src=(\S+)$", 2),
        (r"^(?:invalid user )?(\S+) from (\S+)$", 2),
        (r"^(?P<user>\S+)$", 1),
        (r"^(?<=x)y$", 0),
        (r"^\(literal\)$", 0),
        (r"^$", 0),
        (r"^(a)(b)(c)$", 3),
    ],
)
def test_count_capture_groups(pattern: str, expected: int) -> None:
    assert count_capture_groups(pattern) == expected


# --- безопасный разбор XML ------------------------------------------------------


def test_parse_xml_safe_accepts_plain_xml() -> None:
    assert parse_xml_safe("<rule id='1'/>", 1024).tag == "rule"


def test_parse_xml_safe_rejects_doctype() -> None:
    payload = '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY x SYSTEM "file:///etc/passwd">]><a/>'
    with pytest.raises(ValueError, match="DOCTYPE"):
        parse_xml_safe(payload, 4096)


def test_parse_xml_safe_rejects_oversized_document() -> None:
    with pytest.raises(ValueError, match="лимит"):
        parse_xml_safe("<a>" + "x" * 100 + "</a>", 10)


def test_parse_xml_safe_rejects_malformed_xml() -> None:
    with pytest.raises(Exception):
        parse_xml_safe("<a>", 1024)


def test_parse_still_works_without_defusedxml(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """Ветка без defusedxml должна быть рабочей, а не аварийной."""
    monkeypatch.setattr("siggen.validation._HAS_DEFUSEDXML", False)
    monkeypatch.setattr("siggen.validation._warned_about_parser", False)
    with caplog.at_level(logging.WARNING, logger="siggen.validation"):
        assert parse_xml_safe("<rule id='1'/>", 1024).tag == "rule"
    assert any("defusedxml" in record.message for record in caplog.records)


def test_warning_about_missing_defusedxml_is_logged_once(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setattr("siggen.validation._HAS_DEFUSEDXML", False)
    monkeypatch.setattr("siggen.validation._warned_about_parser", False)
    with caplog.at_level(logging.WARNING, logger="siggen.validation"):
        parse_xml_safe("<a/>", 1024)
        parse_xml_safe("<b/>", 1024)
    assert len([r for r in caplog.records if "defusedxml" in r.message]) == 1


# --- проверки кандидата ---------------------------------------------------------


def test_valid_candidate_passes(settings: Settings, candidate_payload: dict) -> None:
    checks, review = _run(DetectionCandidate.model_validate(candidate_payload), settings)
    assert not [c for c in checks if not c.passed and c.severity == "error"]
    assert review == []


def test_unknown_order_field_is_rejected(settings: Settings, candidate_payload: dict) -> None:
    candidate_payload["decoder"]["order"] = ["srcuser", "attempts"]
    candidate_payload["decoder"]["regex"] = r"^user=(\S+) src=(\S+) attempts=(\S+)$"
    checks, _ = _run(DetectionCandidate.model_validate(candidate_payload), settings)
    assert _failed(checks, "order_fields_allowed")


def test_group_count_mismatch_is_rejected(settings: Settings, candidate_payload: dict) -> None:
    """Три группы захвата при двух полях в <order> — движок такое не примет."""
    candidate_payload["decoder"]["regex"] = r"^user=(\S+) src=(\S+) attempts=(\S+)$"
    checks, _ = _run(DetectionCandidate.model_validate(candidate_payload), settings)
    assert _failed(checks, "order_matches_regex_groups")


def test_invalid_regex_is_rejected(settings: Settings, candidate_payload: dict) -> None:
    candidate_payload["decoder"]["regex"] = r"^user=(\S+ src=(\S+)$"
    candidate_payload["decoder"]["order"] = ["srcuser", "srcip"]
    checks, _ = _run(DetectionCandidate.model_validate(candidate_payload), settings)
    assert _failed(checks, "regex_compiles")


def test_mitre_outside_allowlist_is_rejected(settings: Settings, candidate_payload: dict) -> None:
    candidate_payload["rule"]["mitre"] = ["T9999"]
    checks, _ = _run(DetectionCandidate.model_validate(candidate_payload), settings)
    assert _failed(checks, "mitre_in_allowlist")


def test_decoded_as_must_match_decoder(settings: Settings, candidate_payload: dict) -> None:
    candidate_payload["rule"]["decoded_as"] = "other-decoder"
    checks, _ = _run(DetectionCandidate.model_validate(candidate_payload), settings)
    assert _failed(checks, "decoded_as_matches_decoder")


def test_rule_id_out_of_range_is_rejected(settings: Settings, candidate_payload: dict) -> None:
    checks, _ = _run(
        DetectionCandidate.model_validate(candidate_payload), settings, rule_id=999
    )
    assert _failed(checks, "rule_id_in_range")


def test_rule_id_collision_is_rejected(settings: Settings, candidate_payload: dict) -> None:
    checks, _ = _run(
        DetectionCandidate.model_validate(candidate_payload),
        settings,
        used_ids={100_100: "уже занято"},
    )
    assert _failed(checks, "rule_id_unique")


def test_level_zero_is_rejected(settings: Settings, candidate_payload: dict) -> None:
    candidate_payload["rule"]["level"] = 0
    checks, review = _run(DetectionCandidate.model_validate(candidate_payload), settings)
    assert _failed(checks, "level_not_zero")
    assert "уровень 0" in review


def test_broad_matcher_is_rejected(settings: Settings, candidate_payload: dict) -> None:
    candidate_payload["rule"]["match"] = ".*"
    checks, review = _run(DetectionCandidate.model_validate(candidate_payload), settings)
    assert _failed(checks, "no_broad_suppression")
    assert review


def test_broad_matcher_does_not_trigger_without_match(
    settings: Settings, candidate_payload: dict
) -> None:
    """Правило только на decoded_as — это не «подавление всего»."""
    candidate_payload["rule"]["match"] = None
    checks, _ = _run(DetectionCandidate.model_validate(candidate_payload), settings)
    assert not _failed(checks, "no_broad_suppression")


def test_active_response_is_rejected(settings: Settings, candidate_payload: dict) -> None:
    candidate = DetectionCandidate.model_validate(candidate_payload)
    checks, review = static_checks(
        candidate=candidate,
        decoder_xml=render_decoder(candidate.decoder),
        rule_xml=render_rule(settings.engine, 100_100, candidate.rule)
        + "\n<active-response><command>firewall-drop</command></active-response>",
        rule_id=100_100,
        settings=settings,
        used_ids={},
        duplicate_of=None,
        has_negative_sample=True,
    )
    assert _failed(checks, "no_active_response")
    assert review


def test_same_source_ip_is_a_review_flag(settings: Settings, candidate_payload: dict) -> None:
    candidate = DetectionCandidate.model_validate(candidate_payload)
    checks, review = static_checks(
        candidate=candidate,
        decoder_xml=render_decoder(candidate.decoder),
        rule_xml="<rule id='1' level='5'><same_source_ip /></rule>",
        rule_id=100_100,
        settings=settings,
        used_ids={},
        duplicate_of=None,
        has_negative_sample=True,
    )
    assert _failed(checks, "no_source_ip_whitelist")
    assert review


def test_missing_negative_fixture_is_warning_not_error(
    settings: Settings, candidate_payload: dict
) -> None:
    checks, review = _run(
        DetectionCandidate.model_validate(candidate_payload), settings, has_negative_sample=False
    )
    assert _failed(checks, "negative_fixture_present")
    assert not [c for c in checks if not c.passed and c.severity == "error"]
    assert "нет negative-фикстуры" in review


def test_duplicate_is_warning(settings: Settings, candidate_payload: dict) -> None:
    checks, _ = _run(
        DetectionCandidate.model_validate(candidate_payload), settings, duplicate_of=100_100
    )
    assert _failed(checks, "no_duplicate")
    assert not [c for c in checks if not c.passed and c.severity == "error"]


def test_malformed_xml_in_artifact_is_rejected(settings: Settings, candidate_payload: dict) -> None:
    candidate = DetectionCandidate.model_validate(candidate_payload)
    checks, _ = static_checks(
        candidate=candidate,
        decoder_xml="<decoder name='x'>",
        rule_xml="<rule id='1'/>",
        rule_id=100_100,
        settings=settings,
        used_ids={},
        duplicate_of=None,
        has_negative_sample=True,
    )
    assert _failed(checks, "decoder_wellformed")
