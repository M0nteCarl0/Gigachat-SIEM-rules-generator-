"""Сборка XML: экранирование, различия движков, структура."""

from __future__ import annotations

from xml.etree import ElementTree as ET

from siggen.emit import render_decoder, render_rule, render_ruleset
from siggen.models import DecoderDraft, RuleDraft


def test_decoder_is_wellformed_and_ordered() -> None:
    draft = DecoderDraft(
        name="myapp-login",
        program_name="^myapp$",
        prematch="login_failed ",
        regex=r"^user=(\S+) src=(\S+)$",
        offset="after_prematch",
        order=["srcuser", "srcip"],
    )
    xml = render_decoder(draft)
    root = ET.fromstring(xml)
    assert root.tag == "decoder"
    assert root.get("name") == "myapp-login"
    assert root.findtext("order") == "srcuser, srcip"
    assert root.find("regex").get("offset") == "after_prematch"


def test_decoder_escapes_xml_special_characters() -> None:
    draft = DecoderDraft(name="tricky", prematch="a & b < c", regex=r"^\S+$")
    xml = render_decoder(draft)
    assert "&amp;" in xml and "&lt;" in xml
    assert ET.fromstring(xml).findtext("prematch") == "a & b < c"


def test_rule_escapes_description() -> None:
    draft = RuleDraft(level=10, description="user <x> & \"y\"", match="boom", groups=["g"])
    xml = render_rule("wazuh", 100100, draft)
    assert "<x>" not in xml
    assert ET.fromstring(xml).findtext("description") == 'user <x> & "y"'


def test_rule_id_and_level_are_attributes() -> None:
    draft = RuleDraft(level=12, description="d", decoded_as="dec")
    root = ET.fromstring(render_rule("wazuh", 100500, draft))
    assert root.get("id") == "100500"
    assert root.get("level") == "12"


def test_wazuh_emits_mitre_but_ossec_does_not() -> None:
    draft = RuleDraft(level=10, description="d", match="m", mitre=["T1110"])
    assert ET.fromstring(render_rule("wazuh", 100100, draft)).find("mitre") is not None
    assert ET.fromstring(render_rule("ossec", 100100, draft)).find("mitre") is None


def test_ruleset_wraps_into_group() -> None:
    draft = DecoderDraft(name="dec", prematch="x")
    xml = render_ruleset(render_decoder(draft), render_rule("wazuh", 1, RuleDraft(level=5, description="d", match="m")))
    root = ET.fromstring(xml)
    assert root.tag == "group"
    assert root.find("decoder") is not None
    assert root.find("rule") is not None
