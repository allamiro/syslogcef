from __future__ import annotations

from syslogcef.api import convert_line, normalize_event, parse_syslog, to_cef
from syslogcef.mappings import CISCO_ASA, load_mapping


ASA_LINE = "<166>Jan  1 12:34:56 fw1 asa[1]: %ASA-6-302013: Built inbound TCP connection src=10.0.0.1 dst=10.0.0.2"


def test_severity_is_mapped_from_syslog_to_cef_scale():
    # PRI 166 -> syslog severity 6 (informational) -> CEF severity 2
    cef = convert_line(ASA_LINE, mapping=CISCO_ASA)
    header = cef.split("|")
    assert header[6] == "2"


def test_custom_severity_map_overrides_default():
    mapping = dict(CISCO_ASA)
    mapping["severity_map"] = {"6": "9"}
    cef = convert_line(ASA_LINE, mapping=mapping)
    assert cef.split("|")[6] == "9"


def test_header_templates_resolve_event_fields():
    cef = convert_line(ASA_LINE, mapping=CISCO_ASA)
    fields = cef.split("|")
    assert fields[1] == "Cisco"
    assert fields[2] == "ASA"
    assert fields[4] == "asa.ASA-6-302013"


def test_extensions_with_missing_fields_are_omitted():
    # The ASA mapping references spt/dpt, absent from this message.
    cef = convert_line(ASA_LINE, mapping=CISCO_ASA)
    extension = cef.split("|", 7)[7]
    assert "spt=" not in extension
    assert "dpt=" not in extension
    assert "src=10.0.0.1" in extension


def test_default_mapping_renders_generic_header():
    line = "<14>Jan  1 12:34:56 host1 app: hello world"
    cef = convert_line(line, mapping={})
    assert cef.startswith("CEF:0|Generic|Syslog|1.0|syslog|")


def test_mapping_accepts_json_file_path(tmp_path):
    import json

    path = tmp_path / "mapping.json"
    path.write_text(json.dumps({"deviceVendor": "TestVendor"}), encoding="utf-8")
    normalized = normalize_event(parse_syslog(ASA_LINE))
    cef = to_cef(normalized, mapping=path)
    assert cef.startswith("CEF:0|TestVendor|")


def test_load_mapping_by_name():
    assert load_mapping("cisco_asa")["deviceVendor"] == "Cisco"
    try:
        load_mapping("nope")
    except KeyError:
        pass
    else:
        raise AssertionError("expected KeyError for unknown mapping name")
