from __future__ import annotations

import pytest

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


def test_programmatic_severity_map_accepts_integer_keys_and_values():
    cef = convert_line(ASA_LINE, mapping={"severity_map": {6: 9}})
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


@pytest.mark.parametrize(
    "mapping, message",
    [
        ({"extensions": ["src"]}, "'extensions' must be an object"),
        ({"severity_map": None}, "'severity_map' must be an object"),
        ({"extensions": {"src": 123}}, "extension template for 'src' must be a string"),
        ({"deviceVendor": 123}, "'deviceVendor' must be a string"),
        ({"severity_map": {"6": "urgent"}}, "severity_map value"),
    ],
)
def test_programmatic_mapping_is_validated(mapping, message):
    with pytest.raises(ValueError, match=message):
        convert_line("plain log", mapping=mapping)


def test_mapping_rejects_extension_keys_that_break_cef_structure():
    with pytest.raises(ValueError, match="invalid extension key"):
        convert_line("plain log", mapping={"extensions": {"bad key": "value"}})


@pytest.mark.parametrize(
    "mapping, message",
    [
        # A malformed template used to render as "" and then silently fall the
        # header back to its default or drop the extension entirely.
        ({"deviceVendor": "%(broken"}, "invalid format specifier"),
        ({"deviceVendor": "%q"}, "invalid format specifier"),
        ({"name": "100% clean"}, "invalid format specifier"),
        ({"deviceVendor": "%()s"}, "empty format key"),
        # "*" width consumes a positional argument a mapping cannot supply.
        ({"extensions": {"src": "%(src)*d"}}, "invalid format specifier"),
        ({"extensions": {"src": "%(broken"}}, "invalid format specifier"),
    ],
)
def test_malformed_templates_fail_before_rendering(mapping, message):
    with pytest.raises(ValueError, match=message):
        convert_line("plain log", mapping=mapping)


@pytest.mark.parametrize(
    "mapping",
    [
        {"deviceVendor": "%(host)s"},
        {"name": "100%% clean"},
        {"deviceVendor": "Acme"},
        {"extensions": {"src": "%(src)s:%(spt)s"}},
        # Numeric conversions are syntactically valid; whether a given field
        # can satisfy one is data-dependent and handled at render time.
        {"extensions": {"sev": "%(severity)03d"}},
    ],
)
def test_valid_templates_are_accepted(mapping):
    assert convert_line(
        "<14>Jan  1 12:34:56 fw1 app: src=1.1.1.1 spt=5", mapping=mapping
    ).startswith("CEF:0|")


def test_literal_percent_template_renders():
    cef = convert_line("plain log", mapping={"name": "100%% clean"})
    assert cef.split("|")[5] == "100% clean"
