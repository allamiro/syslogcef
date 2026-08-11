from __future__ import annotations

from syslogcef import convert_line, normalize_event, parse_syslog
from syslogcef.dictionary import cef_keys, consumer_keys, field_aliases
from syslogcef.validation import CEF_KEYS, validate_extensions


def test_dictionary_integrity():
    keys = cef_keys()
    aliases = field_aliases()
    consumers = consumer_keys()

    # Every alias points at a real, producer-scope CEF key and never
    # shadows a real key name.
    for alias, target in aliases.items():
        assert target in keys, f"alias {alias} -> unknown key {target}"
        assert target not in consumers, f"alias {alias} -> consumer key {target}"
        assert alias not in keys, f"alias {alias} shadows a real CEF key"

    # Scopes and types are from the known vocabulary.
    valid_types = {"str", "int", "long", "float", "port", "ip", "ipv4", "ipv6", "mac", "ts"}
    for key, (kind, maxlen) in keys.items():
        assert kind in valid_types, f"{key}: unknown type {kind}"
        assert isinstance(maxlen, int)

    # Consumer knowledge present (the rule from docs/cef_fields.md).
    assert "rawEvent" in consumers
    assert "agt" in consumers


def test_validation_table_comes_from_dictionary():
    assert CEF_KEYS == cef_keys()
    # Spot-check known entries survived the data-file migration.
    assert CEF_KEYS["act"] == ("str", 63)
    assert CEF_KEYS["src"] == ("ipv4", 0)
    assert CEF_KEYS["cs1"] == ("str", 4000)


def test_kv_aliases_canonicalized():
    event = normalize_event(
        parse_syslog("srcip=10.1.1.1 dstport=443 user=alice action=allow protocol=tcp")
    )

    assert event.kv["src"] == "10.1.1.1"
    assert event.kv["dpt"] == "443"
    assert event.kv["suser"] == "alice"
    assert event.kv["act"] == "allow"
    assert event.kv["proto"] == "tcp"
    # Originals are preserved.
    assert event.kv["srcip"] == "10.1.1.1"


def test_alias_never_overwrites_canonical_key():
    event = normalize_event(
        parse_syslog("src=10.0.0.1 srcip=99.9.9.9 dst=10.0.0.2 action=x")
    )

    assert event.kv["src"] == "10.0.0.1"  # explicit canonical key wins


def test_adaptive_event_kv_gets_aliases():
    # An adaptive-parsed line (unknown prefix) with kv pairs in the
    # message: the dictionary aliases must still apply.
    event = normalize_event(
        parse_syslog("## Aug 11 07:00:00 fw9 blocked flow srcip=172.16.0.9 dstport=22")
    )

    assert event.source_hint == "adaptive"
    assert event.kv.get("src") == "172.16.0.9"
    assert event.kv.get("dpt") == "22"


def test_consumer_key_warns_but_does_not_fail():
    findings = validate_extensions({"rawEvent": "x", "src": "10.0.0.1"})

    consumer_findings = [f for f in findings if f.key == "rawEvent"]
    assert consumer_findings and not consumer_findings[0].fatal
    assert "consumer" in consumer_findings[0].problem


def test_aliased_fields_flow_into_cef_output():
    # A mapping written against canonical CEF keys works for a source
    # that only emits vendor-style names — the aliases bridge them.
    mapping = {
        "deviceVendor": "Test",
        "deviceProduct": "Aliases",
        "extensions": {"src": "%(src)s", "dst": "%(dst)s", "dpt": "%(dpt)s", "suser": "%(suser)s"},
    }

    cef = convert_line(
        "srcip=10.1.1.1 dstip=10.2.2.2 dstport=443 user=alice action=allow",
        mapping=mapping,
    )

    assert "src=10.1.1.1" in cef
    assert "dst=10.2.2.2" in cef
    assert "dpt=443" in cef
    assert "suser=alice" in cef


def test_default_mapping_validates_without_consumer_warnings():
    # The default mapping must not trigger its own consumer-key warning:
    # the raw line travels as cs1/cs1Label, not rawEvent (issue #77).
    from syslogcef.cef import MappingResolver

    event = normalize_event(parse_syslog("plain message with no format"))
    raw = MappingResolver({}).resolve_raw_extensions(event.as_field_dict())

    assert raw.get("cs1Label") == "rawEvent"
    assert "rawEvent" not in raw
    findings = validate_extensions(raw)
    assert not [f for f in findings if "consumer-side" in f.problem]


def test_full_consumer_table_classified():
    consumers = consumer_keys()
    for key in ("agentDnsDomain", "customerURI", "deviceZoneURI", "sourceZoneExternalID", "agt", "rawEvent"):
        assert key in consumers, key


def test_cef_12_fields_validated():
    # CEF 1.2 producer keys are in the dictionary with real metadata, so
    # strict mode rejects invalid values instead of treating them as
    # unconstrained custom keys.
    assert CEF_KEYS["threatActor"] == ("str", 40)
    assert CEF_KEYS["agentZoneKey"] == ("long", 0)

    findings = validate_extensions({"agentZoneKey": "not-a-number", "threatActor": "x" * 41})
    fatal = {f.key for f in findings if f.fatal}
    assert fatal == {"agentZoneKey", "threatActor"}


def test_custom_cs1_does_not_inherit_rawevent_label():
    # Overriding one member of the default cs1/cs1Label pair must drop
    # the other default member, not silently mislabel the custom value.
    cef = convert_line(
        "srcip=1.2.3.4 dstip=5.6.7.8 action=x session=abc123",
        mapping={"extensions": {"cs1": "%(session)s"}},
    )

    assert "cs1=abc123" in cef
    assert "cs1Label=rawEvent" not in cef
