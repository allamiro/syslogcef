from __future__ import annotations

"""Regression tests built from real sample lines in the Elastic Beats
filebeat module test corpus (x-pack/filebeat/module/*/test)."""

from syslogcef import convert_line, normalize_event, parse_syslog


def fields(cef: str) -> list[str]:
    return cef.split("|")


def test_asa_with_year_and_tag():
    line = "Oct 10 2018 12:34:56 localhost CiscoASA[999]: %ASA-6-305011: Built dynamic TCP translation from inside:172.31.98.44/1772 to outside:100.66.98.44/8256"
    ev = parse_syslog(line)
    assert ev.source_hint == "rfc3164"
    assert ev.host == "localhost"
    assert ev.app == "CiscoASA"
    assert ev.pid == "999"
    assert ev.ts.year == 2018
    cef = convert_line(line)
    assert fields(cef)[1] == "Cisco"
    assert fields(cef)[4] == "asa.ASA-6-305011"


def test_asa_with_year_and_standalone_colon_host():
    line = "Apr 17 2020 14:08:08 SNL-ASA-VPN-A01 : %ASA-6-302016: Teardown UDP connection 110577675 for Outside:10.123.123.123/53723(LOCAL\\Elastic) to Inside:10.233.123.123/53 duration 0:00:00 bytes 148"
    ev = parse_syslog(line)
    assert ev.source_hint == "rfc3164"
    assert ev.host == "SNL-ASA-VPN-A01"
    assert ev.ts.year == 2020
    cef = convert_line(line)
    assert fields(cef)[4] == "asa.ASA-6-302016"


def test_asa_host_with_trailing_colon():
    line = "Oct 10 2019 10:21:36 localhost: %ASA-6-302021: Teardown ICMP connection for faddr 192.0.2.15/0 gaddr 192.0.2.134/57808 laddr 192.0.2.134/57808"
    ev = parse_syslog(line)
    assert ev.source_hint == "rfc3164"
    assert ev.host == "localhost"
    assert normalize_event(ev).kv["event_code"] == "ASA-6-302021"


def test_ios_sequence_number_line_gets_code_and_severity():
    line = "Feb  8 04:00:48 198.51.100.2 585917: Feb  8 04:00:47.272: %SEC-6-IPACCESSLOGRP: list 177 denied igmp 198.51.100.197 -> 224.0.0.22, 1 packet"
    ev = normalize_event(parse_syslog(line))
    assert ev.kv["event_code"] == "SEC-6-IPACCESSLOGRP"
    assert ev.severity == 6
    cef = convert_line(line)
    assert fields(cef)[1] == "Cisco"
    assert fields(cef)[2] == "IOS"
    assert fields(cef)[4] == "ios.SEC-6-IPACCESSLOGRP"
    # syslog severity 6 maps to CEF severity 2 via the default map
    assert fields(cef)[6] == "2"


def test_ftd_event_code_routes_to_asa_mapping():
    line = "Apr 17 2020 14:00:00 firepower : %FTD-6-305012: Teardown dynamic TCP translation from Inside:10.1.1.1/54000 to Outside:198.51.100.1/54000 duration 0:00:30"
    cef = convert_line(line)
    assert fields(cef)[1] == "Cisco"
    assert fields(cef)[4] == "asa.FTD-6-305012"


def test_pri_survives_sophos_kv_line():
    # Sophos XG style: PRI prefix followed by key=value pairs, no syslog
    # header. Parsed by the dedicated kv parser; PRI is preserved.
    line = '<30>device="SFW" date=2020-05-18 time=14:38:48 timezone="CEST" device_name="XG230" log_type="Anti-Spam" src_ip="" dst_ip=""'
    ev = parse_syslog(line)
    assert ev.source_hint == "kv"
    assert ev.pri == 30
    assert ev.facility == 3
    assert ev.severity == 6
    assert not ev.msg.startswith("<30>")
    cef = convert_line(line)
    assert fields(cef)[6] == "2"


def test_pri_survives_raw_fallback():
    line = "<30>completely nonstandard payload without structure"
    ev = parse_syslog(line)
    assert ev.source_hint == "unknown"
    assert ev.pri == 30
    assert ev.severity == 6
    assert not ev.msg.startswith("<30>")


def test_classic_rfc3164_without_year_still_parses():
    line = "<166>Jan  1 12:34:56 router1 sshd[123]: Accepted password for user"
    ev = parse_syslog(line)
    assert ev.source_hint == "rfc3164"
    assert ev.host == "router1"
    assert ev.app == "sshd"
    assert ev.pid == "123"
