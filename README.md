# syslogcef

`syslogcef` is a small, testable Python package that converts syslog events from
multiple dialects (RFC3164, RFC5424, rsyslog, and systemd journal exports) into
ArcSight Common Event Format (CEF). It ships with deterministic vendor/product
mappings for Cisco ASA/IOS, F5, generic Linux, and VMware sources.

## Installation

```bash
pip install .
```

## Usage

### Python API

```python
from syslogcef import convert_line

line = "<166>Jan  1 12:34:56 router1 %ASA-6-302013: Built inbound TCP connection src=10.0.0.1 dst=10.0.0.2"
cef = convert_line(line)
print(cef)
```

The lower-level APIs are also available when granular control is required:

```python
from syslogcef import parse_syslog, normalize_event, to_cef

parsed = parse_syslog(line)
normalized = normalize_event(parsed)
cef = to_cef(normalized)
```

Mappings can be supplied as dictionaries or JSON files. Built-in mappings are
available in `syslogcef.mappings`.

### Command line interface

```bash
# Read from stdin and emit CEF to stdout
syslogcef < /var/log/syslog

# Convert a file and write to another file
syslogcef /var/log/messages --output messages.cef

# Tail a file in real time with multiprocessing conversion
syslogcef /var/log/asa.log --tail --multiprocess --mapping syslogcef/mappings/cisco_asa.json
```

Use `python -m syslogcef --help` for the full list of options. The CLI supports
watch/tail mode, optional multiprocessing, and graceful back-pressure to avoid
memory spikes when reading large log streams.

## Development

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .[test]
pytest
```

## License

MIT
