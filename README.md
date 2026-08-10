<p align="center">
  <img src="https://raw.githubusercontent.com/allamiro/syslogcef/main/docs/logo.svg" alt="syslogcef logo" width="540">
</p>

# syslogcef

syslogcef converts syslog events into ArcSight Common Event Format (CEF). It
is a small, dependency-free Python package with a command line interface,
built for feeding syslog data from network devices and Linux hosts into SIEM
platforms that consume CEF.

## Features

- Automatic detection and parsing of multiple syslog dialects:
  RFC3164 (BSD), RFC5424 (including structured data), rsyslog JSON and
  file formats, and systemd journal exports (JSON, short, and ISO formats).
- Deterministic vendor/product mappings bundled for Cisco ASA, Cisco IOS,
  F5 BIG-IP, generic Linux, and VMware ESXi, with automatic mapping
  selection based on message content.
- Custom mappings supplied as JSON files or Python dictionaries.
- Escaping of untrusted log content in both CEF header and extension
  fields, so crafted messages cannot forge header fields or split records.
- Streaming CLI with stdin/file input, tail (follow) mode across multiple
  files, optional multiprocessing, and no runtime dependencies.
- Malformed lines never abort a stream: unparseable input falls back to a
  raw-message event.

## Installation

From PyPI (the distribution is named `syslog2cef` because the `syslogcef`
name on PyPI belongs to an unrelated project; the import package and CLI
are still `syslogcef`):

```bash
pip install syslog2cef
```

From source:

```bash
git clone https://github.com/allamiro/syslogcef.git
cd syslogcef
pip install .
```

The GitHub releases page also provides, for every version:

- An RPM package (Fedora/RHEL) with a systemd service — see "Running as a
  Service" below.
- A Debian package (`syslogcef_X.Y.Z-1_all.deb`) with the same systemd
  service: `sudo apt install ./syslogcef_X.Y.Z-1_all.deb`.
- An Alpine APK with an OpenRC service:
  `apk add --allow-untrusted syslogcef-X.Y.Z-r0.apk` (or install the
  signing key from [packaging/apk/syslogcef.rsa.pub](packaging/apk/syslogcef.rsa.pub)
  into `/etc/apk/keys/` first to verify).
- A standalone executable (`syslogcef-X.Y.Z.pyz`) that runs on any system
  with Python 3.9+: `chmod +x syslogcef-X.Y.Z.pyz && ./syslogcef-X.Y.Z.pyz`.
- A source zip and sdist/wheel files.

A multi-arch (amd64/arm64) container image is published to GitHub
Container Registry on each release:

```bash
docker run -i ghcr.io/allamiro/syslogcef < /var/log/syslog
```

Fedora, RHEL/Alma/Rocky 9 and 10, and CentOS Stream users can install
from the [COPR repository](https://copr.fedorainfracloud.org/coprs/allamiro/syslogcef/),
which rebuilds automatically from every commit:

```bash
sudo dnf copr enable allamiro/syslogcef
sudo dnf install syslogcef
```

Every asset ships with a detached GPG signature (`.asc`) and is listed in
a signed `SHA256SUMS` file; RPMs additionally carry embedded `rpmsign`
signatures. The public key is committed at
[packaging/rpm/RPM-GPG-KEY-syslogcef](packaging/rpm/RPM-GPG-KEY-syslogcef).

## Command Line Usage

```bash
# Read from stdin, write CEF to stdout
syslogcef < /var/log/syslog

# Convert one or more files and write to an output file
syslogcef /var/log/messages /var/log/secure --output events.cef

# Follow files in real time (all files are tailed concurrently)
syslogcef /var/log/asa.log /var/log/messages --tail

# Force a parser and mapping instead of auto-detection
syslogcef asa.log --mode rfc3164 --mapping syslogcef/mappings/cisco_asa.json

# Use multiprocessing for high-volume batch conversion
syslogcef big.log --multiprocess --pool-size 4
```

Options:

| Option | Description |
| ------ | ----------- |
| `paths` | Input files; stdin is used when omitted. |
| `-o, --output FILE` | Write CEF lines to a file instead of stdout. |
| `--mode MODE` | Parser override: `rfc3164`, `rfc5424`, `rsyslog_json`, `rsyslog_file`, `journald_json`, `journald_short`, `journald_iso`. Auto-detected when omitted. |
| `--mapping FILE` | Mapping JSON file. Auto-selected from message content when omitted. |
| `--tail` | Follow input files like `tail -f`. |
| `--multiprocess` | Convert lines using a process pool. |
| `--pool-size N` | Worker count for `--multiprocess` (default: CPU count minus one). |
| `--log-level LEVEL` | Python logging level (default `WARNING`). |

`python -m syslogcef` is equivalent to the `syslogcef` entry point.

## Python API

High-level, one call per line:

```python
from syslogcef import convert_line

line = "<166>Jan  1 12:34:56 fw01 %ASA-6-302013: Built inbound TCP connection src=10.0.0.1 dst=10.0.0.2"
print(convert_line(line))
```

Lower-level pipeline when granular control is required:

```python
from syslogcef import parse_syslog, normalize_event, to_cef

parsed = parse_syslog(line)          # ParsedEvent: pri, timestamp, host, app, msg, ...
normalized = normalize_event(parsed) # adds key/value pairs, event codes, derived fields
cef = to_cef(normalized, mapping="my_mapping.json")
```

Bundled mappings are importable from `syslogcef.mappings` (`CISCO_ASA`,
`CISCO_IOS`, `F5`, `LINUX`, `VMWARE`, or `load_mapping(name)`).

## Mapping Files

A mapping is a JSON object that controls the CEF header and extension
fields. Values are Python %-format templates resolved against the
normalized event's fields:

```json
{
  "deviceVendor": "Cisco",
  "deviceProduct": "ASA",
  "deviceVersion": "auto",
  "eventClassId": "asa.%(event_code)s",
  "name": "%(message_short)s",
  "severity_map": { "6": "2", "3": "6" },
  "extensions": {
    "src": "%(src)s",
    "dst": "%(dst)s",
    "cs1Label": "rawEvent",
    "cs1": "%(raw_kv)s"
  }
}
```

- Header keys: `deviceVendor`, `deviceProduct`, `deviceVersion`,
  `eventClassId`, `name`.
- `severity_map` translates syslog severity (0-7) to CEF severity (0-10);
  unmapped values pass through.
- `extensions` maps CEF extension keys to templates. Extensions that
  resolve to an empty value are omitted.
- Available template fields include `host`, `app`, `pid`, `msgid`, `msg`,
  `message_short` (first 120 characters), `raw`, `raw_kv`, `event_code`,
  `facility`, `severity`, `ts`, plus every key=value pair extracted from
  the message and any RFC5424 structured-data or journald fields.

Field templates that reference missing keys resolve to an empty string
rather than failing the event. See [docs/cef_fields.md](docs/cef_fields.md)
for the full CEF extension dictionary.

## Running as a Service

The RPM and Debian packages install a systemd unit and an environment
file (the Alpine APK installs the equivalent OpenRC service with its
configuration in `/etc/conf.d/syslogcef`):

- `/etc/syslogcef/syslogcef.conf` — input file, output file, and extra
  arguments for the converter.
- `syslogcef.service` — runs `syslogcef --tail` against the configured
  input and appends CEF to the configured output.

```bash
sudo dnf install syslogcef-*.rpm
sudo vi /etc/syslogcef/syslogcef.conf
sudo systemctl enable --now syslogcef
```

See [packaging/rpm/](packaging/rpm/) for the spec file and build
instructions, including GPG signing of the RPM.

## Security

Log content is treated as untrusted input. Header and extension values are
escaped per the CEF specification before rendering, and CR/LF are removed
from header fields so records cannot be split or spoofed. To report a
vulnerability, see [SECURITY.md](SECURITY.md) — please do not open public
issues for security reports.

## Development

```bash
git clone https://github.com/allamiro/syslogcef.git
cd syslogcef
python -m venv .venv
source .venv/bin/activate
pip install -e .[test]
pytest
```

Contributions are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md). Notable
changes are tracked in [CHANGELOG.md](CHANGELOG.md).

## License

MIT — see [LICENSE](LICENSE). Copyright (c) Tamir Suliman.
