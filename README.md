<p align="center">
  <img src="https://raw.githubusercontent.com/allamiro/syslog2cef/main/docs/logo.svg" alt="syslog2cef logo" width="540">
</p>

# syslog2cef

syslog2cef converts syslog events into ArcSight Common Event Format (CEF). It
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

From PyPI:

```bash
pip install syslog2cef
```

> **Naming.** The project, this repository, the PyPI distribution and the
> RPM/DEB/APK packages are all `syslog2cef`. The command you run and the
> Python package you import are `syslogcef`, unchanged — as are the config
> paths (`/etc/syslogcef/`), the systemd units and the log directory, so
> upgrading from an earlier release needs no changes. The `syslogcef` name
> on PyPI belongs to an unrelated project, which is why the distribution
> has always been `syslog2cef`.

From source:

```bash
git clone https://github.com/allamiro/syslog2cef.git
cd syslog2cef
pip install .
```

The GitHub releases page also provides, for every version:

- An RPM package (Fedora/RHEL) with a systemd service — see "Running as a
  Service" below.
- A Debian package (`syslog2cef_X.Y.Z-1_all.deb`) with the same systemd
  service: `sudo apt install ./syslog2cef_X.Y.Z-1_all.deb`.
- An Alpine APK with an OpenRC service:
  `apk add --allow-untrusted syslog2cef-X.Y.Z-r0.apk` (or install the
  signing key from [packaging/apk/syslogcef.rsa.pub](packaging/apk/syslogcef.rsa.pub)
  into `/etc/apk/keys/` first to verify).
- A standalone executable (`syslog2cef-X.Y.Z.pyz`) that runs on any system
  with Python 3.9+: `chmod +x syslog2cef-X.Y.Z.pyz && ./syslog2cef-X.Y.Z.pyz`.
- A source zip and sdist/wheel files.

A multi-arch (amd64/arm64) container image is published to GitHub
Container Registry on each release:

```bash
docker run -i ghcr.io/allamiro/syslog2cef < /var/log/syslog
```

Fedora, RHEL/Alma/Rocky 9 and 10, and CentOS Stream users can install
from the [COPR repository](https://copr.fedorainfracloud.org/coprs/allamiro/syslogcef/),
which rebuilds automatically from every commit:

```bash
sudo dnf copr enable allamiro/syslogcef
sudo dnf install syslog2cef
```

The COPR project keeps its original name (`allamiro/syslogcef`) so that
already-enabled repositories keep working; the package it builds is
`syslog2cef`.

Every asset ships with a detached GPG signature (`.asc`) and is listed in
a signed `SHA256SUMS` file; RPMs additionally carry embedded `rpmsign`
signatures. The public key is committed at
[packaging/rpm/RPM-GPG-KEY-syslogcef](packaging/rpm/RPM-GPG-KEY-syslogcef).

## Command Line Usage

<p align="center">
  <img src="https://raw.githubusercontent.com/allamiro/syslog2cef/main/docs/demo.svg" alt="Animated demo of syslog2cef converting different formats" width="820">
</p>

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
rather than failing the event. Mapping files and Python mapping dictionaries
are validated before rendering; malformed templates, severity maps, and CEF
extension keys fail with a configuration error instead of corrupting a record.
See [docs/cef_fields.md](docs/cef_fields.md) for the full CEF extension
dictionary.

## Field Dictionary

`syslogcef/dictionary.json` is the single source of truth for CEF field
knowledge, derived from the ArcSight Extension Dictionary (see
[docs/cef_fields.md](docs/cef_fields.md)):

- **Key metadata** — data type, maximum length, and producer/consumer
  scope for every CEF key. `--validate`/`--strict` check types and
  lengths from it, and warn (without failing) when producer output sets
  a consumer-side key such as `rawEvent`.
- **Field aliases** — common source-log names mapped to canonical CEF
  keys: `srcip`/`source_ip` → `src`, `dstport` → `dpt`, `user` →
  `suser`, `rcvdbyte` → `in`, `action` → `act`, and ~50 more. Aliases
  are applied during normalization for **every** event — including
  key=value pairs extracted from adaptively-parsed unknown formats — so
  mappings and validation always see canonical names. Original keys are
  preserved and an explicit canonical key is never overwritten. Source key
  casing is normalized as well (`SRCIP`, `SrcIp`, and `srcip` all make `src`
  available), while parsed syslog envelope fields such as host and severity
  remain authoritative over same-named text in the message.

This means a Fortinet-style `srcip=10.1.1.1 dstport=443` and an unknown
device emitting the same pairs behind an unrecognized prefix both end up
with `src` and `dpt` available to mapping templates, with no per-device
configuration.

## Custom Parsers

When a device emits a format no built-in parser handles, add your own
detection regexes the same way you add mappings — no code required:

```bash
syslogcef acme.log --patterns /etc/syslogcef/patterns.json
```

```json
{
  "patterns": [
    {
      "name": "acme_fw",
      "regex": "^ACME (?P<ts>\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2}) (?P<host>\\S+) (?P<app>\\w+)\\[(?P<pid>\\d+)\\]: (?P<msg>.*)$",
      "timestamp_format": "%Y-%m-%d %H:%M:%S",
      "priority": "after"
    }
  ]
}
```

- Named groups map to event fields: `pri`, `host`, `app`, `pid`,
  `msgid`, `msg`, and `ts`.
- A `ts` group requires `timestamp_format`: a strptime format,
  `iso8601`, or `epoch`. Yearless formats get the same year-rollover
  inference as the built-in parsers; an unparseable timestamp never
  drops the event.
- `priority` is `"after"` (default: tried after the built-ins, before
  the adaptive fallback) or `"before"` (tried first, overriding
  built-ins).
- Pattern names work as `--mode` values, and files are validated at
  startup — bad regexes, unknown groups, or duplicate names fail with
  a clear message instead of mid-stream.
- Per-service-instance patterns: set
  `EXTRA_ARGS=--patterns /etc/syslogcef/patterns.json` in the
  instance's conf.d file.
- Your regexes run against untrusted log content — keep them anchored
  and avoid nested quantifiers (ReDoS).

From Python, register full parser functions instead:

```python
from syslogcef import register_parser, load_patterns

load_patterns("patterns.json")               # same file format
register_parser("marker", my_parse_fn)       # fn(line) -> ParsedEvent | None
```

## Running as a Service

The RPM and Debian packages install a systemd unit and an environment
file (the Alpine APK installs the equivalent OpenRC service with its
configuration in `/etc/conf.d/syslogcef`):

- `/etc/syslogcef/syslogcef.conf` — input file, output file, and extra
  arguments for the converter.
- `syslogcef.service` — runs `syslogcef --tail` against the configured
  input and appends CEF to the configured output.
- `syslogcef@.service` — template unit for running several independent
  pipelines from `/etc/syslogcef/conf.d/` (see below).
- `/etc/logrotate.d/syslogcef` — daily rotation for flat `.cef` archives.

```bash
sudo dnf install syslog2cef-*.rpm
sudo vi /etc/syslogcef/syslogcef.conf
sudo systemctl enable --now syslogcef
```

The environment file has three variables; everything else goes through
`EXTRA_ARGS`, which accepts any command line flag (`--mode`, `--mapping`,
`--listen`, `--send`, `--eps`, `--validate`, `--strict`,
`--multiprocess`, `--log-level`, ...):

```bash
# File(s) to follow for new syslog lines, separated by spaces.
INPUT_FILE=/var/log/messages

# File that converted CEF events are appended to.
OUTPUT_FILE=/var/log/syslogcef/events.cef

# Extra arguments; leave INPUT_FILE empty and use --listen for a
# network daemon: EXTRA_ARGS=--listen udp:514 --send tcp://siem:514
EXTRA_ARGS=
```

### Timed output files

`OUTPUT_FILE` (and `--output` generally) accepts strftime codes; the
file is reopened whenever the rendered path changes and parent
directories are created automatically:

```bash
# New file each hour, grouped in a directory per day:
OUTPUT_FILE=/var/log/syslogcef/%Y-%m-%d/events-%H.cef
```

Unsupported `%` codes are rejected at startup (use `%%` for a literal
percent). Keep templated outputs in a dated subdirectory as shown above:
the installed logrotate snippet rotates every flat `.cef` file directly
under `/var/log/syslogcef/`, and a templated file rendering flat there
would be rotated twice. Prefer a stable filename if a downstream
collector reads the archive — flat files are rotated daily by logrotate
instead.

### Multiple pipelines (one input per output)

To map specific inputs to specific outputs, run one instance of the
template unit per pipeline. Each instance reads its own file in
`/etc/syslogcef/conf.d/` (a commented `example.conf.sample` is
installed there) and has independent restart, logs, and options:

```bash
sudo cp /etc/syslogcef/conf.d/example.conf.sample /etc/syslogcef/conf.d/secure.conf
sudo cp /etc/syslogcef/conf.d/example.conf.sample /etc/syslogcef/conf.d/firewall.conf
sudo vi /etc/syslogcef/conf.d/secure.conf     # /var/log/secure  -> secure.cef
sudo vi /etc/syslogcef/conf.d/firewall.conf   # --listen udp:514 --mode cisco_seq
sudo systemctl enable --now syslogcef@secure syslogcef@firewall
```

On Alpine, OpenRC gets the same result with symlinked services:

```bash
sudo ln -s syslogcef /etc/init.d/syslogcef.firewall
sudo cp /etc/conf.d/syslogcef /etc/conf.d/syslogcef.firewall
sudo vi /etc/conf.d/syslogcef.firewall   # set a distinct INPUT_FILE and OUTPUT_FILE
sudo rc-update add syslogcef.firewall && sudo rc-service syslogcef.firewall start
```

Give every instance its own `INPUT_FILE` and `OUTPUT_FILE` — two
instances sharing them would process the same events twice and append
to the same file concurrently.

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
git clone https://github.com/allamiro/syslog2cef.git
cd syslog2cef
python -m venv .venv
source .venv/bin/activate
pip install -e .[test]
pytest
```

Contributions are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md). Notable
changes are tracked in [CHANGELOG.md](CHANGELOG.md).

## License

MIT — see [LICENSE](LICENSE). Copyright (c) Tamir Suliman.
