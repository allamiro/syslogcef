# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- Adaptive parsing no longer lets a cached hostless layout suppress hosts on
  later lines with the same reduced signature. Cached hosts now normalize
  trailing delimiters consistently, named timezone remnants are not treated
  as hosts, IP host tokens are accepted, and `ts_orig` is retained.
- Normalization now treats parsed syslog envelope metadata as authoritative
  over same-named message key/value pairs, preventing payload fields such as
  `host=` and `severity=` from changing mapped metadata. Field-name matching
  is case-insensitive while original spellings remain available.
- Key/value extraction supports escaped quotes and comma-delimited pairs
  without splitting ordinary comma-containing values.
- Python mapping dictionaries receive the same eager structural validation as
  JSON mapping files. Invalid header/extension templates, severity maps, and
  extension keys now fail clearly instead of raising during rendering or
  producing structurally invalid CEF.
- Malformed `%`-format templates are rejected when the mapping is loaded
  rather than degrading silently per event. Previously a template such as
  `%{msgid}` or a literal `100% clean` rendered as an empty string, which
  fell a header back to its default or dropped an extension without any
  indication in the output. Use `%%` for a literal percent sign. Templates
  whose syntax is valid but whose conversion a given value cannot satisfy
  (`%(dpt)d` against a non-numeric field) still degrade gracefully at render
  time, so a malformed mapping can no longer be discovered only after
  millions of records have been written.
- Case normalization of canonical CEF keys no longer depends on the order
  fields appear in a message: an explicitly lowercase `deviceexternalid=`
  now wins over `DEVICEEXTERNALID=` in either order.

### Changed

- **Behavior change.** A mapping with a malformed template is now a
  configuration error (`ValueError`) instead of being tolerated with
  degraded output. All bundled mappings validate cleanly; a custom mapping
  that relied on the previous silent fallback must quote literal percent
  signs as `%%`.

## [0.3.2] - 2026-08-12

### Fixed

- The syslog HOSTNAME now maps to `shost` (source host) instead of
  `dhost` (destination): the host that emitted a syslog line is the
  event's source, not a destination. `dhost` stays reserved for
  network-specific logs whose payload names a real destination. Applied
  in the bundled Linux mapping and the default mapping (`shost`, max
  1023 chars, so long RFC 5424 hostnames still pass `--strict`).
- An ordinary RFC3164 / journald-short line whose message body carries
  `key=value` pairs (containerd, dockerd, NetworkManager, systemd) is no
  longer misparsed as the kv format: the header-based parsers now run
  before the kv detector, so host/app are extracted and the syslog
  header is not leaked into the message. Genuine kv streams (Fortinet,
  Sophos) still parse as kv.

## [0.3.1] - 2026-08-11

### Fixed

- Continuation context is scoped per input source: with several input
  files (or several files tailed at once, which interleave), an
  indented line now inherits host/app/timestamp only from its own
  file's preceding event, never from another file's.
- A forced `--mode` no longer aborts on whitespace-indented
  continuation lines: with context available they inherit as in
  auto-detect mode; without context the parser error is still raised.
- `dvcpid=` is emitted only for numeric pids: RFC 5424 PROCID may be an
  arbitrary string ("worker-A"), and the CEF dictionary types dvcpid as
  an integer, so non-numeric identifiers previously produced invalid
  output that `--strict` rejected. They remain available as `%(pid)s`.

## [0.3.0] - 2026-08-11

### Added

- Event time in the CEF output: every event now carries `rt=` (epoch
  milliseconds) from the parsed timestamp, or the processing time when
  the line had no usable timestamp. The bundled Linux mapping also
  emits `dvcpid=` for the syslog tag's pid.
- Continuation-line handling for multi-line records (macOS install.log
  and system.log wrapped payloads, stack traces): whitespace-indented
  lines inherit host, program, pid, PRI, and timestamp from the
  preceding event instead of getting the local machine's hostname —
  which, inside a container, was the container ID. Available in the
  sequential CLI pipeline and as `syslogcef.StreamConverter`; not
  applied under `--multiprocess`.
- The adaptive parser now recognizes a syslog program tag
  (`app:` / `app[pid]:`) after the host token and maps it to the
  process/pid fields instead of leaving it in the message, on both the
  first-sight analysis and the cached-pattern path.

### Fixed

- Compact UTC offsets as written by macOS install.log
  (`2026-07-20 03:23:05+02`) and colonless offsets (`+0200`) parse
  correctly in the ISO syslog, rsyslog-file, and journald-ISO formats
  and in `parse_iso8601` — including on Python 3.9/3.10, where
  `fromisoformat` only accepts the `+02:00` form. Previously such
  lines fell through to the adaptive parser, which lost the hostname
  and program because the stray `+02` token blocked host detection.
- `journald_short` and `journald_iso` split `app[pid]:` tags into
  program and pid instead of reporting `opendirectoryd[69]` as the
  program name.

## [0.2.1] - 2026-08-11

### Fixed

- The standalone zipapp works again — and for the first time actually
  works on Python 3.9: `dictionary.json` was read via a filesystem path
  (broke the v0.2.0 `.pyz` build), and the mapping loader anchored
  `importlib.resources` on `__package__`, which is None under Python
  3.9's legacy zipimport. Both loaders use explicit package anchors,
  and a regression test imports the package from inside a zip archive.

## [0.2.0] - 2026-08-11

### Added

- The CEF field dictionary (`syslogcef/dictionary.json`): 176 keys with
  type, maximum length, and producer/consumer scope (including the full
  Event Consumers table and the CEF 1.2 fields), plus 56 source-field
  aliases (`srcip` -> `src`, `dstport` -> `dpt`, `user` -> `suser`,
  `rcvdbyte`/`sentbyte` -> `in`/`out`, ...) applied during
  normalization for every event — including adaptively-parsed unknown
  formats — so mappings and validation always see canonical CEF keys.

### Changed

- The built-in fallback mapping carries the raw line as `cs1` +
  `cs1Label=rawEvent` (like every bundled mapping) instead of setting
  the consumer-only `rawEvent` key, per the ArcSight dictionary rule
  that producers must not set consumer-side fields. Downstream content
  keyed on `rawEvent=` in default-mapped output must read `cs1=`.
- `--validate`/`--strict` warn (non-fatally) when producer output sets
  a consumer-side CEF key, and validate the CEF 1.2 fields' types and
  lengths; the validation table is loaded from the shared dictionary.
- A custom mapping overriding either member of the default
  `cs1`/`cs1Label` pair drops both defaults, so custom values are never
  mislabeled `rawEvent`.

## [0.1.6] - 2026-08-11

### Fixed

Eleven robustness and correctness bugs found by the new fuzzing
infrastructure (grammar-based property tests, ClusterFuzzLite, and AI
review), each with a regression test:

- The journald JSON parser claimed any JSON object: rsyslog-style
  records lost their host, message, and timestamp. It now requires
  journald-style keys and routes rsyslog-marker shapes to the rsyslog
  parser, which also gained `@timestamp`/`timereported` and `syslogtag`
  support.
- kv streams: `ts=`/`timestamp=`/`datetime=` ISO keys are parsed (was:
  only `date=`+`time=`/`eventtime=`); timestamp aliases in both kv and
  rsyslog records are tried independently, so an invalid value no
  longer masks a valid one; `ts_orig` records the value that parsed;
  out-of-range `tz=` offsets and epoch values are ignored instead of
  raising.
- Severity resolution can no longer crash or corrupt the header: a
  non-numeric kv `pri=`, Unicode digits (`severity=²`), and
  multi-thousand-digit values (Python 3.11+ int-conversion limit) all
  fall back to the default; the resolved value is validated to numeric
  0-10.
- Yearless `Feb 29` timestamps no longer crash when the converting
  host's clock is in a non-leap year, and resolve to the nearest leap
  year in time.
- Non-string JSON scalars (`"message": 123`) are coerced instead of
  crashing sanitization.

### Added

- ClusterFuzzLite coverage-guided fuzzing on every parser-touching PR,
  a structure-aware fuzz harness generating six syslog dialects, a seed
  corpus, grammar-based property tests with planted field values, and a
  ready-to-submit OSS-Fuzz kit (see `fuzz/README.md`).
- `docs/cef_fields.md`: ArcSight producer-vs-consumer rules, CEF
  version notes, and a validated sample record.

## [0.1.5] - 2026-08-11

### Added

- `--output` accepts strftime codes (e.g.
  `/var/log/syslogcef/%Y-%m-%d/events-%H.cef`); the file is reopened
  when the rendered path changes (checked at most once per second,
  rendered with an aware local time so `%z`/`%Z` work), parent
  directories are created, and templated paths always append. Codes
  are validated against a portable allowlist at startup; `%%` is a
  literal percent and keeps plain truncate/append semantics.
- `syslogcef@.service` template unit: run several independent pipelines,
  each configured by its own file in `/etc/syslogcef/conf.d/` (a
  commented `example.conf.sample` is installed). The Alpine OpenRC
  service supports the same via symlinked instances.
- Logrotate snippet (`/etc/logrotate.d/syslogcef`) for flat `.cef`
  archives, using copytruncate.
- User-defined parsers: `--patterns file.json` loads named regexes
  whose named groups map to event fields, with strptime/iso8601/epoch
  timestamps, before/after precedence, and eager startup validation;
  pattern names work as `--mode` values and per service instance via
  conf.d. From Python: `register_parser()` and `load_patterns()`.
- Property-based fuzz tests (hypothesis, `fuzz` extra) verifying the
  pipeline never crashes, emits structurally valid CEF, stays within a
  per-line time budget, and keeps the adaptive cache bounded — run on
  every change, plus a weekly 10k-example deep run and an Atheris
  harness in `fuzz/`.
- CI now lints (ruff, shellcheck, hadolint) and builds + smoke-tests
  the container image on every change; issues and pull requests are
  auto-labeled and assigned.

### Changed

- An empty `--output` value means stdout, so `OUTPUT_FILE=` in the
  service environment file logs to the journal instead of misparsing
  the following arguments; `${OUTPUT_FILE}` is expanded unsplit in the
  systemd units and quoted in the OpenRC script.
- The container image runs as numeric UID 65534 so non-root execution
  is verifiable by container runtimes.
- The RPM `%check` runs the full test suite instead of only an import
  check.

## [0.1.4] - 2026-08-11

### Fixed

- TCP listener buffers are capped at 1 MiB per connection; clients
  streaming data without newlines are dropped instead of exhausting
  memory.
- Listen-mode stdout flushes per record when redirected.
- Kafka delivery futures are observed; asynchronous failures raise on
  the next send and on close instead of being silently lost.
- The `--eps` limiter keeps full spacing after processing pauses, and
  `--eps 0` is rejected.
- Validation: IPv4-typed fields reject IPv6 (use c6a1-c6a4), the nine
  standard `oldFile*` keys are validated, and timestamps are parsed
  rather than shape-matched.
- The man page no longer claims the packaged service runs without
  root; the unit documents how to drop privileges with `User=`.

## [0.1.3] - 2026-08-11

### Added

- Network input: `--listen udp:PORT` / `tcp:PORT` turns syslogcef into a
  syslog receiver feeding the conversion pipeline directly.
- Network output: `--send udp://HOST:PORT`, `tcp://HOST:PORT` (with
  reconnect and backoff), or `kafka://BROKER:PORT/TOPIC` (via
  `pip install syslog2cef[kafka]`); `--eps` rate-limits forwarding.
  Combinable with `--output` and `--listen` for a complete
  receive-convert-forward daemon.
- CEF validation: `--validate` checks extensions against the ArcSight
  dictionary (types, lengths, IP/MAC/port/timestamp formats) and warns;
  `--strict` fails on violations. Also available via the API
  (`convert_line(..., validate=True, strict=True)`).
- Comprehensive syslogcef(1) man page covering every option with eight
  examples.
- The systemd unit carries CAP_NET_BIND_SERVICE so port 514 can be
  bound without root; the service config documents network daemon mode.

### Fixed

- Empty CEF header slots are no longer possible: header templates that
  resolve empty fall back to the default mapping template.
- kv timestamps honor numeric `tz=` offsets; native Cisco timestamps
  keep milliseconds; adaptive month-day timestamps use year-rollover
  inference; cached adaptive patterns revalidate host candidates and
  preserve empty messages.

## [0.1.2] - 2026-08-11

Validated against all 543 filebeat module test logs from elastic/beats
(103,837 lines, zero crashes).

### Fixed

- RFC3164 timestamps may include a year (`Oct 10 2018 12:34:56`), the
  format real Cisco ASA/FTD devices emit.
- Hostnames followed by a trailing or standalone colon now parse.
- Cisco `%FAC-SEV-MNEMONIC` event codes are extracted from anywhere in
  the message (IOS sequence-numbered lines), and their severity digit is
  used when the line has no PRI.
- The raw fallback parser preserves a leading `<PRI>` (Sophos XG style),
  keeping facility and severity.
- Auto-mapping routes FTD event codes to the ASA mapping and other Cisco
  codes to the IOS mapping.

## [0.1.1] - 2026-08-10

### Added

- `syslogcef(1)` man page, installed by the RPM, Debian, and Alpine
  packages.
- Multi-arch (amd64/arm64) container image published to
  `ghcr.io/allamiro/syslogcef` on each release.
- COPR repository (`allamiro/syslogcef`) building for Fedora, EPEL 9/10,
  and CentOS Stream 9/10 on x86_64 and aarch64, rebuilt automatically on
  every push.

### Fixed

- Python 3.9 compatibility: dataclasses no longer use `slots=True`
  (a Python 3.10 feature), so the declared `requires-python >= 3.9` is
  accurate again.
- EPEL 9 RPM builds use the python3.11 stack, whose setuptools supports
  PEP 621 metadata.

## [0.1.0] - 2026-08-10

Initial release.

### Added

- Python package with parsers for RFC3164, RFC5424, rsyslog (JSON and file
  formats), and systemd journal exports (JSON, short, and ISO formats), with
  automatic format detection.
- Normalization layer deriving key/value pairs, event codes, and common
  fields from raw messages.
- CEF renderer with JSON-configurable mappings; bundled mappings for Cisco
  ASA, Cisco IOS, F5, generic Linux, and VMware.
- Command line interface with stdin/file input, output file support, tail
  (follow) mode, and optional multiprocessing.
- Release packaging: PyPI distribution (as `syslog2cef`), signed RPM and
  Debian packages with a systemd service, signed Alpine APK with an
  OpenRC service, standalone executable zipapp, and source zip — all
  GPG-signed with a signed SHA256SUMS manifest.
- Test suite and GitHub Actions CI.

### Fixed

- Default Linux mapping contained an invalid template that crashed every
  conversion routed to it.
- CEF header fields are now escaped so crafted log content cannot forge
  header fields or split records.
- `--tail` now follows all given input files instead of blocking on the
  first one.

[Unreleased]: https://github.com/allamiro/syslogcef/compare/v0.3.2...HEAD
[0.3.2]: https://github.com/allamiro/syslogcef/compare/v0.3.1...v0.3.2
[0.3.1]: https://github.com/allamiro/syslogcef/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/allamiro/syslogcef/compare/v0.2.1...v0.3.0
[0.2.1]: https://github.com/allamiro/syslogcef/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/allamiro/syslogcef/compare/v0.1.6...v0.2.0
[0.1.6]: https://github.com/allamiro/syslogcef/compare/v0.1.5...v0.1.6
[0.1.5]: https://github.com/allamiro/syslogcef/compare/v0.1.4...v0.1.5
[0.1.4]: https://github.com/allamiro/syslogcef/compare/v0.1.3...v0.1.4
[0.1.3]: https://github.com/allamiro/syslogcef/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/allamiro/syslogcef/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/allamiro/syslogcef/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/allamiro/syslogcef/releases/tag/v0.1.0
