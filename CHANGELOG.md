# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/allamiro/syslogcef/compare/v0.1.5...HEAD
[0.1.5]: https://github.com/allamiro/syslogcef/compare/v0.1.4...v0.1.5
[0.1.4]: https://github.com/allamiro/syslogcef/compare/v0.1.3...v0.1.4
[0.1.3]: https://github.com/allamiro/syslogcef/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/allamiro/syslogcef/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/allamiro/syslogcef/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/allamiro/syslogcef/releases/tag/v0.1.0
