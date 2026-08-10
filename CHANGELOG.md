# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/allamiro/syslogcef/compare/v0.1.2...HEAD
[0.1.2]: https://github.com/allamiro/syslogcef/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/allamiro/syslogcef/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/allamiro/syslogcef/releases/tag/v0.1.0
