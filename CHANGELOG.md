# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
- Test suite and GitHub Actions CI.

### Fixed

- Default Linux mapping contained an invalid template that crashed every
  conversion routed to it.
- CEF header fields are now escaped so crafted log content cannot forge
  header fields or split records.
- `--tail` now follows all given input files instead of blocking on the
  first one.

[Unreleased]: https://github.com/allamiro/syslogcef/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/allamiro/syslogcef/releases/tag/v0.1.0
