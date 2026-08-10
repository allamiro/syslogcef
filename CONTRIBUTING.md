# Contributing

Thanks for your interest in syslogcef. Bug reports, feature requests, and
pull requests are welcome.

## Development Setup

```bash
git clone https://github.com/allamiro/syslogcef.git
cd syslogcef
python -m venv .venv
source .venv/bin/activate
pip install -e .[test]
```

## Running Tests

```bash
pytest
```

All tests must pass before a pull request can be merged. New behavior should
come with tests; bug fixes should include a regression test that fails
without the fix.

## Workflow

1. Open an issue describing the bug or proposal before starting significant
   work.
2. Create a topic branch from `main` (for example `fix/short-description` or
   `docs/short-description`). Do not commit directly to `main`.
3. Keep each branch focused on a single change.
4. Open a pull request that references the issue (for example `Fixes #12`).
   CI must pass before merge.

## Coding Guidelines

- Python 3.9+ compatible code.
- Follow the existing style: type hints, dataclasses, standard library only
  (the package intentionally has no runtime dependencies).
- Log content is untrusted input. Any value derived from a log line that is
  rendered into CEF output must go through the escaping helpers in
  `syslogcef/utils.py`.

## Reporting Security Issues

Do not open public issues for vulnerabilities — see [SECURITY.md](SECURITY.md).
