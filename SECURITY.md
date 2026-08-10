# Security Policy

## Supported Versions

| Version | Supported |
| ------- | --------- |
| 0.1.x   | Yes       |

Only the latest release receives security fixes.

## Reporting a Vulnerability

Please do not report security vulnerabilities through public GitHub issues.

Preferred: use GitHub private vulnerability reporting — go to the repository's
Security tab and choose "Report a vulnerability". Alternatively, email the
maintainer at allamiro@gmail.com with the subject line "syslogcef security".

Include as much of the following as you can:

- A description of the issue and its impact.
- Steps to reproduce, ideally with a sample log line and the command or API
  call used.
- The version or commit you tested against.

You can expect an acknowledgement within 7 days. Once a fix is available, the
vulnerability will be disclosed in the release notes and, where appropriate,
a GitHub security advisory. Please allow time for a fix to be released before
public disclosure.

## Threat Model Notes

syslogcef treats all log content as untrusted input:

- Values placed into CEF extension fields are escaped (backslash, pipe,
  equals sign, CR/LF).
- Values placed into CEF header fields are escaped (backslash, pipe) and
  CR/LF are stripped, so crafted log messages cannot forge CEF header fields
  or split records.
- Malformed or unparseable lines fall back to a raw-message event instead of
  raising.

Reports of any bypass of the above — for example, content that still results
in header injection, record splitting, or a crash on attacker-controlled
input — are in scope and very welcome. The CLI reads files and stdin only; it
opens no network sockets.
