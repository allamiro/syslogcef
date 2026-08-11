# Security Policy

## Supported Versions

| Version | Supported |
| ------- | --------- |
| 0.2.x   | Yes       |

Only the latest minor release series receives security fixes.

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

## Threat Model

syslogcef treats **all log content as untrusted input**, whether it arrives
from a file, standard input, or the network.

### CEF output integrity

- Values placed into CEF extension fields are escaped (backslash, pipe,
  equals sign, CR/LF); NUL bytes are replaced with U+FFFD.
- Values placed into CEF header fields are escaped (backslash, pipe) and
  CR/LF are stripped, so crafted log messages cannot forge CEF header fields
  or split records.
- Malformed or unparseable lines fall back to a raw-message event instead of
  raising, so a single hostile line cannot abort a stream.

Reports of any bypass of the above — content that still results in header
injection, record splitting, or a crash on attacker-controlled input — are in
scope and very welcome.

### Input surfaces

- **Files / stdin** (default): the converter reads local logs and opens no
  network sockets.
- **`--listen udp:PORT` / `tcp:PORT`** turns syslogcef into a network
  receiver. Received bytes are **unauthenticated and attacker-controllable**.
  There is no TLS and no source authentication; deploy behind a firewall or
  on a trusted management network and restrict who can reach the port. The TCP
  listener bounds each connection's buffer (dropping a connection that sends
  1 MiB without a newline) and applies aggregate connection limits, but it is
  not a hardened internet-facing endpoint.
- **Custom parser patterns** (`--patterns`) are regular expressions supplied
  by the operator and run against untrusted log lines. Author them anchored
  and free of nested quantifiers to avoid catastrophic backtracking (ReDoS);
  syslogcef validates pattern files at load but does not analyze regex
  complexity.

### Output / forwarding surfaces

- **`--send udp://` / `tcp://` / `kafka://`** forward converted CEF to a
  downstream collector. Built-in UDP and TCP forwarding is **plaintext with no
  TLS or authentication**; use a private network, a VPN, or a TLS-terminating
  relay for transport security. Kafka security depends on the broker
  configuration you supply.

### Packaged service privilege model

- The RPM/Debian systemd units and the Alpine OpenRC service run **as root by
  default**, so they can read arbitrary log files. The units apply systemd
  sandboxing (`ProtectSystem=full` — `/usr`, `/boot`, and `/etc` read-only,
  leaving custom output paths writable — plus `PrivateDevices=yes`, a
  restricted `CapabilityBoundingSet` and `SystemCallFilter`,
  `MemoryDenyWriteExecute`, and `MemoryMax`/`TasksMax` ceilings) to limit the
  blast radius of a defect. Opt into `ProtectSystem=strict` with a
  `ReadWritePaths=` override if your output stays under a known directory.
- For least privilege, set `User=syslogcef` in a systemd drop-in (the packaged
  `syslogcef` system user is created via sysusers.d) and grant only the groups
  that can read your specific inputs (e.g. `adm`, `systemd-journal`).
  `CAP_NET_BIND_SERVICE` is retained for instances that bind ports below 1024.
- Prefer running a dedicated non-root instance for pure network-daemon mode,
  where no arbitrary local-file access is needed.
