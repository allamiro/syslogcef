#!/bin/bash
# Build the syslogcef Debian package.
# Usage: build-deb.sh <version> <path-to-zipapp> <output-dir>
set -euo pipefail

VERSION="$1"
PYZ="$2"
OUTDIR="$3"

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
STAGE="$(mktemp -d)/syslogcef"

mkdir -p \
  "$STAGE/DEBIAN" \
  "$STAGE/usr/bin" \
  "$STAGE/lib/systemd/system" \
  "$STAGE/etc/syslogcef" \
  "$STAGE/usr/share/doc/syslogcef"

install -m 0755 "$PYZ" "$STAGE/usr/bin/syslogcef"
install -m 0644 "$REPO_ROOT/packaging/rpm/syslogcef.service" "$STAGE/lib/systemd/system/syslogcef.service"
install -m 0644 "$REPO_ROOT/packaging/rpm/syslogcef.conf" "$STAGE/etc/syslogcef/syslogcef.conf"
install -m 0644 "$REPO_ROOT/README.md" "$REPO_ROOT/LICENSE" "$REPO_ROOT/CHANGELOG.md" "$STAGE/usr/share/doc/syslogcef/"

INSTALLED_SIZE=$(du -sk "$STAGE" | cut -f1)

cat > "$STAGE/DEBIAN/control" <<EOF
Package: syslogcef
Version: ${VERSION}-1
Section: admin
Priority: optional
Architecture: all
Depends: python3 (>= 3.9)
Installed-Size: ${INSTALLED_SIZE}
Maintainer: Tamir Suliman <allamiro@gmail.com>
Homepage: https://github.com/allamiro/syslogcef
Description: Convert syslog events to ArcSight CEF
 syslogcef converts syslog events (RFC3164, RFC5424, rsyslog, and systemd
 journal exports) into ArcSight Common Event Format (CEF), with bundled
 vendor mappings for Cisco ASA/IOS, F5, Linux, and VMware sources.
 .
 This package installs the syslogcef command line tool and a systemd
 service that follows a configured log file and appends CEF output.
EOF

echo /etc/syslogcef/syslogcef.conf > "$STAGE/DEBIAN/conffiles"

cat > "$STAGE/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e
if [ -d /run/systemd/system ]; then
    systemctl daemon-reload >/dev/null 2>&1 || true
fi
EOF

cat > "$STAGE/DEBIAN/prerm" <<'EOF'
#!/bin/sh
set -e
if [ -d /run/systemd/system ] && [ "$1" = remove ]; then
    systemctl stop syslogcef.service >/dev/null 2>&1 || true
fi
EOF

cat > "$STAGE/DEBIAN/postrm" <<'EOF'
#!/bin/sh
set -e
if [ -d /run/systemd/system ]; then
    systemctl daemon-reload >/dev/null 2>&1 || true
fi
EOF

chmod 0755 "$STAGE/DEBIAN/postinst" "$STAGE/DEBIAN/prerm" "$STAGE/DEBIAN/postrm"

mkdir -p "$OUTDIR"
dpkg-deb --build --root-owner-group "$STAGE" "$OUTDIR/syslogcef_${VERSION}-1_all.deb"
