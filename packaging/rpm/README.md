# RPM Packaging

This directory contains everything needed to build the syslog2cef RPM:

- `syslog2cef.spec` — the spec file (noarch, built from the PyPI sdist).
- `syslogcef.service` — systemd unit that follows the configured input
  file and appends CEF output.
- `syslogcef.conf` — environment file installed to
  `/etc/syslogcef/syslogcef.conf` (marked `%config(noreplace)`).

## Building Locally

On Fedora or an Enterprise Linux 9+ system:

```bash
sudo dnf install rpm-build rpmdevtools python3-devel pyproject-rpm-macros systemd-rpm-macros
rpmdev-setuptree

# From a repository checkout
python -m build --sdist
cp dist/syslog2cef-*.tar.gz ~/rpmbuild/SOURCES/
cp packaging/rpm/syslogcef.service packaging/rpm/syslogcef.conf ~/rpmbuild/SOURCES/
rpmbuild -ba packaging/rpm/syslog2cef.spec
```

The built package appears under `~/rpmbuild/RPMS/noarch/`.

## Signing the RPM

Generate or import a GPG key, then configure rpm to use it:

```bash
gpg --full-generate-key   # or: gpg --import your-key.asc
cat >> ~/.rpmmacros <<'EOF'
%_signature gpg
%_gpg_name  Your Name <you@example.com>
EOF

rpmsign --addsign ~/rpmbuild/RPMS/noarch/syslog2cef-*.noarch.rpm
```

Consumers verify with:

```bash
rpm --import your-public-key.asc
rpm --checksig syslog2cef-*.noarch.rpm
```

The release workflow signs automatically when the `GPG_PRIVATE_KEY` and
`GPG_PASSPHRASE` repository secrets are configured; see
[RELEASING.md](../../RELEASING.md).

## Installing and Running the Service

```bash
sudo dnf install syslog2cef-*.noarch.rpm
sudo vi /etc/syslogcef/syslogcef.conf   # set INPUT_FILE / OUTPUT_FILE
sudo systemctl enable --now syslogcef
journalctl -u syslogcef -f
```
