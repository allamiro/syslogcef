# Releasing

Releases are driven by version tags. Pushing a tag `vX.Y.Z` runs the
release workflow ([.github/workflows/release.yml](.github/workflows/release.yml)),
which:

1. Runs the test suite, then builds the sdist and wheel.
2. Builds a noarch RPM (with the systemd service and configuration file)
   in a Fedora container from [packaging/rpm/syslogcef.spec](packaging/rpm/syslogcef.spec).
3. Builds a standalone executable zipapp (`syslogcef-X.Y.Z.pyz`), a
   Debian package via [packaging/debian/build-deb.sh](packaging/debian/build-deb.sh),
   and a source zip from `git archive`.
4. Builds an Alpine APK with an OpenRC service in an Alpine container
   from [packaging/apk/APKBUILD](packaging/apk/APKBUILD), signed with the
   abuild RSA key (`ABUILD_PRIVATE_KEY` secret; public key committed at
   packaging/apk/syslogcef.rsa.pub).
5. GPG-signs all artifacts when signing secrets are configured (detached
   `.asc` signatures for everything, `rpmsign` for the RPMs) and signs
   the `SHA256SUMS` file.
6. Creates a GitHub Release with generated notes and all of the above.
7. Publishes the sdist and wheel to PyPI.

## Cutting a Release

```bash
# 1. Update the version in pyproject.toml and packaging/rpm/syslogcef.spec
# 2. Move the Unreleased section of CHANGELOG.md under the new version
# 3. Commit via a PR, then tag the merge commit on main:
git checkout main && git pull
git tag -a vX.Y.Z -m "syslogcef X.Y.Z"
git push origin vX.Y.Z
```

The workflow does the rest. (The RPM spec version is also synced from the
tag automatically at build time.)

## One-Time Setup

### PyPI publishing

The publish job supports two methods; it picks automatically:

1. `PYPI_API_TOKEN` repository secret, if present — an API token created
   on pypi.org (Account settings -> API tokens). Simplest to start with.
2. Trusted publishing (OIDC, no token), used when the secret is absent.
   On pypi.org, under the project (or as a pending publisher for the
   first release): Publishing -> Add a new publisher with PyPI project
   name `syslog2cef`, owner `allamiro`, repository `syslogcef`,
   workflow `release.yml`, environment `pypi`.

Note: the PyPI distribution is `syslog2cef` (the `syslogcef` name on
PyPI belongs to an unrelated project); the import package and CLI
remain `syslogcef`.

The GitHub environment named `pypi` already exists in the repository
settings. Once either method is configured, every new tag publishes
automatically.

### Artifact signing

Signing is already configured: the `GPG_PRIVATE_KEY` and
`GPG_PASSPHRASE` repository secrets hold the release signing key

    Tamir Suliman (syslogcef release signing) <allamiro@gmail.com>
    Fingerprint: 3600 2DEB FA3B FAE6 8CE0  0D92 D86C D1CD 2AD1 9481

The workflow produces detached `.asc` signatures for the sdist and
wheel and signs the RPMs with `rpmsign`. If the secrets are ever
removed, the workflow skips signing and still releases unsigned
artifacts with checksums.

The public key is committed at
[packaging/rpm/RPM-GPG-KEY-syslogcef](packaging/rpm/RPM-GPG-KEY-syslogcef).
Users verify with:

```bash
gpg --import RPM-GPG-KEY-syslogcef
gpg --verify syslogcef-X.Y.Z.tar.gz.asc syslogcef-X.Y.Z.tar.gz
rpm --import RPM-GPG-KEY-syslogcef && rpm --checksig syslogcef-X.Y.Z-1.noarch.rpm
```

A backup of the private key and passphrase is stored offline by the
maintainer; it is not in the repository.
