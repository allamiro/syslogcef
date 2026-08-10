# Releasing

Releases are driven by version tags. Pushing a tag `vX.Y.Z` runs the
release workflow ([.github/workflows/release.yml](.github/workflows/release.yml)),
which:

1. Runs the test suite, then builds the sdist and wheel.
2. Builds a noarch RPM (with the systemd service and configuration file)
   in a Fedora container from [packaging/rpm/syslogcef.spec](packaging/rpm/syslogcef.spec).
3. GPG-signs all artifacts when signing secrets are configured (detached
   `.asc` signatures for the sdist/wheel, `rpmsign` for the RPMs).
4. Creates a GitHub Release with generated notes, the artifacts, and a
   `SHA256SUMS` file.
5. Publishes the sdist and wheel to PyPI via trusted publishing.

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

### PyPI trusted publishing

On pypi.org, under the project (or as a pending publisher for the first
release): Publishing -> Add a new publisher with:

- Owner: `allamiro`
- Repository: `syslogcef`
- Workflow: `release.yml`
- Environment: `pypi`

Also create a GitHub environment named `pypi` in the repository settings
(Settings -> Environments). No API tokens are needed.

### Artifact signing (optional)

Add two repository secrets (Settings -> Secrets and variables -> Actions):

- `GPG_PRIVATE_KEY` — ASCII-armored private key
  (`gpg --armor --export-secret-keys KEYID`)
- `GPG_PASSPHRASE` — its passphrase

When absent, the workflow skips signing and still releases unsigned
artifacts with checksums. Publish the corresponding public key (for
example as a repository file or on a keyserver) so users can verify:

```bash
gpg --verify syslogcef-X.Y.Z.tar.gz.asc syslogcef-X.Y.Z.tar.gz
rpm --import public-key.asc && rpm --checksig syslogcef-X.Y.Z-1.noarch.rpm
```
