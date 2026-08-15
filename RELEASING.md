# Releasing

How a maintainer cuts a release and publishes to PyPI. The kit follows
[SemVer](https://semver.org); the version lives in [VERSION](VERSION) and is stamped into
every report.

## One-time: configure PyPI Trusted Publishing

The [release workflow](.github/workflows/release.yml) publishes via PyPI Trusted Publishing
(OIDC) — no API token, no secret to manage. Set it up once:

1. On [PyPI](https://pypi.org), go to **Your projects → (create/manage) scrypto-audit-kit →
   Publishing**, and add a **GitHub** trusted publisher:
   - Owner: `bigdevxrd`
   - Repository: `scrypto-audit-kit`
   - Workflow: `release.yml`
   - Environment: `pypi`
   (For the very first publish, use PyPI's "pending publisher" form — it creates the project on
   first upload.)
2. In the GitHub repo, create an Environment named `pypi`
   (**Settings → Environments → New environment**).

Prefer an API token instead? Drop the `id-token: write` permission from `release.yml`, add
`with: { password: ${{ secrets.PYPI_API_TOKEN }} }` to the publish step, and store that token
as a repo secret.

## Cutting a release

1. Bump [VERSION](VERSION) (e.g. `0.5.0` → `0.5.1`) and add a [CHANGELOG.md](CHANGELOG.md) entry.
2. Verify green:

   ```bash
   make lint && make test
   npx markdownlint-cli@0.39.0 README.md CHANGELOG.md RELEASING.md docs/   # CI pins this version
   ```

3. Commit, then tag and push:

   ```bash
   git commit -am "release v$(cat VERSION)"
   git tag "v$(cat VERSION)"
   git push origin main --tags
   ```

4. Draft a **GitHub Release** for that tag (**Releases → Draft a new release → choose the tag →
   paste the CHANGELOG section → Publish**).
5. Publishing the release triggers [release.yml](.github/workflows/release.yml): it checks the
   tag matches `VERSION`, builds the sdist + wheel, and publishes to PyPI.

## Verify the published release

```bash
pip install "scrypto-audit-kit==<version>"
python -c "import scrypto_audit_kit as s; print(s.__version__)"
sak-static --help
```

The git tag and the CI-green commit are the source of truth; the `report.json` provenance block
records whichever kit version produced a given report.

### Verifying the artifacts are ours (PEP 740)

Trusted Publishing signs every upload with GitHub's OIDC identity, so a consumer can confirm a
release was built by this repo's `release.yml` and not uploaded by someone holding a stolen
token. This has been true since v0.5.0 and was simply never documented — an unverifiable
signature helps nobody.

```bash
pip download --no-deps scrypto-audit-kit==<version>
gh attestation verify scrypto_audit_kit-<version>-py3-none-any.whl --repo bigdevxrd/scrypto-audit-kit
```

PyPI also shows the attestation on each file's page under **Provenance**. For a security tool
this is the point: "pin by tag" and "install from PyPI" are only supply-chain advice if the
artifact's origin can actually be checked.
