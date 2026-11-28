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

3. Land the bump **through a PR**. `main` is covered by a ruleset requiring the four status
   checks, so a direct `git push origin main` is rejected:

   ```bash
   git checkout -b release/v$(cat VERSION)
   git commit -am "release v$(cat VERSION)"
   git push -u origin HEAD
   gh pr create --fill && gh pr merge --squash --delete-branch
   ```

4. Tag the merged commit on `main` and push the tag:

   ```bash
   git checkout main && git pull
   git tag "v$(cat VERSION)"
   git push origin "v$(cat VERSION)"
   ```

   Release tags (`v*`) are protected: they cannot be moved or deleted once pushed. If you tag the
   wrong commit, cut the next patch version rather than trying to move it — which is the point.
   Immutable tags are what makes "pin `kit-ref` to a tag" real advice instead of a suggestion.

5. Draft a **GitHub Release** for that tag (**Releases → Draft a new release → choose the tag →
   paste the CHANGELOG section → Publish**).

   > Pushing the tag alone publishes **nothing** — [release.yml](.github/workflows/release.yml)
   > triggers on `release: published`, not on tag push. This step is the one that ships.

6. Publishing the release runs [release.yml](.github/workflows/release.yml): it re-runs the suite
   against the tagged tree, checks the tag matches `VERSION`, builds the sdist + wheel,
   smoke-tests both, and only then publishes to PyPI.

## Withdrawing a bad release

Not yet needed for any release: nothing below has been run. Use it when a published version is
broken (it crashes, misreports, or gives a wrong verdict) or unsafe to run.

The tag cannot be moved or deleted (step 4 above), and a version number on PyPI cannot be
uploaded twice. So a bad release is never replaced in place: it is marked, and a fixed patch
version follows.

1. **Yank it on PyPI.** On the project's PyPI page: **Manage → Releases → the bad version →
   Options → Yank**, with a short reason. A yanked version stays downloadable, so existing
   exact pins still resolve, but `pip` no longer picks it for a range such as
   `scrypto-audit-kit>=0.8` or for an unpinned install. Prefer yank to delete: a deleted
   version's file names can never be reused, and a pin to it fails with a bare "no matching
   distribution" error that gives no reason.
2. **Mark the GitHub Release.** Edit the release for that tag: put a warning at the top of the
   notes that names the version to use instead and links the issue. Leave the tag in place.
3. **Cut the fix as the next patch version** (for example `0.8.1` → `0.8.2`) by the steps in
   "Cutting a release". Its CHANGELOG entry says which version it replaces and why.
4. **Tell users.** Open an issue, or a GitHub security advisory if the problem is a security
   one (see [SECURITY.md](SECURITY.md)), naming the bad version, the good version and what a
   report made with the bad one may have got wrong.
5. **Move the CI floor.** If the bad version is the one [docs/ci.md](docs/ci.md) and the
   README tell users to pin, update those pins in the patch release's PR.

### What users should pin

- **PyPI:** pin an exact version, `scrypto-audit-kit==<version>`, and change it on purpose.
  An exact pin to a yanked version still installs, so watch the release notes or the issue.
- **The reusable CI workflow:** pin both the `uses:` ref and `kit-ref` to a release tag
  ([docs/ci.md](docs/ci.md)). Release tags cannot move, so a pinned tag always means the same
  code. To roll back after a bad release, set both back to the last good tag.
- **A clone:** check out a release tag, not `main`.
- Each `report.json` records the kit version that made it, so a report made with a withdrawn
  version can be found and re-run.

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

These attestations live on **PyPI**, not in GitHub's attestation store — `gh attestation verify`
looks in the latter and returns a 404 for them. Read them from PyPI's integrity API:

```bash
curl -s https://pypi.org/integrity/scrypto-audit-kit/<version>/scrypto_audit_kit-<version>-py3-none-any.whl/provenance \
  | python3 -c "import json,sys; b=json.load(sys.stdin)['attestation_bundles'][0]['publisher']; print(b['kind'], b['repository'], b['workflow'])"
```

which for a genuine release prints `GitHub bigdevxrd/scrypto-audit-kit release.yml`. PyPI also
shows it on each file's page under **Provenance**, and the
[`pypi-attestations`](https://pypi.org/project/pypi-attestations/) CLI verifies the signature
itself rather than just reading the claim.

For a security tool this is the point: "pin by tag" and "install from PyPI" are only supply-chain
advice if the artifact's origin can actually be checked.
