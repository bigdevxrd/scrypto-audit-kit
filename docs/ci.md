# Running the pre-audit in CI (and the badge)

Wire `scrypto-audit-kit` into your repo's CI so every PR gets a pre-audit, and
display a badge that reflects the result. This is the **path to rung L2** of the [trust ladder](../VISION.md) — a pinned,
version-controlled run on an independent runner rather than a one-off on someone's laptop.

Note what a green badge does and does not establish: it shows a run happened and passed your
threshold. **L2 proper requires the run's provenance to be signed** by the build platform, so a
reader can verify it was not produced by the claimant. Set `sign-provenance: true` to get that —
see [Earning L2](#4-earning-l2--signed-provenance) below. Without it, a CI run is L1 with a strong
audit trail; [attestation-levels.md](attestation-levels.md) has the full rule.

## 1. Add the workflow

Copy [`examples/ci/pre-audit.yml`](../examples/ci/pre-audit.yml) into your repo at
`.github/workflows/pre-audit.yml` and set `package:` to your blueprint path:

```yaml
jobs:
  scrypto-pre-audit:
    uses: bigdevxrd/scrypto-audit-kit/.github/workflows/pre-audit.yml@v0.8.0
    with:
      package: packages/my-blueprint
      fail-on: high
      kit-ref: v0.8.0
    secrets:
      ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
```

Pin both refs to a release, not `@main`: the `uses:` ref selects the workflow, `kit-ref`
selects the audit code the workflow checks out, and `kit-ref` defaults to `main` if you
leave it off. `@main` runs whatever is on the kit's HEAD at that moment, in your CI, with
your `ANTHROPIC_API_KEY` in reach.

**Use v0.8.0 or later — this is a floor, not just "the newest tag".** Every earlier tag lets code
from the package you are auditing run inside your CI job:

- **`v0.7.0` and earlier** run the backend-install probe (`python3 -c 'import anthropic'`) with
  the audited repository as the working directory. Python puts the cwd on `sys.path` for `-c`, so
  an audited package that ships its own `anthropic.py` executes in your runner — one step before
  `ANTHROPIC_API_KEY` enters the job, and the payload *satisfies* the probe, so the guard passes
  while it runs. Even where the key is withheld (fork PRs on public repos), that execution happens
  before the severity gate and can neutralise the gate judging it.
- **`v0.5.0` and `v0.6.0`** additionally interpolate caller inputs straight into `run:` scripts, so
  a crafted `model` or `fail-on` value executes in the same key-bearing job. `v0.6.0` also defaults
  to the `claude-api` backend while installing only aider, so its default run dies mid-audit on a
  missing `anthropic`. (`v0.5.0` predates that backend — only the injection affects it.)

If `v0.8.0` is not tagged yet, pin a commit SHA from the kit's `main` instead of dropping back to
an older tag — a SHA is just as reproducible and does not carry the vulnerable workflow.

## 2. Add the secret

In your repo: **Settings → Secrets and variables → Actions → New repository secret**,
named `ANTHROPIC_API_KEY`. That is the only secret the reusable workflow takes.
The `deepseek` and `both` models are aider cross-model modes that also need a
`DEEPSEEK_API_KEY`, which this workflow does not forward — they work locally
([docs/backends.md](backends.md)) but not through CI yet.

## 3. What it does

On every PR (and on demand via *Run workflow*) it:

1. runs the pre-audit, producing `report.md` + `report.json` (the `cargo` compile pre-flight
   is off by default — the audit reads your code, it doesn't build it);
2. uploads both as a build artifact (`pre-audit-report`);
3. **fails the check** if any finding is at or above `fail-on` (default `high`).

Pin `kit-ref:` to a released tag (e.g. `v0.8.0`) so the *method* is fixed over time: the
static-tier findings then reproduce exactly, while the LLM-tier findings are advisory and
vary run-to-run, so don't expect a byte-identical report.

## 4. Earning L2 — signed provenance

Everything above proves a report exists. It does not prove *who produced it* — and that is the
whole content of rung L2. Opt in:

```yaml
jobs:
  scrypto-pre-audit:
    permissions:
      contents: read
      id-token: write        # OIDC — lets GitHub sign as your repo
      attestations: write    # stores the attestation against your repo
    uses: bigdevxrd/scrypto-audit-kit/.github/workflows/pre-audit.yml@v0.8.0
    with:
      package: packages/my-blueprint
      sign-provenance: true
    secrets:
      ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
```

Both permissions are required on **your** job. A reusable workflow can only narrow the caller's
token, never widen it, so the kit cannot grant these for you — without them the signing step
fails while the audit itself still runs.

Anyone can then verify the report came from your workflow, on your commit, rather than from
someone's laptop:

```bash
gh attestation verify report.json --repo OWNER/REPO
```

Signing runs only when the gate passed — a signed statement for a report that failed its own
threshold would attest to a run you already rejected.

## 5. The badge

Once the workflow has run at least once, add its status badge to your README
(replace `OWNER/REPO`):

```markdown
[![pre-audit](https://github.com/OWNER/REPO/actions/workflows/pre-audit.yml/badge.svg)](https://github.com/OWNER/REPO/actions/workflows/pre-audit.yml)
```

The badge is green when the latest run found nothing at or above your `fail-on`
threshold, red otherwise. It is an **honest** signal — it says "the pre-audit ran and passed
this threshold", not "this code is safe" and not "this run's provenance is signed". It does not replace a human audit
([what the kit is and isn't](../README.md#limitations--read-this-before-relying-on-the-output)).

Two honesty caveats: (1) the pass/fail can **vary between runs** on identical code, because the
LLM layer is non-deterministic — a green badge means *this run* found nothing at/above the
threshold, not that no such issue exists; (2) a relaxed `fail-on` (e.g. `critical` or `none`) is
invisible in the badge, so a green badge alone doesn't tell a reader how strict the gate was.

## Tuning the gate

`fail-on` accepts `none | low | medium | high | critical`:

- `high` (default) — block PRs on High and Critical findings.
- `critical` — block only on Critical (more lenient while you triage).
- `none` — never fail; the badge tracks only whether the run completed (use while adopting).

The gate logic lives in [`bin/ci-gate.py`](../bin/ci-gate.py) — it reads
`report.json` against the [schema](../schema/audit-report.schema.json), so it's
the same structured output any agent consumes.
