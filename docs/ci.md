# Running the pre-audit in CI (and the badge)

Wire `scrypto-audit-kit` into your repo's CI so every PR gets a pre-audit, and
display a badge that reflects the result. This is **rung L2** of the [trust
ladder](../VISION.md) — an attested, version-pinned run (deterministic static tier) rather than a one-off.

## 1. Add the workflow

Copy [`examples/ci/pre-audit.yml`](../examples/ci/pre-audit.yml) into your repo at
`.github/workflows/pre-audit.yml` and set `package:` to your blueprint path:

```yaml
jobs:
  scrypto-pre-audit:
    uses: bigdevxrd/scrypto-audit-kit/.github/workflows/pre-audit.yml@v0.7.0
    with:
      package: packages/my-blueprint
      fail-on: high
      kit-ref: v0.7.0
    secrets:
      ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
```

Pin both refs to a release, not `@main`: the `uses:` ref selects the workflow, `kit-ref`
selects the audit code the workflow checks out, and `kit-ref` defaults to `main` if you
leave it off. `@main` runs whatever is on the kit's HEAD at that moment, in your CI, with
your `ANTHROPIC_API_KEY` in reach.

**Use v0.7.0 or later — this is a floor, not just "the newest tag".** The `v0.5.0` and `v0.6.0`
tags ship a `pre-audit.yml` that interpolates caller inputs directly into `run:` scripts, so a
crafted `model` or `fail-on` value executes in the job that holds your `ANTHROPIC_API_KEY`.
`v0.6.0` additionally defaults to the `claude-api` backend while its workflow installs only
aider, so the default run dies mid-audit on a missing `anthropic`. (`v0.5.0` predates that
backend entirely — its default run works; only the injection affects it.) Both are fixed in
v0.7.0. If v0.7.0 is not tagged
yet, pin a commit SHA from the kit's `main` instead of dropping back to an older tag — a SHA is
just as reproducible and does not carry the injectable workflow.

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

Pin `kit-ref:` to a released tag (e.g. `v0.7.0`) so the *method* is fixed over time: the
static-tier findings then reproduce exactly, while the LLM-tier findings are advisory and
vary run-to-run, so don't expect a byte-identical report.

## 4. The badge

Once the workflow has run at least once, add its status badge to your README
(replace `OWNER/REPO`):

```markdown
[![pre-audit](https://github.com/OWNER/REPO/actions/workflows/pre-audit.yml/badge.svg)](https://github.com/OWNER/REPO/actions/workflows/pre-audit.yml)
```

The badge is green when the latest run found nothing at or above your `fail-on`
threshold, red otherwise. It is an **honest** signal — it says "the pre-audit
passed at level L2", not "this code is safe". It does not replace a human audit
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
