# Hardening triage — the four "unmerged" branches, 2026-09-03

Operator ruling R7 (harden before announcing) asked for a written triage of four branches
believed unmerged: `fix/ci-cwd-rce-and-packaging`, `fix/2026-08-13-bug-hunt-static-analyzer`,
`fix/attestation-records-facts-not-levels`, `feat/structured-output-mode`.

**Headline: all four are already merged into `main`.** Each shipped as its own PR between
2026-08-13 and 2026-08-15, weeks before this triage. `gh pr list --state all` (checked against
`mergedAt`, not the cached `gh pr view` render — see `reference_gh_pr_view_state_stale.md`) is the
source of truth here, cross-checked with `git merge-base --is-ancestor` and, for the two branches
that still exist locally, a byte-for-byte diff of the branch's own commit against the squash-merge
commit on `main`. No branch carries any content that is not already on `main`. **No action taken
on any branch** — this document is triage only, per instruction; merging, closing, or deleting is
left to the operator.

## Method

For each branch:
1. `gh pr list --repo bigdevxrd/scrypto-audit-kit --state all --json number,title,headRefName,state,mergedAt` — ground truth on whether/when it merged.
2. `git merge-base --is-ancestor <branch-tip> origin/main` — is the branch's content already reachable from main.
3. Where the branch ref still exists locally, `git diff <main-parent> <branch-tip> | git hash-object --stdin` compared against `git diff <squash-parent> <squash-commit> | git hash-object --stdin` — proves the *tree change* is identical, not just that a same-named PR merged.

## Branch-by-branch

### `fix/ci-cwd-rce-and-packaging`

- **Branch today:** does not exist, locally or on `origin` (checked `git branch -a` in a fresh
  worktree off `origin/main` — only `origin/fix/public-privileged-method-rule` and
  `origin/harden/2026-07-16-critical-highs` remain as non-dependabot remote branches).
- **PR:** #7, **MERGED** 2026-08-15T09:59:39Z, squash commit `f3bf6f9` — confirmed an ancestor of
  `origin/main` (`git merge-base --is-ancestor f3bf6f9 origin/main` → yes).
- **What it changed** (from the squash commit's own message, `git show --stat f3bf6f9`): closed a
  second instance of the untrusted-cwd code-execution bug a post-release adversarial sweep found
  still open one step after the v0.7.0 fix (`python3 -c 'import anthropic'` ran with the audited
  repo as cwd, so a package under audit shipping its own `anthropic.py` could execute in the CI
  runner before the secret-holding step); made `sak-static` fail closed instead of silently
  reporting "0 findings" on a nonexistent path; and — the "packaging" half of the branch name —
  added `MANIFEST.in` so the sdist actually ships `tests/__init__.py`, `schema/`, `prompts/` and
  `examples/`, without which `unittest discover` couldn't even import the suite from the pip
  package.
- **Does main already have the fix?** Yes, in full — the cwd-RCE close, the fail-closed analyzer,
  and `MANIFEST.in` are all in this one squash commit, which is on `main`.
- **Recommendation: close / no action.** Nothing to merge; the branch ref is already gone.

### `fix/2026-08-13-bug-hunt-static-analyzer`

- **Branch today:** exists locally (not on `origin`), tip `1428b9c`, "fix(static-analyzer): close 5
  false-negatives + the merge's LLM-vs-static blind spot".
- **PR:** #2, **MERGED** 2026-08-13T11:44:41Z, squash commit `0cb83c9` on `main`.
- **Is the local branch's content on main?** Yes, exactly. `1428b9c`'s parent is `84efa91`;
  `0cb83c9`'s parent is also `84efa91`. `git diff 84efa91 1428b9c` and
  `git diff 84efa91 0cb83c9` hash to the **identical** blob
  (`b784520ee25a3172e505450faa5fa54ffb43a00d`) — the local branch is a stale pointer left over
  from before the squash-merge, not a divergent line of work. (`git log origin/main..branch` shows
  a large diffstat because three-dot comparison walks from an old merge-base through everything
  main has gained since 2026-08-02; the two-parent, same-tree check above is the one that actually
  answers "is this content on main".)
- **Recommendation: delete the local branch.** It is 100% subsumed; keeping it around risks a
  future `git push` accidentally reintroducing a branch GitHub already closed out, or a session
  diffing against it and concluding (as the runbook did) that hardening work is still pending. Not
  deleted here per instruction (never delete branches; that is an operator/PR action) — flagging
  for the operator to run `git branch -d fix/2026-08-13-bug-hunt-static-analyzer` in the shared
  checkout.

### `fix/attestation-records-facts-not-levels`

- **Branch today:** does not exist, locally or on `origin`.
- **PR:** #10, **MERGED** 2026-08-15T10:56:37Z, squash commit `c721af5` — confirmed an ancestor of
  `origin/main`.
- **What it changed:** the breaking, pre-deploy fix behind ROADMAP Phase 8 ("Attestations record
  facts, not a trust level"). `attest.py`'s old `level` field conflated *which tiers ran* with *who
  witnessed the run*; it derived the higher claim from any non-`"static-only"` `kit.model` string,
  so an absent, unknown, or user-supplied model asserted an attested hybrid run had happened
  (failed upward), `--level` let a caller pass `"L3-attested"` straight through as an unvalidated
  input (circular — L3 is defined as the record existing), and the documented pip-only path
  produced a schema-invalid, unattestable payload. Replaced with `mode` (`static | llm | hybrid`)
  derived only from a new `kit.tiers` fact the harness itself records, requiring every tier to be
  positively present.
- **Does main already have the fix?** Yes — `docs/attestation-levels.md` and the current
  `attest.py`/`sak_lib.py` on `main` already implement the `mode`/`kit.tiers` scheme this branch
  introduced, and ROADMAP.md marks the item `[x]` under "Phase 8 — Honest claims ✅ (v0.8)".
- **Recommendation: close / no action.** Nothing to merge; the branch ref is already gone.

### `feat/structured-output-mode`

- **Branch today:** exists locally (not on `origin`), tip `10fbffc`, "feat(llm_audit): opt-in
  --structured mode for the claude-api backend".
- **PR:** #3, **MERGED** 2026-08-13T12:49:43Z, squash commit `0adae45` on `main`.
- **Is the local branch's content on main?** Yes, exactly, by the same two-parent check as above:
  `10fbffc`'s parent is `0cb83c9`; `0adae45`'s parent is also `0cb83c9`. Both diffs
  (`bin/llm_audit.py`, `docs/design/structured-output-mode-2026-07-18.md`,
  `tests/test_backends.py`, etc. — 774 insertions / 44 deletions across 7 files) hash to the
  identical blob `7d944d3e0ac7d86a613f27405f6a07da3b2c2aba`.
- **Does main already have the fix?** Yes, byte-for-byte. This also settles ROADMAP's open item
  "Wire `--structured` into `audit.sh` and flip it on by default, once the parity check passes" —
  that item is about *wiring the existing flag into the shell harness by default*, not about
  landing the flag itself; the flag has been on `main` since 2026-08-13.
- **Recommendation: delete the local branch.** Same reasoning as the static-analyzer branch above
  — fully subsumed, safe to drop, flagged for the operator rather than deleted here.

## Bottom line for R7

Hardening work already landed for all four items named in the ruling; there is no unmerged
security or correctness fix sitting on a branch. The two branches that still exist locally are
harmless (identical content to what shipped), but they are stale enough that they cost a future
session real time re-deriving "is this actually unmerged?" — which is exactly what happened here.
The only follow-up this triage recommends is housekeeping: drop the two stale local branches once
the operator has independently confirmed the diffs above.

This triage did not surface a reason to delay announcing SAK on hardening grounds — the four named
items are not open work.
