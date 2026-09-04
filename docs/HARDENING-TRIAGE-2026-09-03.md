# Hardening triage — the four "unmerged" branches, 2026-09-03

Operator ruling R7 (harden before announcing) asked for a written triage of four branches
believed unmerged: `fix/ci-cwd-rce-and-packaging`, `fix/2026-08-13-bug-hunt-static-analyzer`,
`fix/attestation-records-facts-not-levels`, `feat/structured-output-mode`.

**Headline: all four are already merged into `main`.** Each shipped as its own PR between
2026-08-13 and 2026-08-15, weeks before this triage. `gh pr list --state all` (checked against
`mergedAt`, not the cached `gh pr view` render — see `reference_gh_pr_view_state_stale.md`) is the
source of truth here, cross-checked with `git merge-base --is-ancestor` and, for the two branches
that still exist locally, a byte-for-byte diff of the branch's own commit against the squash-merge
commit on `main`. **No action taken on any branch** — this document is triage only, per
instruction; merging, closing, or deleting is left to the operator.

Scoped claim, stated precisely because the unscoped version of it was wrong once already (see the
addendum below): no branch **among the four named in R7** carries any content that is not already
on `main`. This document also *names*, without checking, two further non-dependabot branches still
sitting on `origin` (`fix/public-privileged-method-rule`, `harden/2026-07-16-critical-highs`) — see
the "Branch today" line under `fix/ci-cwd-rce-and-packaging` just below. A later pass (2026-09-04)
checked both; the addendum after the branch-by-branch section has the evidence. The answer turned
out to be the same — already on `main` — but that was verified, not assumed, and it does not
follow automatically from the four-branch result above.

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

## Addendum (2026-09-04) — the two branches named above but not checked

The "Branch today" line under `fix/ci-cwd-rce-and-packaging` says only
`origin/fix/public-privileged-method-rule` and `origin/harden/2026-07-16-critical-highs` remain as
non-dependabot remote branches — and stops there. Neither was in R7's scope, so neither got the
check the four named branches got above. That gap is the same shape as the thing this triage exists
to catch: a branch sitting on `origin` that *looks* live because nobody has actually checked it. It
is closed here rather than left for a third pass to rediscover.

### `origin/fix/public-privileged-method-rule`

- **Branch today:** exists on `origin`, tip `99cd620`, "fix(static): detect PUBLIC privileged
  methods — the kit missed both Criticals in its own fixture". Neither an ancestor of `origin/main`
  nor the reverse — the two diverged at `fab5592` (the `docs: intent/status/roadmap sweep (#21)`
  commit both branch and `main` share as their last common point).
- **PR:** #23, same title, `fix/public-privileged-method-rule` → `main`, **MERGED**
  2026-09-02T21:14:31Z, squash commit `4f3e2c05ae1df67134a76a6b31cc6ca0dd982ed5` — confirmed an
  ancestor of `origin/main` (`git merge-base --is-ancestor 4f3e2c05 origin/main` → yes).
- **Is the branch's content on `main`?** Yes, byte-for-byte: `git diff 99cd620 4f3e2c05` (branch
  tip vs. the squash commit) produces **zero lines of output** — the trees are identical. The
  branch is PR #23's own head ref, left behind after the squash merge; GitHub only auto-deletes a
  head branch when that repo setting is on, and this one wasn't for this merge.
- **Then why did it look unmerged?** Because the branch diverged instead of being an ancestor, the
  two cheap checks both point the wrong way: `git merge-base --is-ancestor` correctly says "no,"
  and a plain two-dot tip-to-tip diff (`git diff origin/main..origin/fix/public-privileged-method-rule`)
  shows "1 commit ahead, 4 files changed, +15/-15" — which reads as live, unmerged content. It
  isn't. Those 4 files are `.github/workflows/{blueprint,lint,pre-audit,release}.yml`, and the
  +15/-15 is entirely the 5 dependabot Actions version bumps (`actions/checkout`,
  `upload-artifact`, `attest-build-provenance`, `setup-python`, `setup-node` — PRs #13–#17) that
  landed on `main` *after* 2026-09-02T21:14, which this abandoned branch never picked up — shown as
  if reverting them, since a two-dot diff is symmetric and can't tell "the branch is behind" from
  "the branch is ahead." This is the Method section's three-dot warning above, running in the
  opposite direction: there, an old merge-base made a fully-merged branch's diff look artificially
  *large*; here, a diverged-then-squashed branch's diff looks *small enough to be plausible new
  work* when it's dependabot noise. Tip-to-tip diffing a branch that isn't an ancestor of `main`
  is not a merge check either way — the byte-for-byte compare against the actual squash commit is
  what settles it, same as the two locally-stale branches above.
- **Independently re-verified on 2026-09-04, not just diffed:**
  - `python3 -m unittest discover -s tests -t .` in a worktree at the branch tip — **227/227
    pass** (Python 3.12; CI's other matrix leg, 3.9, was not available on this machine and was not
    run) — matches the commit's own "227/227 tests pass" claim.
  - `python3 bin/static_analysis.py examples/vulnerable-vault`, run at three points: at the
    pre-fix merge-base `fab5592` — **5 findings, medium:5**, nothing higher; at the branch tip
    `99cd620` — **7 findings: critical:1, high:1, medium:5**; at current `origin/main` (`a854f90`)
    — **identically 7: critical:1, high:1, medium:5**. The two new findings in both post-fix runs
    are `public-privileged-method` at `src/lib.rs:119` (critical, `emergency_drain`, drains the
    vault with no credential) and `src/lib.rs:111` (high, `set_oracle_price`, writes `self.*` from
    a parameter with no credential) — the exact two methods
    `examples/vulnerable-vault.pre-audit.md` rates Critical, and that the commit message says the
    ruleset missed before this rule existed.
  - **No new PR was opened for this.** There is nothing to land — `main` has carried this fix
    since 2026-09-02T21:14:31Z, three weeks before this triage ran.
- **Recommendation: delete the stale remote branch.** Flagged for the operator
  (`git push origin --delete fix/public-privileged-method-rule`) rather than done here, on the same
  standard this document already holds itself to for the two stale local branches above — deleting
  a branch is an operator/PR action, not a triage action.

### `origin/harden/2026-07-16-critical-highs`

- **Branch today:** exists on `origin`, tip `2b555da`, "docs: retire the dated bug-hunt writeup".
- **Is it on `main`?** Yes, and trivially — unlike the branch above, this one is a straight
  ancestor: `git merge-base --is-ancestor origin/harden/2026-07-16-critical-highs origin/main` →
  yes. No divergence, no squash to chase, nothing further to check.
- **Recommendation: delete the stale remote branch.** Same as above — flagged, not actioned.

## Bottom line for R7

Hardening work already landed for all four items named in the ruling; there is no unmerged
security or correctness fix sitting on a branch. The two branches that still exist locally are
harmless (identical content to what shipped), but they are stale enough that they cost a future
session real time re-deriving "is this actually unmerged?" — which is exactly what happened here.
The two remote branches in the addendum above cost exactly that: this document named them on first
pass and moved on, and a later session had to re-derive from scratch that they, too, are fully
subsumed. The only follow-up this triage recommends is housekeeping: drop all four stale branches
(two local, two remote) once the operator has independently confirmed the diffs above.

This triage did not surface a reason to delay announcing SAK on hardening grounds — none of the six
branches it now covers are open work.
