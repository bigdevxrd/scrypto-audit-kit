# References

These files are loaded as read-only context into every audit run. They give the auditor model concrete pattern catalogues to compare the target blueprint against.

## Contents

| File | Source | Purpose |
|------|--------|---------|
| `ignition-patterns.md` | [radixdlt/Ignition](https://github.com/radixdlt/Ignition) (Apache-2.0) | 14 patterns from the canonical Radix-team-maintained reference protocol. Role hierarchies, the `scrypto-interface` macro, pre/post-call invariants, asymmetric circuit breakers, error-constant macros, forced-liquidation state, stateful tests. |
| `caviarnine-hyperstake-patterns.md` | [caviarnine/caviarnine-scrypto](https://github.com/caviarnine/caviarnine-scrypto) (Apache-2.0) | 12 patterns from HyperStake (concentrated-band pool) and the LSULP multi-LSU pool. Wrapping `TwoResourcePool`, soul-bound credit receipts, lazy NAV updates, build-time address injection, rounding-in-vault-favour, fee splits. |
| `subintents-patterns.md` | [docs.radixdlt.com/subintents](https://docs.radixdlt.com/docs/subintents) + [InfluxionLabs/anthic-sdk](https://github.com/InfluxionLabs/anthic-sdk) | Production patterns for Cuttlefish-era subintents (Scrypto 1.3+). Manifest primitives (`YIELD_TO_PARENT`, `YIELD_TO_CHILD`, `VERIFY_PARENT`), limits, signing model, real-world usage by Atomix + Anthic. |
| `strategy-vault-threat-model.md` | Original research | STRIDE-style threat model for a generic algorithmic-trading vault. 20 concrete attack scenarios with adversary, mitigation, detection signal, and required tests. Useful for comparing any vault-shaped blueprint against a known threat surface. |
| `radix-scrypto-knowledge.md` | Original notes | Radix transaction fundamentals (lock-fee minimums, withdraw precision, account model), pool types and their interfaces, manifest patterns for common operations (stake, unstake, swap, LP add/remove), known mainnet resource and pool addresses, defensive guard rails learned from incidents. |

All five files are loaded into every audit run (the harness globs `references/*.md`). Adding a file = it's used automatically; removing one = it's no longer used.

## Curating

References should be **concrete and citable**. The audit model uses them by analogy — "this blueprint resembles pattern X from Ignition; do they implement the same guard?" — so vague guidelines are less useful than specific code snippets with line citations.

### Adding a reference

1. Pick a source that is publicly available, permissively licensed (Apache-2.0, MIT, or similar), and that you can cite by file:line in a public repo.
2. Write a public-safe header at the top (template below).
3. Extract patterns into named, numbered sections. Each section should be self-contained — a reader who skips around can still understand it.
4. Cite specific file paths and lines in the source repo so the audit model (and human readers) can verify.
5. Open a PR. Maintainer review will check for licensing, citation accuracy, and overlap with existing references.

### Header template

```markdown
# <reference title>

**Source:** <repo URL or doc URL>
**Source license:** <Apache-2.0 / MIT / etc.>
**Snapshot date:** <YYYY-MM-DD when this was extracted>
**Curator:** <github handle or "anon">

<one-paragraph context: what this reference covers and why it's in the kit>
```

### Updating a reference

If the upstream source changes substantially (e.g. Ignition adds a new pattern, CaviarNine refactors), open a PR to update the relevant file. Bump the snapshot date in the header. Note the changes in the PR description.

The kit doesn't currently auto-detect upstream drift — that's a manual curator task. Adding drift detection is a [welcome contribution](../CONTRIBUTING.md).

## What does NOT belong here

- **Operator-specific notes.** "Apply this to *our* X blueprint" — generic references should describe the pattern, not its application in any one project.
- **Proprietary or confidential patterns.** If the source isn't publicly available and permissively licensed, don't include it.
- **Speculative patterns.** "I think this might be a good pattern" — patterns belong here once they're battle-tested in a real codebase.
- **Long-running design documents.** A 5000-line design doc is too much context. Extract the *patterns* into 200–500 lines.
