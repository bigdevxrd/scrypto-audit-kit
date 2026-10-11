# Radix posture scan

_Scan `20260911T221913Z-sv557872098` · mainnet · generated 2026-09-11T22:19:13Z._

Reads pinned to ledger state `557872098`.

**2 failing checks** across the cohort (2 medium).

Only `FAIL` carries weight. `info` marks a configuration whose correctness depends on the project's own intent (the canonical case: an ownerless AMM pool is both the correct permissionless design and, from chain data alone, indistinguishable from a missing recovery path) — the scanner refuses to call that a failure on a stranger's project. `n/a` means the check does not apply to that entity kind.

| Entity | Project | Kind | dApp-def two-way | Owner role | Resource authority | Upgrade | Metadata |
|---|---|---|---|---|---|---|---|
| Radix Guild dApp Definition account | Radix Guild | account | PASS | PASS | n/a | n/a | PASS |
| Guild Badge Manager | Radix Guild | component | FAIL | info | n/a | info | info |
| Guild Badge Factory | Radix Guild | component | FAIL | info | n/a | info | PASS |

## Findings

### Guild Badge Manager

`component_rdx1…tyrtva` · component · Radix Guild

- **dApp-def two-way — FAIL (medium).** Does not name a dApp Definition at all (no 'dapp_definition' or 'dapp_definitions' metadata key), and is not listed by any dApp Definition account this scan knows about -- zero-sided, not just unverified.
- **Owner role — info.** Owner role is protected by a fixed requirement with no rotation path (updater: None) -- if the required badge/key is ever lost or compromised, the owner rule can never be repointed. A common and often-intentional pattern; not provably wrong from chain data alone, so this stays informational rather than a guessed fail.
- **Upgrade — info.** No prior scan exists to compare against -- this run establishes the baseline for future upgrade detection. A clean reading here is not yet a claim of 'unchanged'.
- **Metadata — info (low).** Metadata gap(s): missing expected metadata field(s) for a component: ['name'].

### Guild Badge Factory

`component_rdx1…n2km99` · component · Radix Guild

- **dApp-def two-way — FAIL (medium).** Half-pair (reverse direction): entity does not name a dApp Definition itself, but account_rdx12yh4fwevmvnqgd3ppzau66cm9xu874srmrt9g2cye3fa8j8y78z9sq lists this entity in its own claimed_entities. Being claimed is not the same as claiming back.
- **Owner role — info.** Owner role is protected by a fixed requirement with no rotation path (updater: None) -- if the required badge/key is ever lost or compromised, the owner rule can never be repointed. A common and often-intentional pattern; not provably wrong from chain data alone, so this stays informational rather than a guessed fail.
- **Upgrade — info.** No prior scan exists to compare against -- this run establishes the baseline for future upgrade detection. A clean reading here is not yet a claim of 'unchanged'.

## Notes recorded with this scan

- This is the public cohort: only the entities the Guild operates itself. The scanner's full cohort (which also covers a small set of external projects, run locally, never committed) withholds every non-Guild row from anything this repository publishes -- see docs/posture-scanner.md#embargo. Guild rows are first-class here: the scanner holds us to the same standard as anyone else, and does not exempt us from a failing result.

---
_Cohort: `scanner/data/cohort.json`. Generated from the pinned `report.json` by `python3 -m scanner.cli render` — no live network read, so this page is reproducible from the committed JSON alone._
