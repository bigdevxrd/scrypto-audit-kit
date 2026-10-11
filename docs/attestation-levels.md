# Attestation levels — what the kit records, and what you compute

**Rule version: 1.0**

An attestation records **facts about a run**. It does not record a trust level. The L1/L2/L3 rung
is *derived by the reader* from those facts plus who attested. This page is the rule for doing
that derivation, published and versioned so it can be checked rather than trusted.

If you only read one thing: **`mode` is not a level.** `mode` says which analysis ran. The rung
says who witnessed it. They are different axes, and conflating them is how a coverage claim turns
into an over-claim.

## The two axes

| | Question it answers | Where it lives |
|---|---|---|
| **`mode`** | *What analysis ran?* `static` · `llm` · `hybrid` | recorded on-chain, enum-checked |
| **Rung (L1–L4)** | *Who witnessed the run, and how verifiable is it?* | **computed by the reader**, never recorded |

A laptop run and a CI run of the identical command produce the identical `mode`. What separates
them is the witness — which is exactly why the witness cannot be self-declared.

## What is recorded on-chain

Every field is a fact a relying party can check or a value the producer is merely stating:

| Field | Verifiable by a third party? |
|---|---|
| `source_hash` | **Yes** — recompute it from the source (see below) |
| `report_hash` | **Yes**, against an archived report — but not re-derivable for the LLM tier |
| `wasm_hash` | **Yes**, against a build |
| `mode` | Constrained to a closed set on-chain; otherwise producer-stated |
| `kit_version`, `checklist_version`, `static_ruleset_version` | Producer-stated; they tell you *what to re-run* |
| severity counts | Check against the report that `report_hash` pins |
| `attested_at_epoch` | **Yes** — the ledger sets it |
| `issuer_verified` | **Yes** — only the registry's `issuer` role can set it |

Notably **absent**: any `level` field. It was removed in v0.8.0. Recording one would be
self-referential — L3 *is* the existence of the record, so it cannot also be an input to it — and
it is the single field an attacker would forge, on a record the blueprint cannot validate.

## Computing the rung

```text
L1  the kit ran and a report was published
    evidence: a report.json exists; static findings re-derivable from source_hash
              + static_ruleset_version
    anyone can reach this; it says nothing about who ran it

L2  the run happened in an environment the claimant did not control
    evidence: a signed statement from a build platform (e.g. GitHub Actions OIDC)
              naming workflow + commit + kit version
    NOT reachable by a local run, and NOT by a self-attestation. A green CI badge
    alone is not L2 — a badge shows a run happened, not that its provenance is signed.

L3  an L1/L2 result is bound on-ledger to an exact code hash, timestamped
    evidence: the attestation record itself
    conferred by the record existing; strengthened, not created, by issuer_verified

L4  human audit — outside this kit entirely
```

And the honest reading of each combination:

| `mode` | attester | `issuer_verified` | Rung | What you may say |
|---|---|---|---|---|
| `static` | self | false | L1 + L3 anchor | "the deterministic ruleset ran; reproduce it yourself" |
| `hybrid` | self | false | L1 + L3 anchor | "the author says an LLM pass also ran" — unverifiable |
| any | CI, signed | false | L2 + L3 | "an independent runner executed this method on this commit" |
| any | any | **true** | L3, endorsed | "the registry issuer vouches for this record" |

**The LLM tier is unfalsifiable from outside.** Production APIs drift, so the pass is not
byte-reproducible — a reader can never confirm from the artifact alone that it ran. That is why
`hybrid` from a self-attester is a *claim*, and why `issuer_verified` and CI signing are the only
things that turn it into evidence.

## Fail-safe direction

Two different failures, two different answers:

- **Missing anchor → refuse.** `attest.build_payload` raises rather than emitting a payload with
  an empty `source_hash` or no `kit.version`. The on-chain `attest` reverts on it anyway, *after*
  `lock_fee` — so emitting one converts a clear local error into a wasted transaction, or into a
  log line stating a mode before the failure. The artifact is permanent and unburnable.
- **Ambiguous depth → claim the lowest.** `mode` is derived from `kit.tiers`, and every tier must
  be positively present to be claimed. A report with no `tiers` (anything before v0.8.0) derives
  `static`, never `hybrid`.

Both follow the kit's existing idiom: `sak-gate` fails closed on a missing reports dir, an
unknown severity outranks `critical`, and an unauthenticated JSON appendix is refused outright.

## Reproducing `source_hash` yourself

`sha256` of the analyzed files concatenated, in this order: `Cargo.toml`, then every `.rs` under
`src/` sorted by path, then every `.rs` under `tests/` sorted by path.

```bash
python3 -c "import sak_lib; print(sak_lib.source_hash('path/to/package'))"
```

The shell and Python implementations are pinned against each other by
`tests/test_attest.py::TestSourceHashParity`, because a drift between them would mean the same
source attesting under two different anchors.

## Why this shape

This is the split [SLSA](https://slsa.dev) makes, for the same reason. Its provenance predicate
has **no level field**: the build platform asserts facts, and the consumer decides what level
those facts support — because a producer asserting its own trust level is worth exactly nothing.
SLSA is explicit that producer-generated provenance is "trivial to bypass or forge" and defines a
rung for it anyway, *labelled as such*. A forgeable claim is still useful; a forgeable claim
wearing a trusted label is not.

## Changing this rule

The rule is versioned. If the derivation changes, bump **Rule version** at the top and say what
moved — a reader who evaluated an attestation under 1.0 must be able to tell that the meaning
changed underneath them. The on-chain facts are designed to outlive any particular rule.
