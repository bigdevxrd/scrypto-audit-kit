# Attestation registry — the L3 trust primitive

A Scrypto blueprint that records pre-audit attestations **on the Radix ledger**. The kit
audits Scrypto; the proof lives *on* Scrypto. This is rung **L3** of the [trust ladder](../VISION.md).

## What an attestation asserts

A factual, on-ledger record — **not** a safety guarantee, and (for the LLM tier) **not**
byte-reproducible:

> scrypto-audit-kit `<kit_version>` (checklist `<checklist_version>`) produced report
> `<report_hash>` over source `<source_hash>`, at level `<level>`, with these severity
> counts, at epoch `E`.

What is actually verifiable depends on the tier:

- **`source_hash`** (sha256 of the analysed source) is the stable anchor — anyone can recompute it from the code and confirm the attestation is *about* that exact source.
- **`mode: static`** findings are **deterministic**: re-run the ruleset named by `static_ruleset_version` on the same source and you get the same findings.
- **`mode: llm` / `mode: hybrid`** include a non-deterministic LLM pass, so `report.json` (and thus `report_hash`) will **not** be identical on re-run — `report_hash` is then a tamper-evidence fingerprint of *one archived report*, not a value a third party can regenerate.

`mode` records **what ran**, not how much to trust it. The record carries no L-number: the
L1/L2/L3 rung is computed by the reader from mode + who attested + `issuer_verified`, per
[docs/attestation-levels.md](../docs/attestation-levels.md). Recording a level here would be
circular — L3 *is* this record existing.

So an attestation proves *which source was analysed and what one run reported* — it does **not**, by itself, prove the kit was run or that the counts are honest (see self-attestation below). The strongest signal is `issuer_verified`.

## Design

- **Soulbound NFT.** Each `attest` mints a non-transferable [`AttestationData`](src/lib.rs) NFT (withdraw denied once held) — an on-chain receipt bound to a specific code artifact. Soulbound stops it being *transferred*; it does **not** make its contents true.
- **Permissionless self-attestation.** Anyone can `attest` for any source/report hash — so a *self*-attestation proves only that someone recorded these bytes on-ledger, **not** that the kit was run or that the counts are real. Treat self-attestations as unverified.
- **Issuer endorsement = the real signal.** The `issuer` role (held by the OWNER) can `mark_verified` an attestation — meaning a trusted keeper actually ran the kit. Lead with `issuer_verified`, not with the existence of a self-attestation.
- **On-ledger index (issuer-verified only).** `source_hash → latest *issuer-verified* attestation id`, with `latest_attestation` / `is_attested` lookups. Self-attestations are deliberately **not** indexed, so the lookup can't be griefed by anyone writing for an arbitrary source hash; query those via the `AttestationCreated` event / Gateway.
- **Known limits.** The owner badge is a single point of control, and the owner rule is `OwnerRole::Fixed` — it can never be re-pointed to a replacement badge, so losing the badge means no further endorsements ever (self-attestation keeps working; see [what the kit says about this blueprint](#what-the-kit-says-about-this-blueprint)). Attestation NFTs have no burn — receipts are permanent.

## Methods

| Method | Auth | Purpose |
|--------|------|---------|
| `attest(AttestationInput) -> Bucket` | public | record an attestation, mint its soulbound NFT |
| `latest_attestation(source_hash) -> Option<id>` | public | latest **issuer-verified** attestation id for a source hash |
| `is_attested(source_hash) -> bool` | public | does this source have an **issuer-verified** attestation? |
| `mark_verified(attestation_id)` | issuer | endorse an attestation as issuer-verified |

## Producing an attestation from a report

The kit's [`bin/attest.py`](../bin/attest.py) turns a `report.json` into the attestation payload
and a ready-to-submit transaction manifest:

```bash
python3 bin/attest.py audit-reports/<repo>-<pkg>-<date>.json \
  --component <registry_component_address> \
  --account <your_account_address> \
  --wasm path/to/blueprint.wasm \
  --out-manifest attest.rtm
```

It reads the `source_hash` from the report, hashes the report (and optionally the wasm),
counts findings by severity, records the mode that ran (`static` / `llm` / `hybrid`), and renders
the manifest. It refuses a report with no `source_hash` anchor rather than emitting a payload the
chain would reject after your fee is locked. Submit `attest.rtm` with your wallet / the Radix CLI.

## Building & deploying

The blueprint **type-checks** (`cargo check`) and is compile-checked in CI on every change to
`attestation/`. It has **not** been deployed or human-audited — build, test, and **audit it** first:

```bash
cargo check --manifest-path attestation/Cargo.toml   # host target — catches type errors
# Full wasm build + tests on Linux (Mac has a known bulk-memory / blst WASM issue):
cd attestation
scrypto build
scrypto test            # the tests/ scaffolds were generated by the kit — fill them in first
```

Then deploy the package and call `instantiate` (returns the component + the owner badge that
controls the `issuer` role). Record the component address.

## What the kit says about this blueprint

We run the kit on it, and we publish what it reports rather than a clean number.
`./audit.sh --static-only attestation` returns **one finding**: `owner-role-fixed` (low) at
[`src/lib.rs:130`](src/lib.rs), where `prepare_to_globalize(OwnerRole::Fixed(...))` pins the owner
rule for the life of the component. It is a true positive, and it is deliberately **not** waived.

The rule is waivable with `// sak:allow owner-role-fixed` when immutable administration is a
deliberate property of the design. That premise does not hold here. What this registry makes
immutable is the *record* — soulbound NFTs, no burn. Administration is not immutable: the OWNER
can already re-point `issuer` (`issuer => updatable_by: [OWNER]`), so `Fixed` guarantees nothing
about who may endorse. All it removes is the ability to re-point the OWNER rule itself — to a
recovery rule or a multi-sig — after the badge is lost or compromised. Whether to move to
`OwnerRole::Updatable` is an open design question on a blueprint that has not been human-audited;
until it is settled, the finding stands.

The blueprint also ships with kit-generated [property-test scaffolds](tests/property_tests.rs).
Run the full pre-audit on it, and have it human-audited, before trusting it with anything.
