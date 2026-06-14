# Architecture

How the kit fits together — for contributors, evaluators, and anyone deciding whether to
build on it. The short version: **one structured artifact (`report.json`), two analysis
engines that fill it, and many surfaces that produce or consume it.**

## The trust ladder it sits on

The kit owns the empty middle between "it compiles" and "a human audited it" — see
[VISION.md](../VISION.md) for the full argument.

| Rung | What | The kit's part |
|------|------|----------------|
| L0 | `cargo check`, clippy | pre-flight only — `audit.sh` bails if it doesn't compile |
| **L1** | Agentic pre-audit (audit → fix → verify) | the MCP server, the skill, `AGENTS.md`, the example agents |
| **L2** | Attested CI run (pinned method, deterministic tier, badge) | the reusable Action + the severity gate |
| **L3** | On-chain attestation (soulbound, code-hash-bound) | the `attestation/` blueprint + the `attest.py` bridge |
| L4 | Human audit (Hacken, Certik, …) | the kit's report is the *input*, not a replacement |

## The substrate: one report, one schema

Everything orbits `report.json` ([schema](../schema/audit-report.schema.json)). The markdown
report is a *render* of it; the badge, the CI gate, the fix-loop diff, and the on-chain
attestation all *consume* it. Findings carry stable ids (`F-###` LLM, `S-###` static),
severities, a checklist-coverage map, and a provenance block stamped by the harness (kit /
model / checklist version + a sha256 of the analyzed source).

## The two engines

```text
            source: Cargo.toml + src/ + tests/
                          │
          ┌───────────────┴───────────────┐
          ▼                               ▼
   static pass                      LLM checklist pass
   static_analysis.py               audit.sh + aider
   12 rules · free ·                prompts/ + references/
   reproducible                     semantic · advisory · needs API key
          │  S-### findings                │  F-### findings
          └───────────────┬───────────────┘
                          ▼
         merge by signature  (sak_lib.merge_findings)
                          ▼
              report.json  ──render──▶  report.md
        (schema/audit-report.schema.json)
                          │
       consumed by:  CI gate · badge · fix-loop diff · attestation
```

- **Deterministic tier** ([static-analysis.md](static-analysis.md)) catches the mechanical
  footguns a regex can judge — reproducibly, for free. It is the floor every run stands on.
- **LLM tier** handles what static analysis can't: semantics, intent, cross-method
  invariants, the 11 checklist classes. Strong signal, **not** byte-reproducible.
- **Merge** — `sak_lib.merge_findings` appends the static findings the LLM didn't already
  raise (matched by a class+title+severity signature), so one report holds both, de-duplicated.

Why hybrid: determinism where you can get it (trust), an LLM where you can't (coverage). Each
finding records which engine produced it (`source: static | llm`).

## The surfaces

The same logic is reachable however an agent or human arrives:

| Surface | Entry point | Use |
|---------|-------------|-----|
| CLI harness | `audit.sh` | the full hybrid run — the canonical pipeline |
| Console scripts | `sak-static`, `sak-gate`, `sak-attest`, `sak-gen-tests`, `sak-mcp` | standalone deterministic tools |
| Python library | `import scrypto_audit_kit` | call the kit in-process ([sdk.md](sdk.md)) |
| MCP server | `bin/mcp_server.py` — 9 tools | any MCP agent ([mcp-tools.md](mcp-tools.md)) |
| CI action | `.github/workflows/pre-audit.yml` | gate every PR ([ci.md](ci.md)) |
| Claude Code skill | `.claude/skills/scrypto-pre-audit/` | one-command use in a session |

`bin/sak_lib.py` is the shared core under all of them — pure, stdlib-only, unit-tested — so
the gate, the MCP server, the library, and the CLI apply identical severity / diff / merge logic.

## Reproducibility & provenance

The anchor is `target.source_hash` — a sha256 of the concatenated analyzed source. Given the
same source and a pinned kit version, the **static findings reproduce exactly**. The **LLM
findings do not** (production APIs drift, even at temperature 0), so the kit anchors
verification on the source hash plus the deterministic findings, and treats `report_hash` as a
fingerprint of one specific run — not something re-derivable. This honesty is load-bearing;
see [VISION.md — Principles](../VISION.md).

Provenance is stamped by the **harness, never the model**: `extract-report.py` only trusts a
JSON appendix carrying a per-run nonce, so a malicious blueprint can't get the model to echo a
forged report. The kit version, model, and source hash are authoritative because the harness
writes them.

## The L3 bridge

`bin/attest.py` turns a `report.json` into an attestation payload (`source_hash`,
`report_hash`, `wasm_hash`, versions, level, severity counts) and a Radix transaction manifest
that calls `attest()` on the [attestation registry blueprint](../attestation/). The minted
record is **soulbound** and binds *this exact code hash* to *this coverage level* — a coverage
claim anyone can verify on-ledger, never a safety blessing.

## Invariants

- **Read-only core.** The auditor never edits the code under review. Fixes happen in a
  separate, human-supervised session; the kit only ever proposes a direction.
- **Honesty over finding-count.** Residual risk is surfaced as open questions; the kit never
  claims "safe" or "audited".
- **No proprietary content.** Reference patterns come only from public, permissively-licensed
  sources, each with a provenance header. See [CONTRIBUTING.md](../CONTRIBUTING.md).
