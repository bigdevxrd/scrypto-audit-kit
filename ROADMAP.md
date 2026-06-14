# Roadmap

Live status of the plan in [VISION.md](VISION.md). Checked = shipped on `main`.
Anything unchecked is fair game — open an issue to claim it.

## Phase 0 — Foundations ✅

- [x] Public OSS repo, Apache-2.0, CI (shellcheck + markdownlint + links)
- [x] Curated 11-class checklist + reference-pattern catalogue
- [x] Honest framing (read-only, not-an-audit, cite-and-verify)

## Phase 1 — Trustworthy & machine-readable ✅ (v0.1)

- [x] JSON findings output + stable `F-###` ids ([schema](schema/audit-report.schema.json))
- [x] Reproducibility metadata (kit / model / checklist version + source hash) in every report
- [x] Deliberately-vulnerable example + committed sample report
- [x] Reusable pre-audit GitHub Action + severity gate + badge ([docs/ci.md](docs/ci.md))
- [x] VISION + this roadmap
- [ ] First trial reports against public blueprints *(help wanted)*
- [ ] Direct-API structured-output mode (guaranteed-valid JSON, no markdown parse)

## Phase 2 — Agentic ✅ (v0.2)

- [x] MCP server — `audit_package`, `get_findings`, `reaudit_diff`, `gate`, `get_checklist`, `show_finding_source`
- [x] Claude Code skill (`scrypto-pre-audit`) + `.mcp.json`
- [x] `AGENTS.md` convention so any agent can self-serve the kit
- [x] audit → fix → re-verify loop (read-only auditor + supervised fixer)
- [ ] Real-world shakedown — drive the loop on a live blueprint end-to-end *(needs an API key)*

## Phase 3 — Deterministic ✅ (v0.3)

- [x] Hybrid static-analysis pass — 9 high-precision rules, a free `--static-only` tier, and the `static_scan` tool ([docs/static-analysis.md](docs/static-analysis.md))
- [x] Property-test generation — compilable `#[ignore]` scrypto-test scaffolds + the `propose_tests` tool

## Phase 4 — Verifiable & connected 🚧 (v0.4)

- [x] On-chain attestation blueprint (soulbound, source-hash ↔ report-hash) + the `attest.py` manifest bridge ([attestation/](attestation/))
- [ ] Build/deploy the registry to Stokenet + a public dashboard of attested blueprints
- [ ] Auditor partnership (pre-audit funnel) + Radix grant

---

Versioning: `VERSION` tracks the kit; the checklist and schema carry their own version fields.
