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

## Phase 2 — Agentic

- [ ] MCP server (`audit_package`, `get_findings`, `verify_finding`, `reaudit_diff`)
- [ ] Claude Code skill / plugin
- [ ] `AGENTS.md` convention so any agent can self-serve the kit
- [ ] audit → fix → re-verify loop (read-only auditor + supervised fixer)

## Phase 3 — Deterministic

- [ ] Hybrid static-analysis pass (the "Slither for Scrypto")
- [ ] Property-test generation (`scrypto-test`) for flagged invariants

## Phase 4 — Verifiable & connected

- [ ] On-chain attestation blueprint (soulbound, code-hash ↔ report-hash)
- [ ] Public registry / dashboard of attested blueprints
- [ ] Auditor partnership (pre-audit funnel) + Radix grant

---

Versioning: `VERSION` tracks the kit; the checklist and schema carry their own version fields.
