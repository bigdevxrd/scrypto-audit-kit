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
- [ ] First trial reports against public blueprints *(help wanted)* — also the parity check
      (markdown vs. `--structured`) gating the default flip below
- [x] Direct-API structured-output mode (guaranteed-valid JSON, no markdown parse) — `--structured`
      on the `claude-api` backend, opt-in/default off; not yet wired into `audit.sh` — see
      [docs/backends.md](docs/backends.md)

## Phase 2 — Agentic ✅ (v0.2)

- [x] MCP server — `audit_package`, `get_findings`, `reaudit_diff`, `gate`, `get_checklist`, `show_finding_source` (now 9 — `static_scan`, `propose_tests`, `attestation_payload` added in later phases)
- [x] Claude Code skill (`scrypto-pre-audit`) + `.mcp.json`
- [x] `AGENTS.md` convention so any agent can self-serve the kit
- [x] audit → fix → re-verify loop (read-only auditor + supervised fixer)
- [ ] Real-world shakedown — drive the loop on a live blueprint end-to-end *(needs an API key)*

## Phase 3 — Deterministic ✅ (v0.3)

- [x] Hybrid static-analysis pass — a free `--static-only` tier and the `static_scan` tool ([docs/static-analysis.md](docs/static-analysis.md)); 15 high-precision rules (14 at v0.8.0; `public-privileged-method` added in v0.8.1)
- [x] Property-test generation — compilable `#[ignore]` scrypto-test scaffolds + the `propose_tests` tool

## Phase 4 — Verifiable & connected 🚧 (v0.4, still open)

- [x] On-chain attestation blueprint — type-checks + CI-compiled, **not yet deployed/audited** (soulbound; source-hash anchor) + the `attest.py` manifest bridge ([attestation/](attestation/))
- [ ] Build/deploy the registry to Stokenet + a public dashboard of attested blueprints
- [ ] Auditor partnership (pre-audit funnel) + Radix grant

## Phase 5 — Developer experience ✅ (v0.5)

- [x] Pip-installable package (`scrypto_audit_kit`) — importable deterministic core + `sak-*` console scripts ([docs/sdk.md](docs/sdk.md))
- [x] Formal JSON-schema contracts for all 9 MCP tools ([schema/mcp-tools.schema.json](schema/mcp-tools.schema.json))
- [x] Runnable example agents — CI gate, audit → fix → verify, MCP client ([examples/agents/](examples/agents/))
- [x] Documentation suite — quickstart · SDK · MCP tools · architecture ([docs/](docs/README.md))
- [x] Guarded relative cross-imports, and no `sys.path` insert in `bin/__init__.py` — importing the
  package is side-effect free and can no longer shadow a consumer's own top-level modules
  (tracked in the maintainer's issue list)

## Phase 6 — Interchangeable backends ✅ (v0.6)

- [x] `audit.sh` dispatches to a pluggable **backend** behind a stable contract — the LLM pass is
  no longer welded to aider ([docs/backends.md](docs/backends.md))

## Phase 7 — CI hardening and rule precision ✅ (v0.7)

- [x] Closed argument injection in the reusable workflow, and installed the backend it defaults to
  — v0.7.0 was the CI floor until v0.8.0 superseded it (Phase 8)
- [x] Static-rule precision pass

## Phase 8 — Honest claims ✅ (v0.8)

- [x] Attestations record **facts, not a trust level** — the old `level` field conflated "which
  tiers ran" with "who witnessed the run", and failed *upward*. Breaking change to the payload
  and the blueprint ([docs/attestation-levels.md](docs/attestation-levels.md))
- [x] Analyzer no longer fails open; the distribution can test itself
- [x] **v0.8.0 supersedes v0.7.0 as the CI floor**

## Next

- [x] Dapp-scope pass, first slice — questionnaire schema, parallel checklist prompt, and a
      deterministic `sak-dapp-scope` report (validate → render, "unbounded" is a finding).
      Shipped in v0.8.1 (the `sak-dapp-scope` console script is in the wheel), not in v0.8.0. Not
      wired into the blueprint checklist, `report.json`, the MCP tools, or the L1–L4 attestation
      ladder. See [docs/DAPP-SCOPE-EXTENSION.md](docs/DAPP-SCOPE-EXTENSION.md) — remaining: an
      MCP tool, a real-world trial questionnaire, docs indexing
- [ ] Posture scanner — five on-chain checks (dApp-definition two-way verification, owner role,
      resource authority, package/blueprint upgrades, metadata claims vs. reality) against a
      cohort of live mainnet entities. A different surface from the rest of the kit: chain
      state in, no source required. **In the repository and the v0.8.1 sdist, not in the wheel.**
      Scans are run by hand — there is no schedule. Two are committed (2026-09-08, during the
      mainnet halt of 2026-08-31 to 2026-09-11; and 2026-09-11, the first after it resumed); the
      published page covers only the entities Radix Guild operates itself, and the newest scan
      predates the last two of the five cohort entries. Two of the three scanned entities fail
      check 1 and are published as found. Still open: a scheduled cadence, and scanning the two
      newest cohort entries. See [docs/posture-scanner.md](docs/posture-scanner.md),
      [`scanner/`](scanner/). Not yet wired into `report.json`, the L1-L4 ladder, or the MCP
      tools -- see that doc's own scope notes for what's disclosed as unverified (whether
      claimed icon/info URLs resolve; fee-rate-vs-simulated-swap parity)
- [ ] Deploy the attestation registry to Stokenet + a public dashboard (Phase 4 remainder)
- [ ] Auditor partnership (pre-audit funnel) + Radix grant
- [ ] Wire `--structured` into `audit.sh` and flip it on by default, once the parity check passes
- [ ] Real-world shakedown — drive the audit → fix → verify loop on a live blueprint end-to-end
- [ ] First trial reports against **public** blueprints *(help wanted)*

> On that last one: pre-audit reports on blueprints the maintainer operates exist (2026-07-18) but
> are not committed here — findings against live code stay out of this repository. They do not
> satisfy this item, which needs a *third-party public* blueprint.

---

Versioning: `VERSION` tracks the kit; the checklist and schema carry their own version fields.
