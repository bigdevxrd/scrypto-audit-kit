# Changelog

Notable changes to scrypto-audit-kit. The kit version lives in [VERSION](VERSION) and is
stamped into every report; this log follows [Keep a Changelog](https://keepachangelog.com) and
[SemVer](https://semver.org). The kit was built in a compressed timeline — dates reflect that.

## [0.5.0] — 2026-06-14 — Developer experience

The kit becomes something you build on, not just run. **Additive only** — every existing run
path (`audit.sh`, the `bin/` scripts, `.mcp.json`, the test suite) is unchanged.

### Added

- **Pip-installable package.** `pip install scrypto-audit-kit` exposes the deterministic core
  (`from scrypto_audit_kit import static_analysis, sak_lib, attest, gen_tests`) and `sak-*`
  console scripts (`sak-static`, `sak-gate`, `sak-attest`, `sak-gen-tests`, `sak-mcp`). The core
  is stdlib-only with zero required dependencies; `mcp` and `jsonschema` are opt-in extras.
  ([docs/sdk.md](docs/sdk.md))
- **Formal tool contracts.** [schema/mcp-tools.schema.json](schema/mcp-tools.schema.json) —
  input/output JSON Schema for all 9 MCP tools, kept in lockstep with the code by a drift test
  that also validates real fixture output against the published schemas.
- **Example agents.** [examples/agents/](examples/agents/) — three runnable programs: a
  free-tier CI gate, the audit → fix → verify loop, and an MCP client.
- **Documentation suite.** [docs/](docs/README.md) — a quickstart, an SDK reference, an
  MCP-tools reference, and an architecture overview, behind a docs index.

### Changed

- The MCP server resolves the kit root via `SAK_HOME` (env → walk-up → default), so a
  pip-installed server degrades gracefully; running from a clone is byte-identical to before.
- README gains a pip/SDK quickstart and a docs map; AGENTS/VISION reconciled (the kit spans
  L1–L3; tool names current).

### Fixed

- Two unclosed-file `ResourceWarning`s in the test suite.

### Security

A second adversarial hardening pass (2026-07-17) landed before this first published release:

- **Compile pre-flight is now opt-in** (`--compile-check`). `cargo check` executes the
  target's build scripts and proc-macros on your machine, so the default path no longer runs
  any untrusted code; `--no-compile-check` is kept as a back-compat no-op, and API keys are
  scrubbed from the pre-flight environment either way.
- **Prompt boundary.** The audit prompt declares the target source untrusted data — never
  instructions — and requires any attempt to steer or suppress the audit to be reported as a
  finding.
- **CI workflows.** Least-privilege token, credentials not persisted into the untrusted
  checkout, and the release workflow no longer shell-interpolates the release tag name
  (script injection).
- **Fail-closed report handling.** No stale-report provenance, path-traversal confinement,
  nonce adjacency in report extraction, refusals fail loud, and static-only runs emit a clean
  `report.json`.
- **Static analyzer.** Newline-split evasion closed, drain/float rules broadened, and
  `sak:allow all` rejected.

Tests: 88 → 105 green (127 after the hardening pass).

## [0.4.0] — 2026-06-14 — Verifiable & connected, then hardened

### Added

- **L3 on-chain attestation.** A Scrypto [attestation registry blueprint](attestation/) — a
  soulbound NFT binding `{source_hash, report_hash, wasm_hash, versions, level, severity counts}`
  — plus `bin/attest.py` (report → payload → Radix manifest) and the `attestation_payload` tool.
- **Property-test generation.** `bin/gen_tests.py` emits compilable `#[ignore]`d scrypto-test
  scaffolds from the blueprint surface, and the `propose_tests` tool.

### Security

- **Adversarial pass (R1–R6).** Four red-team agents audited every surface; all findings fixed
  with regression tests. Closed a "malicious package → clean badge" chain (nonce-authenticated
  report appendix, fail-closed gate, severity normalisation); made the attestation blueprint
  compile and hardened its index; fixed static-analyzer stripper bugs and evasions; added the
  `raw-decimal-arith`, `unwrap-expect`, and `public-mint-burn` rules; and reframed the
  reproducibility claims honestly (the static tier reproduces, the LLM tier does not).

## [0.3.0] — 2026-06-14 — Deterministic

### Added

- **Hybrid static analysis.** `bin/static_analysis.py` — a comment/string-aware analyzer with
  high-precision Scrypto rules, a free `--static-only` tier (no API key, no toolchain), the
  `static_scan` tool, and `// sak:allow` suppression.
  ([docs/static-analysis.md](docs/static-analysis.md))

## [0.2.0] — 2026-06-13 — Agentic

### Added

- **MCP server** (`bin/mcp_server.py`) exposing the pre-audit as tools, sharing `bin/sak_lib.py`
  with the CI gate; a Claude Code skill, `.mcp.json`, and an [AGENTS.md](AGENTS.md) playbook.
- The **audit → fix → re-verify** loop (read-only auditor + supervised fixer).
  ([docs/agents.md](docs/agents.md))

## [0.1.0] — 2026-06-13 — Trustworthy & machine-readable

### Added

- Machine-readable `report.json` with a [schema](schema/audit-report.schema.json), stable
  finding ids, and a provenance block (kit / model / checklist version + source hash).
- A deliberately-vulnerable [example fixture](examples/vulnerable-vault) + a committed sample
  report; a reusable [pre-audit GitHub Action](.github/workflows/pre-audit.yml) + severity gate +
  badge ([docs/ci.md](docs/ci.md)); [VISION.md](VISION.md) + [ROADMAP.md](ROADMAP.md).

## [0.0.0] — 2026-06-13 — Foundations

### Added

- Public Apache-2.0 repo, CI, the curated 11-class checklist + reference-pattern catalogue, and
  the honest framing (read-only core, not-an-audit, cite-and-verify).
