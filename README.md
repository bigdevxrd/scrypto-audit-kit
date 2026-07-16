# scrypto-audit-kit

[![lint](https://github.com/bigdevxrd/scrypto-audit-kit/actions/workflows/lint.yml/badge.svg)](https://github.com/bigdevxrd/scrypto-audit-kit/actions/workflows/lint.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Scrypto · Radix](https://img.shields.io/badge/Scrypto-Radix-052CC0)](https://docs.radixdlt.com/docs/scrypto-1)
[![status: alpha](https://img.shields.io/badge/status-alpha-orange.svg)](#limitations--read-this-before-relying-on-the-output)
[![PRs welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

Pre-audit harness for [Scrypto](https://docs.radixdlt.com/docs/scrypto-1) blueprints on the Radix network. Runs a **hybrid analysis** — deterministic static rules plus an LLM pass over a curated checklist + reference patterns — and produces a findings report (markdown + JSON) you can hand to a human auditor (or use to fix issues yourself). The static pass alone is free and needs no API key.

This is a **pre-audit** tool, not an audit. It catches the kinds of issues a careful reviewer would catch on a first read so that paid auditors can spend their time on the harder, second-read findings. **It does not replace a human audit before mainnet deployment.**

> **Where this fits** — the kit is the entry rung of a *trust ladder* that climbs from `cargo check` up to a full human audit (Hacken, Certik, …). The bigger plan — agentic audit→fix→verify loops, reproducible attested runs, and on-chain attestation — lives in **[VISION.md](VISION.md)**.

## What it does

For each scrypto package you point it at, the kit:

1. Runs a **deterministic static pass** (free, no API) — a curated set of high-precision Scrypto rules (unbounded drains, no-owner globalize, self-rotating roles, floats, hardcoded addresses, …).
2. Loads the package's source (Cargo.toml + everything under `src/` and `tests/`) into an [aider](https://aider.chat) session.
3. Loads a vulnerability **checklist** (11 classes — auth, reentrancy, decimal, resource handling, time, state machine, external calls, upgrade, oracle, slippage, allowances) and a catalogue of **reference patterns** (Ignition, CaviarNine HyperStake, subintents, a strategy-vault threat model, general scrypto knowledge) as read-only context.
4. Asks Claude Sonnet 4.6 to produce a structured findings report — summary, findings (Critical → Info), checklist coverage walk, pattern conformance check, test-coverage gaps, open questions for the human auditor.
5. Merges both passes and writes a markdown report to `audit-reports/<repo>-<package>-<date>.md` **and** a machine-readable `report.json` ([schema](schema/audit-report.schema.json)) that agents and the CI gate consume.

The kit is **read-only by design**. It produces reports; it does not edit your blueprint. Edits to audit-grade code must go through a separate, human-supervised session.

## Quickstart

```bash
git clone https://github.com/bigdevxrd/scrypto-audit-kit
cd scrypto-audit-kit
pip install .        # optional — the deterministic toolkit + MCP server, no API key needed
```

Everything runs straight from the clone with no install — `./audit.sh`, the `bin/` scripts, the
test suite. The optional `pip install .` adds the free static analysis, test-scaffold
generation, the attestation bridge, and the MCP server as an importable library and `sak-*`
commands. (The kit isn't on PyPI yet — a release is planned; install from the clone for now.)
**[docs/quickstart.md](docs/quickstart.md)** walks all three tiers end to end.

### Requirements (for the full `./audit.sh` audit)

- [aider](https://aider.chat) (`pip install aider-chat` — version 0.86 or newer)
- An Anthropic API key (the kit defaults to Claude Sonnet 4.6 — get one at <https://console.anthropic.com>)
- bash, awk, find (standard on macOS / Linux)
- `python3` — optional; only needed for the machine-readable `report.json` (the markdown report works without it)

The key can be provided in any of three ways:

```bash
# 1. Export in your shell (preferred for CI)
export ANTHROPIC_API_KEY=sk-ant-...

# 2. Point AIDER_ENV_FILE at an existing env file
AIDER_ENV_FILE=~/some/.env ./audit.sh /path/to/package

# 3. Drop a .env file (gitignored) in the kit directory
echo "ANTHROPIC_API_KEY=sk-ant-..." > .env
```

Verify with:

```bash
make check-deps
```

### Run an audit

```bash
git clone https://github.com/bigdevxrd/scrypto-audit-kit
cd scrypto-audit-kit
chmod +x audit.sh

./audit.sh /path/to/your/scrypto/package
# or:
make audit TARGET=/path/to/your/scrypto/package
```

The target must be a scrypto package directory (has a `Cargo.toml` and a `src/lib.rs`). The kit will read everything under `src/` and `tests/`.

The report lands in `audit-reports/<repo>-<package>-<YYYY-MM-DD>.md`. Reports are gitignored — share them by other means, don't commit them.

### Example

```bash
./audit.sh ~/scrypto/my-vault
[pre-flight] cargo check (release wasm)...
[pre-flight] compile OK

==> scrypto-audit-kit
    target:    scrypto / my-vault
    path:      /home/me/scrypto/my-vault
    model:     claude
    sources:   3 files
    refs:      6 files (read-only)
    report ->  audit-reports/scrypto-my-vault-2026-05-11.md

[aider runs ...]

==> done. report: audit-reports/scrypto-my-vault-2026-05-11.md
```

> Note: the harness runs `cargo check --release --target wasm32-unknown-unknown`
> first and bails if the package doesn't compile — no point spending model time
> on broken code. Install the wasm target with `rustup target add wasm32-unknown-unknown`.

### Choosing a model

The default is Claude Sonnet 4.6. A `--model` flag selects the analysis model:

```bash
./audit.sh --model claude   <path>   # default — Sonnet 4.6, best pattern depth
./audit.sh --model deepseek <path>   # cheaper broad scan (needs DEEPSEEK_API_KEY)
./audit.sh --model both     <path>   # DeepSeek broad pass, then Claude deep pass,
                                     # with a cross-model confidence summary
```

`both` runs DeepSeek first for a wide net, feeds its findings to Claude as
context, and tags findings both models agree on as HIGH confidence. Use it when
you want a second opinion on a high-stakes blueprint.

### Free tier: deterministic static analysis

A static pass runs on every audit, and you can run it *alone* with **no API key, no aider, and no toolchain**:

```bash
./audit.sh --static-only <path>     # free, instant, deterministic
```

It applies a curated set of high-precision Scrypto rules — comment/string-aware, so code rules don't match inside comments or string literals — and writes the same `report.json`. Suppress a finding with a `// sak:allow <rule-id>` comment; add `--no-static` to a full run to skip the pass. See [docs/static-analysis.md](docs/static-analysis.md) for the rule list and how to add one.

### Try it on the bundled example

The repo ships a deliberately-vulnerable blueprint so you can see real output without writing any code — the static tier needs no API key:

```bash
./audit.sh --static-only examples/vulnerable-vault   # free; drop --static-only for the full hybrid run
```

The expected result is committed beside it — [`examples/vulnerable-vault.pre-audit.md`](examples/vulnerable-vault.pre-audit.md) (human) and [`.json`](examples/vulnerable-vault.pre-audit.json) (machine-readable). Every `file:line` in it is exact, because the bugs are planted.

### Machine-readable output

Alongside the markdown, the kit writes `report.json` conforming to [`schema/audit-report.schema.json`](schema/audit-report.schema.json) — stable ids (`F-###` from the LLM, `S-###` from the static pass, each tagged with its `source`), severities, full checklist coverage, and a provenance block (kit version, model, checklist version, and a sha256 of the analyzed source). This is what agents, the CI gate, and (later) on-chain attestation consume; the markdown is a render of it.

### Continuous integration & a badge

Run the pre-audit on every PR and show a status badge — full setup in [docs/ci.md](docs/ci.md). In short, call the reusable workflow:

```yaml
jobs:
  scrypto-pre-audit:
    uses: bigdevxrd/scrypto-audit-kit/.github/workflows/pre-audit.yml@main
    with:
      package: packages/my-blueprint
      fail-on: high
    secrets:
      ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
```

It compiles, audits, uploads the report, and fails on High/Critical findings — an honest "pre-audit passing" signal, not a safety guarantee.

### Use it from an agent (MCP + Claude Code)

The kit ships an **MCP server** so an agent can run the pre-audit as tools and walk you through **audit → fix → re-verify**:

```bash
pip install "mcp[cli]"
claude mcp add --transport stdio scrypto-audit-kit -- python3 "$PWD/bin/mcp_server.py"
```

Tools: `static_scan` (free), `audit_package`, `propose_tests`, `attestation_payload`, `get_findings`, `show_finding_source`, `reaudit_diff`, `gate`, `get_checklist`. There's also a Claude Code skill (`/scrypto-pre-audit`) and an [AGENTS.md](AGENTS.md) playbook for any agent. Full setup — including the audit→fix→verify loop — in [docs/agents.md](docs/agents.md); the nine tools and their formal contracts are in [docs/mcp-tools.md](docs/mcp-tools.md).

### Build on it — the Python SDK

`pip install .` from a clone makes the deterministic core importable, with zero required
dependencies (not yet on PyPI — a release is planned):

```python
from scrypto_audit_kit import static_analysis, sak_lib
findings = static_analysis.analyze_package("path/to/package")     # free, no API key
verdict  = sak_lib.gate_verdict(sak_lib.build_report(findings), "high")
```

The full API, the nine tools in-process, and the `sak-*` console scripts are in
[docs/sdk.md](docs/sdk.md). Three runnable example agents — a free-tier CI gate, the
audit→fix→verify loop, and an MCP client — are in [examples/agents/](examples/agents/).

### Generate tests, attest on-chain

- **Property tests.** `propose_tests` (or `python3 bin/gen_tests.py <pkg>`) emits compilable `#[ignore]`d `scrypto-test` scaffolds for the coverage gaps — auth negative-paths, happy paths, a value invariant — so closing them is fill-in-the-blank.
- **On-chain attestation (L3).** `attestation_payload` (or `python3 bin/attest.py <report.json>`) turns a report into a Radix transaction manifest that records an attestation on-ledger via the [attestation/](attestation/) registry blueprint — bound to your exact source hash (the deterministic anchor). A coverage record, not a safety guarantee, and for the LLM tier not byte-reproducible (see [attestation/README.md](attestation/README.md)).

## What's in the kit

```
scrypto-audit-kit/
├── audit.sh                The harness — wraps aider with the right flags + context.
├── Makefile                Convenience targets (audit, lint, test, check-deps).
├── pyproject.toml          Pip packaging — importable SDK + sak-* console scripts.
├── VERSION                 Kit version, stamped into every report.
├── VISION.md / ROADMAP.md  The trust-ladder strategy + the live phase checklist.
├── AGENTS.md               How an agent should drive the kit (audit → fix → verify).
├── .mcp.json               MCP server config (auto-wires the tools in Claude Code).
├── .aider.conf.yml         Tuned config: model=Sonnet 4.6, no editor/commits, cache on.
├── prompts/
│   ├── audit.md            Auditor-role prompt + report structure (incl. the JSON appendix).
│   └── checklist.md        Eleven vulnerability classes with concrete questions per class.
├── references/             Read-only context — production patterns + threat models (5 files).
├── schema/                 JSON Schemas — the report + the MCP tool contracts.
├── bin/                    engine + tools: static_analysis.py, gen_tests.py, attest.py, mcp_server.py, …
├── tests/                  Stdlib unit tests for the tooling (`make test`).
├── docs/                   The docs suite (quickstart · sdk · mcp-tools · architecture · …).
├── attestation/            On-chain attestation registry blueprint (Scrypto, L3).
├── .claude/skills/         The scrypto-pre-audit Claude Code skill.
├── audit-reports/          Output dir, gitignored.
└── examples/
    ├── vulnerable-vault/   Deliberately-vulnerable fixture + its committed report.
    ├── agents/             Runnable example agents (CI gate, audit→fix→verify, MCP client).
    └── ci/                 Drop-in pre-audit workflow for your repo.
```

## Documentation

Everything is in **[docs/](docs/README.md)**; the short list:

- [quickstart.md](docs/quickstart.md) — install + run, all three tiers
- [static-analysis.md](docs/static-analysis.md) — the deterministic rules (and adding one)
- [agents.md](docs/agents.md) · [mcp-tools.md](docs/mcp-tools.md) — drive it from an agent / over MCP
- [sdk.md](docs/sdk.md) — the Python API + console scripts
- [ci.md](docs/ci.md) — CI gate + badge
- [architecture.md](docs/architecture.md) — how the pieces fit together
- [VISION.md](VISION.md) · [ROADMAP.md](ROADMAP.md) · [CHANGELOG.md](CHANGELOG.md) — strategy, status, history

## Limitations — read this before relying on the output

The kit is honest about what it is. Things it explicitly does **not** do:

- **It is not a formal verifier.** No theorem proving, no symbolic execution, no fuzzing. Findings are derived from pattern matching against a checklist by an LLM.
- **It does not run `cargo build` or `cargo test`.** Compilation issues, dependency vulnerabilities, and test failures are not in scope. Run those separately.
- **It does not catch novel attack classes.** It will surface known footguns reliably and propose novel concerns as low-confidence open questions. Novel-attack discovery is the human auditor's job.
- **The LLM can hallucinate file:line citations.** Every finding cites a location; you must verify those citations before acting on them. The audit prompt explicitly instructs the model to cite, but verification is on the reader.
- **It is not a deployment gate.** Do not block deploys on a clean report. The kit is an aid, not approval.

If any of these limitations matter for your use case, do not use this kit as a substitute for a paid audit.

## Cost

With the default config (Sonnet 4.6, prompt caching on, references cached across runs):

- First audit of a session: ~50k input tokens (references) + 5–20k input tokens (target source) + ~5–15k output tokens → roughly $0.20–$0.40 per run.
- Subsequent audits in the same prompt-cache window: cached references reduce cost ~70% → roughly $0.10 per run.

These figures are estimates as of 2026. Check current [Anthropic pricing](https://www.anthropic.com/pricing) for accurate numbers. The kit deliberately does *not* use the architect/editor split (which would add a second model call) because we want analysis, not code edits.

## Contributing

This kit is community-maintained and gets stronger with more eyes on it. The most valuable contributions:

- **New vulnerability classes for the checklist.** Real-world Scrypto exploits or footguns we haven't catalogued yet.
- **New reference patterns.** Open-source Radix blueprints with patterns worth catalogue-ing — adapter scaffolds, role hierarchies, panic modes, etc.
- **Trial reports.** Run the kit against a public blueprint and share what it found (or missed). Negative results are valuable.
- **Harness fixes.** False-positive patterns, brittle parsing, missing edge cases in `audit.sh`.

See [CONTRIBUTING.md](CONTRIBUTING.md) for the workflow.

## License

[Apache 2.0](LICENSE) — the same license most of the upstream Radix ecosystem uses. Forks, derivatives, and commercial use all welcome; attribution preserved per the license.

## Related

- [Radix Scrypto docs](https://docs.radixdlt.com/docs/scrypto-1)
- [radixdlt/Ignition](https://github.com/radixdlt/Ignition) — the canonical Radix-team-maintained reference codebase (most of our `references/ignition-patterns.md` extracts from here)
- [caviarnine/caviarnine-scrypto](https://github.com/caviarnine/caviarnine-scrypto) — Apache-licensed CaviarNine production blueprints
- [aider](https://aider.chat) — the LLM coding agent this kit wraps
