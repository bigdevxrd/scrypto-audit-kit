# Quickstart

Three ways in, cheapest first. The deterministic tier needs nothing but Python; the full
hybrid audit adds an API key and [aider](https://aider.chat).

## Install

```bash
# Clone — everything runs straight from the clone, no install needed
git clone https://github.com/bigdevxrd/scrypto-audit-kit
cd scrypto-audit-kit && chmod +x audit.sh

# Optional: pip-install from the clone — the deterministic toolkit + the MCP
# server, importable anywhere. (Not on PyPI yet — a release is planned.)
pip install .
```

Why install? `pip install .` gives you the free static analysis, test-scaffold generation, the
attestation bridge, and the MCP server — as a library and as `sak-*` commands, usable from any
directory. The full `audit.sh` (the LLM checklist pass over your source) runs from the clone
either way, because it drives aider. [sdk.md](sdk.md) spells out exactly what runs where.

## 1. Free tier — deterministic static analysis (no API key)

```bash
sak-static path/to/your/scrypto/package        # if you pip-installed
./audit.sh --static-only path/to/package        # from a clone
```

Instant, reproducible, no toolchain. See it work on the bundled deliberately-vulnerable
fixture:

```bash
./audit.sh --static-only examples/vulnerable-vault
```

It writes `report.json` ([schema](../schema/audit-report.schema.json)) — the same structured
output every other surface consumes. The rules and how to add one:
[static-analysis.md](static-analysis.md).

## 2. Full tier — hybrid static + LLM pre-audit

```bash
export ANTHROPIC_API_KEY=sk-ant-...
./audit.sh path/to/your/scrypto/package
```

Runs the static pass, then an LLM over the [11-class checklist](../prompts/checklist.md) and
the [reference patterns](../references/), and merges both into one report at
`audit-reports/<repo>-<package>-<date>.md` (and `.json`). The package must have a `Cargo.toml`
and `src/lib.rs`. Requirements, model choice (`--model claude|deepseek|both`), and cost are in
[the README](../README.md#quickstart).

## 3. Agentic — point an agent at it

```bash
pip install "mcp[cli]"
claude mcp add --transport stdio scrypto-audit-kit -- python3 "$PWD/bin/mcp_server.py"
```

An MCP-aware agent (Claude Code, …) can now run the kit as tools and walk you through
**audit → fix → re-verify**. Setup and the loop: [agents.md](agents.md); the tools:
[mcp-tools.md](mcp-tools.md); runnable examples: [../examples/agents/](../examples/agents/).

## What you get, every tier

The same `report.json`: stable finding ids (`F-###` from the LLM, `S-###` from the static
pass), severities, a full checklist-coverage map, and a provenance block (kit / model /
checklist version + a sha256 of the analyzed source). The markdown report is a render of it,
and the [CI gate](ci.md) and [on-chain attestation](architecture.md#the-l3-bridge) read the
same file.

> A pre-audit is the rung below a human audit, not a substitute. Verify every cited line.
