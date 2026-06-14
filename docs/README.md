# Documentation

`scrypto-audit-kit` is a **pre-audit** toolkit for [Scrypto](https://docs.radixdlt.com/docs/scrypto-1)
blueprints on Radix — a deterministic static pass plus an LLM checklist pass that produce a
machine-readable findings report. It is the entry rungs (L1–L3) of a
[trust ladder](../VISION.md) that ends at a human audit; it does not replace one.

Start with what you want to do.

## Use it

| If you want to… | Read |
|---|---|
| Install it and run your first pre-audit | [quickstart.md](quickstart.md) |
| Run only the free, deterministic rules (no API key) | [static-analysis.md](static-analysis.md) |
| Gate every PR on a pre-audit and show a badge | [ci.md](ci.md) |

## Build on it

| If you want to… | Read |
|---|---|
| Call the kit from your own Python or agent | [sdk.md](sdk.md) |
| Drive it over MCP — the 9 tools and their contracts | [mcp-tools.md](mcp-tools.md) · [agents.md](agents.md) |
| Copy a worked example agent | [../examples/agents/](../examples/agents/) |
| Code against the data shapes | [report schema](../schema/audit-report.schema.json) · [tool contracts](../schema/mcp-tools.schema.json) |

## Understand it

| If you want to… | Read |
|---|---|
| See how the pieces fit together | [architecture.md](architecture.md) |
| Understand the strategy and honest scope | [../VISION.md](../VISION.md) · [../ROADMAP.md](../ROADMAP.md) |
| Know exactly what it does and doesn't catch | [README — Limitations](../README.md#limitations--read-this-before-relying-on-the-output) |
| Contribute | [../CONTRIBUTING.md](../CONTRIBUTING.md) · [../AGENTS.md](../AGENTS.md) (agents) |

## The one thing to remember

A pre-audit makes a human audit cheaper and better-targeted — it is **not** a substitute for
one, and a clean report is never a statement that your code is safe. Every finding cites a
`file:line` you must verify; residual risk is surfaced as open questions, never hidden.
