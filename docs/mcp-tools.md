# MCP tools

The kit ships an [MCP](https://modelcontextprotocol.io) server (`bin/mcp_server.py`) exposing
nine tools. Connect it ([agents.md](agents.md)) and any MCP-aware agent can run the pre-audit;
or call the same functions in-process ([sdk.md](sdk.md#the-9-tools-in-process)). The formal,
machine-readable contracts — input and output JSON Schema for every tool — live in
[schema/mcp-tools.schema.json](../schema/mcp-tools.schema.json); this page is the human render,
and [a test](../tests/test_tool_contracts.py) keeps the two in lockstep.

## At a glance

| Tool | Free? | Input | Output |
|------|-------|-------|--------|
| `static_scan` | ✅ | `package_path` | `{count, counts, findings}` |
| `audit_package` | key + clone | `package_path`, `model?`, `no_compile_check?` | the report + `report_path` |
| `propose_tests` | ✅ | `package_path` | `{blueprint, count, specs, rust}` |
| `attestation_payload` | ✅ | `report_path`, `component?`, `account?`, `wasm_path?`, `level?` | `{payload, manifest?}` |
| `get_findings` | ✅ | `report_path`, `severity_min?`, `status?` | `{count, counts, findings}` |
| `reaudit_diff` | key + clone | `package_path`, `baseline_report_path`, `model?` | `{fixed, still_open, new, summary}` |
| `gate` | ✅ | `report_path`, `fail_on?` | `{passed, worst, counts, total}` |
| `get_checklist` | ✅ | — | the checklist markdown |
| `show_finding_source` | ✅ | `report_path`, `finding_id`, `package_path?`, `context?` | `{finding, source}` |

"Free" = no API key, no model call — deterministic and instant. `audit_package` /
`reaudit_diff` run the LLM and need `ANTHROPIC_API_KEY` + a kit clone (they drive `audit.sh`).

## The tools

### static_scan(package_path)

Run only the deterministic rules — the cheap first pass. Findings carry `S-###` ids.

```text
static_scan("packages/my-vault") → {"count": 5, "counts": {"medium": 5}, "findings": [...]}
```

### audit_package(package_path, model="claude", no_compile_check=False)

The full hybrid run (static + LLM checklist). Returns the report.json contents plus
`report_path`, or `{error, log}` if the run produced none. `model` ∈ `claude | deepseek | both`;
`no_compile_check` skips the `cargo` wasm pre-flight.

### propose_tests(package_path)

Compilable `#[ignore]`d scrypto-test scaffolds for the coverage gaps. `specs` is structured;
`rust` is the ready-to-save file. Read-only — it returns them, it never writes into the package.

### attestation_payload(report_path, component="", account="", wasm_path="", level="")

Bridge a report to L3: the hashes, severity counts, and derived level, plus — when you pass
`component` **and** `account` — a Radix transaction manifest calling `attest()`.

### get_findings(report_path, severity_min="", status="")

Read and filter an existing report. `severity_min` ∈ `info … critical` (at/above);
`status` ∈ `open | fixed | wontfix | false_positive`.

### reaudit_diff(package_path, baseline_report_path, model="claude")

Re-audit after a fix and diff against a baseline by finding signature — the **verify** step of
the loop. Returns `{fixed, still_open, new, summary, report_path}`. Watch `new` for regressions.

### gate(report_path, fail_on="high")

Pass/fail at a threshold; **fails closed** on a missing or malformed report. `fail_on` ∈
`none | low | medium | high | critical`. Accepts a single report or a directory of them.

### get_checklist()

The 11 vulnerability classes with concrete questions per class, as markdown.

### show_finding_source(report_path, finding_id, package_path="", context=3)

Show the source a finding cites, with the line marked, so you can verify it before acting — the
model can hallucinate a `file:line`, and this is how you check. Returns `{finding, source}`.

## Two ways to call them

- **In-process** — `from scrypto_audit_kit import mcp_server; mcp_server.static_scan(pkg)`.
  No server, no protocol; best when your agent is Python ([sdk.md](sdk.md)).
- **Over MCP** — connect the server and `call_tool("static_scan", {"package_path": pkg})`.
  Language-agnostic; what Claude Code and other MCP clients use. See [agents.md](agents.md) to
  connect, and [examples/agents/mcp_client.py](../examples/agents/mcp_client.py) for a working client.

The shapes are identical either way — that is the point of the
[contracts](../schema/mcp-tools.schema.json).
