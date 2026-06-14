# Agentic use — point an agent at your Scrypto

The kit ships an **MCP server** so any MCP-aware agent (Claude Code, etc.) can run the
pre-audit as tools and walk a user through **audit → fix → re-verify**. This is rung
L1 of the [trust ladder](../VISION.md).

## Tools the server exposes

| Tool | What it does |
|------|--------------|
| `static_scan(package_path)` | **Free, no API** — deterministic rules only. The cheap first pass. |
| `audit_package(package_path, model?, no_compile_check?)` | Run the full pre-audit (static + LLM); returns structured findings + `report_path`. |
| `get_findings(report_path, severity_min?, status?)` | Read/filter an existing report.json (cheap, no API). |
| `show_finding_source(report_path, finding_id, package_path?)` | Show the cited code so you can verify a citation before acting. |
| `reaudit_diff(package_path, baseline_report_path, model?)` | Re-audit after fixes; returns `fixed / still_open / new`. |
| `gate(report_path, fail_on?)` | Pass/fail at a severity threshold. |
| `get_checklist()` | The 11 vulnerability classes. |

The cheap tools (`get_findings`, `gate`, `get_checklist`, `show_finding_source`) need
no API key. `audit_package` / `reaudit_diff` run the model and need `ANTHROPIC_API_KEY`
in the server's environment.

## Install

```bash
pip install "mcp[cli]"      # or: pip install fastmcp
```

### Claude Code

Working **inside this repo**, the committed [`.mcp.json`](../.mcp.json) wires the server
up automatically — open the project with `claude` and approve it once.

To use it **from your own Scrypto repo**, register the server (point it at your clone):

```bash
claude mcp add --transport stdio scrypto-audit-kit --scope project \
  --env ANTHROPIC_API_KEY="${ANTHROPIC_API_KEY}" \
  -- python3 /absolute/path/to/scrypto-audit-kit/bin/mcp_server.py
```

That writes a project-scoped `.mcp.json` you can commit so your team shares it.

### Other MCP clients

Launch `python3 /path/to/scrypto-audit-kit/bin/mcp_server.py` as a stdio MCP server
and pass `ANTHROPIC_API_KEY` in its environment. Point your client's config at that
command (the `.mcp.json` above is the canonical shape).

## The skill

The repo also ships a Claude Code skill at
[`.claude/skills/scrypto-pre-audit/`](../.claude/skills/scrypto-pre-audit/SKILL.md)
that encodes the audit→fix→verify workflow. It loads automatically when you run
`claude` in this repo; copy that folder into your own project's `.claude/skills/`
to get it there too. Then just ask Claude to "pre-audit my blueprint", or run
`/scrypto-pre-audit`.

## The loop, concretely

1. `audit_package("packages/my-vault")` → findings + `report_path`.
2. For each Critical/High: `show_finding_source(report_path, "F-001", "packages/my-vault")` → verify the line is real.
3. Apply a minimal fix (with the user's review).
4. `reaudit_diff("packages/my-vault", report_path)` → confirm it moved to `fixed` and nothing `new` appeared.
5. Repeat until `gate(report_path, "high")` passes — a pre-audit pass, not a human-audit substitute.
