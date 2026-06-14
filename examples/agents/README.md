# Example agents

Three small, runnable programs that build on the kit — from a 30-line CI gate to a full
agent driving the kit over MCP. Each runs against the bundled
[`vulnerable-vault`](../vulnerable-vault) fixture out of the box, so you can see real output
before pointing them at your own package.

They import the kit two ways depending on how you installed it — both work:

```bash
pip install scrypto-audit-kit        # then the imports below resolve anywhere
# ...or just run them from a clone; each script falls back to ../../bin automatically.
```

| Script | Tier | Needs a key? | Shows |
|--------|------|--------------|-------|
| [`static_gate.py`](static_gate.py) | deterministic | no | The smallest useful build: run the static rules, gate on severity, exit non-zero for CI. |
| [`audit_fix_verify.py`](audit_fix_verify.py) | hybrid | optional | The **audit → fix → verify** loop, using the same functions the MCP server exposes. |
| [`mcp_client.py`](mcp_client.py) | deterministic | no | Driving the kit **over MCP** — spawn the server, discover tools, call them — like any external agent. |

## Run them

```bash
# 1. Free-tier gate — exits 1 if anything is at/above the threshold.
python static_gate.py ../vulnerable-vault --fail-on high

# 2. The loop. With no ANTHROPIC_API_KEY it walks the deterministic half and narrates the
#    model steps; with a key (and a kit clone) it runs the whole thing.
python audit_fix_verify.py

# 3. The same kit, over the Model Context Protocol (only the no-API tools).
pip install "mcp[cli]"
python mcp_client.py
```

## What to copy

- Building a CI check? Start from `static_gate.py` — it's stdlib + the kit, nothing else.
- Building an agent that hardens blueprints? `audit_fix_verify.py` is the reference control
  flow: **triage → audit → verify each citation → fix (you) → re-verify → gate**. The kit is
  read-only; your agent and the user own every edit.
- Integrating an existing MCP agent? `mcp_client.py` is the wire-level pattern.

The Python API these call is documented in [docs/sdk.md](../../docs/sdk.md); the tool
contracts they rely on are in [schema/mcp-tools.schema.json](../../schema/mcp-tools.schema.json)
and [docs/mcp-tools.md](../../docs/mcp-tools.md).

> A pre-audit makes a human audit cheaper — it does not replace one. None of these scripts
> decide your code is safe; they report what was checked and what's residual.
