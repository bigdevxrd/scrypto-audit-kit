# AGENTS.md

Guidance for AI agents working with this repo. (Human contributors: see
[CONTRIBUTING.md](CONTRIBUTING.md).)

`scrypto-audit-kit` is a **pre-audit** toolkit for [Scrypto](https://docs.radixdlt.com/docs/scrypto-1)
blueprints on Radix. Use it to help a user security-review and harden a Scrypto
package before they pay for a human audit. It is rung L1–L2 of a trust ladder, not
a safety guarantee — see [VISION.md](VISION.md). Never tell a user their code is "safe";
report what was checked and what's residual.

## Using the kit to audit a package

**Via the MCP server** (preferred — see [docs/agents.md](docs/agents.md) to connect it):
the `scrypto-audit-kit` server exposes `audit_package`, `get_findings`,
`show_finding_source`, `reaudit_diff`, `gate`, and `get_checklist`.

**Via the CLI:**

```bash
./audit.sh <path-to-package>          # add --no-compile-check if the toolchain isn't set up
# reads audit-reports/<repo>-<package>-<date>.json (schema/audit-report.schema.json)
```

### The loop: audit → fix → re-verify

1. **Audit** the package (`audit_package` or `./audit.sh`). Summarize findings by severity.
2. **Verify each citation** with `show_finding_source` before acting — the model can hallucinate `file:line`.
3. **Fix one finding at a time**, minimally, with the user's review. The kit's auditor is read-only; *you* make edits, the user owns audit-grade changes.
4. **Re-verify** with `reaudit_diff` against the baseline report — confirm findings closed and nothing new appeared.
5. Repeat until `gate(report, "high")` passes; then state plainly this is a pre-audit, not a human audit.

## Working on the kit itself

- **Layout:** `audit.sh` (harness) · `prompts/` (audit prompt + 11-class checklist) · `references/` (pattern catalogue) · `bin/` (`sak_lib.py` shared logic, `mcp_server.py`, `extract-report.py`, `ci-gate.py`) · `schema/` · `tests/` · `examples/vulnerable-vault` (planted-bug fixture).
- **Before committing:** `make lint` (shellcheck + markdownlint + py_compile) and `make test` (stdlib unittest). CI runs both.
- **Invariants:** the auditor never edits code under review; references must be public + permissively licensed with a provenance header; prompts optimise for signal, not finding count. See [CONTRIBUTING.md](CONTRIBUTING.md) for what won't be merged.
