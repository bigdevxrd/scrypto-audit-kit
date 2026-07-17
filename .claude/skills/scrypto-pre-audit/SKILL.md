---
name: scrypto-pre-audit
description: Pre-audit a Scrypto/Radix blueprint and help fix what it finds. Use when the user wants to audit, security-review, or harden Scrypto smart-contract code before a real audit, or asks to "check" / "clean up" a Radix package.
---

# Scrypto pre-audit

Run the scrypto-audit-kit pre-audit over a Scrypto package, then help the user close
the findings — **audit → fix → re-verify**. The auditor is read-only; you apply fixes
with the user in the loop. This is a *pre-audit* (a rung below a human audit), not a
safety guarantee — say so.

## Tools

If the `scrypto-audit-kit` MCP server is connected, prefer its tools:

- `audit_package(package_path)` — run the pre-audit; returns structured findings + `report_path`.
- `show_finding_source(report_path, finding_id, package_path)` — show the cited code. **Always verify a citation before acting on it** — the model can hallucinate line numbers.
- `reaudit_diff(package_path, baseline_report_path)` — after fixes, see what `fixed` / `still_open` / `new`.
- `gate(report_path, fail_on)` — does it pass at a severity threshold?
- `get_checklist()` — the 11 vulnerability classes the kit considers (a few are mechanically enforced by the static tier; the rest are walked by the LLM, not deterministically verified).

If the MCP server isn't available, run the CLI: `./audit.sh <package>`, then read the
`audit-reports/<...>.json` it writes. (No toolchain needed — the compile pre-flight is
off by default; `--compile-check` opts in for trusted code.)

## Workflow

1. **Audit.** Run `audit_package` on the target. Summarize findings by severity.
2. **Triage with the user.** For each Critical/High, call `show_finding_source` and confirm the citation is real. Set aside false positives with a reason.
3. **Fix one finding at a time.** Propose a minimal, focused edit; explain what it changes and why; get the user's OK before editing audit-grade code. Never batch unrelated fixes.
4. **Re-verify.** After a batch, run `reaudit_diff(package_path, <baseline report.json>)` and report `fixed / still_open / new`. A fix that introduces a *new* finding isn't done.
5. **Repeat** until `gate(report, "high")` passes. Then tell the user plainly where they stand: this is a pre-audit, not a substitute for a human audit (e.g. Hacken).

## Rules

- Never tell the user their code is "safe" — state what was checked and what's residual.
- Always verify a finding's `file:line` before changing code.
- Keep fixes minimal and reviewed; the user owns audit-grade changes.
- Surface open questions and residual risk; don't bury them.
