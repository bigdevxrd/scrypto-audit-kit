# vulnerable-vault (planted-bug fixture)

⚠️ **This package is deliberately vulnerable. Do not deploy, copy, or learn patterns from it.**

It's a toy yield vault wired with one planted issue per major checklist class, used as:

1. a **worked example** — run the kit against it to see real output, and
2. a **regression fixture** — the kit should keep catching these as the checklist evolves.

```bash
./audit.sh examples/vulnerable-vault
```

The expected output is committed alongside it:

- [`../vulnerable-vault.pre-audit.md`](../vulnerable-vault.pre-audit.md) — the human report
- [`../vulnerable-vault.pre-audit.json`](../vulnerable-vault.pre-audit.json) — the machine-readable form ([schema](../../schema/audit-report.schema.json))

Because the bugs are planted, every `file:line` citation in that report is exact — a good way to see what "verify the citation" looks like in practice.
