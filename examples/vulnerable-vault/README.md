# vulnerable-vault (planted-bug fixture)

⚠️ **This package is deliberately vulnerable. Do not deploy, copy, or learn patterns from it.**

It's a toy yield vault wired with one planted issue per major checklist class, used as:

1. a **worked example** — run the kit against it to see real output, and
2. a **regression fixture** — the kit should keep catching these as the checklist evolves.

```bash
./audit.sh --static-only examples/vulnerable-vault   # free, no API key (deterministic rules)
./audit.sh examples/vulnerable-vault                 # full hybrid run (static + LLM)
```

The committed report shows the LLM pass:

- [`../vulnerable-vault.pre-audit.md`](../vulnerable-vault.pre-audit.md) — the human report
- [`../vulnerable-vault.pre-audit.json`](../vulnerable-vault.pre-audit.json) — the machine-readable form ([schema](../../schema/audit-report.schema.json))

A full run also appends a deterministic **Static analysis** section (the `S-###` findings — `take_all()`, no-owner globalize, self-rotating role). Because the bugs are planted, every `file:line` citation is exact — a good way to see what "verify the citation" looks like in practice.
