# Posture scanner

Read-only checks, run by hand, against **live Radix mainnet entities** — a different surface from
the rest of scrypto-audit-kit (source in, report out, no chain access). Full design, the severity
rationale behind each check, and the embargo policy: [docs/posture-scanner.md](../docs/posture-scanner.md).

```bash
# From the repo root:
python3 -m scanner.cli scan                              # writes results-full/<date>.json (full) + results/<date>.json (gated)
python3 -m scanner.cli diff OLD.json NEW.json             # "what changed since last scan"
python3 -m scanner.site --sync                            # re-render latest.{json,md} + docs/index.html from the newest scan
python3 -m unittest discover -s tests -t . -p 'test_scanner_*.py'
```

## Layout

| Path | What |
|---|---|
| `gateway.py` | Radix Gateway client (pinned reads, halt detection) — see its docstring for why this shells out to `curl` |
| `cohort.py` + `data/cohort.json` | the list of entities a scan covers (public: the operator's own entities only), and its strict loader |
| `data/cohort-full.json` | optional, gitignored, never committed — an operator's own local cohort covering external projects too; `scan` reads this instead when it exists (see `cli.py`'s `DEFAULT_FULL_COHORT_PATH`) |
| `shapes.py` | shared readers over one Gateway response item (metadata, role assignments) |
| `models.py` | the status/severity contract every check must honor, the embargo helpers, and the shared `is_public` predicate + held-placeholder text both renderers use |
| `checks/` | the five posture checks, one module each |
| `report.py` | orchestrates one scan: cohort → pin → fetch → run checks → assemble; also `render_markdown` |
| `diff.py` | compares two report files |
| `cli.py` | `scan` / `render` / `diff` subcommands |
| `site.py` | renders the public HTML page, and holds `redact_for_publication` — the one gate all three published artefacts pass through (see docs/posture-scanner.md#publication-gate) |
| `results/` | **published** scan output, gated for publication, one file per run date — safe to serve raw from GitHub |
| `results-full/` | full-detail scan output (gitignored, never committed) — what `results/` is redacted *from* |

No check ever hits the network in a test — every one is exercised against fixture JSON captured
from real pinned Gateway reads, with third-party identifiers replaced by synthetic ones (`examples/posture-scanner/`).
