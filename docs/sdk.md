# Python SDK — build on the kit

Pip-installing the kit gives you its **deterministic core** as an importable library and as
`sak-*` commands — this is what an agent developer builds on. The kit isn't on PyPI yet (a
release is planned), so install from a clone. The full LLM audit (`audit.sh`) needs the clone
+ aider + an API key, but everything below runs from the installed package with no key and no
toolchain.

```bash
git clone https://github.com/bigdevxrd/scrypto-audit-kit && cd scrypto-audit-kit
pip install .            # core (stdlib only, zero deps)
pip install ".[mcp]"     # + the MCP server
pip install ".[schema]"  # + jsonschema validation
```

```python
import scrypto_audit_kit as sak
print(sak.__version__)
from scrypto_audit_kit import static_analysis, sak_lib, attest, gen_tests
```

(Running from a clone without installing? Every [example agent](../examples/agents/) falls back
to `../../bin` automatically — the same import shim works in your own scripts.)

## What runs where

| Capability | Module / function | Needs a key? | Needs a clone? |
|---|---|---|---|
| Static analysis | `static_analysis.analyze_package` | no | no |
| Severity gate, diff, merge | `sak_lib` | no | no |
| Test-scaffold generation | `gen_tests.propose_tests` | no | no |
| Attestation payload + manifest | `attest.build_payload` / `render_manifest` | no | no |
| The cheap MCP tools | `mcp_server.*` | no | no |
| Full LLM pre-audit | `mcp_server.audit_package` / `audit.sh` | **yes** | **yes** |
| The checklist text | `mcp_server.get_checklist` | no | clone or `SAK_HOME` |

> The LLM-backed tools shell out to `audit.sh`. Run them from a clone, or set `SAK_HOME` to a
> clone so the installed server can find the harness + prompts.

## The deterministic core

### static_analysis — the free rules

```python
from scrypto_audit_kit import static_analysis, sak_lib

findings = static_analysis.analyze_package("path/to/package")   # schema-shaped findings
print(sak_lib.severity_counts(findings))                        # {'medium': 5}
for f in findings:
    print(f["id"], f["severity"], f["location"], "—", f["title"])
```

`analyze_package(pkg_dir)` walks `<pkg>/src/**.rs`, runs the [12 rules](static-analysis.md)
over a comment/string-aware view, and returns findings with `S-###` ids and `source:"static"`.
Lower-level: `analyze_text(rel_path, src)` (one file) and
`strip_comments_and_strings(src, keep_strings=False, keep_comments=False)`.

### sak_lib — reports, gates, diffs

Pure, stdlib-only helpers over a report dict (or a findings list):

```python
from scrypto_audit_kit import sak_lib

report  = sak_lib.build_report(findings)                # assemble a schema-shaped report
verdict = sak_lib.gate_verdict(report, fail_on="high")  # {passed, worst, counts, total, fail_on}

base = sak_lib.load_report("baseline.json")
cur  = sak_lib.load_report("after-fix.json")
diff = sak_lib.diff_reports(base, cur)                  # {fixed, still_open, new}

span = sak_lib.read_source_span("path/to/package", "src/lib.rs:42")   # verify a citation
```

Also `filter_findings`, `counts_summary`, `worst_severity`, `finding_signature`,
`merge_findings`, `find_reports`, `newest_report`, `render_findings_md`. Severities rank
`info < low < medium < high < critical`; an unknown or blank severity is treated as *above*
critical, so it can never silently slip a gate.

### gen_tests — property-test scaffolds

```python
from pathlib import Path
from scrypto_audit_kit import gen_tests

out = gen_tests.propose_tests("path/to/package")
print(out["count"], "scaffolds for", out["blueprint"])
Path("tests/generated.rs").write_text(out["rust"])      # compilable, #[ignore]d
```

Reads the blueprint's `enable_method_auth!` surface and vault fields, then proposes auth
negative-path, happy-path, and value-conservation scaffolds. The kit never writes them into
your package — you do, then remove the `#[ignore]` and fill in each `todo!()`.

### attest — the on-chain bridge

```python
from scrypto_audit_kit import attest

payload  = attest.build_payload("report.json")          # source/report/wasm hashes + counts + level
manifest = attest.render_manifest(payload, component="component_rdx1...", account="account_rdx1...")
```

`build_payload` computes the hashes, severity counts, and derived level; `render_manifest`
renders the Radix transaction manifest that records the attestation. See
[the attestation blueprint](../attestation/).

## The 9 tools, in-process

The MCP tool functions are plain Python — call them directly, no server needed:

```python
from scrypto_audit_kit import mcp_server as tools

tools.static_scan("path/to/package")                 # {count, counts, findings}
tools.gate("report.json", fail_on="high")            # {passed, worst, ...}
tools.show_finding_source("report.json", "S-001", "path/to/package")
tools.attestation_payload("report.json")             # {payload, manifest?}
tools.audit_package("path/to/package")               # full hybrid run — needs a key + clone
```

Formal input/output contracts: [schema/mcp-tools.schema.json](../schema/mcp-tools.schema.json),
documented in [mcp-tools.md](mcp-tools.md). The same functions are served over MCP by
`bin/mcp_server.py`, so an agent can call them in-process *or* over the protocol — identical
shapes.

## Console scripts

`pip install` puts these on your `PATH`:

| Command | Wraps | Does |
|---|---|---|
| `sak-static <pkg>` | `static_analysis` | print static findings as JSON |
| `sak-gate --reports <path> --fail-on high` | `ci_gate` | exit non-zero past a threshold (CI) |
| `sak-gen-tests <pkg>` | `gen_tests` | print the test scaffolds |
| `sak-attest <report.json>` | `attest` | print the payload / manifest |
| `sak-mcp` | `mcp_server` | run the MCP server (stdio) |

## Worked examples

[`examples/agents/`](../examples/agents/) has three runnable programs — a free-tier CI gate, the
full audit → fix → verify loop, and an MCP client — each working against the bundled fixture.
Start from the one closest to what you're building.

> Whatever you build, keep the kit's contract with the user: report what was checked and what's
> residual; never decide their code is safe.
