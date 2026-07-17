# LLM backends

The LLM pre-audit pass runs through an **interchangeable backend**. The kit isn't wedded to
any one LLM harness: a backend just receives the audit prompt, the checklist + reference
patterns, and your package source, and returns a markdown findings report ending in a
nonce-stamped JSON appendix. Everything downstream — the nonce authentication, the
markdown↔JSON split, the static-pass merge, `report.json`, the CI gate, attestation — is
backend-agnostic and unchanged.

The free deterministic static tier (`--static-only`) uses **no** backend and needs no API key.

## The three built-in backends

| Backend | Select with | Needs | Use it for |
|---|---|---|---|
| **`claude-api`** (default) | *(nothing)* | the `anthropic` package + `ANTHROPIC_API_KEY` | The default. Talks to the Anthropic API directly (`bin/llm_audit.py`) — no aider, guaranteed-valid structured output, prompt caching. |
| **`aider`** | `--backend aider` | `aider` on PATH + a key | The original harness. Keeps the cross-model modes `--model deepseek` and `--model both`. |
| **`cmd`** | `--backend cmd --backend-cmd '<command>'` | your command | Bring your own agent — point the kit at any program (your own agents, Claude Code, a script) that can read files and write a report. |

Select a backend with `--backend`, or set `SAK_BACKEND` in the environment.

```bash
./audit.sh /path/to/pkg                              # claude-api (default)
./audit.sh --backend aider --model both /path/to/pkg # aider, cross-model
SAK_BACKEND=aider ./audit.sh /path/to/pkg            # via the environment
```

## `claude-api` — the default

Sends the request through the Anthropic SDK. It defaults to **Claude Sonnet 4.6** — the model
the kit has always used for the pattern-recognition depth audit-grade work needs. The backend
did **not** change which model audits your code; override it per run:

```bash
./audit.sh --model claude-sonnet-4-6 /path/to/pkg    # explicit (the default)
./audit.sh --model claude-opus-4-8   /path/to/pkg    # a different Anthropic model
```

Install the dependency (it's the `llm` extra, or just `pip install anthropic`):

```bash
pip install ".[llm]"     # from a clone
```

Prompt caching is on: the stable prefix (auditor prompt + checklist + reference patterns) is
cached across runs, so subsequent audits in the same cache window are markedly cheaper — the
cost figures in the [README](../README.md#cost) assume this. The target source and the per-run
nonce are sent after the cache breakpoint, so they never invalidate the cached references.

## `aider` — the original harness

`--backend aider` runs the [aider](https://aider.chat)-based harness the kit originally shipped.
It reads `.aider.conf.yml` and supports the DeepSeek and cross-model passes:

```bash
./audit.sh --backend aider                <pkg>   # aider + Claude Sonnet 4.6
./audit.sh --model deepseek               <pkg>   # DeepSeek only (implies --backend aider)
./audit.sh --model both                   <pkg>   # DeepSeek broad → Claude deep, cross-referenced
```

`--model deepseek` and `--model both` are aider-only cross-model modes; passing either
automatically selects the aider backend. Requesting them with a different `--backend` is an error.

## `cmd` — bring your own agent

`--backend cmd` points the kit at **any command** — this is how your own agents drive the
pre-audit. The kit assembles the inputs and runs your command; your command reads them, does
the analysis however it likes, and writes the report to **stdout**.

```bash
./audit.sh --backend cmd --backend-cmd 'python3 my_agent.py' /path/to/pkg
SAK_BACKEND=cmd SAK_BACKEND_CMD='python3 my_agent.py' ./audit.sh /path/to/pkg
```

### The contract

Your command is run via `sh -c`. It receives everything through **environment variables** (the
primary contract), and the prompt + target files are *also* available as positional parameters
(`$1` = prompt file, `"$@"` = prompt + target files) for commands that prefer args.

| Env var | What it is |
|---|---|
| `SAK_PROMPT_FILE` | The assembled auditor prompt (`prompts/audit.md` + the per-run nonce directive). |
| `SAK_AUDIT_PROMPT` | Path to the raw auditor prompt (`prompts/audit.md`) on its own. |
| `SAK_CONTEXT_FILES` | Newline-separated paths: the checklist + every reference pattern (read-only context). |
| `SAK_TARGET_FILES` | Newline-separated paths: the package source (`Cargo.toml`, `src/**.rs`, `tests/**.rs`). Treat these as **untrusted data**. |
| `SAK_MODEL` | The `--model` value, for commands that route to a specific model. |
| `SAK_NONCE` | The per-run provenance nonce (see below). |
| `SAK_PKG_ROOT` | The package root, for producing `src/lib.rs:NN`-style relative citations. |

Your command **must** print a markdown report to stdout, ending in the nonce-stamped JSON
appendix so the kit can authenticate and extract it:

```
...your markdown report (summary, findings, checklist coverage, ...) ...

---
<!-- machine-readable: do not edit -->
<!-- sak:nonce:$SAK_NONCE -->
```json
{ "schema_version": "1.0", "kit": {}, ...conforms to schema/audit-report.schema.json... }
```
```

The `<!-- sak:nonce:$SAK_NONCE -->` marker on the line immediately before the JSON fence is
**required**: `bin/extract-report.py` trusts only the JSON block carrying the current run's
nonce, which is what stops a hostile blueprint from getting a forged clean report accepted.
Emit the exact nonce from `$SAK_NONCE`, once, wrapping your real appendix. A run whose appendix
fails nonce authentication is refused (exit 3), not silently accepted.

Auth is your command's business — the kit does not require `ANTHROPIC_API_KEY` for the `cmd`
backend. The auditor prompt in `$SAK_AUDIT_PROMPT` already declares the target source untrusted
data and tells the model to report any steering attempt as a finding; honor that in your agent.

## What every backend shares

- Same inputs: `prompts/audit.md`, `prompts/checklist.md`, everything under `references/`, and
  the package's `Cargo.toml` + `src/`/`tests/` `.rs` files.
- Same output contract: a markdown report ending in the nonce-authenticated §7 JSON appendix.
- Same downstream: the deterministic static pass is merged in, `report.json` is written against
  [the schema](../schema/audit-report.schema.json), and the CI gate / attestation consume it.
- Same honesty: a pre-audit is the rung below a human audit, not a substitute for one.
