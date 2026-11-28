# Configuration

Every environment variable the kit's source reads, where it is read, and whether it is a
secret. Swept on 2026-11-28 over the non-test source: `audit.sh`, `bin/*.py`, `scanner/`,
`attestation/src/` and `.github/leak-gate.mjs` (searches for `os.environ`, `os.getenv`,
`std::env`, `env::var`, `process.env` and shell `${NAME}` reads). Tests, examples and
reference docs were left out.

Result: **8 names** read by the kit itself, **10 names** read by the CI leak gate, and none by
the Rust attestation crate. Command-line flags win over the environment wherever both exist.

## The kit

| Name | Read in | Secret | What it does | Default |
|---|---|---|---|---|
| `ANTHROPIC_API_KEY` | `audit.sh:130-146`; `bin/llm_audit.py:283` (through the Anthropic SDK) | **yes** | API key for the `claude-api` and `aider` backends. Not needed for `--static-only` or the `cmd` backend. Never echoed | none: the LLM pass refuses to start without it |
| `AIDER_ENV_FILE` | `audit.sh:131-134` | no (the file it names holds secrets) | Path to an env file that `audit.sh` sources when `ANTHROPIC_API_KEY` is not already set | unset; then a `.env` in the kit directory is tried |
| `SAK_BACKEND` | `audit.sh:87-89` | no | LLM backend: `claude-api`, `aider` or `cmd` ([backends.md](backends.md)). `--backend` wins | `claude-api` |
| `SAK_BACKEND_CMD` | `audit.sh:101-103` | no | The command the `cmd` backend runs. `--backend-cmd` wins | none: required for `--backend cmd` |
| `SAK_MODEL` | `bin/llm_audit.py:362` | no | Anthropic model id, read only when `bin/llm_audit.py` is run on its own. `audit.sh` always passes `--model` (`audit.sh:345-350`), so with `audit.sh` set the model with `./audit.sh --model`. (`audit.sh` also sets `SAK_MODEL` for the `cmd` backend; see below.) | `DEFAULT_MODEL` in `bin/llm_audit.py` |
| `SAK_MAX_TOKENS` | `bin/llm_audit.py:370` | no | Output token cap for the `claude-api` backend. Must be an integer | `DEFAULT_MAX_TOKENS` in `bin/llm_audit.py` |
| `SAK_HOME` | `bin/mcp_server.py:40`; `bin/dapp_scope.py:63` | no | Path to a kit clone (a folder with `audit.sh`), so a pip-installed MCP server or `sak-dapp-scope` can find the kit's resources | the folder found by walking up from the installed file |
| `TMPDIR` | `audit.sh:294,440` | no | Where `audit.sh` writes its temporary prompt files | `/tmp` |

### Names the kit sets or removes, but does not read

- `SAK_MODEL`, `SAK_NONCE`, `SAK_PROMPT_FILE`, `SAK_AUDIT_PROMPT`, `SAK_CONTEXT_FILES`,
  `SAK_TARGET_FILES`, `SAK_PKG_ROOT`: set by `audit.sh` for the command the `cmd` backend
  runs (`audit.sh:375-400`). The contract is in [backends.md](backends.md).
- `ANTHROPIC_API_KEY` and `DEEPSEEK_API_KEY`: removed from the environment of the compile
  check, so a target's build scripts cannot read them (`audit.sh:207`). `DEEPSEEK_API_KEY` is
  read by aider for `--model deepseek|both`, not by the kit.

Third-party tools the kit runs (the Anthropic SDK, aider, cargo) read their own documented
variables as well. They are not listed here.

## CI only: the leak gate

`.github/leak-gate.mjs` runs in the `leak gate` workflow. See
[`.github/LEAK-GATE.md`](../.github/LEAK-GATE.md) for how to run it locally.

| Name | Secret | What it does |
|---|---|---|
| `PII_BLOCKLIST_JSON` | **yes** | The private blocklist, as JSON. Supplied as a repository secret |
| `PII_BLOCKLIST_LOCAL_PATH` | no (the file it names is private) | Path to a local blocklist file, used when `PII_BLOCKLIST_JSON` is unset |
| `LEAK_GATE_AUDIT_ALLOW` | no | Regular expression of audit-shaped paths that are allowed |
| `LEAK_GATE_BASE` | no | Base ref to compare against (default: `origin/$GITHUB_BASE_REF`, else the push event's `before`, else `origin/main`; `leak-gate.mjs:170`) |
| `LEAK_GATE_HEAD` | no | Head ref to check (default `HEAD`) |
| `LEAK_GATE_BRANCH` | no | An extra branch name to check, read on every run with GitHub's refs; meant for local runs, where those are unset |
| `GITHUB_EVENT_PATH` | no | Set by GitHub Actions: the event payload |
| `GITHUB_REF` | no | Set by GitHub Actions |
| `GITHUB_HEAD_REF` | no | Set by GitHub Actions on pull requests |
| `GITHUB_BASE_REF` | no | Set by GitHub Actions on pull requests |

Sources: `.github/leak-gate.mjs:19,49-51,131,144,153,163-170`.
