# scrypto-audit-kit

Pre-audit harness for [Scrypto](https://docs.radixdlt.com/docs/scrypto-1) blueprints on the Radix network. Runs an LLM-driven static analysis against a curated checklist + reference patterns, and produces a markdown findings report that you can hand to a human auditor (or use to fix issues yourself).

This is a **pre-audit** tool, not an audit. It catches the kinds of issues a careful reviewer would catch on a first read so that paid auditors can spend their time on the harder, second-read findings. **It does not replace a human audit before mainnet deployment.**

## What it does

For each scrypto package you point it at, the kit:

1. Loads the package's source (Cargo.toml + everything under `src/` and `tests/`) into an [aider](https://aider.chat) session.
2. Loads a vulnerability **checklist** (11 classes — auth, reentrancy, decimal, resource handling, time, state machine, external calls, upgrade, oracle, slippage, allowances) and a catalogue of **reference patterns** (Ignition, CaviarNine HyperStake, subintents, a strategy-vault threat model, general scrypto knowledge) as read-only context.
3. Asks Claude Sonnet 4.6 to produce a structured findings report — summary, findings (Critical → Info), checklist coverage walk, pattern conformance check, test-coverage gaps, open questions for the human auditor.
4. Writes the report to `audit-reports/<repo>-<package>-<date>.md`.

The kit is **read-only by design**. It produces reports; it does not edit your blueprint. Edits to audit-grade code must go through a separate, human-supervised session.

## Quickstart

### Requirements

- [aider](https://aider.chat) (`pip install aider-chat` — version 0.86 or newer)
- An Anthropic API key (the kit defaults to Claude Sonnet 4.6 — get one at <https://console.anthropic.com>)
- bash, awk, find (standard on macOS / Linux)

The key can be provided in any of three ways:

```bash
# 1. Export in your shell (preferred for CI)
export ANTHROPIC_API_KEY=sk-ant-...

# 2. Point AIDER_ENV_FILE at an existing env file
AIDER_ENV_FILE=~/some/.env ./audit.sh /path/to/package

# 3. Drop a .env file (gitignored) in the kit directory
echo "ANTHROPIC_API_KEY=sk-ant-..." > .env
```

Verify with:

```bash
make check-deps
```

### Run an audit

```bash
git clone https://github.com/bigdevxrd/scrypto-audit-kit
cd scrypto-audit-kit
chmod +x audit.sh

./audit.sh /path/to/your/scrypto/package
# or:
make audit TARGET=/path/to/your/scrypto/package
```

The target must be a scrypto package directory (has a `Cargo.toml` and a `src/lib.rs`). The kit will read everything under `src/` and `tests/`.

The report lands in `audit-reports/<repo>-<package>-<YYYY-MM-DD>.md`. Reports are gitignored — share them by other means, don't commit them.

### Example

```bash
./audit.sh ~/scrypto/my-vault
[pre-flight] cargo check (release wasm)...
[pre-flight] compile OK

==> scrypto-audit-kit
    target:    scrypto / my-vault
    path:      /home/me/scrypto/my-vault
    model:     claude
    sources:   3 files
    refs:      6 files (read-only)
    report ->  audit-reports/scrypto-my-vault-2026-05-11.md

[aider runs ...]

==> done. report: audit-reports/scrypto-my-vault-2026-05-11.md
```

> Note: the harness runs `cargo check --release --target wasm32-unknown-unknown`
> first and bails if the package doesn't compile — no point spending model time
> on broken code. Install the wasm target with `rustup target add wasm32-unknown-unknown`.

### Choosing a model

The default is Claude Sonnet 4.6. A `--model` flag selects the analysis model:

```bash
./audit.sh --model claude   <path>   # default — Sonnet 4.6, best pattern depth
./audit.sh --model deepseek <path>   # cheaper broad scan (needs DEEPSEEK_API_KEY)
./audit.sh --model both     <path>   # DeepSeek broad pass, then Claude deep pass,
                                     # with a cross-model confidence summary
```

`both` runs DeepSeek first for a wide net, feeds its findings to Claude as
context, and tags findings both models agree on as HIGH confidence. Use it when
you want a second opinion on a high-stakes blueprint.

## What's in the kit

```
scrypto-audit-kit/
├── audit.sh              The harness — wraps aider with the right flags + context.
├── Makefile              Convenience targets (audit, lint, check-deps).
├── .aider.conf.yml       Tuned config: model=Sonnet 4.6, no editor, no commits, prompt cache on.
├── .aiderignore          Aider no-fly zones (build artifacts, secrets, prior reports).
├── prompts/
│   ├── audit.md          The system-style prompt that frames the auditor role + report structure.
│   └── checklist.md      Eleven vulnerability classes with concrete questions per class.
├── references/           Read-only context — production patterns + threat models.
│   ├── README.md         Curator notes and update procedure.
│   ├── ignition-patterns.md
│   ├── caviarnine-hyperstake-patterns.md
│   ├── subintents-patterns.md
│   ├── strategy-vault-threat-model.md
│   └── radix-scrypto-knowledge.md
├── audit-reports/        Output dir, gitignored.
└── examples/             Worked examples (sample reports, usage recipes).
```

## Limitations — read this before relying on the output

The kit is honest about what it is. Things it explicitly does **not** do:

- **It is not a formal verifier.** No theorem proving, no symbolic execution, no fuzzing. Findings are derived from pattern matching against a checklist by an LLM.
- **It does not run `cargo build` or `cargo test`.** Compilation issues, dependency vulnerabilities, and test failures are not in scope. Run those separately.
- **It does not catch novel attack classes.** It will surface known footguns reliably and propose novel concerns as low-confidence open questions. Novel-attack discovery is the human auditor's job.
- **The LLM can hallucinate file:line citations.** Every finding cites a location; you must verify those citations before acting on them. The audit prompt explicitly instructs the model to cite, but verification is on the reader.
- **It is not a deployment gate.** Do not block deploys on a clean report. The kit is an aid, not approval.

If any of these limitations matter for your use case, do not use this kit as a substitute for a paid audit.

## Cost

With the default config (Sonnet 4.6, prompt caching on, references cached across runs):

- First audit of a session: ~50k input tokens (references) + 5–20k input tokens (target source) + ~5–15k output tokens → roughly $0.20–$0.40 per run.
- Subsequent audits in the same prompt-cache window: cached references reduce cost ~70% → roughly $0.10 per run.

These figures are estimates as of 2026. Check current [Anthropic pricing](https://www.anthropic.com/pricing) for accurate numbers. The kit deliberately does *not* use the architect/editor split (which would add a second model call) because we want analysis, not code edits.

## Contributing

This kit is community-maintained and gets stronger with more eyes on it. The most valuable contributions:

- **New vulnerability classes for the checklist.** Real-world Scrypto exploits or footguns we haven't catalogued yet.
- **New reference patterns.** Open-source Radix blueprints with patterns worth catalogue-ing — adapter scaffolds, role hierarchies, panic modes, etc.
- **Trial reports.** Run the kit against a public blueprint and share what it found (or missed). Negative results are valuable.
- **Harness fixes.** False-positive patterns, brittle parsing, missing edge cases in `audit.sh`.

See [CONTRIBUTING.md](CONTRIBUTING.md) for the workflow.

## License

[Apache 2.0](LICENSE) — the same license most of the upstream Radix ecosystem uses. Forks, derivatives, and commercial use all welcome; attribution preserved per the license.

## Related

- [Radix Scrypto docs](https://docs.radixdlt.com/docs/scrypto-1)
- [radixdlt/Ignition](https://github.com/radixdlt/Ignition) — the canonical Radix-team-maintained reference codebase (most of our `references/ignition-patterns.md` extracts from here)
- [caviarnine/caviarnine-scrypto](https://github.com/caviarnine/caviarnine-scrypto) — Apache-licensed CaviarNine production blueprints
- [aider](https://aider.chat) — the LLM coding agent this kit wraps
