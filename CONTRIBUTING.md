# Contributing to scrypto-audit-kit

Thanks for your interest. This kit gets stronger as more people run it against more blueprints and report what worked / didn't. Here's how to help.

## What's most useful

In rough order of impact:

### 1. Trial reports against public blueprints

Run the kit against an open-source Radix blueprint, share the report and your assessment. We're especially interested in:

- **False positives** — findings the kit raised that aren't real issues. Helps us tighten the checklist.
- **False negatives** — known bugs in audited blueprints that the kit missed. Helps us add new checklist entries.
- **Citation failures** — findings where the kit cited a non-existent line. Helps us tune the prompt.

Open an issue with the report attached and the reference blueprint linked.

### 2. New checklist entries

Found a Scrypto footgun the checklist doesn't cover? Submit a PR to `prompts/checklist.md`. A good entry:

- Names the class clearly
- Lists 3–6 concrete questions an auditor should ask
- Cites a real-world incident (forum post, postmortem, audit report) if you have one
- Doesn't overlap heavily with existing classes (consolidate if it does)

### 3. New reference patterns

Open-source Radix blueprint with a pattern worth catalogue-ing? Submit a PR to `references/`. Each reference file should:

- Have a public-safe header (source repo, license, snapshot date, curator)
- Cite specific file paths and line ranges in the source repo so readers can verify
- Be self-contained — don't assume readers will follow links
- Use Apache-2.0, MIT, or similarly permissive licensed source — we don't redistribute proprietary content

### 4. Harness improvements

Bug fixes, edge cases, better error messages, support for non-standard package layouts. Standard PR flow.

## Workflow

```bash
# Fork on GitHub, then:
git clone git@github.com:<you>/scrypto-audit-kit
cd scrypto-audit-kit
git checkout -b feat/your-change

# Make changes. Run linters:
make lint

# Verify the harness still runs against at least one trial blueprint:
./audit.sh /path/to/some/scrypto/package

# Push + open a PR.
```

## Code standards

- **`audit.sh`**: `set -euo pipefail` at the top, every variable quoted, `shellcheck` clean. Comment any non-obvious flag.
- **Prompts (`prompts/*.md`)**: every change should improve at least one trial report. Include a before/after report excerpt in the PR description.
- **References (`references/*.md`)**: keep each file under 500 lines if possible. If a reference is growing past that, split it.
- **README / docs**: GitHub-flavoured markdown, no emoji except where they're load-bearing (e.g. status legends).

## Review process

PRs land via squash-merge after one maintainer approval. Trial-report and false-positive PRs are merged faster (no review cost — just data). Prompt and reference changes get more scrutiny because they affect every future audit run.

For contentious changes (e.g. fundamental restructuring of the checklist), open an issue first to discuss before opening a PR.

## What we won't merge

- **Auto-edit features.** This kit is deliberately read-only. Any patch that lets aider edit blueprint source under audit is out of scope. If you want LLM-driven scrypto editing, that's a different tool.
- **Closed-source dependencies.** Everything in this kit must work with no proprietary inputs.
- **Findings padding.** Prompt changes that make the model raise more findings to look thorough are anti-productive. We optimise for *signal*, not finding count.

## Conduct

See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## Questions

Open a [GitHub Discussion](https://github.com/bigdevxrd/scrypto-audit-kit/discussions) (once the repo has them enabled) or file an issue with the `question` label.
