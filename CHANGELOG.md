# Changelog

Notable changes to scrypto-audit-kit. The kit version lives in [VERSION](VERSION) and is
stamped into every report; this log follows [Keep a Changelog](https://keepachangelog.com) and
[SemVer](https://semver.org). The kit was built in a compressed timeline — dates reflect that.

## [0.8.0] — 2026-08-15 — honest claims, and the rest of the CI hole

v0.7.0 closed argument injection in the reusable workflow. A post-release adversarial sweep found
the **same bug class still open one step later in the same file**, plus an analyzer that failed
open, a distribution that could not test itself, and an attestation that claimed a trust level it
could not justify. **`v0.8.0` supersedes `v0.7.0` as the floor for CI callers.**

**A minor, not a patch.** This log claims SemVer, and the release breaks published surfaces:
`attest.build_payload()` returns `mode` + `static_ruleset_version` instead of `level`, the
`--level` flag and the `attestation_payload` MCP tool's `level` parameter are gone, and
`import scrypto_audit_kit` no longer mutates `sys.path`. For a kit whose whole pitch is never
overclaiming, the version number is part of the claim — shipping this as `0.7.1` would have been
the same category of error as the attestation level it fixes.

### Fixed

- **Attestations recorded a trust level they could not justify — now they record facts**
  ([bin/attest.py](bin/attest.py), [attestation/src/lib.rs](attestation/src/lib.rs),
  [docs/attestation-levels.md](docs/attestation-levels.md)) — **high, and a breaking change to
  the attestation payload and the blueprint.** The `level` field conflated two different axes.
  [VISION.md](VISION.md) defines L1/L2/L3 by *who witnessed a run* (L2 = attested CI run);
  `attest.py` emitted `L1-static`/`L2-hybrid` by *which tiers ran*. So a laptop run stamped
  `L2-hybrid`, and a reader who learned the ladder from our own docs read that as an attested
  CI run. Three consequences, all now closed:
  - **It failed upward.** The level came from parsing the free-text `kit.model` for the substring
    `static-only`, returning the *higher* claim on anything else — so an absent, unknown, or
    user-supplied model asserted that the LLM checklist pass had run. `--no-static` (no
    deterministic tier at all) also derived "hybrid".
  - **The level was forgeable and self-referential.** `--level` passed any string straight
    through to the chain, and `attest()` never validated it. `"L3-attested"` as an *input* is
    circular — L3 *is* the record existing. The test asserting that override worked was a
    regression test **for** the forgery path; it is now a test that no level field exists.
  - **The documented pip-only path produced an unattestable payload.** `sak_lib.build_report`
    emitted `kit: {}, target: {}` — schema-*invalid*, with an empty `source_hash` — which
    [docs/sdk.md](docs/sdk.md) presented as the finished product.

  Now: the payload carries **`mode`** (`static` | `llm` | `hybrid`) plus `static_ruleset_version`,
  derived only from the new `kit.tiers` fact and requiring positive evidence to climb — absent
  tiers derive the *lowest* claim. `mode` is enum-checked on-chain so garbage is unrepresentable,
  and `level` is gone from `AttestationInput`, `AttestationData` and the event. The L1/L2/L3 rung
  is computed by the reader from mode + attester identity + `issuer_verified`, under a published,
  versioned rule ([docs/attestation-levels.md](docs/attestation-levels.md)). This is the split
  [SLSA](https://slsa.dev) makes for the same reason: a producer asserting its own trust level is
  worth nothing.

  `build_payload` now **refuses** — raising `attest.AttestationError` — on a missing `source_hash`
  or `kit.version`, instead of emitting a payload the chain rejects *after* `lock_fee`. The
  artifact is permanent and unburnable; an over-claim is not a bad log line, it is an immutable
  one. `sak_lib.build_report(findings, pkg_dir)` stamps real provenance so the pip path produces
  something attestable, and `sak_lib.source_hash()` gives the SDK the anchor computation that
  previously existed only in shell — pinned byte-for-byte against `audit.sh` by a parity test.

  **The blueprint change is free only until first deploy.** The registry has never been deployed,
  so no on-chain record is invalidated. This window closes permanently at the first Stokenet
  deploy, which is why it is being taken now.
- **Code execution in the pre-audit job, one step before your API key enters it**
  ([.github/workflows/pre-audit.yml](.github/workflows/pre-audit.yml)) — **critical**. The
  backend-install step ran `python3 -c 'import anthropic'` with the *audited* repository as its
  working directory. CPython puts the cwd on `sys.path` for `-c`, so a package under audit that
  ships its own `anthropic.py` got arbitrary execution in the caller's runner — and, because the
  payload satisfies the import, the guard *passed* while it ran. The next step is the one holding
  `ANTHROPIC_API_KEY`, and the payload can rewrite `audit.sh` or `$GITHUB_PATH` before it. Two
  independent fixes, either sufficient: the untrusted checkout now lands under `target/` so the
  workspace root is never attacker-owned, and the probe runs with `-P`. Secret theft needs the
  key present (so not fork PRs on public repos, but fully applies to private repos — the kit's
  core audience); **gate bypass applies to every caller**, since code execution before the gate
  step can neutralise the gate judging it. Both properties are pinned by tests.
- **`sak-static` reported a clean scan of packages it never opened** ([bin/static_analysis.py](bin/static_analysis.py))
  — **high**. `os.walk()` on a missing path yields nothing and raises nothing, so a typo'd,
  renamed, or wrong-cwd package path produced `{"count": 0}` and exit `0`. A build stayed green
  because the analyzer read *nothing*. It now fails closed on a missing directory and on a package
  with no `.rs` files, with `--allow-empty` as the explicit opt-out — matching `sak-gate`, which
  has always failed closed on a missing reports dir. The two entry points in one wheel no longer
  ship opposite safety defaults.
- **Importing the package no longer shadows the consumer's own modules**
  ([`bin/__init__.py`](bin/__init__.py), [#5](https://github.com/bigdevxrd/scrypto-audit-kit/issues/5))
  — **behaviour change, and the reason to upgrade if you build on the SDK.** `bin/__init__.py`
  did `sys.path.insert(0, <package dir>)` so the modules' bare cross-imports (`import sak_lib`)
  resolved when `bin/` was imported as `scrypto_audit_kit`. That insert was process-global and at
  index 0: any application importing the kit had `attest`, `sak_lib`, `static_analysis`,
  `gen_tests`, `llm_audit`, `mcp_server` and `ci_gate` silently redirected to ours for the rest of
  its run — including modules sitting in its own working directory. The cross-imports are now
  guarded (relative when we are a package, bare when a module runs directly as a script), so the
  bare-clone and direct-script paths still work with no global mutation. `import scrypto_audit_kit`
  is now side-effect free. The kit's own `examples/agents/mcp_client.py` did the same
  unconditional insert and was fixed alongside, so the shipped examples no longer teach the
  pattern.
- **The kit version no longer trusts a `VERSION` file it does not own** ([`bin/__init__.py`](bin/__init__.py)).
  Installed, the path it read resolves to `site-packages/VERSION` — anything dropping a file there
  would be reported as the kit's version, and that string is stamped into every report's
  provenance block. The file is now trusted only beside an `audit.sh` (a real clone or editable
  install); otherwise the installed metadata is authoritative.

- **`pip install "scrypto-audit-kit[mcp]"` was broken** ([pyproject.toml](pyproject.toml)) —
  **high**, and live in the published v0.7.0. The extra pinned `mcp[cli]>=1.0` with no upper
  bound, so pip now resolves **mcp 2.0.0**, which removed `mcp.server.fastmcp` — the module
  [bin/mcp_server.py](bin/mcp_server.py) imports. `sak-mcp` then exits with *"needs the MCP SDK:
  `pip install mcp[cli]`"*, which is exactly what the user had just run. Bounded to `<2`; lifting
  it requires porting the server to the 2.x entry point first.

### Security & supply chain

- **CI runs can now earn rung L2** ([.github/workflows/pre-audit.yml](.github/workflows/pre-audit.yml),
  [docs/ci.md](docs/ci.md)). New opt-in `sign-provenance` input has GitHub sign the report's
  provenance over OIDC, binding it to the workflow, repo and commit — so a reader verifies against
  GitHub's identity instead of the author's word (`gh attestation verify`). Until now L2 was
  *documented but unreachable*: everything the workflow did proved a report existed, never who
  produced it. Off by default (it writes an attestation against the caller's repo) and it runs
  only when the gate passed, since a signed statement for a report that failed its own threshold
  would attest to a run the caller already rejected.
- **Every third-party action is SHA-pinned**, with [Dependabot](.github/dependabot.yml) added in
  the same change to move the pins. A tag is mutable: `@v4` is whatever that tag points at today,
  inside a job holding an API key. Pinning without automated updates is how a pin that was a
  security control becomes the thing keeping a known-vulnerable version — the two halves only work
  together.
- **`deepseek` / `both` are rejected up front** rather than failing deep inside the audit. They
  need a `DEEPSEEK_API_KEY` this workflow never forwards, so they could not authenticate; they
  installed aider and then died with an auth error that read like a kit bug. Traced first: neither
  the `env:` block nor `audit.sh`'s `.env` fallback can supply that key here, so no path existed
  where they worked. The now-unreachable aider install step is gone.
- **PEP 740 attestations are documented** ([RELEASING.md](RELEASING.md)). Trusted Publishing has
  signed every upload since v0.5.0 — nobody was told, and an unverifiable signature helps nobody.
  "Install from PyPI" is only supply-chain advice if the artifact's origin can be checked.

### Packaging

- **CI tests the Python floor it advertises** ([.github/workflows/lint.yml](.github/workflows/lint.yml)).
  The suite ran on 3.12 only, which is precisely how the uninstallable `[mcp]`/`[dev]` extras
  shipped. Now a matrix of the floor (on `ubuntu-22.04`) and 3.12 — and it earned its keep on the
  first run, catching the item below.
- **`requires-python` is now `>=3.9`, was `>=3.8`** — a narrowing, and the honest resolution of a
  conflict the new matrix surfaced immediately. setuptools 75.3.4 is the last release supporting
  3.8, and PEP 639 license metadata needs `>=77`; the two cannot coexist, so the sdist could not
  build on the floor the project advertised. 3.8 has been end-of-life since 2024-10, and a floor
  the project cannot build on is a claim rather than a support commitment. Wheel installs were
  unaffected either way (`py3-none-any`); source builds and contributors were not.
- **PEP 639 license metadata.** The `license = { text = ... }` table is deprecated with a hard
  removal date of 2027-02-18 against a build backend floored at `>=64` — i.e. the build was going
  to break on a day nobody chose. Now `license = "Apache-2.0"` + `license-files`, backend floor
  raised to `>=77`.
- **The PyPI project page's links work.** All 29 relative links in the README resolved against
  pypi.org and 404'd; they are absolute now. Per-version Python classifiers added so the sidebar
  shows the real support surface.
- `audit_package`'s missing-harness error now names the `SAK_HOME` remedy, as `get_checklist`'s
  already did — an agent reading "audit.sh not found" cannot know the fix is an env var.

### Removed

Each of these was verified dead by re-deriving every reference across the tree and re-running the
suite, the analyzer, and a full `audit.sh --static-only` against the removal — analyzer output and
report are byte-identical, 211 tests green.

- **The `Add wasm target` step in the reusable CI workflow.** It installed a Rust target on every
  consumer run for a job that never compiles — `--compile-check` is opt-in and this workflow never
  passes it. It was also the job's only dependency on `rustup` existing on the runner image, so it
  was a latent failure liability for zero benefit.
- **Three unused `ctx` keys in the analyzer** (`rel_path`, `raw`, `raw_lines`,
  [bin/static_analysis.py](bin/static_analysis.py)). No rule reads them; `rel_path` reaches
  findings by a separate route.
- **A duplicated `--read` argument rebuild** in `audit.sh`'s `claude-api` backend — `READ_ARGS` is
  already built before dispatch and `READ_FILES` is never mutated in between. Verified by capturing
  the real argv on both sides: identical.
- **`weak-model` from [.aider.conf.yml](.aider.conf.yml)** — both configured models resolve their
  weak model to themselves, so the line never changed behaviour.

Deliberately **not** removed, having checked: `llm_audit.assemble_report()` (not dead —
not-yet-wired, and specified/tested/tracked), and the MCP `no_compile_check` parameter (inert, but
a published tool contract; its docstrings now say so).

### Changed

- **The sdist can build and test itself** (new [MANIFEST.in](MANIFEST.in)) — **high**. setuptools'
  distutils-era defaults shipped `bin/*.py` and `test*.py` and nothing else: no `tests/__init__.py`
  (so `unittest discover` could not even import the suite), no `schema/`, `prompts/`, or
  `examples/`. Unpacking the v0.7.0 sdist and running the project's own documented test command
  died immediately, and after that 27 tests failed on absent fixtures. Downstream packagers
  (conda-forge, Debian, Nix, corporate mirrors) build from the sdist by convention, and for a
  security tool it is also how someone verifies from source that the artifact matches the repo.
  The sdist now runs its full 224-test suite green.
- **The `[mcp]` and `[dev]` extras are installable on the Python version we claim to support**
  ([pyproject.toml](pyproject.toml)) — **high**. Every published `mcp` release requires 3.10+,
  but `requires-python` is `>=3.8` and the wheel is `py3-none-any`, so pip served it to 3.8/3.9
  users and then failed with an unresolvable `No matching distribution found for mcp[cli]`. A
  contributor on the declared floor could not install the `[dev]` extras the test suite needs.
  An environment marker now resolves the extra to nothing there instead of erroring.
- **Releases are gated on the tagged tree passing** ([.github/workflows/release.yml](.github/workflows/release.yml)).
  `lint.yml` runs on push and PR to `main`, never on tags, so nothing tied a published PyPI
  artifact to a commit CI had gone green on. The release workflow now runs the suite against the
  exact tagged tree first, then smoke-tests the built wheel and sdist — install, version match,
  console scripts, and the sdist's own suite — before the irreversible upload.
- **Least-privilege tokens and a job timeout.** `lint.yml` and `blueprint.yml` declare
  `permissions: contents: read` instead of inheriting a repo-wide web setting, and the reusable
  pre-audit job caps at 30 minutes so a hostile package cannot burn a caller's runner minutes.

### Added

- Regression tests for both security fixes ([tests/test_security.py](tests/test_security.py)) —
  8 new cases. They pin the analyzer's fail-closed behaviour, assert no `python3 -c` runs without
  `-P` in any workflow, assert the untrusted checkout stays out of the workspace root, and
  *demonstrate the attack itself* so a future "`-P` looks like cargo-culting" cleanup fails loudly.
- Import-hygiene regression tests ([tests/test_import_hygiene.py](tests/test_import_hygiene.py)) —
  6 cases that synthesize a consuming application owning modules named like ours and assert, in a
  subprocess, that importing the kit neither mutates `sys.path` nor shadows them, while the kit
  still resolves its own. 4 of the 6 fail against v0.7.0.
- Attestation-honesty tests ([tests/test_attest.py](tests/test_attest.py)) — fail-low derivation
  on absent/junk tiers, refusal on a missing anchor, the absence of any `level` field, and a
  parity test running the real `audit.sh` hashing pipeline against `sak_lib.source_hash` on two
  packages, so the shell and Python anchors can never drift.
- Coverage for `sak_lib.newest_report`, which was advertised in [docs/sdk.md](docs/sdk.md) with no
  test and no in-tree caller. Kept rather than removed — it is public API on an already-published
  package, so deleting it breaks a downstream importer silently for no gain. **224 tests total.**

## [0.7.0] — 2026-08-15 — CI hardening and rule precision

The reusable CI workflow is the headline: it took caller input into `run:` scripts in the job
holding your API key, and — separately — never installed the backend it defaults to, so the
default path could not have run even without the first problem. Both are fixed here, which is
why **`v0.7.0` is a floor for CI callers, not just the newest tag**. Alongside that, the static
tier gains two rules and loses a false positive on its Auth-bypass class.

### Added

- **`--structured` mode on the `claude-api` backend** ([bin/llm_audit.py](bin/llm_audit.py)).
  Forces the pre-audit report via a tool call (`tool_choice`) instead of a markdown report +
  JSON appendix, so the Anthropic API validates the JSON against a schema server-side before
  returning it — no markdown, no parse step, no way for the model to hand back malformed
  JSON. The tool's `input_schema` is derived at runtime from
  [schema/audit-report.schema.json](schema/audit-report.schema.json) (single source of
  truth), with `$ref`s to `$defs` inlined since intra-schema `$ref` support in tool
  `input_schema` is unverified. Shares the cached system prefix with markdown mode, so
  switching modes doesn't cost a fresh cache fill. Design:
  [docs/design/structured-output-mode-2026-07-18.md](docs/design/structured-output-mode-2026-07-18.md)
  (specced 2026-07-18, implemented 2026-08-13).
  - **Opt-in, default off.** The design calls for a markdown-vs-structured parity check
    (run both modes on the same targets, diff the JSON) before flipping the default; that
    check needs API credits the kit doesn't have right now, so it's deferred — see
    [ROADMAP.md](ROADMAP.md).
  - **Not yet wired into `audit.sh`.** This PR scopes the flag to the `llm_audit.py` layer
    only (request assembly + tool-schema derivation + response handling, all unit-tested with
    canned responses). Branching `audit.sh` on `--structured`, and stamping `kit`/`target`
    provenance onto the model subset in place of `extract-report.py`'s markdown parse, is a
    follow-up — `assemble_report()` is included as a tested building block for it.
  - Docs: [docs/backends.md](docs/backends.md) `--structured` section,
    [docs/architecture.md](docs/architecture.md) note on the two shared-cache output
    contracts.
- **Two static rules** ([bin/static_analysis.py](bin/static_analysis.py)):
  - **`owner-role-fixed`** (`low`, Upgrade safety) — `prepare_to_globalize(OwnerRole::Fixed(…))`
    pins the owner rule for the life of the component, so a lost, burned, or compromised owner
    badge leaves administration permanently stuck where that badge is. `low` deliberately, not
    medium: unlike `OwnerRole::None` there *is* an authority here, so nothing is immediately
    exploitable — what's gone is the recovery path, which is a deployment property a reviewer
    signs off rather than a bug. Immutable administration can be a deliberate choice; waive it
    with `// sak:allow owner-role-fixed` when it is. The kit's own
    [attestation registry](attestation/) does *not* waive it — the rule fires there, and
    `attestation/README.md` publishes the finding and argues why the waiver premise fails on
    that blueprint.
  - **`hand-rolled-address-check`** (`medium`, External calls / composability) — an address
    validated by `.starts_with("account_rdx1")` and friends instead of a bech32m decode. A
    prefix test accepts any attacker-chosen string of the right shape with the checksum never
    verified, and the garbage that passes is then persisted on-ledger and trusted downstream.
    Narrow on purpose: only a `starts_with` against a Radix HRP, and one finding per line, so
    the usual mainnet-plus-testnet HRP pair reads as the single hand-rolled validator it is.
    Reads the strings-kept view, so it does not fire on a prefix quoted in a comment.
- **[SECURITY.md](SECURITY.md)** — a disclosure policy. Separates a vulnerability *in* the kit
  from a finding the kit *reports* about your blueprint (the second is an ordinary issue, and
  the most useful contribution there is); states response windows as honest expectations rather
  than an SLA; and writes down both what's out of scope and what the kit does not defend
  against, so nobody has to discover either via an advisory. A private GitHub security advisory
  is the preferred channel, with a fallback that stays reachable while private vulnerability
  reporting is switched off on the repo — as it is today, which the file says out loud instead
  of assuming. There is no bounty. Discoverable from [CONTRIBUTING.md](CONTRIBUTING.md) and the
  [docs index](docs/README.md), and added to the markdownlint lists in
  [.github/workflows/lint.yml](.github/workflows/lint.yml) and the [Makefile](Makefile) — it
  was the one root `.md` neither list named, so it could have drifted silently.

### Fixed

- **The reusable CI workflow never ran its own default backend.**
  [.github/workflows/pre-audit.yml](.github/workflows/pre-audit.yml) installed aider and
  nothing else, but `audit.sh` has defaulted to the `claude-api` backend since 0.6.0, and that
  backend imports `anthropic` ([bin/llm_audit.py](bin/llm_audit.py)). `pipx install aider-chat`
  puts aider in its own virtualenv and leaves the runner's `python3` without `anthropic`, while
  `audit.sh`'s pre-flight for this backend only checks that `python3` exists — so every default
  run cleared the pre-flight and then exited 2 at the import guard, after the checkouts and the
  toolchain setup. Nobody hit it in the kit's own CI because the kit does not call its own
  reusable workflow. The workflow now installs the kit with its `[llm]` extra, and installs
  aider only for `model: deepseek | both`, the cross-model modes that actually need it.
- **`public-mint-burn` fired on OWNER-restricted methods.** The rule matched `pub fn` plus a
  mint/burn-shaped name and stopped there — it never read `enable_method_auth!`, which is where
  a Scrypto method's gate actually lives (`pub fn` is how *every* blueprint method is written,
  gated or not). A component whose auth block said
  `mint_manager_badge => restrict_to: [admin, OWNER];` was still reported as an unrestricted
  mint: a `medium` raised against correct code, on an Auth-bypass rule, which is exactly the
  kind of noise that teaches a reader to skim the class. Matches are now resolved against their
  own blueprint's `enable_method_auth!` — scoped per `#[blueprint]` for the same reason
  `missing-method-auth` was in 0.6.0, so one blueprint's rules never speak for a sibling in the
  same `.rs`. A method declared `=> PUBLIC`, or absent from the macro, or in a blueprint with no
  auth macro at all, still fires, and the finding now names which of those it is. A restriction
  that exists only inside a comment does not suppress. The new `_method_auth_index` helper reads
  only the `methods { … }` sub-block, because the sibling `roles { … }` block uses the identical
  `name => …;` shape and would otherwise register roles as methods.

### Security

- **Argument and command injection in the reusable `pre-audit.yml` workflow.** It interpolated
  caller-controlled `${{ inputs.model }}`, `${{ inputs.package }}` and `${{ inputs.fail-on }}`
  directly into `run:` scripts. GitHub substitutes those values into the script text *before*
  bash parses it, so an input carrying shell metacharacters executes as commands in the audit
  job — and two of the three sat in the step that has `ANTHROPIC_API_KEY` in its environment
  (the third in the gate step of the same job, on the same runner). All three now pass through
  `env:` and are referenced as quoted shell variables, the same fix the release workflow got in
  0.5.0. `kit-ref` stays interpolated on purpose: it feeds `actions/checkout`'s `ref:` input,
  which the runner hands to that action's JavaScript, which execs `git` with an argv array — no
  shell parses it.
  - **Callers pinned at `v0.6.0` or earlier are affected and should bump to `v0.7.0`.** What
    it's worth to an attacker depends on where your inputs come from: a literal in your own YAML
    is not reachable, an input derived from a fork's PR, a branch name, or another workflow's
    output is.
  - `kit-ref`'s description now says it defaults to `main` — pinning only the `uses:` ref leaves
    the audit code itself unpinned, which the CI docs and the example caller now spell out too.

Tests: 169 → 197 green.

## [0.6.0] — 2026-07-17 — Interchangeable LLM backends

The LLM pre-audit pass is no longer welded to aider. `audit.sh` now dispatches to a pluggable
**backend** behind a stable inputs/output contract; everything downstream (nonce
authentication, markdown↔JSON split, static-pass merge, `report.json`, the CI gate,
attestation) is unchanged. See [docs/backends.md](docs/backends.md).

### Added

- **`claude-api` backend (new default).** [bin/llm_audit.py](bin/llm_audit.py) talks to the
  Anthropic API directly via the SDK — no aider, no litellm. Prompt caching keeps the auditor
  prompt + checklist + reference patterns cached across runs. The `llm` extra installs it
  (`pip install ".[llm]"`). It defaults to **Claude Sonnet 4.6** — the model the kit has always
  used — and does not change which model audits your code; override with `--model`.
- **`cmd` backend — bring your own agent.** `--backend cmd --backend-cmd '<command>'` (or
  `$SAK_BACKEND_CMD`) points the kit at any program that can read the assembled inputs (via
  `SAK_*` env vars) and print a nonce-stamped report — how your own agents drive the pre-audit.
- **`--backend` / `$SAK_BACKEND`** select the engine: `claude-api` (default), `aider`, or `cmd`.
- **[docs/backends.md](docs/backends.md)** — the backends, the model override, and the full
  BYO-command contract; plus `tests/test_backends.py` (10 tests, the first coverage for
  `audit.sh` itself).

### Changed

- The **aider harness is now one backend** (`--backend aider`), selected automatically by the
  cross-model modes `--model deepseek` and `--model both`. Requesting those with a different
  backend is an error.
- **Fixed:** `.aider.conf.yml` set `temperature: 0`, which aider ≥ 0.86 rejects
  (`unrecognized arguments: --temperature=0`) — it had broken the aider LLM path since v0.5.0's
  R5 pass. Removed; the aider backend runs again.

### Fixed

- **`unsafe-block`** now also catches `unsafe fn` / `unsafe impl` (previously only matched
  `unsafe { }`), and **`float-usage`**'s numeric-literal-suffix branch now catches exponent-form
  floats (`1e5f64`, `1.5e3f32`).

### Security

A follow-up false-negative sweep of the analyzer itself (2026-07-18) — every finding reproduced
against a crafted input with a passing control, not just read off the rules — found the issues
below, fixed here:

- **`merge_findings`** collapsed two distinct findings sharing a (class, title, severity)
  signature into one whenever they sat at different lines. Among the static findings themselves
  this silently dropped a real finding from every merged report — e.g. `raw-decimal-arith` at
  `src/lib.rs:86` and `:98` in the vulnerable-vault fixture merged down to one — and was fixed
  first. The LLM-vs-static half of the same merge had the identical bug and a second, sharper
  edge: one LLM finding could swallow every static finding sharing its signature *anywhere in
  the file*, not just its actual duplicate, and a model-marked `false_positive` could mask an
  `open` deterministic static finding at the very same spot, silently overriding a reproducible
  rule with a non-deterministic model opinion. Both halves are now location-aware the same way —
  same signature AND same location is required to count as a duplicate — and a non-open primary
  finding no longer suppresses a same-location extra.
- **`raw-decimal-arith`** missed a rustfmt-wrapped Decimal `*`/`/` split across two lines
  (operator leading the continuation line, ordinary rustfmt output for a long expression) — it
  had been left on the old per-line scan when its siblings were migrated to a whole-text scan
  specifically to defeat newline-splitting.
- **`missing-method-auth`** — the kit's highest-severity rule — checked `enable_method_auth!`
  against the *whole file* instead of each `#[blueprint]`'s own body, so pairing one authed
  blueprint with one unauthed blueprint in the same `.rs` reported clean; the unauthed
  blueprint's public methods were invisible to the rule. Now scoped per blueprint.
- **`// sak:allow <rule>`** suppression trailing a line's own code was leaking onto the *next*
  line — that next line's "line above" is the suppressed line, and nothing checked that a
  "line above" was actually a dedicated comment line rather than code with its own inline
  suppression. The "line above" form now only applies when that line carries no code of its own.

Tests: 127 → 137 green (141 after the static-vs-static merge-fix; 154 after this pass).

## [0.5.0] — 2026-06-14 — Developer experience

The kit becomes something you build on, not just run. **Additive only** — every existing run
path (`audit.sh`, the `bin/` scripts, `.mcp.json`, the test suite) is unchanged.

### Added

- **Pip-installable package.** `pip install scrypto-audit-kit` exposes the deterministic core
  (`from scrypto_audit_kit import static_analysis, sak_lib, attest, gen_tests`) and `sak-*`
  console scripts (`sak-static`, `sak-gate`, `sak-attest`, `sak-gen-tests`, `sak-mcp`). The core
  is stdlib-only with zero required dependencies; `mcp` and `jsonschema` are opt-in extras.
  ([docs/sdk.md](docs/sdk.md))
- **Formal tool contracts.** [schema/mcp-tools.schema.json](schema/mcp-tools.schema.json) —
  input/output JSON Schema for all 9 MCP tools, kept in lockstep with the code by a drift test
  that also validates real fixture output against the published schemas.
- **Example agents.** [examples/agents/](examples/agents/) — three runnable programs: a
  free-tier CI gate, the audit → fix → verify loop, and an MCP client.
- **Documentation suite.** [docs/](docs/README.md) — a quickstart, an SDK reference, an
  MCP-tools reference, and an architecture overview, behind a docs index.

### Changed

- The MCP server resolves the kit root via `SAK_HOME` (env → walk-up → default), so a
  pip-installed server degrades gracefully; running from a clone is byte-identical to before.
- README gains a pip/SDK quickstart and a docs map; AGENTS/VISION reconciled (the kit spans
  L1–L3; tool names current).

### Fixed

- Two unclosed-file `ResourceWarning`s in the test suite.

### Security

A second adversarial hardening pass (2026-07-17) landed before this first published release:

- **Compile pre-flight is now opt-in** (`--compile-check`). `cargo check` executes the
  target's build scripts and proc-macros on your machine, so the default path no longer runs
  any untrusted code; `--no-compile-check` is kept as a back-compat no-op, and API keys are
  scrubbed from the pre-flight environment either way.
- **Prompt boundary.** The audit prompt declares the target source untrusted data — never
  instructions — and requires any attempt to steer or suppress the audit to be reported as a
  finding.
- **CI workflows.** Least-privilege token, credentials not persisted into the untrusted
  checkout, and the release workflow no longer shell-interpolates the release tag name
  (script injection).
- **Fail-closed report handling.** No stale-report provenance, path-traversal confinement,
  nonce adjacency in report extraction, refusals fail loud, and static-only runs emit a clean
  `report.json`.
- **Static analyzer.** Newline-split evasion closed, drain/float rules broadened, and
  `sak:allow all` rejected.

Tests: 88 → 105 green (127 after the hardening pass).

## [0.4.0] — 2026-06-14 — Verifiable & connected, then hardened

### Added

- **L3 on-chain attestation.** A Scrypto [attestation registry blueprint](attestation/) — a
  soulbound NFT binding `{source_hash, report_hash, wasm_hash, versions, level, severity counts}`
  — plus `bin/attest.py` (report → payload → Radix manifest) and the `attestation_payload` tool.
- **Property-test generation.** `bin/gen_tests.py` emits compilable `#[ignore]`d scrypto-test
  scaffolds from the blueprint surface, and the `propose_tests` tool.

### Security

- **Adversarial pass (R1–R6).** Four red-team agents audited every surface; all findings fixed
  with regression tests. Closed a "malicious package → clean badge" chain (nonce-authenticated
  report appendix, fail-closed gate, severity normalisation); made the attestation blueprint
  compile and hardened its index; fixed static-analyzer stripper bugs and evasions; added the
  `raw-decimal-arith`, `unwrap-expect`, and `public-mint-burn` rules; and reframed the
  reproducibility claims honestly (the static tier reproduces, the LLM tier does not).

## [0.3.0] — 2026-06-14 — Deterministic

### Added

- **Hybrid static analysis.** `bin/static_analysis.py` — a comment/string-aware analyzer with
  high-precision Scrypto rules, a free `--static-only` tier (no API key, no toolchain), the
  `static_scan` tool, and `// sak:allow` suppression.
  ([docs/static-analysis.md](docs/static-analysis.md))

## [0.2.0] — 2026-06-13 — Agentic

### Added

- **MCP server** (`bin/mcp_server.py`) exposing the pre-audit as tools, sharing `bin/sak_lib.py`
  with the CI gate; a Claude Code skill, `.mcp.json`, and an [AGENTS.md](AGENTS.md) playbook.
- The **audit → fix → re-verify** loop (read-only auditor + supervised fixer).
  ([docs/agents.md](docs/agents.md))

## [0.1.0] — 2026-06-13 — Trustworthy & machine-readable

### Added

- Machine-readable `report.json` with a [schema](schema/audit-report.schema.json), stable
  finding ids, and a provenance block (kit / model / checklist version + source hash).
- A deliberately-vulnerable [example fixture](examples/vulnerable-vault) + a committed sample
  report; a reusable [pre-audit GitHub Action](.github/workflows/pre-audit.yml) + severity gate +
  badge ([docs/ci.md](docs/ci.md)); [VISION.md](VISION.md) + [ROADMAP.md](ROADMAP.md).

## [0.0.0] — 2026-06-13 — Foundations

### Added

- Public Apache-2.0 repo, CI, the curated 11-class checklist + reference-pattern catalogue, and
  the honest framing (read-only core, not-an-audit, cite-and-verify).
