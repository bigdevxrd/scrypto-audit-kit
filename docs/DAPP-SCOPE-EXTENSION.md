# Scoping the kit to a dapp, not just a blueprint — a proposal

**Date:** 2026-09-03
**Status:** First slice shipped in PR #25 — `prompts/dapp-scope-checklist.md`, the
questionnaire schema (`schema/dapp-scope-questionnaire.schema.json`) with a worked example, and a
deterministic `sak-dapp-scope` CLI (validate → render, "unbounded" is a finding per §3). Built
exactly to the §5 shape below and nothing more: not wired into `prompts/checklist.md`,
`schema/audit-report.schema.json`, the MCP tools, or the L1–L4 attestation ladder. Originally
filed alongside the hardening triage in
[HARDENING-TRIAGE-2026-09-03.md](HARDENING-TRIAGE-2026-09-03.md) as part of "harden before
announcing" — this document remains the design any further work here should follow.
**Relationship to the trust ladder:** [architecture.md](architecture.md) frames the kit as owning
the middle rungs between "it compiles" and "a human audited it." Everything on that ladder today
audits **one Scrypto package** — `Cargo.toml` + `src/` + `tests/`. This proposal is about the rung
below all of them: most of what makes a dapp lose money isn't in the package at all.

## 1. Why this rung is missing

The kit's two engines — the static rules and the LLM checklist — both take a single Scrypto
package as input and both reason about code. Two motivating patterns:

- **A blueprint with no logic defect at all, fed an input far outside any range its author
  imagined.** Correct code, wrong data. Nothing in `src/` is wrong; nothing a source-only pass —
  static or LLM — can see is wrong. The bug lives in what feeds the blueprint, not in the
  blueprint.
- **A missing authority check at the seam *between* two systems**, neither of which is wrong on
  its own. The blueprint enforces its own auth correctly; the caller enforces its own correctly;
  the gap is in what each assumes the other already checked. A single-package audit has no
  vantage point from which that gap is even visible — both packages, read separately, look fine.

Both are named, without identifying either incident, in the README's honesty paragraph precisely
because a green `report.json` for the blueprint says nothing about either failure mode. A
dapp-scoped pass is how the kit would start to say something about them.

## 2. What "dapp scope" means

A dapp is a blueprint plus everything around it that can make the blueprint's own-correct logic
produce a loss. Four surfaces, none of which are Scrypto source and none of which the kit reads
today:

### 2.1 Data sources

Every value the blueprint trusts that did not originate inside the blueprint's own state: price
feeds, oracle components, off-chain relayers, cross-package reads of another component's vault
balance or NFT metadata. For each one, the checklist question isn't "is the read correct" (that's
already Class 7, external calls) — it's:

- What is the *source's own* trust model? Single oracle, median-of-N, TWAP window, an operator's
  own signed message?
- What happens to the consuming blueprint if this source returns a value outside its historical
  range — not malicious, just wrong, stale, or a decimal-place slip upstream?
- Is there a sanity bound (a max single-block delta, a floor/ceiling) *in the consuming code*, or
  does the blueprint fully inherit whatever the source hands it?

### 2.2 Listing / registry configuration

Which assets, pairs, or components a dapp treats as first-class — the difference between "this
blueprint is correct" and "this blueprint is correct for the resources it was designed against."
Config here is often a KVS entry, an env var read by an off-chain service, or a governance-set
allowlist, not Rust source, so it is invisible to a source-only audit:

- Who can add or remove a listing, and is that action logged/attributable on-chain or only in an
  admin panel's database?
- Does adding a listing re-run any of the checks that applied to the original set (decimal places,
  divisor-by-zero exposure, price-source trust), or is it assumed safe by precedent?
- Is there a difference in code path between "the resources this was tested against" and "the
  resources it now accepts" — e.g. an assumption that all vaults hold 18-decimal resources baked
  into a formula, silently wrong for a 6-decimal stablecoin?

### 2.3 Admin powers

Every capability a badge, role, or key holder has *in practice*, independent of what the Scrypto
`enable_method_auth!` block says in isolation (Class 1 already covers that block). This is about
composing the powers across the whole system:

- Enumerate every privileged method across every component in the dapp, then ask what the
  *union* of one badge's privileges can do in a single transaction or a tight sequence of them —
  not each method's blast radius alone.
- Is any admin action a single signature, or does anything load-bearing (owner rotation, fee
  changes, pausing withdrawals) require a timelock or multisig? If not, is that a documented,
  accepted risk or an oversight?
- Does the off-chain half (a keeper, a bot, a cron job) hold or can it obtain any of these
  privileges, and if compromised, does it inherit the on-chain badge's full power or a narrower,
  purpose-built one? A separated signer process with an allowlist over transaction content,
  per-transaction and rolling-window caps, and a pinned recipient set is the shape of "narrower" —
  named here as a pattern to check for, not tied to any specific deployment.

### 2.4 Operational response

What happens in the minutes after something goes wrong, which is entirely off-chain today and
therefore entirely outside the kit's current scope:

- Is there a pause/halt path, who can trigger it, and has it ever been exercised outside a test?
- Is there monitoring that would notice the failure modes in 2.1–2.3 (an oracle value outside
  historical range, an admin action outside a change-managed window, a new listing that skips the
  original checklist) before a human happens to look?
- Who is paged, and what can they actually do without a human audit or a governance vote first —
  i.e., does "operational response" mean anything faster than "redeploy," or is pausing the only
  lever that exists?

## 3. The cross-cutting check: max loss under one maximally-wrong input

Rather than one more checklist class, this is proposed as a **standing question asked once per
dapp, covering all of 2.1–2.4 at once**: for each external input the system trusts (a price, a
listing, a signature, an admin action), what is the maximum loss if *that one input, and only
that one*, takes its worst possible value, holding everything else correct?

This differs from the existing checklist in two ways worth being explicit about:

- It is a **system-level bound**, not a per-blueprint finding. The answer usually depends on a
  vault's actual balance, a rate limit's actual cap, and a pause switch's actual latency — facts
  that live in deployment config and account state, not in `src/`. The kit would need to *ask* for
  these (a small structured input, not a code scan) rather than infer them from source.
- It is explicitly **not** trying to find whether the input *can* be manipulated (that's Class 7
  and the data-sources questions above) — it assumes the worst case arrives by any means,
  including an honest upstream mistake, and asks what the blast radius is regardless of cause.
  This is the question that would have been answerable, in principle, for both motivating
  incidents in §1: "if the price this blueprint trusts is off by an arbitrary factor, what's the
  cap on loss" and "if the caller skips the check this blueprint assumes it made, what's the cap
  on loss" are both instances of the same question, asked of different inputs.

A "no bound exists" answer is itself the finding — the honest output of this check on a system
with no circuit breaker is "unbounded," not silence.

## 4. What this would NOT be

- **Not a replacement for the blueprint-level checklist.** Sections 1–11 of
  [checklist.md](../prompts/checklist.md) stay exactly as scoped; this is an additional pass with
  a different, wider input.
- **Not automatic.** Unlike the static pass, most of 2.1–2.4 cannot be extracted from a git
  checkout — it needs a human (or the dapp's own operator) to answer a structured questionnaire
  about data sources, listing process, admin topology, and incident response, the same way the
  checklist today asks the LLM to mark a class "not applicable" with a justification rather than
  guess.
- **Not scored the same way.** A single-package report can be schema-validated and attested
  ([attestation-levels.md](attestation-levels.md)) because the input (a source tree) is
  reproducible. A dapp-scope report's input is partly organizational fact, which can go stale the
  day after the report is written (a listing gets added, an admin key rotates). It would need its
  own freshness marker, not inherit `L1`–`L3` as defined today.

## 5. Shape of an eventual implementation (not scoped for build yet)

If this is taken up:

1. A new prompt/checklist pair (`prompts/dapp-scope-checklist.md`) parallel to, not merged into,
   the existing blueprint checklist — same "no answer is a finding" discipline as
   [checklist.md](../prompts/checklist.md) §0.
2. A structured intake format for the four surfaces in §2 (likely a YAML/JSON the operator fills
   in once per dapp and updates on change — the closest existing precedent in the kit is how
   `examples/ci/pre-audit.yml` configures a per-repo CI run, not a code artifact).
3. The max-loss check in §3 as a required field per listed input in that intake, not a free-text
   finding — so a "no bound / unbounded" answer is structurally visible in `report.json` rather
   than buried in a findings list.
4. A new report `mode` (extending the `static | llm | hybrid` set from
   [attestation-levels.md](attestation-levels.md)) so a dapp-scope report is never confused with,
   or silently claimed as, a blueprint-source attestation.

None of this is committed to the roadmap yet; it is filed here so a contributor picking up the
"dapp-scope extension" issue has a starting design rather than a one-line ask.
