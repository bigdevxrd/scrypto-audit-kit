# Vision — a trust ladder for Scrypto

> **TL;DR** — Audits are expensive and scarce, so most Scrypto code ships with *nothing* between "it compiles" and "we hope it's fine." `scrypto-audit-kit` aims to be the missing rungs in between: a free, transparent, **agentic** pre-audit that any builder (or their agent) can run in minutes, that produces a versioned, partly-reproducible artifact (the static tier is deterministic; the LLM layer is advisory), and that escalates cleanly into a full human audit (Hacken, Certik, …) rather than pretending to replace one.

This document is the north star. It's deliberately ambitious. Nothing here is a promise of safety — see [Honest scope](#honest-scope).

---

## The problem

Ethereum builders have a whole security stack they reach for *before* they ever pay for an audit: Slither, Mythril, Semgrep, Echidna/Foundry fuzzing, MythX, then contest platforms like Code4rena and Sherlock. By the time code reaches a paid auditor, the obvious footguns are already gone.

Scrypto has **none of that**, and the Ethereum tools don't port. Radix's asset-oriented model deletes whole bug classes (no ERC-20 approval draining, far less raw reentrancy) but introduces new ones: resource/bucket handling, `enable_method_auth!` role hierarchies, manifest and subintent composition, `Decimal` rounding direction. The vulnerability surface is *different*, so the tooling has to be **native**.

Right now that tooling barely exists. The result is a cliff:

- **Free, instant:** `cargo check`, `clippy`. Tells you it compiles. Says nothing about whether it's safe.
- **…a giant gap with nothing in it…**
- **$$$, weeks out:** a full manual audit. Out of reach for a solo builder, a hackathon team, or anything pre-revenue.

Most Scrypto in the wild lives in that gap, unprotected. **Closing the gap is the mission.**

## The thesis: a trust ladder

Trust in code isn't binary; it's a ladder you climb as far as your risk demands. Each rung is cheap to reach and strengthens the one above it.

| Rung | What | Cost | Who |
|------|------|------|-----|
| **L0** | Compile & lint (`cargo check`, clippy) | free · seconds | everyone |
| **L1** | **Agentic pre-audit** — point an agent at your repo; audit → fix → re-verify | free · OSS | this kit |
| **L2** | **Attested CI run** — pinned method + deterministic static tier, runs in CI → live badge | free–$ · minutes | this kit |
| **L3** | **On-chain attestation** — soulbound proof on Radix binds code-hash ↔ report | tamper-evident | this kit |
| **L4** | **Human audit** — Hacken, Certik, … the kit's report is the *input* | $$$ · weeks | partners |

`scrypto-audit-kit` owns **L1–L3** — the empty middle. We are not trying to be L4; we are trying to make L4 cheaper, faster, and better-targeted by handing auditors pre-cleaned code with a coverage map and the open questions already surfaced.

## Principles (why this is trustworthy, not snake-oil)

An LLM pre-audit is worthless *the moment it overclaims*. Our entire credibility rests on never doing that. These are non-negotiable:

1. **Never claim "safe" or "audited."** We claim exactly what ran: "passed kit vX, checklist vY, N classes covered, 0 critical/high, M residual open questions." A coverage statement, not a guarantee.
2. **Transparent by construction.** The checklist, the reference patterns, and the prompt are all open. Anyone can see *exactly* what is and isn't checked. No black box.
3. **Reproducible where it can be.** Every report records the kit version, model, checklist version, and reference-set hash, so the *method* is pinned and the deterministic static-tier findings reproduce exactly. The LLM pass is **not** byte-reproducible (production APIs drift, even at temperature 0) — we say so, and anchor verification on the source hash + static findings rather than pretend the whole report regenerates.
4. **Honest about misses.** Residual risk and low-confidence concerns are surfaced as open questions, not buried. We publish our own false-positive / false-negative track record.
5. **A funnel, not a replacement.** We are structurally *aligned* with human auditors — we send them cleaner code — not competing with them. The ladder ends at L4 on purpose.
6. **Read-only core.** The auditor never edits the code under review. Fixes happen in a separate, human-supervised session. Analysis and mutation stay apart.

Honesty is the moat. A tool that reliably says "here's what I checked and here's what I can't promise" is more valuable — and more defensible — than one that claims to bless code.

## Architecture: agentic by design

"Point an agent at your repo and let it help clean up your Scrypto" is the product. Three things make that real:

**Structured output is the substrate.** Findings become JSON with a stable schema and stable IDs; the human-readable markdown is just a *render* of that JSON. Everything else — the badge, the fix-loop, the on-chain attestation — consumes the JSON. This is foundation move zero.

**The kit becomes a capability any agent can pick up**, via three surfaces:
- an **MCP server** (`audit_package`, `get_findings`, `verify_finding`, `reaudit_diff`) so any MCP-aware agent can use the kit as a tool;
- a **Claude Code skill / plugin** for one-command use inside a coding session;
- an **`AGENTS.md`** the repo advertises, so any agent that lands in a user's Scrypto project knows to pull the kit in.

**The loop is audit → fix → re-verify.** The read-only auditor flags findings; a *separate, human-supervised* fixer proposes edits; a re-audit confirms each finding is closed with no regression. The user climbs to L1-clean with a verifiable trail — `12 findings → 0`, every step recorded — instead of a vibe.

## The engine roadmap

The analysis engine grows past "just an LLM," adding determinism (and therefore trust) at each layer:

- **v1 — LLM-only** *(today)*. Strong checklist + reference patterns, one-shot. Good signal, not reproducible.
- **v2 — Hybrid static + LLM.** A deterministic Rust/AST pass — the "Slither for Scrypto" — catches the mechanical stuff for free and reproducibly: missing `enable_method_auth!` rules, raw `*`/`/` on `Decimal`, `unwrap()`/`expect()` on user input, lost buckets, hardcoded addresses. The LLM layer handles what static analysis can't: semantics, intent, cross-method invariants.
- **v3 — Property-test generation.** The kit emits `scrypto-test` property tests for the invariants it flags (NAV = Σ vaults, caps hold, role negative-paths). Findings become *executable* checks.
- **v4 — Fuzzing / symbolic / formal.** The hard frontier. Later, and never over-promised.

## The web3-native primitive: on-chain attestation

The cleverest rung is **L3**, and it's pure Radix. A Scrypto blueprint mints a **soulbound attestation** binding:

```
{ source_hash, wasm_hash, kit_version, checklist_version, report_hash, level, date }
```

It never says "safe." It says *this exact bytecode* passed kit vX at level Y on date Z — and anyone can verify that on-ledger, forever, against the code actually deployed. The kit audits Scrypto; the proof *lives* on Radix. We'd be dogfooding the ecosystem we're securing.

## Ecosystem & sustainability

- **Auditor partnership (Hacken et al.).** Pitch the pre-audit funnel: cleaner code arrives, reviews go faster, and L2/L3-attested projects get a discount or fast-track. Win-win — it makes the ladder real and gives L3 teeth.
- **Radix grant.** Ecosystem security infrastructure is a public good; more secure blueprints means a healthier network. This is grant-shaped work.
- **Native fit.** The kit plugs into the wider stack: a marketplace can sell "pre-audit my Scrypto" as a paid agent task; on-chain projects dogfood it; the attestation component is itself a blueprint we ship and run.
- **Freemium / public-good.** OSS core stays free (adoption + trust). Hosted attested runs and the registry/badge can be paid or grant-funded.

## Roadmap

- **Phase 0 — Foundations** *(done)*. Public OSS repo, Apache-2.0, CI, honest framing, curated checklist + reference patterns.
- **Phase 1 — Make it trustworthy & machine-readable** *(in progress)*. JSON findings + stable IDs · a shipped vulnerable example + sample report · a reusable pre-audit GitHub Action + badge · reproducibility metadata (kit/model/checklist versions) · this vision in the repo.
- **Phase 2 — Make it agentic.** MCP server · Claude Code skill · `AGENTS.md` · the audit → fix → re-verify loop.
- **Phase 3 — Make it deterministic.** The hybrid static-analysis pass (Slither-for-Scrypto) · property-test generation.
- **Phase 4 — Make it verifiable & connected.** On-chain attestation blueprint · public registry/dashboard · the auditor-partnership and grant conversations.

See [ROADMAP.md](ROADMAP.md) for the live checklist (created as Phase 1 lands).

## Honest scope

What this is **not**, and will never claim to be:

- **Not a formal verifier.** No theorem proving, no symbolic execution (yet). Findings come from a checklist + patterns, not proofs.
- **Not a replacement for a human audit.** It is the rung *below* one. Do not ship mainnet value on a clean pre-audit alone.
- **Not a safety guarantee.** An attestation is a *coverage* claim about specific code, not a blessing.
- **Not infallible.** LLMs hallucinate; every cited line must be verified. The kit is honest about this in every report.

If any of those limits matter for your use case, climb to L4.

## Get involved

This is ecosystem infrastructure, and it gets stronger with more eyes. The highest-leverage contributions are trial reports against public blueprints, new checklist classes from real-world footguns, and reference patterns from permissively-licensed Radix code. See [CONTRIBUTING.md](CONTRIBUTING.md).

If you're an auditor, a Radix team member, or building Scrypto in anger — open an issue or a discussion. We want to build the rung you wish existed.
