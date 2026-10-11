<!-- dapp-scope-checklist-version: 1.0 -->
# Dapp-Scope Checklist

Parallel to, not merged into, [checklist.md](checklist.md). That checklist's eleven classes all
audit one Scrypto package's own source. This one audits everything around the package that can
make its own-correct logic produce a loss — see
[docs/DAPP-SCOPE-EXTENSION.md](../docs/DAPP-SCOPE-EXTENSION.md) for the full design and why this
exists as a separate pass.

Same discipline as `checklist.md`: if the answer to a concrete question is missing, unclear, or
"no" where "yes" was expected, that's a finding. A surface that genuinely doesn't apply to this
dapp is marked **not applicable** with a one-sentence justification — never silently skipped.

**This is not automatic.** Nothing here can be extracted from a git checkout. Answer it as a
structured questionnaire (`schema/dapp-scope-questionnaire.schema.json`,
`examples/dapp-scope/questionnaire.example.json`) — a human or the dapp's own operator, not a
source-reading pass. **It is not scored under the L1–L4 attestation ladder** and a report from it
must never be presented as one (see [attestation-levels.md](../docs/attestation-levels.md)).

---

## 2.1 Data sources

Every value the blueprint trusts that did not originate inside its own state: price feeds,
oracle components, off-chain relayers, cross-package reads of another component's vault balance
or NFT metadata.

- What is the *source's own* trust model? Single oracle, median-of-N, TWAP window, an operator's
  own signed message?
- What happens to the consuming blueprint if this source returns a value outside its historical
  range — not malicious, just wrong, stale, or a decimal-place slip upstream?
- Is there a sanity bound (a max single-block delta, a floor/ceiling) *in the consuming code*, or
  does the blueprint fully inherit whatever the source hands it?
- Per §3 below: if this one source, and only this one, returns its worst possible value, what is
  the loss cap?

## 2.2 Listing / registry configuration

Which assets, pairs, or components the dapp treats as first-class — the difference between "this
blueprint is correct" and "this blueprint is correct for the resources it was designed against."

- Who can add or remove a listing, and is that action logged/attributable on-chain or only in an
  admin panel's database?
- Does adding a listing re-run any of the checks that applied to the original set (decimal
  places, divisor-by-zero exposure, price-source trust), or is it assumed safe by precedent?
- Is there a difference in code path between "the resources this was tested against" and "the
  resources it now accepts" — e.g. an assumption that all vaults hold 18-decimal resources baked
  into a formula, silently wrong for a 6-decimal stablecoin?
- Per §3 below: if this one listing, and only this one, is the worst-case input, what is the loss
  cap?

## 2.3 Admin powers

Every capability a badge, role, or key holder has *in practice* — the union across the whole
system, not each method's blast radius alone.

- Enumerate every privileged method across every component in the dapp, then ask what the
  *union* of one badge's privileges can do in a single transaction or a tight sequence of them.
- Is any admin action a single signature, or does anything load-bearing (owner rotation, fee
  changes, pausing withdrawals) require a timelock or multisig? If not, is that a documented,
  accepted risk or an oversight?
- Does the off-chain half (a keeper, a bot, a cron job) hold or can it obtain any of these
  privileges, and if compromised, does it inherit the on-chain badge's full power or a narrower,
  purpose-built one?
- Per §3 below: if this one admin action, and only this one, is exercised maximally against the
  system, what is the loss cap?

## 2.4 Operational response

What happens in the minutes after something goes wrong.

- Is there a pause/halt path, who can trigger it, and has it ever been exercised outside a test?
- Is there monitoring that would notice the failure modes in 2.1–2.3 (an oracle value outside
  historical range, an admin action outside a change-managed window, a new listing that skips the
  original checklist) before a human happens to look?
- Who is paged, and what can they actually do without a human audit or a governance vote first —
  i.e., does "operational response" mean anything faster than "redeploy," or is pausing the only
  lever that exists?

This surface has no per-item max-loss field of its own (§3 below): it is the mitigation, not one
of the trusted inputs being bounded.

---

## §3 — Standing question: max loss under one maximally-wrong input

Asked once per dapp, covering all of 2.1–2.4 at once, and attached **per listed input** in the
questionnaire rather than as one free-text answer: for each external input the system trusts (a
price, a listing, an admin action), what is the maximum loss if *that one input, and only that
one*, takes its worst possible value, holding everything else correct?

This is a **system-level bound**, not a per-blueprint finding — the answer usually depends on a
vault's actual balance, a rate limit's actual cap, and a pause switch's actual latency, which is
exactly why this pass asks rather than infers from source. It is explicitly **not** trying to
find whether the input *can* be manipulated (that's already Class 7 in `checklist.md` and the
2.1 questions above) — it assumes the worst case arrives by any means, including an honest
upstream mistake, and asks what the blast radius is regardless of cause.

**A "no bound exists" answer is itself the finding.** The honest output of this check on a system
with no circuit breaker is "unbounded," not silence — the questionnaire schema requires a
`rationale` on every `max_loss` answer either way, so an unbounded input is never left blank.
