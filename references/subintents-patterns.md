# Radix Subintents — Production Patterns

**Source:** [docs.radixdlt.com/subintents](https://docs.radixdlt.com/docs/subintents) + [InfluxionLabs/anthic-sdk](https://github.com/InfluxionLabs/anthic-sdk)
**Source license:** Anthic SDK is open-source; Radix docs are CC-BY-licensed
**Snapshot date:** 2026-04-27
**Curator:** scrypto-audit-kit contributors

Subintents are signed, off-ledger transaction fragments that get pulled into a parent transaction at execution time. Each fragment has its own validity window, signers, and authorization rules. **Live on Radix mainnet since Cuttlefish (Dec 2024)** alongside Scrypto v1.3.0.

When auditing blueprints with subintent integration, the questions are: who signs which leg, who can replay, who pays fees, and what happens if a sub-fragment expires.

## Manifest primitives (3 instructions)

| Instruction | Where | Purpose |
|---|---|---|
| `YIELD_TO_PARENT [bucket1, ...];` | end of every subintent | finishes subintent, returns control + buckets to parent |
| `YIELD_TO_CHILD Intent("name") [bucket1, ...];` | in parent | invokes a named child subintent, optionally passing buckets |
| `VERIFY_PARENT <access_rule>;` | top of subintent (optional) | asserts parent's auth zone satisfies rule (e.g. matcher's signature) — gates which parents can use this subintent |

**Critical:** subintent stubs must NOT include `LOCK_FEE`. Parent pays fees. This enables delegated/gasless UX.

## Limits

- Intent depth: **4** (root + 3 nested layers)
- Max subintents per tx: **32**
- Max signatures: **64** total across the tree
- Max instructions per manifest: 1000 (each intent independently)
- Each subintent has independent **expiry** (epoch range or `afterDelay` seconds) and **nonce**

## Signing model

Each intent in the tree is signed **independently** by whichever signers its access requires. There's no single "transaction signature" covering everything.

Typical pattern:
- End-user's wallet signs subintent that touches their account
- A matcher / aggregator signs the parent
- Notary signs only the root

Wallet returns a `SignedPartialTransaction` (hex-encoded) — a single signed subintent. dApp assembles into larger tx + submits.

## What `VERIFY_PARENT` actually verifies

NOT a manifest hash. It asserts an `AccessRule` against the **parent's auth zone** at the moment the parent calls `YIELD_TO_CHILD`. Parent's auth zone contains:
- Implicit signature proofs (engine inserts NF proof per signing pubkey)
- Explicit badge proofs the parent has created during execution

So `VERIFY_PARENT require(signature_of(MATCHER_PUBKEY))` = "this subintent only valid when invoked by a parent the matcher has signed." Prevents third parties from picking up + griefing with someone else's signed subintent.

**Audit checks**: any subintent with no `VERIFY_PARENT` is replayable by anyone who can see the signed payload. Audit each subintent for whether replay is acceptable. If the user signs an open-ended "withdraw 100 XRD" subintent without `VERIFY_PARENT`, ANY relayer can submit it.

## dApp Toolkit usage

```ts
const result = await dAppToolkit.walletApi.sendPreAuthorizationRequest(
  SubintentRequestBuilder()
    .manifest(subintentManifestString)
    .setExpiration('afterDelay', 3600)
    .message('Sign limit order: sell 100 XRD @ 0.95 fUSD')
    .onSubmittedSuccess((intentHash) => { ... })
);
// result is hex-encoded SignedPartialTransaction
```

Backend assembles SignedPartialTransaction + other subintents + root manifest → notarizes → submits via Gateway.

## Production users

### 1. Atomix — P2P trading (live)

- User A signs subintent: "withdraw 100 XRD, expect ≥95 fUSD back"
- User B signs mirror subintent
- Atomix relayer builds parent that fans out, locks fee, submits
- No middleman custody, atomic settlement, CEX-like off-chain matching with DEX-grade security

### 2. Anthic — intent-based DEX (live, **public SDK**)

- Repo: [`InfluxionLabs/anthic-sdk`](https://github.com/InfluxionLabs/anthic-sdk) — worked manifest examples in `examples/dex-subintent`
- Architecture: makers (institutional liquidity providers) post quotes; takers sign limit-order subintents; matching engine bundles maker+taker subintents into one tx; routes through Ociswap/CaviarNine/Astrolescent for liquidity backstop
- Best concrete reference for any intent-based DEX flow

## When to use subintents vs full transactions

**Full transaction** when:
- One party constructs + submits the whole thing
- All signers can sign in one wallet review
- No need to mix in components someone else signed elsewhere

**Subintent** when:
- Multiple parties sign at different times / places (P2P, limit order)
- Atomic multi-leg execution depending on a counterparty
- Delegated fees (service pays, user only signs their leg)
- Conditional pre-authorization (user signs "I'll sell X for Y if Z" and walks away)

## Pattern sketches

### A. Pool-to-pool rotation (delegated relayer)

User-signed subintent (`rotate_user_leg`):
```
VERIFY_PARENT require(signature_of(RELAYER_PUBKEY));
CALL_METHOD Address("<user_account>") "withdraw" Address("<lpA_token>") Decimal("<amount>");
TAKE_FROM_WORKTOP Address("<lpA_token>") Decimal("<amount>") Bucket("lpA");
YIELD_TO_PARENT Bucket("lpA");
# expects to receive lpB (wallet shows static bound)
```

Parent (relayer-built):
```
LOCK_FEE Address("<fee_payer>") Decimal("5");
YIELD_TO_CHILD Intent("rotate_user_leg") -> Bucket("lpA");
CALL_METHOD Address("<poolA>") "redeem" Bucket("lpA");
TAKE_ALL_FROM_WORKTOP Address("<tokenX>") Bucket("x");
CALL_METHOD Address("<dex>") "swap" Bucket("x") Address("<tokenZ>");
TAKE_ALL_FROM_WORKTOP Address("<tokenY>") Bucket("y");
TAKE_ALL_FROM_WORKTOP Address("<tokenZ>") Bucket("z");
CALL_METHOD Address("<poolB>") "contribute" Bucket("y") Bucket("z");
TAKE_ALL_FROM_WORKTOP Address("<lpB_token>") Bucket("lpB");
CALL_METHOD Address("<user_account>") "deposit" Bucket("lpB");
```

Atomic (no slippage / front-run / partial-fill), delegated fee (relayer pays), user signs once, wallet preview clean.

### B. Emergency-close-all-positions (relayer-driven)

Two patterns:

**(a) One subintent per vault, parent fans out.** Each vault's subintent does `VERIFY_PARENT require(signature_of(USER))` + calls `vault.emergency_close()`. Cap at 31 vaults (32 subintent limit minus 1 headroom).

**(b) Single subintent, multiple CALL_METHODs.** All vaults same owner = same signer. Just do all closes in one subintent. 1000-instruction limit = huge headroom.

**Pattern guidance: (b) for own-funds case.** Subintents are the wrong tool when one signer. Use them only when a third party (e.g. an engine relayer) submits + pays fees on user's behalf — then user signs once, relayer fires when kill-switch trips.

### C. N-of-M multi-sig coordination

Subintents enable off-chain signature coordination without a babysitting component:
- Each signer signs subintent: `VERIFY_PARENT require(signature_of(PROPOSAL_COORDINATOR)); CALL_METHOD <signer_account> "create_proof_of_amount" <governor_badge>; YIELD_TO_PARENT;`
- Coordinator collects N signed subintents, builds parent that fans out (each contributes badge proof to auth zone), then calls protected method requiring N-of-M rule
- Atomic: either all N show up + executes, or nothing

Caveat: 32-subintent limit + depth 4 = scales to ~31 signers per proposal. Plenty for any realistic governance multi-sig.

**Alternative:** Radix's native `AccessRule::Protected(...ProofRule::CountOf(n, [...])`) on a proposal component — traditional approach where signers each call `vote()` with their badge. Both work; subintent approach saves operational state.

## Audit checklist for subintent-using blueprints

- [ ] Every subintent has explicit expiry (epoch range or `afterDelay`)
- [ ] Every subintent that performs irreversible action has `VERIFY_PARENT` constraining replayers
- [ ] Subintent stubs never include `LOCK_FEE` (parent pays)
- [ ] Bucket flows: every bucket taken from worktop is either yielded, deposited, or burned
- [ ] No subintent depth > 4
- [ ] No tx with > 32 subintents
- [ ] No tx with > 64 signatures
- [ ] Expiry windows are appropriate to the use case (short for time-sensitive, long is okay for limit orders)

## Reference repos

- [radix-dapp-toolkit](https://github.com/radixdlt/radix-dapp-toolkit) — official frontend SDK for subintent submission
- [InfluxionLabs/anthic-sdk/tree/main/examples/dex-subintent](https://github.com/InfluxionLabs/anthic-sdk/tree/main/examples/dex-subintent) — worked manifest examples
- [docs.anthic.io/concepts/subintents](https://docs.anthic.io/concepts/subintents) — production patterns
- [docs.radixdlt.com/docs/subintents](https://docs.radixdlt.com/docs/subintents) — official primitive docs
- [docs.radixdlt.com/docs/pre-authorizations-and-subintents](https://docs.radixdlt.com/docs/pre-authorizations-and-subintents) — flow walkthrough
- [docs.radixdlt.com/docs/intent-structure](https://docs.radixdlt.com/docs/intent-structure) — limits + auth rules
