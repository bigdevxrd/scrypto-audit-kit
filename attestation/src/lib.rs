//! Scrypto Pre-Audit Attestation Registry — the L3 trust primitive for scrypto-audit-kit.
//!
//! Records an on-ledger claim: "scrypto-audit-kit <kit_version> (checklist <checklist_version>)
//! produced report <report_hash> over source <source_hash>, running <mode>, with these severity
//! counts, at epoch E." It is NOT a safety guarantee. The `source_hash` is the stable anchor;
//! static-tier findings are reproducible from it (re-run `static_ruleset_version`), but the LLM
//! pass is non-deterministic, so `report_hash` is a tamper-evidence fingerprint of one archived
//! report, not a re-derivable value.
//!
//! It records FACTS, never a trust level. `mode` says which analysis ran ("static" | "llm" |
//! "hybrid"), enum-checked so garbage is unrepresentable. The L1/L2/L3 ladder in VISION.md is a different
//! axis — who WITNESSED the run — and is computed off-ledger by the reader from mode + attester
//! identity + `issuer_verified`, per docs/attestation-levels.md. Recording an L-number here would
//! be self-referential: L3 *is* the existence of this record, so it can never be an input to it.
//!
//! Attestation is permissionless: a self-attestation proves only that someone wrote these bytes
//! on-ledger, NOT that the kit was run. The meaningful trust signal is `issuer_verified`, set by a
//! trusted `issuer` (the OWNER). The minted NFT is soulbound (non-transferable once held).
//!
//! ⚠️ REFERENCE IMPLEMENTATION. It type-checks (`cargo check`) and is compile-checked in CI, but it
//! has not been deployed or human-audited. Build, test, pre-audit (run the kit on it), and human-audit
//! before any mainnet use. The wasm32 build needs Linux (Mac's bulk-memory / blst issue).

use scrypto::prelude::*;

/// The data bound into each soulbound attestation NFT.
#[derive(ScryptoSbor, NonFungibleData)]
pub struct AttestationData {
    pub source_hash: String,        // sha256 (hex) of the analyzed source — the code anchor
    pub report_hash: String,        // sha256 (hex) of report.json
    pub wasm_hash: String,          // sha256 (hex) of the built blueprint wasm ("" if unknown)
    pub kit_version: String,
    pub checklist_version: String,
    /// What analysis RAN: "static" | "llm" | "hybrid". A fact, not a trust level — see the
    /// note above `attest` on why no L-number is recorded here.
    pub mode: String,
    /// Version of the deterministic ruleset, so a verifier knows which rules to re-run.
    pub static_ruleset_version: String,
    pub critical: u16,
    pub high: u16,
    pub medium: u16,
    pub low: u16,
    pub info: u16,
    pub attested_at_epoch: u64,
    #[mutable]
    pub issuer_verified: bool,      // false = self-attested; true = endorsed by the issuer
}

/// Caller-supplied attestation fields (one struct keeps the method + manifest tidy).
#[derive(ScryptoSbor)]
pub struct AttestationInput {
    pub source_hash: String,
    pub report_hash: String,
    pub wasm_hash: String,
    pub kit_version: String,
    pub checklist_version: String,
    pub mode: String,
    pub static_ruleset_version: String,
    pub critical: u16,
    pub high: u16,
    pub medium: u16,
    pub low: u16,
    pub info: u16,
}

#[derive(ScryptoSbor, ScryptoEvent)]
pub struct AttestationCreated {
    pub attestation_id: u64,
    pub source_hash: String,
    pub report_hash: String,
    pub mode: String,
    pub critical: u16,
    pub high: u16,
}

#[blueprint]
#[events(AttestationCreated)]
mod attestation_registry {
    enable_method_auth! {
        roles {
            issuer => updatable_by: [OWNER];
        },
        methods {
            attest             => PUBLIC;                // permissionless self-attestation
            latest_attestation => PUBLIC;
            is_attested        => PUBLIC;
            mark_verified      => restrict_to: [issuer]; // trusted endorsement
        }
    }

    struct AttestationRegistry {
        /// The soulbound attestation NFT (non-withdrawable once held).
        attestations: NonFungibleResourceManager,
        /// source_hash -> latest ISSUER-VERIFIED attestation id. Self-attestations are NOT
        /// indexed, so a permissionless caller cannot grief this lookup.
        index: KeyValueStore<String, NonFungibleLocalId>,
        count: u64,
    }

    impl AttestationRegistry {
        /// Instantiate the registry. Returns the component and the owner badge (controls `issuer`).
        pub fn instantiate() -> (Global<AttestationRegistry>, Bucket) {
            let owner_badge = ResourceBuilder::new_fungible(OwnerRole::None)
                .metadata(metadata!(init {
                    "name" => "scrypto-audit-kit attestation owner", locked;
                }))
                .divisibility(DIVISIBILITY_NONE)
                .mint_initial_supply(1);

            let owner_rule = rule!(require(owner_badge.resource_address()));

            let attestations = ResourceBuilder::new_integer_non_fungible::<AttestationData>(
                    OwnerRole::Fixed(owner_rule.clone()))
                .metadata(metadata!(init {
                    "name" => "Scrypto Pre-Audit Attestation", locked;
                    "description" =>
                        "Reproducible record that scrypto-audit-kit produced a given report over given \
                         source. A coverage claim, NOT a safety guarantee.", locked;
                }))
                .mint_roles(mint_roles! {
                    minter => rule!(require(global_caller(AttestationRegistry::blueprint_id())));
                    minter_updater => rule!(deny_all);
                })
                .non_fungible_data_update_roles(non_fungible_data_update_roles! {
                    non_fungible_data_updater =>
                        rule!(require(global_caller(AttestationRegistry::blueprint_id())));
                    non_fungible_data_updater_updater => rule!(deny_all);
                })
                // soulbound: once deposited it can never be withdrawn or moved
                .withdraw_roles(withdraw_roles! {
                    withdrawer => rule!(deny_all);
                    withdrawer_updater => rule!(deny_all);
                })
                .create_with_no_initial_supply();

            let component = Self {
                attestations,
                index: KeyValueStore::new(),
                count: 0,
            }
            .instantiate()
            .prepare_to_globalize(OwnerRole::Fixed(owner_rule.clone()))
            .roles(roles! {
                issuer => owner_rule.clone();
            })
            .globalize();

            (component, owner_badge.into())
        }

        /// Record an attestation and mint its soulbound NFT (deposit it to keep the receipt).
        ///
        /// PERMISSIONLESS BY DESIGN, and the rule below is right to ask. `attest` is declared
        /// PUBLIC, takes no credential and mints — the exact shape `public-privileged-method`
        /// flags. It is accepted here because a self-attestation establishes nothing about
        /// itself: trust is derived by the reader from `mode` + `attester` + `issuer_verified`,
        /// never from the record existing, and an unindexed self-attestation is inert. Anyone
        /// paying their own fee to mint one is the intended behaviour, not a bypass.
        pub fn attest(&mut self, input: AttestationInput) -> Bucket {
            assert!(!input.source_hash.is_empty(), "source_hash is required");
            assert!(!input.report_hash.is_empty(), "report_hash is required");
            // `mode` is a closed set, so garbage is unrepresentable on-ledger. This is the one
            // claim-shaped field left, and the enum check is what keeps it a fact rather than a
            // free-text assertion. NOTE what is deliberately absent: a trust LEVEL. An L-number
            // records who witnessed a run, which a self-attestation cannot establish about
            // itself — "L3-attested" as an input is circular, since L3 *is* this record
            // existing. The reader derives the rung from mode + attester + issuer_verified.
            assert!(
                input.mode == "static" || input.mode == "llm" || input.mode == "hybrid",
                "mode must be \"static\", \"llm\" or \"hybrid\", got {:?}",
                input.mode
            );

            self.count += 1;
            let id = NonFungibleLocalId::integer(self.count);
            let data = AttestationData {
                source_hash: input.source_hash.clone(),
                report_hash: input.report_hash.clone(),
                wasm_hash: input.wasm_hash,
                kit_version: input.kit_version,
                checklist_version: input.checklist_version,
                mode: input.mode.clone(),
                static_ruleset_version: input.static_ruleset_version,
                critical: input.critical,
                high: input.high,
                medium: input.medium,
                low: input.low,
                info: input.info,
                attested_at_epoch: Runtime::current_epoch().number(),
                issuer_verified: false,
            };

            let nft = self.attestations.mint_non_fungible(&id, data);

            Runtime::emit_event(AttestationCreated {
                attestation_id: self.count,
                source_hash: input.source_hash,
                report_hash: input.report_hash,
                mode: input.mode,
                critical: input.critical,
                high: input.high,
            });

            // The NFT is the record; self-attestations are queryable via the event / Gateway but
            // are intentionally NOT indexed — only mark_verified indexes (see below).
            nft.into()
        }

        /// The latest ISSUER-VERIFIED attestation id for a source hash, if any. Self-attestations
        /// are not indexed — query those via the AttestationCreated event / Gateway.
        pub fn latest_attestation(&self, source_hash: String) -> Option<NonFungibleLocalId> {
            self.index.get(&source_hash).map(|id| id.clone())
        }

        /// Whether an ISSUER-VERIFIED attestation exists for a source hash.
        pub fn is_attested(&self, source_hash: String) -> bool {
            self.index.get(&source_hash).is_some()
        }

        /// Endorse an attestation as issuer-verified (a higher trust tier than self-attestation),
        /// and index it so latest_attestation / is_attested reflect only endorsed records.
        pub fn mark_verified(&mut self, attestation_id: u64) {
            assert!(
                attestation_id >= 1 && attestation_id <= self.count,
                "no such attestation"
            );
            let id = NonFungibleLocalId::integer(attestation_id);
            self.attestations
                .update_non_fungible_data(&id, "issuer_verified", true);
            let data: AttestationData = self.attestations.get_non_fungible_data(&id);
            self.index.insert(data.source_hash, id);
        }
    }
}
