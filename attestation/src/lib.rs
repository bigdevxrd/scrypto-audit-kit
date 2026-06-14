//! Scrypto Pre-Audit Attestation Registry — the L3 trust primitive for scrypto-audit-kit.
//!
//! Records a reproducible, on-ledger claim: "scrypto-audit-kit <kit_version> (checklist
//! <checklist_version>) produced report <report_hash> over source <source_hash>, at <level>,
//! with these severity counts, at epoch E." It is **not** a safety guarantee — it is a coverage
//! claim anyone can verify by re-running the kit on the same source and comparing report hashes.
//!
//! Attestation is permissionless (self-attestation); trust comes from reproducibility, not from
//! who minted. A trusted `issuer` (the OWNER) can additionally endorse an attestation. The minted
//! NFT is soulbound (non-transferable once held).
//!
//! ⚠️ REFERENCE IMPLEMENTATION. Build, test, and — eat our own dogfood — pre-audit (run the kit on
//! it) and human-audit this on Linux before any mainnet deployment. It has not been compiled in CI.

use scrypto::prelude::*;

/// The data bound into each soulbound attestation NFT.
#[derive(ScryptoSbor, NonFungibleData)]
pub struct AttestationData {
    pub source_hash: String,        // sha256 (hex) of the analyzed source — the code anchor
    pub report_hash: String,        // sha256 (hex) of report.json
    pub wasm_hash: String,          // sha256 (hex) of the built blueprint wasm ("" if unknown)
    pub kit_version: String,
    pub checklist_version: String,
    pub level: String,              // "L1-static" | "L2-hybrid" | ...
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
    pub level: String,
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
    pub level: String,
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
        attestations: ResourceManager,
        /// source_hash -> latest attestation id, for quick on-ledger lookup.
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

            (component, owner_badge)
        }

        /// Record an attestation and mint its soulbound NFT (deposit it to keep the receipt).
        pub fn attest(&mut self, input: AttestationInput) -> Bucket {
            assert!(!input.source_hash.is_empty(), "source_hash is required");
            assert!(!input.report_hash.is_empty(), "report_hash is required");

            self.count += 1;
            let id = NonFungibleLocalId::integer(self.count);
            let data = AttestationData {
                source_hash: input.source_hash.clone(),
                report_hash: input.report_hash.clone(),
                wasm_hash: input.wasm_hash,
                kit_version: input.kit_version,
                checklist_version: input.checklist_version,
                level: input.level.clone(),
                critical: input.critical,
                high: input.high,
                medium: input.medium,
                low: input.low,
                info: input.info,
                attested_at_epoch: Runtime::current_epoch().number(),
                issuer_verified: false,
            };

            let nft = self.attestations.mint_non_fungible(&id, data);
            self.index.insert(input.source_hash.clone(), id);

            Runtime::emit_event(AttestationCreated {
                attestation_id: self.count,
                source_hash: input.source_hash,
                report_hash: input.report_hash,
                level: input.level,
                critical: input.critical,
                high: input.high,
            });

            nft
        }

        /// The latest attestation id recorded for a source hash, if any.
        pub fn latest_attestation(&self, source_hash: String) -> Option<NonFungibleLocalId> {
            self.index.get(&source_hash).map(|id| id.clone())
        }

        /// Whether any attestation exists for a source hash.
        pub fn is_attested(&self, source_hash: String) -> bool {
            self.index.get(&source_hash).is_some()
        }

        /// Endorse an attestation as issuer-verified (a higher trust tier than self-attestation).
        pub fn mark_verified(&mut self, attestation_id: u64) {
            let id = NonFungibleLocalId::integer(attestation_id);
            self.attestations
                .update_non_fungible_data(&id, "issuer_verified", true);
        }
    }
}
