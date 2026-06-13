//! ⚠️ DELIBERATELY VULNERABLE — a fixture for scrypto-audit-kit, not real code.
//!
//! This is a toy "yield vault": users deposit XRD and receive shares priced via
//! an oracle; an admin can tune parameters and pause the vault. Every issue below
//! is planted so the kit has something to find. See the matching report at
//! examples/vulnerable-vault.pre-audit.md.
//!
//! DO NOT deploy or copy any of this.

use scrypto::prelude::*;

#[derive(ScryptoSbor)]
pub struct OraclePrice {
    pub price: Decimal,
    pub updated_at: Instant,
}

#[blueprint]
mod vulnerable_vault {
    enable_method_auth! {
        roles {
            // Anti-pattern: admin can rotate itself (no higher authority).
            admin => updatable_by: [admin];
        },
        methods {
            deposit          => PUBLIC;
            withdraw         => PUBLIC;
            set_fee_bps      => restrict_to: [admin];
            set_oracle_price => PUBLIC; // should be admin-only
            emergency_drain  => PUBLIC; // should be admin-only
            pause            => restrict_to: [admin];
            unpause          => restrict_to: [admin];
        }
    }

    struct VulnerableVault {
        vault: Vault,
        share_resource: ResourceManager,
        total_shares: Decimal,
        oracle: OraclePrice,
        fee_bps: Decimal,
        paused: bool,
        unlock_epoch: Epoch,
    }

    impl VulnerableVault {
        pub fn instantiate(initial_price: Decimal) -> (Global<VulnerableVault>, Bucket) {
            let admin_badge = ResourceBuilder::new_fungible(OwnerRole::None)
                .divisibility(DIVISIBILITY_NONE)
                .mint_initial_supply(1);

            let share_resource = ResourceBuilder::new_fungible(OwnerRole::None)
                .mint_roles(mint_roles! {
                    minter => rule!(require(global_caller(VulnerableVault::blueprint_id())));
                    minter_updater => rule!(deny_all);
                })
                .create_with_no_initial_supply();

            let component = Self {
                vault: Vault::new(XRD),
                share_resource,
                total_shares: dec!(0),
                oracle: OraclePrice {
                    price: initial_price,
                    updated_at: Clock::current_time_rounded_to_seconds(),
                },
                fee_bps: dec!(30),
                paused: false,
                unlock_epoch: Runtime::current_epoch(),
            }
            .instantiate()
            .prepare_to_globalize(OwnerRole::None)
            .roles(roles! {
                admin => rule!(require(admin_badge.resource_address()));
            })
            .globalize();

            (component, admin_badge)
        }

        /// Deposit XRD, receive vault shares priced via the oracle.
        pub fn deposit(&mut self, funds: Bucket) -> Bucket {
            let amount = funds.amount();
            // Raw `*` and `/`: division by zero on the first deposit (total_value == 0)
            // and an unchecked multiply that panics on overflow.
            let total_value = self.vault.amount() * self.oracle.price;
            let shares = amount * self.oracle.price / total_value * self.total_shares;
            self.vault.put(funds);
            self.total_shares += shares;
            self.share_resource.mint(shares)
        }

        /// Burn shares, withdraw a proportional amount of XRD.
        pub fn withdraw(&mut self, shares: Bucket) -> Bucket {
            // No `paused` check — withdrawals keep working while the vault is paused.
            let share_amount = shares.amount();
            let proportion = share_amount / self.total_shares;
            let payout = self.vault.amount() * proportion;
            self.total_shares -= share_amount;
            shares.burn();
            self.vault.take(payout)
        }

        /// Set the swap fee. No upper bound — admin can set it above 100%.
        pub fn set_fee_bps(&mut self, bps: Decimal) {
            self.fee_bps = bps;
        }

        /// Update the oracle price. PUBLIC, single-source, no staleness or sanity bound:
        /// anyone can set any price and immediately mint/redeem against it.
        pub fn set_oracle_price(&mut self, price: Decimal) {
            self.oracle = OraclePrice {
                price,
                updated_at: Clock::current_time_rounded_to_seconds(),
            };
        }

        /// Emergency drain. PUBLIC, takes the entire vault in one call, no cap, no cooldown.
        pub fn emergency_drain(&mut self) -> Bucket {
            self.vault.take_all()
        }

        pub fn pause(&mut self) {
            self.paused = true;
            self.unlock_epoch = Runtime::current_epoch();
        }

        /// Unpause. Off-by-one: `>` lets unpause happen one epoch earlier than the
        /// "2 full epochs" the message promises.
        pub fn unpause(&mut self) {
            assert!(
                Runtime::current_epoch().number() > self.unlock_epoch.number() + 1,
                "must stay paused for 2 full epochs"
            );
            self.paused = false;
        }
    }
}
