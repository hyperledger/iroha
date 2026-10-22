//! Native execution checks for shared UID ownership, limits and retained usage.

use super::*;
use crate::{
    kura::Kura,
    query::store::LiveQueryStore,
    state::{State, World, WorldReadOnly},
};
use iroha_crypto::{Algorithm, Hash, KeyPair};
use iroha_data_model::{
    Registrable,
    asset::{Asset, AssetDefinition, uid::AssetUidPolicyV1},
    escrow::{
        ConditionalEscrowCondition, ConditionalEscrowOracleCondition, ConditionalEscrowPredicate,
        ConditionalEscrowValue, EscrowId,
    },
    isi::{
        Mint, Transfer, Unregister,
        escrow::{
            AttestEscrowCondition, ExpireConditionalEscrow, OpenAssetLock, OpenConditionalEscrow,
        },
        transfer::{TransferAssetBatch, TransferAssetBatchEntry},
    },
    prelude::{Account, BlockHeader, Domain},
};
use iroha_model_base::domain::DomainId;
use iroha_primitives::numeric::Quantity;
use std::{collections::BTreeSet, num::NonZeroU64};

struct Fixture {
    owner: AccountId,
    first: AccountId,
    second: AccountId,
    payee: AccountId,
    attestor: AccountId,
    definition: AssetDefinitionId,
}

fn account(seed: u8) -> AccountId {
    AccountId::new(
        KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519)
            .expect("fixture key")
            .public_key()
            .clone(),
    )
}

fn fixture(first: u32, second: u32) -> (Fixture, State) {
    let f = Fixture {
        owner: account(121),
        first: account(122),
        second: account(123),
        payee: account(124),
        attestor: account(125),
        definition: AssetDefinitionId::derive_from_components(
            DomainId::try_new("uid", "universal").unwrap(),
            "ds".parse().unwrap(),
        ),
    };
    let domain = Domain::new(DomainId::try_new("uid", "universal").unwrap()).build(&f.owner);
    let mut definition =
        AssetDefinition::numeric(f.definition.clone(), "DS", AssetBalancePolicy::Global, None)
            .build(&f.owner);
    definition.total_quantity = Quantity::from(1_000 + first + second);
    let assets = [(&f.owner, 1_000), (&f.first, first), (&f.second, second)]
        .into_iter()
        .filter(|(_, amount)| *amount > 0)
        .map(|(id, amount)| Asset::new(f.asset(id), Quantity::from(amount)));
    let world = World::with_assets(
        [domain],
        [&f.owner, &f.first, &f.second, &f.payee, &f.attestor]
            .into_iter()
            .map(|id| Account::new(id.clone()).build(&f.owner)),
        [definition],
        assets,
        [],
    );
    {
        let mut parameters = world.parameters.block();
        parameters
            .set_parameter(crate::sumeragi::lanes::routing::test_support::metadata(
                iroha_data_model::block::consensus::SumeragiRootScope::Global,
            ))
            .unwrap();
        parameters.commit();
    }
    let state = State::new_for_testing(
        world,
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    );
    (f, state)
}

fn header(height: u64, now_ms: u64) -> BlockHeader {
    BlockHeader::new(NonZeroU64::new(height).unwrap(), None, None, now_ms, 0)
}

impl Fixture {
    fn asset(&self, account: &AccountId) -> AssetId {
        AssetId::new(self.definition.clone(), account.clone())
    }
    fn policy(&self, revision: u64, cap: u32, daily: u32) -> AssetUidPolicyV1 {
        AssetUidPolicyV1 {
            asset_definition_id: self.definition.clone(),
            uid: [7; 32],
            revision,
            accounts: BTreeSet::from([self.first.clone(), self.second.clone()]),
            holding_limit: Some(cap.into()),
            daily_window: iroha_data_model::asset::uid::AssetUidDailyWindowV1::UtcDay,
            daily_spend_limit: Some(daily.into()),
            daily_outgoing_limit: None,
        }
    }
    fn configure(&self, tx: &mut StateTransaction<'_, '_>, revision: u64, cap: u32, daily: u32) {
        SetAssetUidPolicyV1 {
            policy: self.policy(revision, cap, daily),
        }
        .execute(&self.owner, tx)
        .expect("configure UID");
    }
    fn transfer(
        &self,
        tx: &mut StateTransaction<'_, '_>,
        from: &AccountId,
        to: &AccountId,
        amount: u32,
    ) -> Result<(), Error> {
        Transfer::asset_quantity(self.asset(from), amount, to.clone()).execute(from, tx)
    }
    fn holdings(&self, tx: &StateTransaction<'_, '_>) -> Quantity {
        let policy = asset_uid::policy(tx.world(), &self.definition, &[7; 32])
            .unwrap()
            .unwrap();
        asset_uid::holdings(tx.world(), &policy, &Default::default()).unwrap()
    }
    fn balance(&self, tx: &StateTransaction<'_, '_>, account: &AccountId) -> Quantity {
        tx.world
            .assets
            .get(&self.asset(account))
            .map(|v| v.as_ref().clone())
            .unwrap_or_else(Quantity::zero)
    }
    fn escrow(&self, label: &str, amount: u32, expiry: u64) -> OpenConditionalEscrow {
        OpenConditionalEscrow::new(
            EscrowId::new(Hash::new(label)),
            self.definition.clone(),
            self.payee.clone(),
            amount,
            vec![ConditionalEscrowCondition::Oracle(
                ConditionalEscrowOracleCondition {
                    id: "confirmed".parse().unwrap(),
                    attestor: self.attestor.clone(),
                    predicate: ConditionalEscrowPredicate::Equals(ConditionalEscrowValue::Bool(
                        true,
                    )),
                    sequence: core::num::NonZeroU32::new(1).unwrap(),
                },
            )],
            expiry,
        )
    }
}

#[test]
fn uid_owner_revision_and_membership_cannot_be_bypassed() {
    let (f, state) = fixture(30, 20);
    let mut block = state.block(header(1, 1_000));
    let mut tx = block.transaction();
    let policy = f.policy(1, 50, 100);
    assert!(
        SetAssetUidPolicyV1 {
            policy: policy.clone()
        }
        .execute(&f.first, &mut tx)
        .is_err()
    );
    assert!(
        asset_uid::binding(tx.world(), &f.definition, &f.first)
            .unwrap()
            .is_none()
    );
    f.configure(&mut tx, 1, 50, 100);
    assert!(
        SetAssetUidPolicyV1 { policy }
            .execute(&f.owner, &mut tx)
            .is_err()
    );
    let mut shrink = f.policy(2, 50, 100);
    shrink.accounts.remove(&f.first);
    assert!(
        SetAssetUidPolicyV1 { policy: shrink }
            .execute(&f.owner, &mut tx)
            .is_err()
    );
    let mut rebind = f.policy(1, 50, 100);
    rebind.uid = [8; 32];
    assert!(
        SetAssetUidPolicyV1 { policy: rebind }
            .execute(&f.owner, &mut tx)
            .is_err()
    );
    assert!(
        Unregister::account(f.first.clone())
            .execute(&f.owner, &mut tx)
            .is_err()
    );
    assert!(
        Unregister::asset_definition(f.definition.clone())
            .execute(&f.owner, &mut tx)
            .is_err()
    );
    asset_uid::validate_persistence(tx.world()).expect("canonical reciprocal bindings");
}

#[test]
fn uid_mint_and_direct_transfer_share_one_receiving_cap() {
    let (f, state) = fixture(30, 20);
    let mut block = state.block(header(1, 1_000));
    let mut tx = block.transaction_for_fastpq_testing(Hash::new("uid-cap"));
    f.configure(&mut tx, 1, 50, 100);
    let mint_error = Mint::asset_quantity(1_u32, f.asset(&f.second))
        .execute(&f.owner, &mut tx)
        .unwrap_err();
    assert!(matches!(
        mint_error,
        Error::AssetTransferAdmission(
            iroha_data_model::isi::error::AssetTransferAdmissionError::HoldingLimitExceeded(_)
        )
    ));
    f.transfer(&mut tx, &f.owner, &f.first, 1)
        .expect_err("sibling wallet has exhausted the UID cap");
    assert_eq!(f.holdings(&tx), Quantity::from(50_u32));
    f.transfer(&mut tx, &f.first, &f.payee, 10).unwrap();
    f.transfer(&mut tx, &f.owner, &f.second, 10).unwrap();
    assert_eq!(f.holdings(&tx), Quantity::from(50_u32));
    assert_eq!(f.balance(&tx, &f.first), Quantity::from(20_u32));
    assert_eq!(f.balance(&tx, &f.second), Quantity::from(30_u32));
}

#[test]
fn uid_reduction_preserves_funds_and_daily_usage() {
    let (f, state) = fixture(30, 20);
    let mut block = state.block(header(1, 1_000));
    let mut tx = block.transaction_for_fastpq_testing(Hash::new("uid-reduction"));
    f.configure(&mut tx, 1, 50, 30);
    f.transfer(&mut tx, &f.first, &f.payee, 15).unwrap();
    f.configure(&mut tx, 2, 20, 20);
    assert_eq!(f.holdings(&tx), Quantity::from(35_u32));
    f.transfer(&mut tx, &f.owner, &f.second, 1)
        .expect_err("new credit exceeds reduced cap");
    f.transfer(&mut tx, &f.second, &f.payee, 6)
        .expect_err("revision retains consumed activity");
    f.transfer(&mut tx, &f.second, &f.first, 5)
        .expect("same UID transfer creates no new holdings");
    f.transfer(&mut tx, &f.first, &f.payee, 1)
        .expect_err("shared daily activity is exhausted");
    assert_eq!(f.holdings(&tx), Quantity::from(35_u32));
    asset_uid::validate_persistence(tx.world())
        .expect("reduced cap with retained holdings is valid state");
}

#[test]
fn uid_batch_legs_observe_prior_credits_and_keep_refusals_local() {
    let (f, state) = fixture(20, 20);
    let mut block = state.block(header(1, 1_000));
    let mut tx = block.transaction_for_fastpq_testing(Hash::new("uid-independent"));
    f.configure(&mut tx, 1, 50, 100);
    let entries = vec![
        TransferAssetBatchEntry::with_leg_id(
            "first",
            f.owner.clone(),
            f.first.clone(),
            f.definition.clone(),
            10_u32,
        ),
        TransferAssetBatchEntry::with_leg_id(
            "second",
            f.owner.clone(),
            f.second.clone(),
            f.definition.clone(),
            1_u32,
        ),
    ];
    TransferAssetBatch::new(entries.clone())
        .execute(&f.owner, &mut tx)
        .expect_err("atomic aggregate overflow");
    assert_eq!(f.holdings(&tx), Quantity::from(40_u32));
    TransferAssetBatch::independent(entries)
        .execute(&f.owner, &mut tx)
        .expect("one settled and one refused");
    assert_eq!(f.balance(&tx, &f.first), Quantity::from(30_u32));
    assert_eq!(f.balance(&tx, &f.second), Quantity::from(20_u32));
    assert_eq!(f.balance(&tx, &f.owner), Quantity::from(990_u32));
}

#[test]
fn uid_conditional_custody_keeps_holdings_and_spending_charged_once() {
    let (f, state) = fixture(40, 10);
    let mut block = state.block(header(1, 1_000));
    let mut tx = block.transaction_for_fastpq_testing(Hash::new("uid-escrow-release"));
    f.configure(&mut tx, 1, 50, 30);
    let opening = f.escrow("uid-conditional", 30, 50_000);
    let escrow_id = opening.escrow_id;
    opening.execute(&f.first, &mut tx).unwrap();
    assert_eq!(f.balance(&tx, &f.first), Quantity::from(10_u32));
    assert_eq!(f.holdings(&tx), Quantity::from(50_u32));
    f.transfer(&mut tx, &f.owner, &f.second, 1)
        .expect_err("locked funds still count");
    f.transfer(&mut tx, &f.first, &f.payee, 1)
        .expect_err("opening already used the daily budget");
    AttestEscrowCondition::new(
        escrow_id,
        "confirmed".parse().unwrap(),
        ConditionalEscrowValue::Bool(true),
        Some(Hash::new("scanner fact")),
    )
    .execute(&f.attestor, &mut tx)
    .expect("release consumes no second activity allowance");
    assert_eq!(f.holdings(&tx), Quantity::from(20_u32));
    assert_eq!(f.balance(&tx, &f.payee), Quantity::from(30_u32));
    f.transfer(&mut tx, &f.owner, &f.second, 30).unwrap();
    f.transfer(&mut tx, &f.second, &f.payee, 1)
        .expect_err("release did not reset usage");
}

#[test]
fn uid_expiry_refunds_above_reduced_cap_without_resetting_usage() {
    let (f, state) = fixture(40, 10);
    {
        let mut block = state.block(header(1, 1_000));
        let mut tx = block.transaction_for_fastpq_testing(Hash::new("uid-escrow-refund-open"));
        f.configure(&mut tx, 1, 50, 30);
        f.escrow("uid-refund", 30, 2_000)
            .execute(&f.first, &mut tx)
            .unwrap();
        f.configure(&mut tx, 2, 20, 30);
        tx.apply();
        block.commit_world_overlay_for_testing().unwrap();
    }
    {
        let mut block = state.block(header(2, 2_001));
        let mut tx = block.transaction_for_fastpq_testing(Hash::new("uid-escrow-refund-expire"));
        ExpireConditionalEscrow::new(EscrowId::new(Hash::new("uid-refund")))
            .execute(&f.attestor, &mut tx)
            .expect("refund does not increase beneficial holdings");
        assert_eq!(f.balance(&tx, &f.first), Quantity::from(40_u32));
        assert_eq!(f.holdings(&tx), Quantity::from(50_u32));
        f.transfer(&mut tx, &f.second, &f.payee, 1)
            .expect_err("refund does not reset activity");
        tx.apply();
        block.commit_world_overlay_for_testing().unwrap();
    }
    let mut block = state.block(header(3, 86_400_000));
    let mut tx = block.transaction_for_fastpq_testing(Hash::new("uid-next-day"));
    f.transfer(&mut tx, &f.second, &f.payee, 1)
        .expect("UTC calendar day starts a fresh budget");
    assert_eq!(f.holdings(&tx), Quantity::from(49_u32));
}

#[test]
fn uid_expiry_refund_preserves_exhausted_outgoing_budget_after_cap_reduction() {
    use iroha_data_model::asset::uid::AssetUidDailyWindowV1;

    // Both the exact exhausted ceiling and a later reduction must allow the
    // original payer to recover custody without charging the same funds again.
    for outgoing_after in [1_000_u32, 999] {
        let (f, state) = fixture(1_400, 100);
        let now = 1_792_843_200_000;
        let id = EscrowId::new(Hash::new("uid-exhausted-outgoing-refund"));
        {
            let mut block = state.block(header(1, now));
            let mut tx = block
                .transaction_for_fastpq_testing(Hash::new("uid-exhausted-outgoing-refund-open"));
            let mut policy = f.policy(1, 1_500, 1_000);
            policy.daily_window = AssetUidDailyWindowV1::JerusalemDay;
            policy.daily_outgoing_limit = Some(1_000_u32.into());
            SetAssetUidPolicyV1 {
                policy: policy.clone(),
            }
            .execute(&f.owner, &mut tx)
            .unwrap();
            f.escrow("uid-exhausted-outgoing-refund", 1_000, now + 1_000)
                .execute(&f.first, &mut tx)
                .expect("funding may consume exactly the two daily ceilings");
            f.transfer(&mut tx, &f.second, &f.payee, 1)
                .expect_err("sibling wallets share the exhausted outgoing ceiling");
            assert_eq!(f.balance(&tx, &f.first), Quantity::from(400_u32));
            assert_eq!(f.balance(&tx, &f.second), Quantity::from(100_u32));
            assert_eq!(f.balance(&tx, &f.payee), Quantity::zero());
            let used = asset_uid::views(tx.world(), &f.definition, Some(&[7; 32]), now, 1)
                .unwrap()
                .remove(0);
            assert_eq!(used.daily_spend_usage, Quantity::from(1_000_u32));
            assert_eq!(used.daily_outgoing_usage, Quantity::from(1_000_u32));
            policy.revision = 2;
            policy.holding_limit = Some(200_u32.into());
            policy.daily_outgoing_limit = Some(outgoing_after.into());
            SetAssetUidPolicyV1 { policy }
                .execute(&f.owner, &mut tx)
                .unwrap();
            tx.apply();
            block.commit_world_overlay_for_testing().unwrap();
        }
        let mut block = state.block(header(2, now + 1_001));
        let mut tx =
            block.transaction_for_fastpq_testing(Hash::new("uid-exhausted-outgoing-refund-expire"));
        ExpireConditionalEscrow::new(id)
            .execute(&f.attestor, &mut tx)
            .expect("already charged custody returns despite exhausted or reduced ceilings");
        assert_eq!(f.balance(&tx, &f.first), Quantity::from(1_400_u32));
        assert_eq!(f.balance(&tx, &f.second), Quantity::from(100_u32));
        assert_eq!(f.holdings(&tx), Quantity::from(1_500_u32));
        f.transfer(&mut tx, &f.second, &f.payee, 1)
            .expect_err("recovery does not renew either daily allowance");
        assert_eq!(f.balance(&tx, &f.second), Quantity::from(100_u32));
        assert_eq!(f.balance(&tx, &f.payee), Quantity::zero());
        let after = asset_uid::views(tx.world(), &f.definition, Some(&[7; 32]), now + 1_001, 2)
            .unwrap()
            .remove(0);
        assert_eq!(after.daily_spend_usage, Quantity::from(1_000_u32));
        assert_eq!(after.daily_outgoing_usage, Quantity::from(1_000_u32));
        assert_eq!(after.policy.daily_spend_limit, Some(1_000_u32.into()));
        assert_eq!(
            after.policy.daily_outgoing_limit,
            Some(outgoing_after.into())
        );
        asset_uid::validate_persistence(tx.world()).unwrap();
    }
}

#[test]
fn uid_native_lock_cannot_create_an_alternative_holding_bucket() {
    let (f, state) = fixture(40, 10);
    let mut block = state.block(header(1, 1_000));
    let mut tx = block.transaction_for_fastpq_testing(Hash::new("uid-generic-lock"));
    f.configure(&mut tx, 1, 50, 100);
    OpenAssetLock::new(
        EscrowId::new(Hash::new("uid-generic-lock")),
        f.definition.clone(),
        f.payee.clone(),
        30_u32,
    )
    .execute(&f.first, &mut tx)
    .unwrap();
    assert_eq!(f.holdings(&tx), Quantity::from(50_u32));
    Mint::asset_quantity(1_u32, f.asset(&f.second))
        .execute(&f.owner, &mut tx)
        .expect_err("all native custody counts");
}

#[test]
fn uid_snapshot_roundtrip_retains_membership_usage_and_existing_balances() {
    let (f, state) = fixture(30, 20);
    // Complete fixture asset registration before testing the production World
    // decoder. This projection does not grant an authenticated ledger tip.
    state
        .block(header(1, 999))
        .commit_world_overlay_for_testing()
        .unwrap();
    let initial = crate::state::deserialize::decode_world_component_for_testing(&state.world)
        .expect("existing asset state without UID policies remains decodable");
    assert_eq!(
        initial
            .view()
            .assets()
            .get(&f.asset(&f.first))
            .unwrap()
            .as_ref(),
        &Quantity::from(30_u32)
    );
    {
        let mut block = state.block(header(2, 1_000));
        let mut tx = block.transaction_for_fastpq_testing(Hash::new("uid-before-restart"));
        f.configure(&mut tx, 1, 50, 10);
        f.transfer(&mut tx, &f.first, &f.payee, 10).unwrap();
        tx.apply();
        block.commit_world_overlay_for_testing().unwrap();
    }
    let restored = crate::state::deserialize::decode_world_component_for_testing(&state.world)
        .expect("UID policies and usage survive canonical World decoding");
    let state = State::new_for_testing(
        restored,
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    );
    let mut block = state.block(header(3, 2_000));
    let mut tx = block.transaction_for_fastpq_testing(Hash::new("uid-after-restart"));
    f.transfer(&mut tx, &f.second, &f.payee, 1)
        .expect_err("restart preserves sibling usage");
    assert_eq!(f.holdings(&tx), Quantity::from(40_u32));
}

#[test]
fn uid_jerusalem_window_tracks_dst_and_preserves_revision_usage() {
    use iroha_data_model::asset::uid::AssetUidDailyWindowV1;
    use time::macros::datetime;
    let ms = |date: time::OffsetDateTime| u64::try_from(date.unix_timestamp()).unwrap() * 1_000;
    let before = ms(datetime!(2026-03-27 20:59:59 UTC));
    let next = ms(datetime!(2026-03-27 21:00 UTC));
    let (f, state) = fixture(30, 20);
    {
        let mut block = state.block(header(1, before));
        let mut tx = block.transaction_for_fastpq_testing(Hash::new("uid-jerusalem-before"));
        let mut policy = f.policy(1, 50, 10);
        policy.daily_window = AssetUidDailyWindowV1::JerusalemDay;
        SetAssetUidPolicyV1 {
            policy: policy.clone(),
        }
        .execute(&f.owner, &mut tx)
        .unwrap();
        f.transfer(&mut tx, &f.first, &f.payee, 10).unwrap();
        policy.revision = 2;
        policy.holding_limit = Some(20_u32.into());
        SetAssetUidPolicyV1 {
            policy: policy.clone(),
        }
        .execute(&f.owner, &mut tx)
        .unwrap();
        f.transfer(&mut tx, &f.second, &f.payee, 1)
            .expect_err("revision preserves used allowance");
        policy.revision = 3;
        policy.daily_window = AssetUidDailyWindowV1::UtcDay;
        SetAssetUidPolicyV1 { policy }
            .execute(&f.owner, &mut tx)
            .expect_err("calendar cannot change");
        tx.apply();
        block.commit_world_overlay_for_testing().unwrap();
    }
    let mut block = state.block(header(2, next));
    let mut tx = block.transaction_for_fastpq_testing(Hash::new("uid-jerusalem-after"));
    f.transfer(&mut tx, &f.second, &f.payee, 10)
        .expect("Jerusalem midnight starts new day before UTC midnight");
}

#[test]
fn uid_query_rows_enumerate_exact_asset_with_committed_time_and_custody() {
    let (f, state) = fixture(40, 10);
    let mut block = state.block(header(1, 1_000));
    let mut tx = block.transaction_for_fastpq_testing(Hash::new("uid-query-custody"));
    f.configure(&mut tx, 1, 50, 100);
    f.escrow("uid-query-lock", 30, 50_000)
        .execute(&f.first, &mut tx)
        .unwrap();
    let mut other = f.policy(1, 100, 100);
    other.uid = [8; 32];
    other.accounts = BTreeSet::from([f.payee.clone()]);
    SetAssetUidPolicyV1 { policy: other }
        .execute(&f.owner, &mut tx)
        .unwrap();
    let rows = asset_uid::views(tx.world(), &f.definition, None, 1_000, 1).unwrap();
    assert_eq!(rows.len(), 2);
    let selected = asset_uid::views(tx.world(), &f.definition, Some(&[7; 32]), 1_000, 1).unwrap();
    assert_eq!(selected.len(), 1);
    assert_eq!(selected[0].beneficial_holdings, Quantity::from(50_u32));
    assert_eq!(selected[0].daily_spend_usage, Quantity::from(30_u32));
    assert_eq!(selected[0].policy.revision, 1);
    assert_eq!(selected[0].policy.accounts.len(), 2);
    assert_eq!(selected[0].day_start_ms, 0);
    assert_eq!(selected[0].ledger_time_ms, 1_000);
    assert_eq!(selected[0].as_of_height, 1);
    assert!(
        asset_uid::views(tx.world(), &f.definition, Some(&[9; 32]), 1_000, 1)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn uid_controlled_lock_retains_payer_and_blocks_generic_or_unframed_mutation() {
    use crate::executor::{ContractRuntimeExecutionContext, Executor};
    use iroha_data_model::{
        account::{AccountDetails, AccountValue},
        escrow::control::{AssetLockControlV1, controlled_asset_lock_id},
        isi::{
            InstructionBox,
            escrow::{CancelAssetLock, DrawdownAssetLock, ExpireAssetLock},
            escrow_control::{
                CancelControlledAssetLockV1, DrawdownControlledAssetLockV1,
                ExpireControlledAssetLockV1, OpenControlledAssetLockV1,
            },
        },
        smart_contract::ContractAddress,
    };
    use iroha_model_base::topology::DataSpaceId;
    let (f, state) = fixture(40, 10);
    let address =
        ContractAddress::derive(&state.network_id, &f.owner, 901, DataSpaceId::UNIVERSAL).unwrap();
    let controller = address.subject_id();
    let other_address =
        ContractAddress::derive(&state.network_id, &f.owner, 902, DataSpaceId::UNIVERSAL).unwrap();
    {
        let mut world = state.world.block();
        let code = Hash::new("uid-controlled-lock-contract");
        for instance in [&address, &other_address] {
            world.accounts.insert(
                instance.subject_id(),
                AccountValue::new(AccountDetails::default()),
            );
            world.contract_instances.insert(instance.clone(), code);
            world
                .contract_subject_addresses
                .insert(instance.subject_id(), instance.clone());
            world.contract_subject_bindings.insert(
                instance.clone(),
                crate::smartcontracts::code::ContractSubjectBinding::new_direct(
                    instance,
                    f.owner.clone(),
                )
                .with_active_code_hash(code),
            );
        }
        world.commit();
    }
    let context = ContractRuntimeExecutionContext {
        contract_address: address.clone(),
        contract_subject: controller.clone(),
        contract_alias: None,
        entrypoint: "lock".into(),
    };
    let key = b"uid-controlled-native-lock".to_vec();
    let id = controlled_asset_lock_id(&address, &key);
    let mut lock = OpenAssetLock::new(id, f.definition.clone(), f.payee.clone(), 30_u32);
    lock.release_authority = Some(controller.clone());
    lock.expires_at_ms = Some(2_000);
    let open = OpenControlledAssetLockV1 {
        source: f.first.clone(),
        key,
        lock,
        control: AssetLockControlV1 {
            controller: address,
            release_until_ms: NonZeroU64::new(1_500),
            cancel_not_before_ms: NonZeroU64::new(2_500),
        },
    };
    let run = |tx: &mut StateTransaction<'_, '_>,
               instruction: InstructionBox,
               context: Option<&ContractRuntimeExecutionContext>| {
        Executor::Initial.execute_instruction_with_contract_runtime_context(
            tx,
            &controller,
            instruction,
            context,
        )
    };
    {
        state
            .block(header(1, 999))
            .commit_world_overlay_for_testing()
            .unwrap();
        let mut block = state.block(header(2, 1_000));
        let mut tx = block.transaction_for_fastpq_testing(Hash::new("uid-controlled-open"));
        f.configure(&mut tx, 1, 50, 30);
        open.lock
            .clone()
            .execute(&f.first, &mut tx)
            .expect_err("generic lock cannot squat a controller's reserved id");
        iroha_data_model::isi::escrow::OpenAssetEscrow::new(id, f.definition.clone(), 1_u32)
            .execute(&f.first, &mut tx)
            .expect_err("generic escrow cannot squat a controller's reserved id");
        let mut conditional = f.escrow("controlled-id-squat", 1, 2_000);
        conditional.escrow_id = id;
        conditional
            .execute(&f.first, &mut tx)
            .expect_err("conditional and atomic opening admission reserve controlled ids");
        let mut other = open.clone();
        other.control.controller = other_address.clone();
        other.lock.release_authority = Some(other_address.subject_id());
        let other_context = ContractRuntimeExecutionContext {
            contract_address: other_address.clone(),
            contract_subject: other_address.subject_id(),
            ..context.clone()
        };
        let error = Executor::Initial
            .execute_instruction_with_contract_runtime_context(
                &mut tx,
                &other_address.subject_id(),
                other.into(),
                Some(&other_context),
            )
            .expect_err("another authenticated controller cannot squat this id");
        assert!(
            matches!(
                &error,
                iroha_data_model::executor::ValidationFail::InstructionFailed(
                    iroha_data_model::isi::error::InstructionExecutionError::InvariantViolation(message)
                ) if message.as_ref() == "controlled asset lock id differs from its exact controller and key"
            ),
            "{error:?}"
        );
        for key in [Vec::new(), vec![0; 4_097], b"changed-key".to_vec()] {
            let mut invalid = open.clone();
            invalid.key = key;
            run(&mut tx, invalid.into(), Some(&context))
                .expect_err("keys must be bounded and match the exact derived id");
        }
        run(&mut tx, open.clone().into(), Some(&context)).expect_err("source debit grant required");
        assert_eq!(f.balance(&tx, &f.first), Quantity::from(40_u32));
        tx.world.account_permissions.insert(
            controller.clone(),
            BTreeSet::from([
                iroha_executor_data_model::permission::asset::CanTransferAsset {
                    asset: f.asset(&f.first),
                }
                .into(),
            ]),
        );
        run(&mut tx, open.clone().into(), None)
            .expect_err("signed subject alone is not a runtime frame");
        run(&mut tx, open.clone().into(), Some(&context))
            .expect("authenticated controller directly funds from payer");
        run(&mut tx, open.into(), Some(&context)).expect_err("duplicate lock cannot fund twice");
        assert_eq!(tx.world.asset_escrows.get(&id).unwrap().seller, f.first);
        assert_eq!(f.balance(&tx, &controller), Quantity::zero());
        assert_eq!(f.balance(&tx, &f.first), Quantity::from(10_u32));
        assert_eq!(f.holdings(&tx), Quantity::from(50_u32));
        f.transfer(&mut tx, &f.owner, &f.second, 1)
            .expect_err("payer's retained custody still fills cap");
        let drawdown = DrawdownAssetLock {
            escrow_id: id,
            amount: 10_u32.into(),
            expected_remaining_amount: 30_u32.into(),
        };
        drawdown
            .clone()
            .execute(&controller, &mut tx)
            .expect_err("generic drawdown cannot bypass contract");
        let cancel = CancelAssetLock {
            escrow_id: id,
            expected_remaining_amount: 30_u32.into(),
        };
        cancel
            .clone()
            .execute(&f.first, &mut tx)
            .expect_err("payer cannot bypass controller cancellation");
        run(
            &mut tx,
            CancelControlledAssetLockV1 { cancel, waterfall: None }.into(),
            Some(&context),
        )
        .expect_err("immutable refund window is not open");
        let draw: InstructionBox = DrawdownControlledAssetLockV1 {
            drawdown: drawdown.clone(),
            waterfall: None,
        }
        .into();
        run(&mut tx, draw.clone(), None).expect_err("unframed wrapper denied");
        let mut wrong = context.clone();
        wrong.contract_subject = f.payee.clone();
        run(&mut tx, draw.clone(), Some(&wrong)).expect_err("inconsistent runtime subject denied");
        run(&mut tx, draw.clone(), Some(&context)).unwrap();
        run(&mut tx, draw, Some(&context)).expect_err("remaining CAS prevents replay");
        assert_eq!(f.balance(&tx, &f.payee), Quantity::from(10_u32));
        assert_eq!(f.holdings(&tx), Quantity::from(40_u32));
        f.configure(&mut tx, 2, 10, 30);
        crate::smartcontracts::isi::escrow::controlled::validate_persistence(tx.world()).unwrap();
        tx.apply();
        block.commit_world_overlay_for_testing().unwrap();
    }
    for (height, now, succeeds) in [(3, 2_000, false), (4, 2_500, true)] {
        let mut block = state.block(header(height, now));
        let mut tx = block
            .transaction_for_fastpq_testing(Hash::new(format!("uid-controlled-expire-{height}")));
        let expiry = ExpireAssetLock { escrow_id: id };
        expiry
            .clone()
            .execute(&f.first, &mut tx)
            .expect_err("generic expiry is not controller invocation");
        let result = run(
            &mut tx,
            ExpireControlledAssetLockV1 { expiry, waterfall: None }.into(),
            Some(&context),
        );
        assert_eq!(
            result.is_ok(),
            succeeds,
            "refund requires both expiry and immutable cancellation window: {result:?}"
        );
        if succeeds {
            assert_eq!(f.balance(&tx, &f.first), Quantity::from(30_u32));
            assert_eq!(f.holdings(&tx), Quantity::from(40_u32));
            f.transfer(&mut tx, &f.second, &f.payee, 1)
                .expect_err("refund preserves original activity usage");
        }
        tx.apply();
        block.commit_world_overlay_for_testing().unwrap();
    }
}

mod enrollment;
mod fi_link;
mod controlled_waterfall;
