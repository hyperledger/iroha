//! Mixed-source settlement must never borrow receiving capacity or debit other wallets.

use super::*;
use crate::executor::{ContractRuntimeExecutionContext, Executor};
use iroha_data_model::{
    escrow::control::{
        AssetLockControlV1, AssetLockWaterfallSettlementV1, controlled_asset_lock_id,
    },
    isi::{
        InstructionBox,
        asset_fi::SetAssetFiLinkV1,
        escrow::DrawdownAssetLock,
        escrow_control::{DrawdownControlledAssetLockV1, OpenControlledAssetLockV1},
    },
};

fn run(
    tx: &mut StateTransaction<'_, '_>,
    context: &ContractRuntimeExecutionContext,
    instruction: impl Into<InstructionBox>,
) -> Result<(), iroha_data_model::executor::ValidationFail> {
    Executor::Initial.execute_instruction_with_contract_runtime_context(
        tx,
        &context.contract_subject,
        instruction.into(),
        Some(context),
    )
}

fn open(
    f: &Fixture,
    tx: &mut StateTransaction<'_, '_>,
    context: &ContractRuntimeExecutionContext,
    source: &AccountId,
    amount: u32,
    label: &str,
) -> EscrowId {
    let key = label.as_bytes().to_vec();
    let id = controlled_asset_lock_id(&context.contract_address, &key);
    tx.world.account_permissions.insert(
        context.contract_subject.clone(),
        BTreeSet::from([
            iroha_executor_data_model::permission::asset::CanTransferAsset {
                asset: f.asset(source),
            }
            .into(),
        ]),
    );
    let mut lock = OpenAssetLock::new(id, f.definition.clone(), f.first.clone(), amount);
    lock.release_authority = Some(context.contract_subject.clone());
    lock.expires_at_ms = Some(3_000);
    run(
        tx,
        context,
        OpenControlledAssetLockV1 {
            source: source.clone(),
            key,
            lock,
            control: AssetLockControlV1 {
                controller: context.contract_address.clone(),
                release_until_ms: NonZeroU64::new(2_000),
                cancel_not_before_ms: NonZeroU64::new(3_000),
            },
        },
    )
    .unwrap();
    id
}

fn configure_link(
    f: &Fixture,
    tx: &mut StateTransaction<'_, '_>,
    context: &ContractRuntimeExecutionContext,
) {
    let mut link = super::fi_link::setup(f, tx);
    link.revision = 2;
    link.controller = Some(context.contract_address.clone());
    link.waterfall = true;
    SetAssetFiLinkV1 {
        link,
        expected_policy_revision: 1,
    }
    .execute(&f.first, tx)
    .unwrap();
}

fn draw(id: EscrowId, amount: u32, policy_revision: u64) -> DrawdownControlledAssetLockV1 {
    DrawdownControlledAssetLockV1 {
        drawdown: DrawdownAssetLock {
            escrow_id: id,
            amount: amount.into(),
            expected_remaining_amount: amount.into(),
        },
        waterfall: Some(AssetLockWaterfallSettlementV1 {
            expected_policy_revision: policy_revision,
            expected_link_revision: 2,
        }),
    }
}

#[test]
fn controlled_waterfall_sweeps_existing_funds_and_custody_in_one_occurrence() {
    let (f, state) = fixture(40, 10);
    let context = super::fi_link::controller(&f, &state);
    state
        .block(header(1, 999))
        .commit_world_overlay_for_testing()
        .unwrap();
    let mut block = state.block(header(2, 1_000));
    let mut tx =
        block.transaction_for_fastpq_testing(Hash::new("mixed-source-controlled-waterfall"));
    f.configure(&mut tx, 1, 50, 0);
    configure_link(&f, &mut tx, &context);
    let id = open(&f, &mut tx, &context, &f.owner, 30, "mixed-sweep");
    f.configure(&mut tx, 2, 20, 0);
    let mut stale = draw(id, 30, 1);
    run(&mut tx, &context, stale.clone()).expect_err("old policy quote cannot settle");
    assert_eq!(f.balance(&tx, &f.first), Quantity::from(40_u32));
    assert_eq!(f.balance(&tx, &f.payee), Quantity::zero());
    stale.waterfall.as_mut().unwrap().expected_policy_revision = 2;
    run(&mut tx, &context, stale.clone()).unwrap();
    assert_eq!(f.holdings(&tx), Quantity::from(20_u32));
    assert_eq!(f.balance(&tx, &f.first), Quantity::from(10_u32));
    assert_eq!(f.balance(&tx, &f.second), Quantity::from(10_u32));
    assert_eq!(f.balance(&tx, &f.payee), Quantity::from(60_u32));
    assert_eq!(f.balance(&tx, &f.owner), Quantity::from(970_u32));
    let usage = asset_uid::views(tx.world(), &f.definition, Some(&[7; 32]), 1_000, 2)
        .unwrap()
        .remove(0);
    assert_eq!(usage.daily_spend_usage, Quantity::zero());
    assert_eq!(usage.daily_outgoing_usage, Quantity::from(30_u32));
    assert!(
        tx.world
            .asset_escrows
            .get(&id)
            .unwrap()
            .remaining_amount
            .is_zero()
    );
    run(&mut tx, &context, stale).expect_err("one CAS consumes the reserve only once");
    assert_eq!(f.balance(&tx, &f.payee), Quantity::from(60_u32));
}

#[test]
fn controlled_waterfall_cannot_use_other_wallets_or_locked_holdings_to_prefund_sweep() {
    let (f, state) = fixture(5, 45);
    let context = super::fi_link::controller(&f, &state);
    state
        .block(header(1, 999))
        .commit_world_overlay_for_testing()
        .unwrap();
    let mut block = state.block(header(2, 1_000));
    let mut tx = block.transaction_for_fastpq_testing(Hash::new("mixed-source-prefunding-refusal"));
    f.configure(&mut tx, 1, 50, 0);
    configure_link(&f, &mut tx, &context);
    let id = open(&f, &mut tx, &context, &f.owner, 30, "unfunded-sweep");
    f.configure(&mut tx, 2, 20, 0);
    run(&mut tx, &context, draw(id, 30, 2))
        .expect_err("selected beneficiary cannot cover its 30 DS sweep");
    assert_eq!(f.balance(&tx, &f.first), Quantity::from(5_u32));
    assert_eq!(f.balance(&tx, &f.second), Quantity::from(45_u32));
    assert_eq!(f.balance(&tx, &f.payee), Quantity::zero());
    assert_eq!(
        tx.world.asset_escrows.get(&id).unwrap().remaining_amount,
        Quantity::from(30_u32)
    );
}

#[test]
fn same_uid_controlled_release_never_adds_retained_reserves_to_holdings_twice() {
    let (f, state) = fixture(40, 10);
    let context = super::fi_link::controller(&f, &state);
    state
        .block(header(1, 999))
        .commit_world_overlay_for_testing()
        .unwrap();
    let mut block = state.block(header(2, 1_000));
    let mut tx = block.transaction_for_fastpq_testing(Hash::new("same-uid-waterfall"));
    f.configure(&mut tx, 1, 50, 30);
    configure_link(&f, &mut tx, &context);
    let id = open(&f, &mut tx, &context, &f.first, 30, "same-uid-release");
    assert_eq!(f.holdings(&tx), Quantity::from(50_u32));
    f.configure(&mut tx, 2, 20, 30);
    run(&mut tx, &context, draw(id, 30, 2)).unwrap();
    assert_eq!(f.holdings(&tx), Quantity::from(20_u32));
    assert_eq!(f.balance(&tx, &f.first), Quantity::from(10_u32));
    assert_eq!(f.balance(&tx, &f.payee), Quantity::from(30_u32));
    let usage = asset_uid::views(tx.world(), &f.definition, Some(&[7; 32]), 1_000, 2)
        .unwrap()
        .remove(0);
    assert_eq!(usage.daily_spend_usage, Quantity::from(30_u32));
    assert_eq!(usage.daily_outgoing_usage, Quantity::from(30_u32));
}

#[test]
fn controlled_waterfall_obeys_link_changes_and_fi_revocation_after_opening() {
    use iroha_data_model::{asset::fi_link::AssetFiV1, isi::asset_fi::SetAssetFiV1};
    let (f, state) = fixture(40, 10);
    let context = super::fi_link::controller(&f, &state);
    state
        .block(header(1, 999))
        .commit_world_overlay_for_testing()
        .unwrap();
    let mut block = state.block(header(2, 1_000));
    let mut tx = block.transaction_for_fastpq_testing(Hash::new("mixed-source-link-revocation"));
    f.configure(&mut tx, 1, 50, 0);
    configure_link(&f, &mut tx, &context);
    let id = open(
        &f,
        &mut tx,
        &context,
        &f.owner,
        30,
        "revocable-fi-waterfall",
    );
    let mut link = crate::state::asset_fi::link(tx.world(), &f.definition, &f.first)
        .unwrap()
        .unwrap();
    link.revision = 3;
    link.waterfall = false;
    SetAssetFiLinkV1 {
        link: link.clone(),
        expected_policy_revision: 1,
    }
    .execute(&f.first, &mut tx)
    .unwrap();
    let mut payment = draw(id, 30, 1);
    run(&mut tx, &context, payment.clone())
        .expect_err("opening cannot pin superseded owner consent");
    payment.waterfall.as_mut().unwrap().expected_link_revision = 3;
    run(&mut tx, &context, payment.clone())
        .expect_err("new revision does not bypass disabled waterfall");
    link.revision = 4;
    link.waterfall = true;
    SetAssetFiLinkV1 {
        link,
        expected_policy_revision: 1,
    }
    .execute(&f.first, &mut tx)
    .unwrap();
    SetAssetFiV1 {
        fi: AssetFiV1 {
            asset_definition_id: f.definition.clone(),
            fi_account_id: f.payee.clone(),
            revision: 2,
            enabled: false,
        },
    }
    .execute(&f.owner, &mut tx)
    .unwrap();
    payment.waterfall.as_mut().unwrap().expected_link_revision = 4;
    run(&mut tx, &context, payment)
        .expect_err("revoked FI cannot receive through retained old approval");
    assert_eq!(f.balance(&tx, &f.first), Quantity::from(40_u32));
    assert_eq!(f.balance(&tx, &f.payee), Quantity::zero());
    assert_eq!(
        tx.world.asset_escrows.get(&id).unwrap().remaining_amount,
        Quantity::from(30_u32)
    );
    assert_eq!(f.holdings(&tx), Quantity::from(50_u32));
}
