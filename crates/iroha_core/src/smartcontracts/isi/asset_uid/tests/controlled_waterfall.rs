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

fn retained_waterfall_refund_to_closed_payer(expire: bool) {
    use iroha_data_model::{
        asset::{AssetTransferAvailability, uid_enrollment::AssetUidSystemAccountV1},
        escrow::AssetEscrowStatus,
        isi::{
            asset_transfer_control::{SetAssetHoldingLimit, SetAssetTransferAvailability},
            asset_uid_enrollment::{ActivateAssetUidEnrollmentV1, SetAssetUidSystemAccountV1},
            escrow::{CancelAssetLock, ExpireAssetLock},
            escrow_control::{CancelControlledAssetLockV1, ExpireControlledAssetLockV1},
        },
    };
    let (f, state) = fixture(40, 10);
    let context = super::fi_link::controller(&f, &state);
    let label = if expire {
        "retained-split-expiry"
    } else {
        "retained-split-cancel"
    };
    state
        .block(header(1, 999))
        .commit_world_overlay_for_testing()
        .unwrap();
    let id;
    {
        let mut block = state.block(header(2, 1_000));
        let mut tx = block.transaction_for_fastpq_testing(Hash::new(label));
        f.configure(&mut tx, 1, 50, 30);
        configure_link(&f, &mut tx, &context);
        SetAssetUidSystemAccountV1 {
            account: AssetUidSystemAccountV1 {
                asset_definition_id: f.definition.clone(),
                account_id: f.owner.clone(),
                revision: 1,
                enabled: true,
            },
        }
        .execute(&f.owner, &mut tx)
        .unwrap();
        ActivateAssetUidEnrollmentV1 {
            asset_definition_id: f.definition.clone(),
        }
        .execute(&f.owner, &mut tx)
        .unwrap();
        id = open(&f, &mut tx, &context, &f.first, 30, label);
        // Existing ownership is 50, including the reserve. The owner-approved
        // current cap requires exactly 10 to the FI and 20 back to this payer.
        f.configure(&mut tx, 2, 40, 30);
        SetAssetTransferAvailability {
            account_id: f.first.clone(),
            asset_definition_id: f.definition.clone(),
            expected_revision: 0,
            incoming: AssetTransferAvailability::Disabled,
            outgoing: AssetTransferAvailability::Disabled,
            reason: Some("closed payer after opening".into()),
        }
        .execute(&f.owner, &mut tx)
        .unwrap();
        SetAssetHoldingLimit {
            account_id: f.first.clone(),
            asset_definition_id: f.definition.clone(),
            holding_limit: Some(Quantity::zero()),
        }
        .execute(&f.owner, &mut tx)
        .unwrap();
        assert_eq!(f.balance(&tx, &f.first), Quantity::from(10_u32));
        assert_eq!(f.holdings(&tx), Quantity::from(50_u32));
        tx.apply();
        block.commit_world_overlay_for_testing().unwrap();
    }
    let mut block = state.block(header(3, 3_000));
    let mut tx = block.transaction_for_fastpq_testing(Hash::new(format!("{label}-settle")));
    let original = tx.world.asset_escrows.get(&id).unwrap().clone();
    assert_eq!(original.seller, f.first);
    let waterfall = Some(AssetLockWaterfallSettlementV1 {
        expected_policy_revision: 2,
        expected_link_revision: 2,
    });
    let instruction: InstructionBox = if expire {
        ExpireControlledAssetLockV1 {
            expiry: ExpireAssetLock::new(id),
            waterfall,
        }
        .into()
    } else {
        CancelControlledAssetLockV1 {
            cancel: CancelAssetLock::new(id, 30_u32),
            waterfall,
        }
        .into()
    };
    run(&mut tx, &context, instruction.clone()).expect(
        "split retained-payer refund keeps the receiver-control exemption in the aggregate",
    );
    assert_eq!(f.balance(&tx, &f.first), Quantity::from(30_u32));
    assert_eq!(f.balance(&tx, &f.second), Quantity::from(10_u32));
    assert_eq!(f.balance(&tx, &f.payee), Quantity::from(10_u32));
    assert_eq!(f.balance(&tx, &original.custody), Quantity::zero());
    assert_eq!(f.holdings(&tx), Quantity::from(40_u32));
    let terminal = tx.world.asset_escrows.get(&id).unwrap().clone();
    assert_eq!(terminal.seller, original.seller);
    assert_eq!(terminal.custody, original.custody);
    assert_eq!(
        terminal.status,
        if expire {
            AssetEscrowStatus::Expired
        } else {
            AssetEscrowStatus::Cancelled
        }
    );
    assert!(terminal.remaining_amount.is_zero());
    assert_eq!(terminal.closed_at_ms, Some(3_000));
    let usage = asset_uid::views(tx.world(), &f.definition, Some(&[7; 32]), 3_000, 3)
        .unwrap()
        .remove(0);
    assert_eq!(usage.daily_spend_usage, Quantity::from(30_u32));
    assert_eq!(usage.daily_outgoing_usage, Quantity::from(30_u32));
    run(&mut tx, &context, instruction).expect_err("the exact retained remainder is consumed once");
    assert_eq!(tx.world.asset_escrows.get(&id), Some(&terminal));
    assert_eq!(f.balance(&tx, &f.first), Quantity::from(30_u32));
    assert_eq!(f.balance(&tx, &f.payee), Quantity::from(10_u32));
    f.transfer(&mut tx, &f.owner, &f.first, 1)
        .expect_err("ordinary third-party incoming remains closed");
    f.transfer(&mut tx, &f.first, &f.payee, 1)
        .expect_err("ordinary outgoing remains closed after the retained refund");
}

#[test]
fn controlled_waterfall_cancel_preserves_exact_retained_payer_cap_exemption() {
    retained_waterfall_refund_to_closed_payer(false);
}

#[test]
fn controlled_waterfall_expiry_preserves_exact_retained_payer_cap_exemption() {
    retained_waterfall_refund_to_closed_payer(true);
}

#[test]
fn controlled_waterfall_still_checks_combined_fi_destination_cap() {
    use iroha_data_model::isi::{
        asset_transfer_control::SetAssetHoldingLimit, error::AssetTransferAdmissionError,
    };
    let (f, state) = fixture(40, 10);
    let context = super::fi_link::controller(&f, &state);
    state
        .block(header(1, 999))
        .commit_world_overlay_for_testing()
        .unwrap();
    let mut block = state.block(header(2, 1_000));
    let mut tx = block.transaction_for_fastpq_testing(Hash::new("aggregate-fi-cap-preserved"));
    f.configure(&mut tx, 1, 50, 0);
    configure_link(&f, &mut tx, &context);
    let id = open(&f, &mut tx, &context, &f.owner, 30, "fi-cap-split");
    f.configure(&mut tx, 2, 20, 0);
    // Each independently prepared FI credit is 30. Only the aggregate sees 60.
    let mut cap = SetAssetHoldingLimit {
        account_id: f.payee.clone(),
        asset_definition_id: f.definition.clone(),
        holding_limit: Some(Quantity::from(50_u32)),
    };
    cap.clone().execute(&f.owner, &mut tx).unwrap();
    let original = tx.world.asset_escrows.get(&id).unwrap().clone();
    let error = run(&mut tx, &context, draw(id, 30, 2))
        .expect_err("two different source policies cannot evade the common FI destination cap");
    assert!(matches!(
        error,
        iroha_data_model::executor::ValidationFail::InstructionFailed(
            Error::AssetTransferAdmission(AssetTransferAdmissionError::HoldingLimitExceeded(_))
        )
    ));
    assert_eq!(tx.world.asset_escrows.get(&id), Some(&original));
    assert_eq!(f.balance(&tx, &f.first), Quantity::from(40_u32));
    assert_eq!(f.balance(&tx, &f.payee), Quantity::zero());
    assert_eq!(f.balance(&tx, &original.custody), Quantity::from(30_u32));
    let usage = asset_uid::views(tx.world(), &f.definition, Some(&[7; 32]), 1_000, 2)
        .unwrap()
        .remove(0);
    assert_eq!(usage.daily_spend_usage, Quantity::zero());
    assert_eq!(usage.daily_outgoing_usage, Quantity::zero());
    cap.holding_limit = Some(Quantity::from(60_u32));
    cap.execute(&f.owner, &mut tx).unwrap();
    run(&mut tx, &context, draw(id, 30, 2)).expect("the exact combined FI limit is sufficient");
    assert_eq!(f.balance(&tx, &f.payee), Quantity::from(60_u32));
    assert_eq!(f.balance(&tx, &f.first), Quantity::from(10_u32));
    assert_eq!(f.balance(&tx, &original.custody), Quantity::zero());
    assert_eq!(f.holdings(&tx), Quantity::from(20_u32));
}

#[test]
fn controlled_waterfall_new_beneficiary_keeps_ordinary_destination_cap() {
    use iroha_data_model::isi::{
        asset_transfer_control::SetAssetHoldingLimit, error::AssetTransferAdmissionError,
    };
    let (f, state) = fixture(40, 10);
    let context = super::fi_link::controller(&f, &state);
    state
        .block(header(1, 999))
        .commit_world_overlay_for_testing()
        .unwrap();
    let mut block = state.block(header(2, 1_000));
    let mut tx = block.transaction_for_fastpq_testing(Hash::new("nonpayer-cap-preserved"));
    f.configure(&mut tx, 1, 80, 0);
    configure_link(&f, &mut tx, &context);
    let id = open(&f, &mut tx, &context, &f.owner, 30, "new-beneficiary-cap");
    let mut cap = SetAssetHoldingLimit {
        account_id: f.first.clone(),
        asset_definition_id: f.definition.clone(),
        holding_limit: Some(Quantity::from(40_u32)),
    };
    cap.clone().execute(&f.owner, &mut tx).unwrap();
    let original = tx.world.asset_escrows.get(&id).unwrap().clone();
    assert_ne!(original.seller, f.first);
    let error = run(&mut tx, &context, draw(id, 30, 1))
        .expect_err("native custody alone does not grant the retained-payer exemption");
    assert!(matches!(
        error,
        iroha_data_model::executor::ValidationFail::InstructionFailed(
            Error::AssetTransferAdmission(AssetTransferAdmissionError::HoldingLimitExceeded(_))
        )
    ));
    assert_eq!(tx.world.asset_escrows.get(&id), Some(&original));
    assert_eq!(f.balance(&tx, &f.first), Quantity::from(40_u32));
    assert_eq!(f.balance(&tx, &original.custody), Quantity::from(30_u32));
    cap.holding_limit = Some(Quantity::from(70_u32));
    cap.execute(&f.owner, &mut tx).unwrap();
    run(&mut tx, &context, draw(id, 30, 1))
        .expect("ordinary beneficiary cap still admits its boundary");
    assert_eq!(f.balance(&tx, &f.first), Quantity::from(70_u32));
    assert_eq!(f.balance(&tx, &f.payee), Quantity::zero());
    assert_eq!(f.holdings(&tx), Quantity::from(80_u32));
}
