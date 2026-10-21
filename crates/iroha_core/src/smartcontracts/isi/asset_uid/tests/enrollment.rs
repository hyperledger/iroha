//! Mandatory enrollment, retained classification and native custody-return checks.

use super::*;
use iroha_data_model::{
    asset::{AssetTransferAvailability, uid_enrollment::AssetUidSystemAccountV1},
    isi::{
        Register,
        asset_transfer_control::{SetAssetHoldingLimit, SetAssetTransferAvailability},
        asset_uid_enrollment::{ActivateAssetUidEnrollmentV1, SetAssetUidSystemAccountV1},
    },
};

fn system(
    f: &Fixture,
    tx: &mut StateTransaction<'_, '_>,
    account: &AccountId,
    revision: u64,
    enabled: bool,
) {
    SetAssetUidSystemAccountV1 {
        account: AssetUidSystemAccountV1 {
            asset_definition_id: f.definition.clone(),
            account_id: account.clone(),
            revision,
            enabled,
        },
    }
    .execute(&f.owner, tx)
    .unwrap();
}

fn activate(f: &Fixture, tx: &mut StateTransaction<'_, '_>) -> Result<(), Error> {
    ActivateAssetUidEnrollmentV1 {
        asset_definition_id: f.definition.clone(),
    }
    .execute(&f.owner, tx)
}

#[test]
fn uid_enrollment_blocks_direct_mint_and_batch_credits_to_new_unbound_accounts() {
    let (f, state) = fixture(20, 20);
    let mut block = state.block(header(1, 1_000));
    let mut tx = block.transaction_for_fastpq_testing(Hash::new("uid-unbound-credit"));
    f.configure(&mut tx, 1, 50, 100);
    system(&f, &mut tx, &f.owner, 1, true);
    activate(&f, &mut tx).unwrap();
    let newcomer = account(126);
    Register::account(Account::new(newcomer.clone()))
        .execute(&newcomer, &mut tx)
        .unwrap();
    f.transfer(&mut tx, &f.owner, &newcomer, 1)
        .expect_err("a newly created unbound account cannot evade UID limits");
    Mint::asset_quantity(1_u32, f.asset(&newcomer))
        .execute(&f.owner, &mut tx)
        .expect_err("issuer mint uses the same mandatory enrollment boundary");
    let entries = vec![
        TransferAssetBatchEntry::with_leg_id(
            "unbound",
            f.owner.clone(),
            newcomer.clone(),
            f.definition.clone(),
            1_u32,
        ),
        TransferAssetBatchEntry::with_leg_id(
            "bound",
            f.owner.clone(),
            f.first.clone(),
            f.definition.clone(),
            10_u32,
        ),
    ];
    TransferAssetBatch::new(entries.clone())
        .execute(&f.owner, &mut tx)
        .expect_err("atomic enrollment refusal changes neither leg");
    assert_eq!(f.balance(&tx, &f.owner), Quantity::from(1_000_u32));
    TransferAssetBatch::independent(entries)
        .execute(&f.owner, &mut tx)
        .expect("independent batch commits the enrolled leg only");
    assert_eq!(f.balance(&tx, &newcomer), Quantity::zero());
    assert_eq!(f.balance(&tx, &f.owner), Quantity::from(990_u32));
    assert_eq!(f.holdings(&tx), Quantity::from(50_u32));
    SetAssetUidSystemAccountV1 {
        account: AssetUidSystemAccountV1 {
            asset_definition_id: f.definition.clone(),
            account_id: newcomer.clone(),
            revision: 1,
            enabled: true,
        },
    }
    .execute(&newcomer, &mut tx)
    .expect_err("wallet owners cannot self-exempt as institutions");
    assert_eq!(f.balance(&tx, &newcomer), Quantity::zero());
}

#[test]
fn uid_enrollment_activation_reconciles_retained_money_without_reset_or_identity_assignment() {
    let (f, state) = fixture(20, 20);
    let mut block = state.block(header(1, 1_000));
    let mut tx = block.transaction_for_fastpq_testing(Hash::new("uid-enrollment-reconcile"));
    f.configure(&mut tx, 1, 50, 100);
    system(&f, &mut tx, &f.owner, 1, true);
    Mint::asset_quantity(5_u32, f.asset(&f.attestor))
        .execute(&f.owner, &mut tx)
        .unwrap();
    activate(&f, &mut tx)
        .expect_err("pre-existing unclassified positive balance blocks activation");
    assert_eq!(f.balance(&tx, &f.attestor), Quantity::from(5_u32));
    assert!(
        asset_uid::binding(tx.world(), &f.definition, &f.attestor)
            .unwrap()
            .is_none()
    );
    assert!(
        crate::state::asset_uid_enrollment::enrollment(tx.world(), &f.definition)
            .unwrap()
            .is_none()
    );
    let mut reconciled = f.policy(1, 10, 100);
    reconciled.uid = [9; 32];
    reconciled.accounts = BTreeSet::from([f.attestor.clone()]);
    SetAssetUidPolicyV1 { policy: reconciled }
        .execute(&f.owner, &mut tx)
        .unwrap();
    activate(&f, &mut tx).unwrap();
    assert_eq!(f.balance(&tx, &f.attestor), Quantity::from(5_u32));
    assert_eq!(f.balance(&tx, &f.owner), Quantity::from(1_000_u32));
    system(&f, &mut tx, &f.owner, 2, false);
    f.transfer(&mut tx, &f.owner, &f.first, 1)
        .expect_err("revoked institutional source is not active for ordinary monetary use");
    f.transfer(&mut tx, &f.first, &f.owner, 1)
        .expect_err("institutional revocation blocks new beneficial credits");
    let mut ambiguous = f.policy(2, 2_000, 100);
    ambiguous.accounts.insert(f.owner.clone());
    SetAssetUidPolicyV1 { policy: ambiguous }
        .execute(&f.owner, &mut tx)
        .expect_err(
            "revocation retains institutional classification rather than creating a UID loophole",
        );
    crate::state::asset_uid_enrollment::validate_persistence(tx.world()).unwrap();
}

#[test]
fn enrolled_expiry_returns_existing_ownership_to_closed_payer_without_new_link_or_usage() {
    let (f, state) = fixture(40, 10);
    let id = EscrowId::new(Hash::new("uid-closed-payer-refund"));
    {
        let mut block = state.block(header(1, 1_000));
        let mut tx = block.transaction_for_fastpq_testing(Hash::new("uid-closed-payer-open"));
        f.configure(&mut tx, 1, 50, 30);
        system(&f, &mut tx, &f.owner, 1, true);
        system(&f, &mut tx, &f.payee, 1, true);
        activate(&f, &mut tx).unwrap();
        f.escrow("uid-closed-payer-refund", 30, 2_000)
            .execute(&f.first, &mut tx)
            .unwrap();
        let custody = tx.world.asset_escrows.get(&id).unwrap().custody.clone();
        f.transfer(&mut tx, &f.owner, &custody, 1)
            .expect_err("an existing custody address is not an ordinary enrollment exemption");
        Mint::asset_quantity(1_u32, f.asset(&custody))
            .execute(&f.owner, &mut tx)
            .expect_err("direct mint cannot create reserves outside the retained lock amount");
        f.configure(&mut tx, 2, 20, 30);
        SetAssetTransferAvailability {
            account_id: f.first.clone(),
            asset_definition_id: f.definition.clone(),
            expected_revision: 0,
            incoming: AssetTransferAvailability::Disabled,
            outgoing: AssetTransferAvailability::Disabled,
            reason: Some("closed wallet".into()),
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
        tx.apply();
        block.commit_world_overlay_for_testing().unwrap();
    }
    let mut block = state.block(header(2, 2_001));
    let mut tx = block.transaction_for_fastpq_testing(Hash::new("uid-closed-payer-expire"));
    ExpireConditionalEscrow::new(id)
        .execute(&f.attestor, &mut tx)
        .expect("native expiry returns retained ownership without a new incoming payment");
    assert_eq!(f.balance(&tx, &f.first), Quantity::from(40_u32));
    assert_eq!(f.holdings(&tx), Quantity::from(50_u32));
    let view = asset_uid::views(tx.world(), &f.definition, Some(&[7; 32]), 2_001, 2)
        .unwrap()
        .remove(0);
    assert_eq!(view.daily_spend_usage, Quantity::from(30_u32));
    assert_eq!(view.daily_outgoing_usage, Quantity::from(30_u32));
    assert!(
        crate::state::asset_fi::link(tx.world(), &f.definition, &f.first)
            .unwrap()
            .is_none()
    );
    f.transfer(&mut tx, &f.owner, &f.first, 1)
        .expect_err("third-party incoming remains closed");
    f.transfer(&mut tx, &f.first, &f.payee, 1)
        .expect_err("returned funds remain frozen for ordinary spending");
    ExpireConditionalEscrow::new(id)
        .execute(&f.attestor, &mut tx)
        .expect_err("a terminal refund cannot move the same reserve twice");
    assert_eq!(f.balance(&tx, &f.first), Quantity::from(40_u32));
}
