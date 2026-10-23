//! Real native assertion execution against the UID/FI World fixture.
use super::*;
use crate::smartcontracts::isi::asset_fi_context::current_snapshot;
use iroha_data_model::{
    asset::fi_context::{
        AssetFiContextTargetV1, asset_fi_context_snapshot_hash_v1,
        asset_fi_transfer_receipt_hash_v1,
    },
    isi::{
        asset_fi::SetAssetFiLinkV1,
        asset_fi_context::{AssertAssetFiContextV1, AssertAssetFiTransferReceiptV1},
    },
};

fn floor_fixture() -> (Fixture, State, [u8; 32]) {
    let (f, state) = fixture(40, 10);
    let floor = header(1, 999);
    let hash = *floor.hash().as_ref();
    state.block(floor).commit_empty_block_for_testing().unwrap();
    (f, state, hash)
}
fn assertion(
    tx: &StateTransaction<'_, '_>,
    target: AssetFiContextTargetV1,
    floor: [u8; 32],
) -> AssertAssetFiContextV1 {
    let selected = crate::smartcontracts::isi::asset_fi_context::target_selection(&target).unwrap();
    let incarnation = *tx
        .world()
        .axt_asset_incarnations()
        .get(selected.asset_definition_id)
        .unwrap();
    let snapshot = current_snapshot(tx, &target, &incarnation, &[7; 32]).unwrap();
    AssertAssetFiContextV1 {
        target,
        expected_incarnation: incarnation,
        expected_uid: [7; 32],
        expected_context_hash: asset_fi_context_snapshot_hash_v1(&snapshot).unwrap(),
        request_sha256: [0x80; 32],
        challenge: [0x81; 32],
        minimum_height: 1,
        minimum_block_hash: floor,
    }
}
#[test]
fn fi_current_assertion_is_owner_only_exact_at_cut_and_observes_stale_relationships() {
    let (f, state, floor) = floor_fixture();
    let mut block = state.block(header(2, 1_000));
    let mut tx = block.transaction_for_fastpq_testing(Hash::new("fi-context-current"));
    f.configure(&mut tx, 1, 50, 10);
    let link = fi_link::setup(&f, &mut tx);
    let target = AssetFiContextTargetV1::LinkApproval(SetAssetFiLinkV1 {
        link: link.clone(),
        expected_policy_revision: 1,
    });
    let value = assertion(&tx, target, floor);
    let before = tx.pending_transfer_transcript_count_for_testing();
    value.clone().execute(&f.owner, &mut tx).unwrap();
    value
        .clone()
        .execute(&f.first, &mut tx)
        .expect_err("current snapshot is asset-owner only");
    value
        .clone()
        .execute(&f.payee, &mut tx)
        .expect_err("FI status is not assertion authority");
    for changed in 0..7 {
        let mut bad = value.clone();
        match changed {
            0 => bad.challenge = [0; 32],
            1 => bad.request_sha256 = [0; 32],
            2 => bad.minimum_height = 0,
            3 => bad.minimum_height = 2,
            4 => bad.minimum_block_hash = *Hash::new("other floor").as_ref(),
            5 => bad.expected_context_hash = Hash::new("other context"),
            _ => bad.expected_uid = [8; 32],
        }
        bad.execute(&f.owner, &mut tx)
            .expect_err("mismatched assertion must reject");
    }
    let stale = AssetFiContextTargetV1::Transfer {
        instruction: iroha_data_model::isi::asset_fi::TransferToLinkedFiV1 {
            asset_definition_id: f.definition.clone(),
            account_id: f.first.clone(),
            amount: 1_u32.into(),
            expected_link_revision: 3,
            expected_policy_revision: 1,
        },
        fi_account_id: f.payee.clone(),
        reference_digest: link.reference_digest,
        expected_fi_revision: 3,
        expected_attestation_revision: 3,
    };
    assertion(&tx, stale.clone(), floor)
        .execute(&f.owner, &mut tx)
        .unwrap();
    let mut mismatched = assertion(&tx, stale, floor);
    if let AssetFiContextTargetV1::Transfer {
        expected_fi_revision,
        ..
    } = &mut mismatched.target
    {
        *expected_fi_revision = 0;
    }
    mismatched
        .execute(&f.owner, &mut tx)
        .expect_err("descriptive transfer requires positive retained revisions");
    let mut revoked = link;
    revoked.enabled = false;
    revoked.revision = 2;
    SetAssetFiLinkV1 {
        link: revoked,
        expected_policy_revision: 1,
    }
    .execute(&f.first, &mut tx)
    .unwrap();
    value
        .clone()
        .execute(&f.owner, &mut tx)
        .expect_err("same-block native changes invalidate the old context hash");
    assertion(&tx, value.target.clone(), floor)
        .execute(&f.owner, &mut tx)
        .unwrap();
    assert_eq!(tx.pending_transfer_transcript_count_for_testing(), before);
    assert_eq!(f.balance(&tx, &f.first), Quantity::from(40_u32));
    assert_eq!(f.balance(&tx, &f.payee), Quantity::zero());
}
#[test]
fn fi_current_assertion_preserves_explicit_unbound_state_and_active_controller_semantics() {
    let (f, state, floor) = floor_fixture();
    let frame = fi_link::controller(&f, &state);
    let mut block = state.block(header(2, 1_000));
    let mut tx = block.transaction_for_fastpq_testing(Hash::new("fi-context-controller"));
    f.configure(&mut tx, 1, 50, 10);
    let mut link = fi_link::setup(&f, &mut tx);
    link.controller = Some(frame.contract_address.clone());
    link.waterfall = true;
    let target = AssetFiContextTargetV1::LinkApproval(SetAssetFiLinkV1 {
        link: link.clone(),
        expected_policy_revision: 1,
    });
    let value = assertion(&tx, target, floor);
    let snapshot = current_snapshot(
        &tx,
        &value.target,
        &value.expected_incarnation,
        &value.expected_uid,
    )
    .unwrap();
    assert_eq!(
        snapshot.controller.as_ref().unwrap().subject,
        frame.contract_subject
    );
    value.clone().execute(&f.owner, &mut tx).unwrap();
    tx.world
        .contract_instances
        .remove(frame.contract_address.clone());
    let inactive = current_snapshot(
        &tx,
        &value.target,
        &value.expected_incarnation,
        &value.expected_uid,
    )
    .unwrap();
    assert!(inactive.controller.is_none());
    value
        .clone()
        .execute(&f.owner, &mut tx)
        .expect_err("active controller cannot be claimed after deactivation");
    assertion(&tx, value.target, floor)
        .execute(&f.owner, &mut tx)
        .unwrap();
    link.account_id = f.owner.clone();
    link.controller = None;
    link.waterfall = false;
    let target = AssetFiContextTargetV1::LinkApproval(SetAssetFiLinkV1 {
        link,
        expected_policy_revision: 1,
    });
    let incarnation = *tx
        .world()
        .axt_asset_incarnations()
        .get(&f.definition)
        .unwrap();
    let snapshot = current_snapshot(&tx, &target, &incarnation, &[8; 32]).unwrap();
    assert!(snapshot.binding.is_none() && snapshot.policy.is_none() && snapshot.link.is_none());
    AssertAssetFiContextV1 {
        target,
        expected_uid: [8; 32],
        expected_incarnation: incarnation,
        expected_context_hash: asset_fi_context_snapshot_hash_v1(&snapshot).unwrap(),
        request_sha256: [1; 32],
        challenge: [2; 32],
        minimum_height: 1,
        minimum_block_hash: floor,
    }
    .execute(&f.owner, &mut tx)
    .unwrap();
}
#[test]
fn fi_assertions_preserve_local_decode_refusal_in_the_original_transaction_owner() {
    let (f, state, floor) = floor_fixture();
    let mut block = state.block(header(2, 1_000));
    let mut tx = block.transaction_for_fastpq_testing(Hash::new("fi-context-deferred"));
    f.configure(&mut tx, 1, 50, 10);
    let link = fi_link::setup(&f, &mut tx);
    let value = assertion(
        &tx,
        AssetFiContextTargetV1::LinkApproval(SetAssetFiLinkV1 {
            link,
            expected_policy_revision: 1,
        }),
        floor,
    );
    let result =
        norito::core::with_decode_limits_scope(norito::DecodeLimits::new(0, 0, 0, 0, 0), || {
            value.execute(&f.owner, &mut tx)
        });
    assert!(result.is_err());
    let original = tx
        .take_execution_deferral()
        .expect("assertion must retain original local refusal");
    assert!(original.decode_refusal().is_some());
}
#[test]
fn fi_historical_assertion_is_exact_wallet_or_current_owner_and_ignores_later_relationships() {
    let (f, state, floor) = floor_fixture();
    let call = Hash::new("fi-historical-original");
    let mut block = state.block(header(2, 1_000));
    let mut tx = block.transaction_for_fastpq_testing(call);
    f.configure(&mut tx, 1, 50, 10);
    let mut link = fi_link::setup(&f, &mut tx);
    iroha_data_model::isi::asset_fi::TransferToLinkedFiV1 {
        asset_definition_id: f.definition.clone(),
        account_id: f.first.clone(),
        amount: 2_u32.into(),
        expected_link_revision: 1,
        expected_policy_revision: 1,
    }
    .execute(&f.first, &mut tx)
    .unwrap();
    let key = crate::state::asset_fi::receipt::key(&f.definition, &f.first, &call, 0);
    let original = crate::state::asset_fi::receipt::read_record(tx.world(), &key).unwrap();
    let value = AssertAssetFiTransferReceiptV1 {
        asset_definition_id: f.definition.clone(),
        expected_incarnation: original.asset_incarnation,
        account_id: f.first.clone(),
        execution_call_hash: call,
        transcript_index: 0,
        expected_receipt_hash: asset_fi_transfer_receipt_hash_v1(&original).unwrap(),
        request_sha256: [3; 32],
        challenge: [4; 32],
        minimum_height: 1,
        minimum_block_hash: floor,
    };
    value.clone().execute(&f.first, &mut tx).unwrap();
    value.clone().execute(&f.owner, &mut tx).unwrap();
    value
        .clone()
        .execute(&f.payee, &mut tx)
        .expect_err("FI destination cannot read private occurrence history");
    link.revision = 2;
    link.enabled = false;
    SetAssetFiLinkV1 {
        link,
        expected_policy_revision: 1,
    }
    .execute(&f.first, &mut tx)
    .unwrap();
    tx.world.axt_asset_incarnations.insert(
        f.definition.clone(),
        iroha_data_model::nexus::AxtAssetIncarnationV1::try_from_bytes(
            *Hash::new("later incarnation").as_ref(),
        )
        .unwrap(),
    );
    value.clone().execute(&f.first, &mut tx).unwrap();
    tx.world
        .asset_definitions
        .get_mut(&f.definition)
        .unwrap()
        .set_owned_by(f.payee.clone());
    value
        .clone()
        .execute(&f.owner, &mut tx)
        .expect_err("old owner no longer authorizes private history");
    value.clone().execute(&f.payee, &mut tx).unwrap();
    for changed in 0..4 {
        let mut bad = value.clone();
        match changed {
            0 => bad.transcript_index = 1,
            1 => bad.execution_call_hash = Hash::new("other call"),
            2 => bad.expected_receipt_hash = Hash::new("altered receipt"),
            _ => {
                bad.expected_incarnation = *tx
                    .world()
                    .axt_asset_incarnations()
                    .get(&f.definition)
                    .unwrap()
            }
        }
        bad.execute(&f.first, &mut tx)
            .expect_err("historical occurrence and captured incarnation must match exactly");
    }
    assert_eq!(f.balance(&tx, &f.first), Quantity::from(38_u32));
    assert_eq!(f.balance(&tx, &f.payee), Quantity::from(2_u32));
    assert_eq!(
        crate::state::asset_fi::receipt::read_record(tx.world(), &key).unwrap(),
        original
    );
}
