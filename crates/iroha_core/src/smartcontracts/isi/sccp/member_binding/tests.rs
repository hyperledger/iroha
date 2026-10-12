//! Original-seat binding tests, independent of mutable key registration and SCCP legacy state.

use super::*;
use iroha_crypto::{Algorithm, KeyPair};
use iroha_data_model::nexus::PublicLaneValidatorStatus;
use iroha_model_base::{metadata::Metadata, peer::PeerId};
use iroha_primitives::numeric::Quantity;

fn member() -> ValidatorCommitteeMemberV1 {
    let key = KeyPair::from_seed(vec![1; 32], Algorithm::BlsNormal);
    ValidatorCommitteeMemberV1 {
        validator: PeerId::new(key.public_key().clone()),
        proof_of_possession: iroha_crypto::bls_normal_pop_prove(key.private_key()).unwrap(),
    }
}

fn row(seed: u8, lane: LaneId) -> ((LaneId, AccountId), PublicLaneValidatorRecord) {
    let account = AccountId::new(
        KeyPair::from_seed(vec![seed; 32], Algorithm::Ed25519)
            .public_key()
            .clone(),
    );
    let record = PublicLaneValidatorRecord {
        lane_id: lane,
        validator: account.clone(),
        peer_id: member().validator,
        stake_account: account.clone(),
        total_stake: Quantity::from(10_u32),
        self_stake: Quantity::from(10_u32),
        metadata: Metadata::default(),
        status: PublicLaneValidatorStatus::PendingActivation(10),
        activation_height: 10,
        election_exit_height: None,
        deactivation_height: Some(20),
    };
    ((lane, account), record)
}

#[test]
fn original_seat_resolves_only_primary_lane_with_inclusive_exclusive_tenure() {
    let primary = row(1, LaneId::SINGLE);
    let other = row(2, LaneId::new(1));
    let rows = [other, primary];
    let source = || rows.iter().map(|(key, record)| (key, record));
    let original = member();
    assert!(
        resolve_generation_member(&original, 9, source())
            .unwrap()
            .is_none()
    );
    for height in [10, 19] {
        let resolved = resolve_generation_member(&original, height, source())
            .unwrap()
            .unwrap();
        assert!(
            std::ptr::eq(resolved, &rows[1].1),
            "exact original source borrow"
        );
        assert_eq!(resolved.activation_height, 10);
    }
    assert!(
        resolve_generation_member(&original, 20, source())
            .unwrap()
            .is_none()
    );
    assert!(
        resolve_generation_member(&original, 10, std::iter::once((&rows[0].0, &rows[0].1)))
            .unwrap()
            .is_none()
    );
    assert_eq!(
        resolve_generation_member(&original, 0, source()),
        Err(SccpMemberBindingError::Height)
    );
}

#[test]
fn current_status_or_requested_exit_does_not_rewrite_frozen_tenure() {
    let (key, mut record) = row(1, LaneId::SINGLE);
    record.status = PublicLaneValidatorStatus::Exited;
    record.election_exit_height = Some(11);
    let original = member();
    let credentials = original.clone();
    let selected = resolve_generation_member(&original, 19, [(&key, &record)])
        .unwrap()
        .unwrap();
    assert_eq!(selected.validator, key.1);
    assert_eq!(original, credentials, "no credential replacement path");
    record.activation_height = 0;
    assert!(
        resolve_generation_member(&original, 1, [(&key, &record)])
            .unwrap()
            .is_some(),
        "zero activation is valid under the original retained-tenure contract"
    );
    // A fresh consensus key cannot silently replace the original epoch's seat.
    record.peer_id = PeerId::new(
        KeyPair::from_seed(vec![2; 32], Algorithm::BlsNormal)
            .public_key()
            .clone(),
    );
    assert!(
        resolve_generation_member(&original, 19, [(&key, &record)])
            .unwrap()
            .is_none()
    );
}

#[test]
fn g2_source_cut_binds_successor_start_tenure_not_current_height_tenure() {
    let original = member();
    let (key, mut pending) = row(1, LaneId::SINGLE);
    let source_height = 9;
    let successor_start = source_height + 1;
    // This pending row is already bound in h's source but begins its native seat at h+1.
    assert!(
        resolve_generation_member(&original, source_height, [(&key, &pending)])
            .unwrap()
            .is_none()
    );
    assert!(
        resolve_generation_member(&original, successor_start, [(&key, &pending)])
            .unwrap()
            .is_some()
    );
    pending.activation_height = 1;
    pending.status = PublicLaneValidatorStatus::Active;
    pending.deactivation_height = Some(successor_start);
    assert!(
        resolve_generation_member(&original, source_height, [(&key, &pending)])
            .unwrap()
            .is_some()
    );
    assert!(
        resolve_generation_member(&original, successor_start, [(&key, &pending)])
            .unwrap()
            .is_none(),
        "an exited-at-h+1 registration cannot bear the successor's start-height liability"
    );
}

#[test]
fn ambiguous_or_malformed_retained_sources_never_choose_a_binding() {
    let first = row(1, LaneId::SINGLE);
    let mut second = row(2, LaneId::SINGLE);
    second.1.activation_height = 30;
    second.1.status = PublicLaneValidatorStatus::PendingActivation(30);
    second.1.deactivation_height = None;
    // Even if just one duplicate is active now, native primary registration is ambiguous.
    assert_eq!(
        resolve_generation_member(
            &member(),
            10,
            [(&first.0, &first.1), (&second.0, &second.1)]
        ),
        Err(SccpMemberBindingError::DuplicatePeer)
    );
    for mutation in 0..4 {
        let (mut key, mut record) = row(1, LaneId::SINGLE);
        match mutation {
            0 => key.0 = LaneId::new(2),
            1 => record.validator = row(3, LaneId::SINGLE).0.1,
            2 => record.deactivation_height = Some(9),
            _ => record.status = PublicLaneValidatorStatus::PendingActivation(11),
        }
        let expected = if mutation < 2 {
            SccpMemberBindingError::StoreIdentity
        } else {
            SccpMemberBindingError::Tenure
        };
        assert_eq!(
            resolve_generation_member(&member(), 10, [(&key, &record)]),
            Err(expected)
        );
    }
}
