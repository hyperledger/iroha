//! Exact-input epoch reuse, unchanged graph/codec outputs, and malformed-credential rejection.

use super::*;
use crate::{
    sumeragi::epoch::tests::{fixture, retained},
    sumeragi_finality::{ExecutionCommitment, ExecutionResultCommitment, NativeLaneStateProof},
};
use iroha_crypto::{Hash, HashOf};
use iroha_sumeragi::types::ChainParams;

fn params() -> ChainParamsRecord {
    ChainParamsRecord::from_core(&ChainParams::default())
}

fn slot(height: u64, epoch: &ValidatorEpochContextV1) -> ScheduledSlot {
    ScheduledSlot::Ready(ScheduledConfig {
        height,
        epoch: epoch.clone(),
        params: params(),
    })
}

fn ordinary(height: u64, epoch: &ValidatorEpochContextV1) -> ScheduleOutcome {
    ScheduleOutcome {
        height,
        current: epoch.clone(),
        boundary: None,
        next: slot(height + 1, epoch),
        after_next: slot(height + 2, epoch),
    }
}

fn commitment(epoch: &ValidatorEpochContextV1) -> ExecutionResultCommitment {
    let (native_lanes, ordinary_root) =
        NativeLaneStateProof::empty_for_testing(epoch.network_id, 2);
    ExecutionResultCommitment::new(
        2,
        ExecutionCommitment {
            parent_state_root: Hash::new(b"scope parent"),
            post_state_root: ordinary_root,
            ordinary_writes_root: ordinary_root,
            kagemusha_top_up_root: None,
            kagemusha_top_up_count: 0,
            parent_world_state_root: Hash::new(b"scope parent world"),
            world_state_root: Hash::new(b"scope world"),
            event_commitment: None,
            executed_block_wire_len: 1,
            executed_block_wire_hash: Hash::new(b"scope executed wire"),
            transaction_input_commitment: None,
            transaction_output_commitment: None,
        },
        ordinary(2, epoch),
        None,
        native_lanes,
    )
    .unwrap()
}

#[test]
fn one_scope_validates_identical_epoch_once_across_complete_schedule_operations() {
    let epoch = fixture(4);
    let mut validation = EpochValidationScope::new();
    let mut schedule =
        ConsensusSchedule::from_genesis_with_validation(epoch.clone(), params(), &mut validation)
            .unwrap();
    let genesis = ordinary(1, &epoch);
    assert_eq!(
        ConsensusSchedule::from_genesis_outcome_with_validation(&genesis, &mut validation).unwrap(),
        schedule
    );
    for height in 2..=7 {
        let outcome = ordinary(height, &epoch);
        let expected = schedule.advanced(&outcome).unwrap();
        schedule = schedule
            .advanced_with_validation(&outcome, &mut validation)
            .unwrap();
        assert_eq!(schedule, expected);
        assert_eq!(
            norito::encode_canonical(&schedule).unwrap(),
            norito::encode_canonical(&expected).unwrap()
        );
        let config = schedule.ready(height).unwrap();
        assert_eq!(
            config
                .height_config_with_validation(&mut validation)
                .unwrap(),
            config.height_config().unwrap()
        );
    }
    assert_eq!(
        validation.validations, 1,
        "one exact context owns the repeated pure work"
    );
    assert_eq!(validation.entries.iter().flatten().count(), 1);
    assert_eq!(
        validation.core_epoch(&epoch).unwrap(),
        core_epoch(&epoch).unwrap()
    );
    assert_eq!(validation.validations, 1);
}

#[test]
fn scoped_canonical_commitment_decode_preserves_bytes_and_all_other_validation() {
    let epoch = fixture(4);
    let value = commitment(&epoch);
    let bytes = value.preimage().unwrap();
    let mut validation = EpochValidationScope::new();
    for _ in 0..3 {
        let decoded =
            ExecutionResultCommitment::decode_with_validation(&bytes, &mut validation).unwrap();
        assert_eq!(decoded, value);
        assert_eq!(decoded.preimage().unwrap(), bytes);
        assert_eq!(decoded.result().unwrap(), value.result().unwrap());
        decoded.validate_with_validation(&mut validation).unwrap();
    }
    assert_eq!(validation.validations, 1);
    let mut invalid = value.clone();
    invalid.height += 1;
    assert!(invalid.validate_with_validation(&mut validation).is_err());
    let mut invalid = value.clone();
    invalid.execution.executed_block_wire_len = 0;
    assert!(invalid.validate_with_validation(&mut validation).is_err());
    let mut truncated = bytes.clone();
    truncated.pop();
    assert!(
        ExecutionResultCommitment::decode_with_validation(&truncated, &mut validation).is_err()
    );
    let mut trailing = bytes;
    trailing.push(0);
    assert!(ExecutionResultCommitment::decode_with_validation(&trailing, &mut validation).is_err());
    assert_eq!(validation.validations, 1);
}

#[test]
fn warm_epoch_scope_rejects_substituted_credentials_and_authority_bindings() {
    let epoch = fixture(4);
    let mut validation = EpochValidationScope::new();
    let original = validation.core_epoch(&epoch).unwrap();
    for mutation in 0..10 {
        let mut invalid = epoch.clone();
        match mutation {
            0 => invalid.committee[0].proof_of_possession[0] ^= 1,
            1 => invalid.committee[0].proof_of_possession.clear(),
            2 => invalid.authority.validators[0].eq_proof_public_key = [0xff; 32],
            3 => invalid.authority.validators[0].ep_proof_public_key = [0xff; 32],
            4 => invalid.authorization.authority_id[0] ^= 1,
            5 => invalid.authorization.authority_generation += 1,
            6 => invalid.committee.swap(0, 1),
            7 => invalid.leader_seed = [0; 32],
            8 => invalid.version = 2,
            _ => {
                invalid.committee.pop();
            }
        }
        if matches!(mutation, 2 | 3) {
            // Preserve the declared authority hash so real point decoding must reject this.
            invalid.authorization.authority_id = invalid.authority.authority_id().unwrap();
        }
        assert!(
            invalid.validate().is_err(),
            "fixture {mutation} must be invalid"
        );
        assert!(
            validation.core_epoch(&invalid).is_err(),
            "warm context must not accept mutation {mutation}"
        );
        let mut value = commitment(&epoch);
        value.schedule = ordinary(2, &invalid);
        let bytes = value.preimage().unwrap();
        assert!(
            ExecutionResultCommitment::decode_with_validation(&bytes, &mut validation).is_err()
        );
        assert_eq!(
            validation.entries.iter().flatten().count(),
            1,
            "invalid values never enter retained ownership"
        );
        assert_eq!(validation.core_epoch(&epoch).unwrap(), original);
    }
    assert_eq!(validation.validations, 1);
}

#[test]
fn epoch_scope_is_exact_owned_and_bounded_with_revalidation_after_eviction() {
    let original = fixture(4);
    let mut first = original.clone();
    let mut validation = EpochValidationScope::default();
    let first_core = validation.core_epoch(&first).unwrap();
    first.leader_seed[0] ^= 1;
    let second_core = validation.core_epoch(&first).unwrap();
    assert_ne!(
        first_core.id, second_core.id,
        "same epoch number cannot reuse another complete body"
    );
    assert_eq!(validation.core_epoch(&original).unwrap(), first_core);
    assert_eq!(
        validation.validations, 2,
        "mutating the caller never mutates the retained entry"
    );
    first.leader_seed[1] ^= 1;
    validation.core_epoch(&first).unwrap();
    assert_eq!(validation.entries.iter().flatten().count(), 2);
    assert_eq!(validation.validations, 3);
    assert_eq!(validation.core_epoch(&original).unwrap(), first_core);
    assert_eq!(
        validation.validations, 4,
        "eviction requires full validation again"
    );
    assert_eq!(validation.entries.iter().flatten().count(), 2);
    let mut independent = EpochValidationScope::new();
    independent.core_epoch(&original).unwrap();
    assert_eq!(
        independent.validations, 1,
        "a new operation starts without retained work"
    );
}

#[test]
fn warm_scope_preserves_height_parameter_and_boundary_relationship_checks() {
    let current = fixture(4);
    let next = retained(&current);
    let mut validation = EpochValidationScope::new();
    validation.core_epoch(&current).unwrap();
    validation.core_epoch(&next).unwrap();
    let boundary = ScheduleOutcome {
        height: 10,
        current: current.clone(),
        boundary: Some(ValidatorEpochBoundaryV1 {
            version: 1,
            height: 10,
            predecessor_context_id: current.context_id().unwrap(),
            selection_anchor: HashOf::from_untyped_unchecked(Hash::new(b"scope boundary parent")),
            next: next.clone(),
            preparation: None,
        }),
        next: slot(11, &next),
        after_next: slot(12, &next),
    };
    boundary.validate_with_validation(&mut validation).unwrap();
    assert_eq!(validation.validations, 2);
    for mutation in 0..4 {
        let mut invalid = boundary.clone();
        match mutation {
            0 => invalid.height -= 1,
            1 => invalid.boundary.as_mut().unwrap().predecessor_context_id[0] ^= 1,
            2 => invalid.next = slot(11, &current),
            _ => invalid.boundary = None,
        }
        assert!(invalid.validate_with_validation(&mut validation).is_err());
    }
    let schedule =
        ConsensusSchedule::from_genesis_with_validation(current.clone(), params(), &mut validation)
            .unwrap();
    let mut invalid = ordinary(2, &current);
    let ScheduledSlot::Ready(config) = &mut invalid.next else {
        unreachable!()
    };
    config.params.max_block_bytes -= 1;
    assert!(
        schedule
            .advanced_with_validation(&invalid, &mut validation)
            .is_err()
    );
    assert_eq!(validation.validations, 2);
}

#[test]
fn scoped_schedule_walk_invokes_full_crypto_validation_once_per_exact_context() {
    let current = fixture(4);
    let next = retained(&current);
    let before = crate::sumeragi::epoch::validation_counts::calls();
    let mut scope = EpochValidationScope::new();
    let mut schedule =
        ConsensusSchedule::from_genesis_with_validation(current.clone(), params(), &mut scope)
            .unwrap();
    for height in 2..=8 {
        schedule = schedule
            .advanced_with_validation(&ordinary(height, &current), &mut scope)
            .unwrap();
        schedule
            .ready(height)
            .unwrap()
            .height_config_with_validation(&mut scope)
            .unwrap();
    }
    assert_eq!(
        crate::sumeragi::epoch::validation_counts::calls() - before,
        1
    );
    let boundary = ScheduleOutcome {
        height: 10,
        current: current.clone(),
        boundary: Some(ValidatorEpochBoundaryV1 {
            version: 1,
            height: 10,
            predecessor_context_id: scope.core_epoch(&current).unwrap().id.context.0,
            selection_anchor: HashOf::from_untyped_unchecked(Hash::new(b"counted boundary")),
            next: next.clone(),
            preparation: None,
        }),
        next: slot(11, &next),
        after_next: slot(12, &next),
    };
    boundary.validate_with_validation(&mut scope).unwrap();
    boundary.validate_with_validation(&mut scope).unwrap();
    assert_eq!(
        crate::sumeragi::epoch::validation_counts::calls() - before,
        2,
        "shared boundary geometry cannot silently re-run original credential crypto"
    );
}

#[test]
fn scoped_decode_keeps_inherited_resource_refusal_and_reuses_epoch_work_after_retry() {
    use crate::sumeragi_finality::commitment::CommitmentError;
    let value = commitment(&fixture(4));
    let bytes = value.preimage().unwrap();
    let original = bytes.clone();
    let canonical = norito::canonical_decode_limits(bytes.len());
    let limits = norito::DecodeLimits::new(
        96,
        super::super::commitment::MAX_RESULT_PREIMAGE_BYTES,
        canonical.max_total_elements(),
        0,
        32,
    );
    let mut validation = EpochValidationScope::new();
    let refused = norito::with_decode_limits_scope(limits, || {
        ExecutionResultCommitment::decode_with_validation(&bytes, &mut validation)
    });
    assert!(matches!(
        refused,
        Err(CommitmentError::Resource(
            norito::core::DecodeResourceError::TotalAllocationExceeded { .. }
        ))
    ));
    assert_eq!(validation.validations, 0);
    assert!(validation.entries.iter().all(Option::is_none));
    assert_eq!(bytes, original);
    for _ in 0..3 {
        assert_eq!(
            ExecutionResultCommitment::decode_with_validation(&bytes, &mut validation).unwrap(),
            value
        );
    }
    assert_eq!(validation.validations, 1);
    assert_eq!(validation.entries.iter().flatten().count(), 1);
}
