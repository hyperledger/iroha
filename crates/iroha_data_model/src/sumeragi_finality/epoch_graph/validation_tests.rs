//! Exact-input epoch reuse, unchanged graph/codec outputs, and malformed-credential rejection.

use super::*;
use crate::{
    sumeragi::epoch::tests::{fixture, retained},
    sumeragi_finality::{ExecutionCommitment, ExecutionResultCommitment, NativeLaneStateProof},
};
use iroha_crypto::{Hash, HashOf};
use iroha_sumeragi::types::ChainParams;

fn fixture_other_network() -> crate::NetworkId {
    crate::NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(Hash::new(
        b"another epoch-scope network",
    )))
}

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
        let x = crate::sumeragi_finality::SccpFinalityHeaderV1::inactive(
            *value.schedule.current.network_id.as_bytes(),
            value.height,
            0,
        )
        .unwrap();
        let result = |body: &ExecutionResultCommitment| {
            crate::sumeragi_finality::certified_result::outer_result(
                &x,
                &crate::sumeragi_finality::certified_result::body_digest(&body.preimage().unwrap()),
            )
        };
        assert_eq!(result(&decoded), result(&value));
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
            2 => invalid.committee[1] = invalid.committee[0].clone(),
            3 => invalid.authorization.network_id = fixture_other_network(),
            4 => invalid.authorization.authority_id[0] ^= 1,
            5 => invalid.authorization.authority_generation += 1,
            6 => invalid.committee.swap(0, 1),
            7 => invalid.leader_seed = [0; 32],
            8 => invalid.version = 2,
            _ => {
                invalid.committee.pop();
            }
        }
        if mutation == 2 {
            // Rebind the declared generation so the repeated roster seat itself must reject.
            if let Ok(id) = invalid.generation().generation_id() {
                invalid.authorization.authority_id = id;
            }
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

#[test]
fn validation_only_lookup_never_admits_or_retains_a_missed_context() {
    use crate::sumeragi::epoch::validation_counts;
    use norito::core::DecodeBudgetContext;

    let epoch = fixture(4);
    let mut validation = EpochValidationScope::new();
    let original = validation.core_epoch(&epoch).unwrap();
    assert_eq!(validation.entries.iter().flatten().count(), 1);
    let before = validation_counts::calls();
    validation.validate_known_or_fresh(&epoch).unwrap();
    assert_eq!(validation_counts::calls() - before, 0);
    let mut changed = epoch.clone();
    changed.leader_seed[0] ^= 1;
    let limits =
        norito::DecodeLimits::new(1024 * 1024, 1024 * 1024, 1024 * 1024, 16 * 1024 * 1024, 64);
    let independent = DecodeBudgetContext::new(limits);
    independent.with(|| changed.validate()).unwrap();
    let original_charge = independent.consumed_allocated_bytes();
    for _ in 0..2 {
        let current = DecodeBudgetContext::new(limits);
        let before = validation_counts::calls();
        current
            .with(|| validation.validate_known_or_fresh(&changed))
            .unwrap();
        assert_eq!(
            validation_counts::calls() - before,
            1,
            "a valid miss is never inserted by the validation-only gate"
        );
        assert_eq!(current.consumed_allocated_bytes(), original_charge);
        assert_eq!(validation.entries.iter().flatten().count(), 1);
        assert_eq!(validation.validations, 1);
    }
    changed.committee[0].proof_of_possession[0] ^= 1;
    let independent = DecodeBudgetContext::new(limits);
    let expected = independent.with(|| changed.validate()).unwrap_err();
    let current = DecodeBudgetContext::new(limits);
    let before = validation_counts::calls();
    assert_eq!(
        current
            .with(|| validation.validate_known_or_fresh(&changed))
            .unwrap_err(),
        expected
    );
    assert_eq!(validation_counts::calls() - before, 1);
    assert_eq!(
        current.consumed_allocated_bytes(),
        independent.consumed_allocated_bytes()
    );
    assert_eq!(validation.entries.iter().flatten().count(), 1);
    let before = validation_counts::calls();
    validation.validate_known_or_fresh(&epoch).unwrap();
    assert_eq!(validation_counts::calls() - before, 0);
    assert_eq!(validation.core_epoch(&epoch).unwrap(), original);
    assert_eq!(validation.validations, 1);
}

#[test]
fn epoch_scope_retains_exact_context_without_a_hidden_heap_graph() {
    use crate::amx_prepare_streaming_allocations::PhysicalObservation;
    use iroha_allocation::AllocationBudget;
    use norito::core::DecodeBudgetContext;

    // This is native structural validation, not a source/certificate authority fixture.
    // Both native root scopes use this same bounded committee contract.
    for count in [4, crate::sumeragi::epoch::MAX_VALIDATORS] {
        for mode in [ConsensusMode::Npos, ConsensusMode::Permissioned] {
            let mut context = fixture(count);
            context.mode = mode;
            let source = norito::encode_canonical(&context).unwrap();
            let pointers = context
                .committee
                .iter()
                .map(|member| {
                    (
                        member
                            .validator
                            .public_key()
                            .borrowed_parts()
                            .unwrap()
                            .1
                            .as_ptr(),
                        member.proof_of_possession.as_ptr(),
                    )
                })
                .collect::<Vec<_>>();
            let budget = AllocationBudget::new(1 << 20);
            let decoder = DecodeBudgetContext::try_new_owned(
                norito::DecodeLimits::new(1 << 20, 1 << 20, 1 << 20, 16 << 20, 64),
                &budget,
            )
            .unwrap();
            // Warm the shared canonical/crypto machinery outside both comparable measurements.
            context.context_id().unwrap();
            let retained = budget.reserved_bytes();
            let physical = PhysicalObservation::start();
            let expected = decoder.with(|| context.context_id());
            let validation_requests = physical.snapshot().requests();
            drop(physical);
            let before_debit = decoder.consumed_allocated_bytes();
            let mut validation = EpochValidationScope::new();
            let physical = PhysicalObservation::start();
            let actual = decoder.with(|| validation.core_epoch(&context));
            let scope_requests = physical.snapshot().requests();
            drop(physical);
            let after_debit = decoder.consumed_allocated_bytes();
            eprintln!(
                "epoch cache observation count={count} mode={mode:?} baseline_ok={} scope_ok={} baseline_requests={validation_requests:?} scope_requests={scope_requests:?} before_debit={before_debit} after_debit={after_debit} entries={}",
                expected.is_ok(),
                actual.is_ok(),
                validation.entries.iter().flatten().count(),
            );
            let expected = expected.expect("original mandatory context validation must succeed");
            let actual = actual.expect("same mandatory epoch validation must succeed");
            assert_eq!(actual.id.context.0, expected);
            // Preserve both observations, but let the own heap-graph assertion be causal first.
            assert_eq!(
                scope_requests, validation_requests,
                "epoch cache adds no heap graph beyond original context validation"
            );
            assert_eq!(validation.entries.iter().flatten().count(), 1);
            assert_eq!(
                after_debit, before_debit,
                "exact cache retention must not debit a hidden encode/decode roundtrip"
            );

            assert_eq!(budget.reserved_bytes(), retained);
            for (member, original) in context.committee.iter().zip(&pointers) {
                assert_eq!(
                    member
                        .validator
                        .public_key()
                        .borrowed_parts()
                        .unwrap()
                        .1
                        .as_ptr(),
                    original.0
                );
                assert_eq!(member.proof_of_possession.as_ptr(), original.1);
            }
            assert_eq!(norito::encode_canonical(&context).unwrap(), source);
            // Saturation is a separate positive control after the own allocation cause above.
            // The old optional insertion is allowed to refuse; it cannot mask that cause.
            let blocker = budget
                .try_reserve_bytes(budget.limit_bytes() - budget.reserved_bytes())
                .unwrap();
            let full_charge = budget.reserved_bytes();
            let mut full_scope = EpochValidationScope::new();
            let physical = PhysicalObservation::start();
            let full_insert = decoder.with(|| full_scope.core_epoch(&context));
            let full_requests = physical.snapshot().requests();
            drop(physical);
            assert_eq!(full_insert.unwrap(), actual);
            assert_eq!(full_requests, validation_requests);
            assert_eq!(full_scope.entries.iter().flatten().count(), 1);
            assert_eq!(budget.reserved_bytes(), full_charge);
            let physical = PhysicalObservation::start();
            let repeated = decoder.with(|| full_scope.core_epoch(&context));
            let repeat_requests = physical.snapshot().requests();
            drop(physical);
            assert_eq!(repeated.unwrap(), actual);
            assert_eq!(repeat_requests, [0, 0, 0]);
            assert_eq!(decoder.consumed_allocated_bytes(), after_debit);
            drop(blocker);
            drop(decoder);
            assert_eq!(budget.reserved_bytes(), 0);
        }
    }
    // Native validation runs on libtest's unchanged default stack. Report actual target layout;
    // no stack-size override, allocator pool replacement or protocol limit is introduced.
    eprintln!(
        "EpochValidationScope inline bytes: {}",
        size_of::<EpochValidationScope>()
    );
    assert!(size_of::<EpochValidationScope>() <= 12 * 1024);
}

#[test]
fn epoch_scope_compares_every_original_field_and_last_bounded_credential() {
    use crate::sumeragi::epoch::{
        BeaconEpochBindingV1, InstalledBeaconEpochBindingV1, ValidatorEpochDecisionV1,
    };
    let original = fixture(crate::sumeragi::epoch::MAX_VALIDATORS);
    let wire = norito::encode_canonical(&original).unwrap();
    let mut validation = EpochValidationScope::new();
    let original_core = validation.core_epoch(&original).unwrap();
    for mutation in 0..25 {
        let mut changed = original.clone();
        match mutation {
            0 => changed.da_layout.chunk_size_bytes += 1,
            1 => changed.da_layout.data_shards += 1,
            2 => changed.da_layout.parity_shards += 1,
            3 => changed.da_layout.max_payload_size_bytes += 1,
            4 => changed.da_layout.max_chunk_count += 1,
            5 => changed.version = 2,
            6 => changed.network_id = fixture_other_network(),
            7 => changed.mode = ConsensusMode::Permissioned,
            8 => changed.leader_seed[31] ^= 1,
            9 => changed.authorization.version = 2,
            10 => changed.authorization.network_id = fixture_other_network(),
            11 => changed.authorization.epoch += 1,
            12 => changed.authorization.first_height += 1,
            13 => changed.authorization.last_height += 1,
            14 => changed.authorization.authority_generation += 1,
            15 => changed.authorization.authority_id[31] ^= 1,
            16 => {
                changed.authorization.beacon =
                    BeaconEpochBindingV1::Installed(InstalledBeaconEpochBindingV1 {
                        session_id: [0x45; 32],
                        transcript_hash: [0x46; 32],
                    })
            }
            17 => changed.authorization.previous_authorization_id[31] ^= 1,
            18 => changed.authorization.transition_id[31] ^= 1,
            19 => changed.authorization.decision = ValidatorEpochDecisionV1::Retain,
            20 => changed.committee.last_mut().unwrap().proof_of_possession[95] ^= 1,
            21 => {
                changed.committee.pop();
            }
            22 => {
                changed
                    .committee
                    .push(changed.committee.last().unwrap().clone());
            }
            23 => {
                let last = changed.committee.len() - 1;
                changed.committee.swap(last - 1, last);
            }
            _ => {
                changed.committee.last_mut().unwrap().validator =
                    original.committee[0].validator.clone()
            }
        }
        // The independent original validator is the oracle, including every existing error.
        let expected = EpochValidationScope::new().core_epoch(&changed);
        let actual = validation.core_epoch(&changed);
        match (actual, expected) {
            (Ok(actual), Ok(expected)) => {
                assert_eq!(actual, expected, "field {mutation}");
                assert_ne!(
                    actual.id, original_core.id,
                    "changed field {mutation} must miss exact reuse"
                );
            }
            (Err(actual), Err(expected)) => {
                assert_eq!(actual.to_string(), expected.to_string(), "field {mutation}")
            }
            _ => panic!("warm epoch scope changed original validation result for field {mutation}"),
        }
        assert_eq!(validation.core_epoch(&original).unwrap(), original_core);
    }
    assert_eq!(norito::encode_canonical(&original).unwrap(), wire);
    // Cache lifetime cannot borrow the caller's heap: unchanged owned originals still hit
    // after the first source retires, while a new source at another epoch must validate.
    let independent = original.clone();
    drop(original);
    assert_eq!(validation.core_epoch(&independent).unwrap(), original_core);
    let next = retained(&independent);
    assert_eq!(
        validation.core_epoch(&next).unwrap(),
        core_epoch(&next).unwrap()
    );
}

#[test]
fn inline_height_projection_preserves_complete_native_configuration_and_rejection_order() {
    fn projected(candidate: &ScheduledConfig) -> Result<HeightConfig, ScheduleError> {
        let (epoch, params) =
            candidate.core_parameters_with_validation(&mut EpochValidationScope::new())?;
        iroha_sumeragi::pacemaker::validate_height_parts(
            &epoch,
            &params,
            super::super::CHAIN_TRANSPORT_FRAME_LIMIT,
        )
        .map_err(ScheduleError::Params)?;
        Ok(HeightConfig {
            epoch: Box::new(epoch),
            committee: global_committee(
                candidate
                    .epoch
                    .committee
                    .iter()
                    .map(|member| consensus_key(&member.validator))
                    .collect::<Result<_, _>>()?,
            )?,
            params,
        })
    }
    for count in [4, 31] {
        let context = fixture(count);
        for mode in [ConsensusMode::Npos, ConsensusMode::Permissioned] {
            let mut original = ScheduledConfig {
                height: 2,
                epoch: context.clone(),
                params: params(),
            };
            original.epoch.mode = mode;
            assert_eq!(
                projected(&original).unwrap(),
                original.height_config().unwrap()
            );
            let mut cases = Vec::new();
            let mut changed = original.clone();
            changed.height = 0;
            cases.push(changed);
            let mut changed = original.clone();
            changed.height = original.epoch.authorization.last_height + 1;
            cases.push(changed);
            let mut changed = original.clone();
            changed.epoch.leader_seed = [0; 32];
            changed.height = 0;
            cases.push(changed);
            let mut changed = original.clone();
            changed.epoch.committee[count - 1].proof_of_possession[0] ^= 1;
            changed.params.payload_retry_interval_ms = 0;
            cases.push(changed);
            let mut changed = original.clone();
            changed.epoch.committee.swap(0, count - 1);
            cases.push(changed);
            let mut changed = original.clone();
            changed.params.payload_retry_interval_ms = 0;
            cases.push(changed);
            let mut changed = original.clone();
            changed.params.block_time_ms = original.params.payload_retry_interval_ms + 1;
            cases.push(changed);
            let mut changed = original.clone();
            changed.params.max_block_bytes = u32::MAX;
            cases.push(changed);
            for changed in cases {
                assert_eq!(
                    projected(&changed).unwrap_err(),
                    changed.height_config().unwrap_err()
                );
            }
        }
    }
}
