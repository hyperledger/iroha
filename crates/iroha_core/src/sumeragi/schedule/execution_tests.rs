//! Reconcile independently signed genesis authority with actual executed registration rows.

use super::*;
use crate::state::{World, derive_validator_key_id};
use iroha_crypto::{Algorithm, KeyPair};
use iroha_data_model::{consensus::ConsensusKeyStatus, parameter::system::SumeragiConsensusMode};
use iroha_model_base::peer::PeerId;

fn registered_world(context: &iroha_data_model::sumeragi::epoch::ValidatorEpochContextV1) -> World {
    let mut world = World::new();
    {
        let mut parameters = world.parameters.block();
        parameters
            .set_parameter(crate::sumeragi::lanes::routing::test_support::metadata(
                iroha_data_model::block::consensus::SumeragiRootScope::Global,
            ))
            .expect("valid fixture parameters");
        parameters.commit();
    }
    for member in &context.committee {
        world.register_validator_pop_for_testing(
            member.validator.public_key().clone(),
            member.proof_of_possession.clone(),
        );
    }
    {
        let mut overlay = world.block();
        let mut peers = overlay.peers_mut_for_testing().transaction();
        for member in &context.committee {
            peers.push(member.validator.clone());
        }
        peers.apply();
        overlay.commit();
    }
    world
}

#[test]
fn sccp_executed_genesis_rejects_work_budgets_that_starve_pause_enactment() {
    use iroha_data_model::parameter::{CustomParameter, GovernanceClockParametersV1, Parameter};
    let signed = crate::sumeragi::epoch::tests::genesis_fixture(
        SumeragiConsensusMode::Permissioned,
        10,
        false,
    );
    let context = crate::sumeragi::epoch::authenticated_genesis(&signed)
        .map(|genesis| genesis.into_parts().0)
        .unwrap();
    let world = registered_world(&context);
    for units in [0, 1, 4, 9, 10, 64] {
        let policy = GovernanceClockParametersV1 {
            governance_block_start_work_units: units,
            ..GovernanceClockParametersV1::default()
        };
        {
            let mut parameters = world.parameters.block();
            parameters
                .set_parameter(Parameter::Custom(CustomParameter::new(
                    GovernanceClockParametersV1::parameter_id().clone(),
                    norito::json::to_json(&policy)
                        .unwrap()
                        .parse::<iroha_primitives::json::Json>()
                        .unwrap(),
                )))
                .unwrap();
            parameters.commit();
        }
        let result = validate_executed_genesis(&world.view(), &context);
        if units < 10 {
            assert!(
                matches!(result,
                    Err(crate::execution_attempt::ExecutionAttemptError::Rejected(
                        ScheduleError::Epoch(ref message)))
                        if message == "governance block-start work budget must be at least ten"
                ),
                "genesis must reject budgets that cannot certify six rounds and enact one pause"
            );
        } else {
            result.expect("the inclusive ten-unit floor supports SCCP progress");
        }
    }
}

#[test]
fn executed_genesis_clock_drift_bound_cannot_be_bypassed_by_raw_state() {
    use iroha_data_model::parameter::system::MAX_CLOCK_DRIFT_BOUND_MS;
    let signed = crate::sumeragi::epoch::tests::genesis_fixture(
        SumeragiConsensusMode::Permissioned,
        10,
        false,
    );
    let context = crate::sumeragi::epoch::authenticated_genesis(&signed)
        .map(|genesis| genesis.into_parts().0)
        .unwrap();
    let world = registered_world(&context);
    for value in [
        0,
        MAX_CLOCK_DRIFT_BOUND_MS,
        MAX_CLOCK_DRIFT_BOUND_MS + 1,
        u64::MAX,
    ] {
        {
            let mut parameters = world.parameters.block();
            parameters
                .set_parameter(iroha_data_model::parameter::Parameter::Sumeragi(
                    iroha_data_model::parameter::SumeragiParameter::MaxClockDriftMs(value),
                ))
                .expect("raw State bypasses instruction admission for this control");
            parameters.commit();
        }
        let result = validate_executed_genesis(&world.view(), &context);
        if value <= MAX_CLOCK_DRIFT_BOUND_MS {
            result.expect("inclusive protocol bound");
        } else {
            let expected = iroha_data_model::parameter::system::validate_max_clock_drift_ms(value)
                .unwrap_err();
            assert!(matches!(
                result,
                Err(crate::execution_attempt::ExecutionAttemptError::Rejected(
                    ScheduleError::Epoch(message)
                )) if message == expected.to_string()
            ));
        }
    }
}

#[test]
fn executed_genesis_must_retain_every_exact_signed_registration() {
    let signed = crate::sumeragi::epoch::tests::genesis_fixture(
        SumeragiConsensusMode::Permissioned,
        10,
        false,
    );
    let context = crate::sumeragi::epoch::authenticated_genesis(&signed)
        .map(|genesis| genesis.into_parts().0)
        .unwrap();
    let mut world = registered_world(&context);
    validate_executed_genesis(&world.view(), &context).unwrap();
    let id = derive_validator_key_id(context.committee[0].validator.public_key());
    let original = world.consensus_keys.view().get(&id).unwrap().clone();
    for mutation in 0..3 {
        let mut bad = original.clone();
        match mutation {
            0 => bad.status = ConsensusKeyStatus::Disabled,
            1 => bad.pop.as_mut().unwrap()[0] ^= 1,
            _ => bad.activation_height = 2,
        }
        world.consensus_keys.insert(id.clone(), bad);
        assert!(validate_executed_genesis(&world.view(), &context).is_err());
    }
    world.consensus_keys.insert(id, original);
    validate_executed_genesis(&world.view(), &context).unwrap();
}

#[test]
fn executed_genesis_rejects_an_extra_voting_registration() {
    let signed = crate::sumeragi::epoch::tests::genesis_fixture(
        SumeragiConsensusMode::Permissioned,
        10,
        false,
    );
    let context = crate::sumeragi::epoch::authenticated_genesis(&signed)
        .map(|genesis| genesis.into_parts().0)
        .unwrap();
    let mut world = registered_world(&context);
    let pair = KeyPair::from_seed(vec![0xa7; 32], Algorithm::BlsNormal);
    world.register_validator_pop_for_testing(
        pair.public_key().clone(),
        iroha_crypto::bls_normal_pop_prove(pair.private_key()).unwrap(),
    );
    {
        let mut overlay = world.block();
        let mut peers = overlay.peers_mut_for_testing().transaction();
        peers.push(PeerId::new(pair.public_key().clone()));
        peers.apply();
        overlay.commit();
    }
    assert!(validate_executed_genesis(&world.view(), &context).is_err());
}

#[test]
fn executed_genesis_fee_scope_decode_refusal_defers_and_retries_same_authority() {
    let signed = crate::sumeragi::epoch::tests::genesis_fixture(
        SumeragiConsensusMode::Permissioned,
        10,
        false,
    );
    let context = crate::sumeragi::epoch::authenticated_genesis(&signed)
        .map(|genesis| genesis.into_parts().0)
        .unwrap();
    let world = registered_world(&context);
    let refused = norito::with_decode_limits_scope(
        norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, usize::MAX),
        || validate_executed_genesis(&world.view(), &context).unwrap_err(),
    );
    assert!(matches!(
        refused,
        crate::execution_attempt::ExecutionAttemptError::Deferred(_)
    ));
    validate_executed_genesis(&world.view(), &context).unwrap();
}

#[test]
fn boundary_capture_attempts_retain_capacity_release_and_deterministic_errors() {
    use crate::execution_attempt::ExecutionAttemptError;
    use crate::sumeragi::epoch_election::BoundaryCaptureError;
    let budget = iroha_allocation::AllocationBudget::new(8);
    let occupied = budget.try_reserve_bytes(8).unwrap();
    let refusal = budget.try_reserve_bytes(1).unwrap_err();
    let error = boundary_capture_attempt_error(BoundaryCaptureError::Admission(refusal.clone()));
    let ExecutionAttemptError::Deferred(owner) = error else {
        panic!("local capacity cannot reject a schedule");
    };
    assert_eq!(owner.allocation_refusal(), Some(&refusal));
    drop(occupied);
    assert!(budget.try_reserve_bytes(1).is_ok());
    assert!(matches!(
        boundary_capture_attempt_error(BoundaryCaptureError::Allocator { requested_bytes: 9 }),
        ExecutionAttemptError::Deferred(owner)
            if owner.reason() == ivm::error::ExecutionDeferral::AllocationUnavailable
    ));
    assert!(matches!(
        boundary_capture_attempt_error(BoundaryCaptureError::Invalid("bad authority".into())),
        ExecutionAttemptError::Rejected(ScheduleError::Epoch(message))
            if message == "bad authority"
    ));
}
