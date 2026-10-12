//! L1 checks both actual snapshot cuts and preserves original local admission refusal.

use super::*;
use crate::smartcontracts::isi::sccp::{committee_owner::RetainedSccpCommitteeGeneration, params};
use iroha_config::parameters::actual::Nexus;
use std::time::Duration;

fn policy() -> Nexus {
    let parameters = iroha_data_model::sccp::params::SccpParametersV1::taira_default();
    let mut policy = Nexus::default();
    policy.staking.max_slash_bps = 1;
    policy.staking.unbonding_delay = Duration::from_millis(
        parameters.committee_validity_ms + parameters.forgery_evidence_grace_ms,
    );
    policy
}

#[test]
fn config_free_restore_never_substitutes_default_staking_for_present_sccp() {
    let absent = World::default();
    let budget = absent
        .sccp_committee_generations
        .allocation_budget()
        .clone();
    validate_sccp_policy_versions(&absent, None, &budget).unwrap();
    let world = crate::state::sccp_snapshot_state::tests::sccp_world();
    let budget = world.sccp_committee_generations.allocation_budget().clone();
    let error = validate_sccp_policy_versions(&world, None, &budget).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("explicit original replay staking policy")
    );
    validate_sccp_policy_versions(&world, Some(&policy()), &budget).unwrap();
}

#[test]
fn undo_only_retained_liability_is_checked_against_its_complete_original_cut() {
    let world = crate::state::sccp_snapshot_state::tests::sccp_world();
    let budget = world.sccp_committee_generations.allocation_budget().clone();
    let mut original = world
        .sccp_committee_generations
        .view()
        .get(&1)
        .unwrap()
        .record()
        .clone();
    original.grace_ms += 1;
    original.liable_until_lc += 1;
    let original = RetainedSccpCommitteeGeneration::admit_claim(&original, &budget).unwrap();
    {
        let mut block = world.block();
        block
            .sccp_committee_generations
            .try_insert_admitted(1, original)
            .unwrap();
        block.commit();
    }
    {
        let mut block = world.block();
        block
            .sccp_committee_generations
            .try_remove_admitted(1)
            .unwrap();
        block.commit();
    }
    let policy = policy();
    let current = world.view();
    let parameters = params::parameters(&current).unwrap();
    params::validate_staking_policy(&current, &parameters, &policy.staking).unwrap();
    drop(current);
    let error = validate_sccp_policy_versions(&world, Some(&policy), &budget).unwrap_err();
    assert!(
        error.to_string().contains("staking_policy.revert"),
        "{error}"
    );
    assert!(error.to_string().contains("generation 1"), "{error}");
    assert!(world.sccp_committee_generations.view().get(&1).is_none());
}

#[test]
fn original_undo_acquisition_refusal_remains_local_and_can_retry() {
    let world = World::default();
    let budget = world.sccp_committee_generations.allocation_budget().clone();
    let limit = budget.limit_bytes();
    budget.set_limit_bytes(0);
    let error = validate_sccp_policy_versions(&world, None, &budget).unwrap_err();
    assert!(matches!(error, StateRestoreError::Admission(_)), "{error}");
    budget.set_limit_bytes(limit);
    validate_sccp_policy_versions(&world, None, &budget).unwrap();
}
