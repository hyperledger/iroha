//! Actual State transaction tests for original-cut binding and sticky refusal.

use super::*;
use crate::{
    smartcontracts::isi::sccp::test_support::{blank_state, header},
    state::storage_transactions::TransactionsBlockError,
};

#[test]
fn unchanged_original_cut_records_degradation_without_creating_authority() {
    let state = blank_state();
    let candidate = header(2);
    let mut block = state.block(candidate);
    let parameters = SccpParametersV1::taira_default();
    {
        let mut transaction = block.transaction();
        *transaction.world.sccp_parameters.get_mut() = Some(parameters);
        *transaction.world.sccp_degraded_run.get_mut() = 7;
        transaction.apply();
    }
    let budget = block.execution_budget();
    let prepared = prepare(
        &block.world,
        &parameters,
        *block.network_id(),
        candidate.height().get(),
        candidate.creation_time_ms,
        None,
        None,
        None,
        &budget,
    )
    .unwrap();
    assert_eq!(prepared.degraded, Some(Degraded::MissingCurrentGeneration));
    let mut transaction = block.transaction();
    assert_eq!(prepared.apply(&mut transaction, &budget).unwrap(), None);
    assert_eq!(*transaction.world.sccp_degraded_run.get(), 8);
    assert_eq!(*transaction.world.sccp_committee_current.get(), 0);
    assert!(
        transaction
            .world
            .sccp_committee_generations
            .iter()
            .next()
            .is_none()
    );
    assert!(transaction.require_storage_admission().is_ok());
    transaction.apply();
    assert_eq!(block.world.sccp_degraded_run(), 8);
}

#[test]
fn changed_original_cut_is_sticky_even_when_the_inner_error_is_handled() {
    for changed in 0..4 {
        let state = blank_state();
        let candidate = header(2);
        let mut block = state.block(candidate);
        let parameters = SccpParametersV1::taira_default();
        {
            let mut transaction = block.transaction();
            *transaction.world.sccp_parameters.get_mut() = Some(parameters);
            transaction.apply();
        }
        let budget = block.execution_budget();
        let prepared = prepare(
            &block.world,
            &parameters,
            *block.network_id(),
            candidate.height().get() + u64::from(changed == 0),
            candidate.creation_time_ms,
            None,
            None,
            None,
            &budget,
        )
        .unwrap();
        let mut transaction = block.transaction();
        match changed {
            1 => *transaction.world.sccp_liability_clock.get_mut() = 1,
            2 => *transaction.world.sccp_degraded_run.get_mut() = 1,
            3 => *transaction.world.sccp_parameters.get_mut() = None,
            _ => {}
        }
        assert!(matches!(
            prepared.apply(&mut transaction, &budget),
            Err(GenerationWriteError::SourceCut)
        ));
        assert!(matches!(
            transaction.require_storage_admission(),
            Err(StateStorageAdmissionError::SccpGeneration(
                SccpGenerationLocalError::Invariant(_)
            ))
        ));
        transaction.apply();
        assert!(matches!(
            block.commit_world_overlay_for_testing(),
            Err(TransactionsBlockError::LocalStateStorage(
                StateStorageAdmissionError::SccpGeneration(_)
            ))
        ));
        assert_eq!(*state.world.sccp_parameters.view(), None);
        assert_eq!(*state.world.sccp_liability_clock.view(), 0);
        assert_eq!(*state.world.sccp_degraded_run.view(), 0);
    }
}
