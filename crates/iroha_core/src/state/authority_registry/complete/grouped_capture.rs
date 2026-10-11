//! Consume exact native grouping derivations before scoped canonical encoding.

use super::super::grouped_ownership::{
    ACCOUNT_REKEY_WORK_PER_ROW, ASSET_BALANCE_WORK_PER_ROW, ASSET_DEFINITION_WORK_PER_ROW,
    CONTRACT_ALIAS_WORK_PER_ROW, CheckedAccountRekeys, CheckedAssetDefinitions, CheckedAssets,
    CheckedContractAliases, CheckedContractSubjects, CheckedEscrows, CheckedNfts,
    CheckedProofRecords, CheckedRepoAgreements, CheckedRwas, CheckedValidationFeeProposals,
    CheckedVerifyingKeys, ESCROW_WORK_PER_ROW, GroupedOwnershipError, NFT_WORK_PER_ROW,
    REPO_AGREEMENT_WORK_PER_ROW, RWA_WORK_PER_ROW, VALIDATION_FEE_PROPOSAL_WORK_PER_ROW,
};
use super::*;
use mv::{PublicationPreparationError, storage::StorageReadOnly};

// All concrete captures retain all original readers through encoding and the
// final native identity check. The State fence rejects mixed publication cuts.
// This remains scoped preparation, never a finalized execution anchor.
macro_rules! grouped_capture {
    ($function:ident, $checker:ident, $table:literal, $work_per_row:expr) => {
        /// Capture exact canonical rows after checking every retained grouped index.
        pub(crate) fn $function(
            state: &State,
            limits: LeafLimits,
        ) -> Result<Option<CanonicalTablePairedSnapshot>, LeafError> {
            let generation = state.state_view_generation();
            if generation & 1 != 0 {
                return Ok(None);
            }
            let budget = state
                .pipeline_ivm_prepared_cache
                .read()
                .execution_budget()
                .clone();
            // Count physical scans, references and partition-range visits. This
            // is a local allowance; larger predecessor images can require a
            // larger admitted row allowance without changing ledger validity.
            let checked =
                $checker::capture(&state.world, limits.max_rows.saturating_mul($work_per_row));
            if !is_stable_state_view_generation(generation, state.state_view_generation()) {
                return Ok(None);
            }
            let checked = match checked {
                Ok(checked) => checked,
                Err(GroupedOwnershipError::Publication(PublicationPreparationError::Changed)) => {
                    return Ok(None)
                }
                Err(error) => return Err(error.into()),
            };
            let snapshot = CanonicalTableLeafSet::paired_table_from_rows(
                $table,
                limits,
                &budget,
                checked.rows().iter(),
            );
            // A refusal still belongs to the retained source cut. Observe its native owners,
            // release the readers, and let State publication win before reporting either error.
            let current = checked.matches_current();
            drop(checked);
            if !is_stable_state_view_generation(generation, state.state_view_generation()) {
                return Ok(None);
            }
            if !current? {
                return Ok(None);
            }
            Ok(Some(snapshot?))
        }
    };
}

/// Capture exact nfts while retaining every original native reader through encoding.
pub(crate) fn capture_nfts_once(
    state: &State,
    limits: LeafLimits,
) -> Result<Option<CanonicalTablePairedSnapshot>, LeafError> {
    let generation = state.state_view_generation();
    if generation & 1 != 0 {
        return Ok(None);
    }
    let budget = state
        .pipeline_ivm_prepared_cache
        .read()
        .execution_budget()
        .clone();
    let checked = CheckedNfts::capture(
        &state.world,
        limits.max_rows.saturating_mul(NFT_WORK_PER_ROW),
    );
    if !is_stable_state_view_generation(generation, state.state_view_generation()) {
        return Ok(None);
    }
    let checked = match checked {
        Ok(checked) => checked,
        Err(GroupedOwnershipError::Publication(PublicationPreparationError::Changed)) => {
            return Ok(None);
        }
        Err(error) => return Err(error.into()),
    };
    let snapshot = CanonicalTableLeafSet::paired_table_from_rows(
        "world.nfts",
        limits,
        &budget,
        checked.rows().iter(),
    );
    finish_nfts_encoding(state, generation, checked, snapshot)
}
fn finish_nfts_encoding(
    state: &State,
    generation: u64,
    checked: CheckedNfts<'_>,
    snapshot: Result<CanonicalTablePairedSnapshot, LeafError>,
) -> Result<Option<CanonicalTablePairedSnapshot>, LeafError> {
    let current = checked.matches_current();
    drop(checked);
    if !is_stable_state_view_generation(generation, state.state_view_generation()) {
        return Ok(None);
    }
    if !current? {
        return Ok(None);
    }
    Ok(Some(snapshot?))
}
grouped_capture!(
    capture_contract_subject_bindings_once,
    CheckedContractSubjects,
    "world.contract_subject_bindings",
    16_384
);

grouped_capture!(
    capture_proofs_once,
    CheckedProofRecords,
    "world.proofs",
    512
);
grouped_capture!(
    capture_governance_proposals_once,
    CheckedValidationFeeProposals,
    "world.governance_proposals",
    VALIDATION_FEE_PROPOSAL_WORK_PER_ROW
);
/// Capture canonical account_rekey_records through all four original native owners.
pub(crate) fn capture_account_rekey_records_once(
    state: &State,
    limits: LeafLimits,
) -> Result<Option<CanonicalTablePairedSnapshot>, LeafError> {
    let generation = state.state_view_generation();
    if generation & 1 != 0 {
        return Ok(None);
    }
    let budget = state.ivm_execution_budget();
    let checked = CheckedAccountRekeys::capture(
        &state.world,
        limits.max_rows.saturating_mul(ACCOUNT_REKEY_WORK_PER_ROW),
    );
    if !is_stable_state_view_generation(generation, state.state_view_generation()) {
        return Ok(None);
    }
    let checked = match checked {
        Ok(checked) => checked,
        Err(GroupedOwnershipError::Publication(PublicationPreparationError::Changed)) => {
            return Ok(None);
        }
        Err(error) => return Err(error.into()),
    };
    let snapshot = CanonicalTableLeafSet::paired_table_from_rows(
        "world.account_rekey_records",
        limits,
        &budget,
        checked.rows().iter(),
    );
    finish_account_rekey_records_encoding(state, generation, checked, snapshot)
}
fn finish_account_rekey_records_encoding(
    state: &State,
    generation: u64,
    checked: CheckedAccountRekeys<'_>,
    snapshot: Result<CanonicalTablePairedSnapshot, LeafError>,
) -> Result<Option<CanonicalTablePairedSnapshot>, LeafError> {
    let current = checked.matches_current();
    drop(checked);
    if !is_stable_state_view_generation(generation, state.state_view_generation()) {
        return Ok(None);
    }
    if !current? {
        return Ok(None);
    }
    Ok(Some(snapshot?))
}
#[cfg(test)]
#[path = "grouped_capture/account_rekeys_fence_tests.rs"]
mod account_rekeys_fence_tests;

/// Capture canonical balances through their eight exact native dependencies.
pub(crate) fn capture_assets_once(
    state: &State,
    limits: LeafLimits,
) -> Result<Option<CanonicalTablePairedSnapshot>, LeafError> {
    let generation = state.state_view_generation();
    if generation & 1 != 0 {
        return Ok(None);
    }
    let budget = state.ivm_execution_budget();
    let checked = CheckedAssets::capture(
        &state.world,
        limits.max_rows.saturating_mul(ASSET_BALANCE_WORK_PER_ROW),
    );
    if !is_stable_state_view_generation(generation, state.state_view_generation()) {
        return Ok(None);
    }
    let checked = match checked {
        Ok(checked) => checked,
        Err(GroupedOwnershipError::Publication(PublicationPreparationError::Changed)) => {
            return Ok(None);
        }
        Err(error) => return Err(error.into()),
    };
    let snapshot = CanonicalTableLeafSet::paired_table_from_rows(
        "world.assets",
        limits,
        &budget,
        checked.rows().iter(),
    );
    finish_assets_encoding(state, generation, checked, snapshot)
}

fn finish_assets_encoding(
    state: &State,
    generation: u64,
    checked: CheckedAssets<'_>,
    snapshot: Result<CanonicalTablePairedSnapshot, LeafError>,
) -> Result<Option<CanonicalTablePairedSnapshot>, LeafError> {
    let current = checked.matches_current();
    drop(checked);
    if !is_stable_state_view_generation(generation, state.state_view_generation()) {
        return Ok(None);
    }
    if !current? {
        return Ok(None);
    }
    Ok(Some(snapshot?))
}

#[cfg(test)]
#[path = "grouped_capture/assets_fence_tests.rs"]
mod assets_fence_tests;
grouped_capture!(
    capture_contract_alias_bindings_once,
    CheckedContractAliases,
    "world.contract_alias_bindings",
    CONTRACT_ALIAS_WORK_PER_ROW
);
/// Capture canonical definitions through their seven exact native dependencies.
pub(crate) fn capture_asset_definitions_once(
    state: &State,
    limits: LeafLimits,
) -> Result<Option<CanonicalTablePairedSnapshot>, LeafError> {
    let generation = state.state_view_generation();
    if generation & 1 != 0 {
        return Ok(None);
    }
    let budget = state.ivm_execution_budget();
    let checked = CheckedAssetDefinitions::capture(
        &state.world,
        limits
            .max_rows
            .saturating_mul(ASSET_DEFINITION_WORK_PER_ROW),
    );
    if !is_stable_state_view_generation(generation, state.state_view_generation()) {
        return Ok(None);
    }
    let checked = match checked {
        Ok(checked) => checked,
        Err(GroupedOwnershipError::Publication(PublicationPreparationError::Changed)) => {
            return Ok(None);
        }
        Err(error) => return Err(error.into()),
    };
    let snapshot = CanonicalTableLeafSet::paired_table_from_rows(
        "world.asset_definitions",
        limits,
        &budget,
        checked.rows().iter(),
    );
    finish_asset_definition_encoding(state, generation, checked, snapshot)
}

fn finish_asset_definition_encoding(
    state: &State,
    generation: u64,
    checked: CheckedAssetDefinitions<'_>,
    snapshot: Result<CanonicalTablePairedSnapshot, LeafError>,
) -> Result<Option<CanonicalTablePairedSnapshot>, LeafError> {
    let current = checked.matches_current();
    drop(checked);
    if !is_stable_state_view_generation(generation, state.state_view_generation()) {
        return Ok(None);
    }
    if !current? {
        return Ok(None);
    }
    Ok(Some(snapshot?))
}

#[cfg(test)]
#[path = "grouped_capture/asset_definition_tests.rs"]
mod asset_definition_tests;
/// Capture exact rwas while retaining every original native reader through encoding.
pub(crate) fn capture_rwas_once(
    state: &State,
    limits: LeafLimits,
) -> Result<Option<CanonicalTablePairedSnapshot>, LeafError> {
    let generation = state.state_view_generation();
    if generation & 1 != 0 {
        return Ok(None);
    }
    let budget = state
        .pipeline_ivm_prepared_cache
        .read()
        .execution_budget()
        .clone();
    let checked = CheckedRwas::capture(
        &state.world,
        limits.max_rows.saturating_mul(RWA_WORK_PER_ROW),
    );
    if !is_stable_state_view_generation(generation, state.state_view_generation()) {
        return Ok(None);
    }
    let checked = match checked {
        Ok(checked) => checked,
        Err(GroupedOwnershipError::Publication(PublicationPreparationError::Changed)) => {
            return Ok(None);
        }
        Err(error) => return Err(error.into()),
    };
    let snapshot = CanonicalTableLeafSet::paired_table_from_rows(
        "world.rwas",
        limits,
        &budget,
        checked.rows().iter(),
    );
    finish_rwas_encoding(state, generation, checked, snapshot)
}
fn finish_rwas_encoding(
    state: &State,
    generation: u64,
    checked: CheckedRwas<'_>,
    snapshot: Result<CanonicalTablePairedSnapshot, LeafError>,
) -> Result<Option<CanonicalTablePairedSnapshot>, LeafError> {
    let current = checked.matches_current();
    drop(checked);
    if !is_stable_state_view_generation(generation, state.state_view_generation()) {
        return Ok(None);
    }
    if !current? {
        return Ok(None);
    }
    Ok(Some(snapshot?))
}
/// Capture canonical escrows through all four original native owners.
pub(crate) fn capture_escrows_once(
    state: &State,
    limits: LeafLimits,
) -> Result<Option<CanonicalTablePairedSnapshot>, LeafError> {
    let generation = state.state_view_generation();
    if generation & 1 != 0 {
        return Ok(None);
    }
    let budget = state.ivm_execution_budget();
    let checked = CheckedEscrows::capture(
        &state.world,
        limits.max_rows.saturating_mul(ESCROW_WORK_PER_ROW),
    );
    if !is_stable_state_view_generation(generation, state.state_view_generation()) {
        return Ok(None);
    }
    let checked = match checked {
        Ok(checked) => checked,
        Err(GroupedOwnershipError::Publication(PublicationPreparationError::Changed)) => {
            return Ok(None);
        }
        Err(error) => return Err(error.into()),
    };
    let snapshot = CanonicalTableLeafSet::paired_table_from_rows(
        "world.asset_escrows",
        limits,
        &budget,
        checked.rows().iter(),
    );
    finish_escrows_encoding(state, generation, checked, snapshot)
}
fn finish_escrows_encoding(
    state: &State,
    generation: u64,
    checked: CheckedEscrows<'_>,
    snapshot: Result<CanonicalTablePairedSnapshot, LeafError>,
) -> Result<Option<CanonicalTablePairedSnapshot>, LeafError> {
    let current = checked.matches_current();
    drop(checked);
    if !is_stable_state_view_generation(generation, state.state_view_generation()) {
        return Ok(None);
    }
    if !current? {
        return Ok(None);
    }
    Ok(Some(snapshot?))
}
#[cfg(test)]
#[path = "grouped_capture/escrows_fence_tests.rs"]
mod escrows_fence_tests;
/// Capture canonical repo_agreements through all four original native owners.
pub(crate) fn capture_repo_agreements_once(
    state: &State,
    limits: LeafLimits,
) -> Result<Option<CanonicalTablePairedSnapshot>, LeafError> {
    let generation = state.state_view_generation();
    if generation & 1 != 0 {
        return Ok(None);
    }
    let budget = state.ivm_execution_budget();
    let checked = CheckedRepoAgreements::capture(
        &state.world,
        limits.max_rows.saturating_mul(REPO_AGREEMENT_WORK_PER_ROW),
    );
    if !is_stable_state_view_generation(generation, state.state_view_generation()) {
        return Ok(None);
    }
    let checked = match checked {
        Ok(checked) => checked,
        Err(GroupedOwnershipError::Publication(PublicationPreparationError::Changed)) => {
            return Ok(None);
        }
        Err(error) => return Err(error.into()),
    };
    let snapshot = CanonicalTableLeafSet::paired_table_from_rows(
        "world.repo_agreements",
        limits,
        &budget,
        checked.rows().iter(),
    );
    finish_repo_agreements_encoding(state, generation, checked, snapshot)
}
fn finish_repo_agreements_encoding(
    state: &State,
    generation: u64,
    checked: CheckedRepoAgreements<'_>,
    snapshot: Result<CanonicalTablePairedSnapshot, LeafError>,
) -> Result<Option<CanonicalTablePairedSnapshot>, LeafError> {
    let current = checked.matches_current();
    drop(checked);
    if !is_stable_state_view_generation(generation, state.state_view_generation()) {
        return Ok(None);
    }
    if !current? {
        return Ok(None);
    }
    Ok(Some(snapshot?))
}
#[cfg(test)]
#[path = "grouped_capture/repo_agreements_fence_tests.rs"]
mod repo_agreements_fence_tests;

grouped_capture!(
    capture_verifying_keys_once,
    CheckedVerifyingKeys,
    "world.verifying_keys",
    1024
);

#[cfg(test)]
#[path = "grouped_capture/nfts_rwas_fence_tests.rs"]
mod nfts_rwas_fence_tests;

#[cfg(test)]
mod direct_home_admission_tests {
    use super::*;
    use crate::{
        kura::Kura, query::store::LiveQueryStore,
        state::authority_registry::grouped_ownership::asset_balance_test_support as fixture,
    };
    use iroha_model_base::topology::DataSpaceId;

    #[test]
    fn committed_readers_retry_in_the_same_state_allocation_pool() {
        let _pin = crossbeam_epoch::pin();
        let mut world = *fixture::fixture(false);
        world
            .set_asset_definition_dataspace_for_testing(
                fixture::definition("coin"),
                DataSpaceId::new(7),
            )
            .unwrap();
        let state = State::new_for_testing(
            world,
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        );
        let pool = state.ivm_execution_budget();
        let original_limit = pool.limit_bytes();
        let generation = state.state_view_generation();
        let baseline = pool.reserved_bytes();
        let limits = LeafLimits {
            max_tables: 1,
            max_rows: 64,
            max_payload_bytes: 65536,
            max_ordered_table_bytes: 131072,
            max_streamed_value_bytes: 131072,
        };
        type Capture =
            fn(&State, LeafLimits) -> Result<Option<CanonicalTablePairedSnapshot>, LeafError>;
        let captures: [Capture; 2] = [capture_assets_once, capture_asset_definitions_once];
        for capture in captures {
            pool.set_limit_bytes(0);
            // Direct-home rows need no extra backing; the leaf encoder refuses the empty pool.
            assert!(matches!(
                capture(&state, limits),
                Err(LeafError::Admission(_) | LeafError::OrderedRange(_))
            ));
            assert_eq!(pool.reserved_bytes(), baseline);
            assert_eq!(state.state_view_generation(), generation);
            pool.set_limit_bytes(original_limit);
            let snapshot = capture(&state, limits).unwrap().unwrap();
            assert!(pool.reserved_bytes() > baseline);
            drop(snapshot);
            assert_eq!(pool.reserved_bytes(), baseline);
            assert_eq!(state.state_view_generation(), generation);
        }
    }
}
