//! Original generation graph, record wire and current/undo admission controls.

use super::*;
use crate::smartcontracts::isi::sccp::test_support::sample_generation;
use norito::codec::Encode as _;

fn source_with_account() -> SccpCommitteeGenerationV1 {
    use iroha_crypto::{Algorithm, KeyPair};
    use iroha_data_model::account::{MultisigMember, MultisigPolicy};
    let members = (31..=32)
        .map(|seed| {
            let pair = KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519).unwrap();
            MultisigMember::new(pair.public_key().clone(), 1).unwrap()
        })
        .collect();
    let account = AccountId::new_multisig(MultisigPolicy::new(2, members).unwrap());
    let mut record = sample_generation(1, 1);
    record.members[0] = Some(SccpGenerationMemberV1 {
        lane_id: LaneId::SINGLE,
        validator: account,
        activation_height: 1,
    });
    assert!(record.is_well_formed());
    record
}

#[test]
fn nested_account_graph_is_retained_once_and_wire_is_unchanged() {
    let source = source_with_account();
    let budget = AllocationBudget::new(1 << 20);
    let owner = RetainedGeneration::try_copy(&source, &budget).unwrap();
    let bytes = budget.reserved_bytes();
    assert!(bytes > std::mem::size_of::<SccpCommitteeGenerationV1>());
    assert!(owner.belongs_to(&budget));
    assert!(!owner.belongs_to(&AllocationBudget::new(1 << 20)));
    assert_eq!(owner.encode(), source.encode());
    assert_eq!(
        norito::json::to_json(&owner).unwrap(),
        norito::json::to_json(&source).unwrap()
    );
    let reader = owner.clone();
    assert_eq!(budget.reserved_bytes(), bytes);
    assert!(std::ptr::eq(&*owner, &*reader));
    drop(owner);
    assert_eq!(budget.reserved_bytes(), bytes);
    assert_eq!(&*reader, &source);
    drop(reader);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn exact_record_capacity_refuses_before_any_retained_owner_and_retries() {
    let source = source_with_account();
    let measure = AllocationBudget::new(1 << 20);
    let owner = RetainedGeneration::try_copy(&source, &measure).unwrap();
    let demand = measure.reserved_bytes();
    drop(owner);
    let budget = AllocationBudget::new(demand - 1);
    assert!(matches!(
        RetainedGeneration::try_copy(&source, &budget),
        Err(GenerationAdmissionError::Storage(
            AdmittedStorageError::Allocation(_)
        ))
    ));
    assert_eq!(budget.reserved_bytes(), 0);
    budget.set_limit_bytes(demand);
    let owner = RetainedGeneration::try_copy(&source, &budget).unwrap();
    assert_eq!(budget.reserved_bytes(), demand);
    assert_eq!(&*owner, &source);
    drop(owner);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn ended_and_progress_records_do_not_mutate_retained_predecessors() {
    let source = source_with_account();
    let budget = AllocationBudget::new(1 << 20);
    let original = RetainedGeneration::try_copy(&source, &budget).unwrap();
    let end = SccpGenerationEndV1 {
        end_height: 2,
        end_timestamp_ms: 8_000,
        next_committee_root: source.committee_root,
        successor_validity_ms: source.validity_ms,
    };
    let ended = original.with_end(end, &budget).unwrap();
    let cleared = ended.with_progress(ended.deadline_ms + 1, &budget).unwrap();
    assert_eq!(&*original, &source);
    assert_eq!(ended.end, Some(end));
    assert_eq!(ended.dest_cleared_lc, None);
    assert_eq!(cleared.dest_cleared_lc, Some(ended.deadline_ms + 1));
    assert!(!std::ptr::eq(&*original, &*ended));
    assert!(matches!(
        ended.with_progress(0, &budget),
        Err(GenerationAdmissionError::Invalid)
    ));
    drop((original, ended, cleared));
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn snapshot_decoder_retains_original_budget_and_composes_outer_refusal() {
    let source = source_with_account();
    let hex = hex::encode(source.encode());
    let budget = AllocationBudget::new(1 << 20);
    let owner = RetainedGeneration::decode_snapshot_hex(&hex, &budget).unwrap();
    assert_eq!(&*owner, &source);
    assert!(owner.belongs_to(&budget));
    assert_eq!(owner.encode(), source.encode());
    drop(owner);
    assert_eq!(budget.reserved_bytes(), 0);
    let invalid = format!("{hex}00");
    assert!(matches!(
        RetainedGeneration::decode_snapshot_hex(&invalid, &budget),
        Err(GenerationAdmissionError::Invalid)
    ));
    assert_eq!(budget.reserved_bytes(), 0);
    let outer = norito::core::DecodeBudgetContext::new(norito::DecodeLimits::new(
        usize::MAX,
        usize::MAX,
        usize::MAX,
        0,
        usize::MAX,
    ));
    let result = outer.with(|| RetainedGeneration::decode_snapshot_hex(&hex, &budget));
    assert!(matches!(result, Err(GenerationAdmissionError::Codec(_))));
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn current_undo_restore_moves_noncopy_owners_and_preserves_exact_envelope() {
    let budget = AllocationBudget::new(1 << 20);
    let old = sample_generation(1, 1);
    let new = sample_generation(2, 2);
    let map = GenerationStorage::try_restore_admitted(budget.clone(), |current, undo| {
        undo(1, Some(RetainedGeneration::try_copy(&old, &budget)?))?;
        undo(2, None)?;
        current(2, RetainedGeneration::try_copy(&new, &budget)?)?;
        Ok::<_, GenerationAdmissionError>(())
    })
    .unwrap();
    let mut envelope = String::new();
    crate::state::snapshot_storage::serialize(&map, &mut envelope);
    let restored_budget = AllocationBudget::new(1 << 20);
    let source: crate::state::snapshot_storage::SnapshotStorage =
        norito::json::from_str(&envelope).unwrap();
    let restored = source.decode_generations(&restored_budget).unwrap();
    let mut again = String::new();
    crate::state::snapshot_storage::serialize(&restored, &mut again);
    assert_eq!(again, envelope);
    let snapshot = restored.snapshot();
    assert_eq!(snapshot.current().get(&2).map(|v| &**v), Some(&new));
    assert_eq!(
        snapshot.revert_map().get(&1).unwrap().as_deref(),
        Some(&old)
    );
    assert!(snapshot.revert_map().get(&2).unwrap().is_none());
    drop(snapshot);
    drop((map, restored));
    assert_eq!(budget.reserved_bytes(), 0);
    assert_eq!(restored_budget.reserved_bytes(), 0);
}

#[test]
fn streamed_restore_failure_releases_partial_owned_current_and_undo() {
    let budget = AllocationBudget::new(1 << 20);
    let source = source_with_account();
    let result = GenerationStorage::try_restore_admitted(budget.clone(), |current, undo| {
        undo(1, Some(RetainedGeneration::try_copy(&source, &budget)?))?;
        current(1, RetainedGeneration::try_copy(&source, &budget)?)?;
        Err::<(), _>(GenerationAdmissionError::Invalid)
    });
    assert!(matches!(
        result,
        Err(mv::storage::AdmittedBlockError::Callback(
            GenerationAdmissionError::Invalid
        ))
    ));
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn child_drop_restores_current_and_undo_and_keeps_original_pool() {
    let budget = AllocationBudget::new(1 << 20);
    let map = GenerationStorage::try_new_admitted(budget.clone()).unwrap();
    let source = source_with_account();
    map.try_with_admitted_block(|block| {
        assert!(block.allocation_budget().same_pool(&budget));
        block
            .try_insert_admitted(1, RetainedGeneration::try_copy(&source, &budget)?)
            .map_err(|(_, e)| e)?;
        {
            let mut child = block.try_transaction_admitted()?;
            assert!(child.allocation_budget().same_pool(&budget));
            child.try_remove_admitted(1).map_err(|(_, e)| e)?;
            assert!(child.get(&1).is_none());
        }
        assert_eq!(block.get(&1).map(|v| &**v), Some(&source));
        Ok::<_, GenerationAdmissionError>(())
    })
    .unwrap();
    assert_eq!(map.view().get(&1).map(|v| &**v), Some(&source));
    assert!(map.snapshot().revert_map().get(&1).unwrap().is_none());
    drop(map);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn snapshot_capacity_is_typed_local_admission_not_corruption() {
    let source = source_with_account();
    let hex = hex::encode(source.encode());
    let budget = AllocationBudget::new(1);
    let original = RetainedGeneration::decode_snapshot_hex(&hex, &budget)
        .err()
        .unwrap();
    assert!(matches!(
        original,
        GenerationAdmissionError::Storage(AdmittedStorageError::Allocation(_))
    ));
    let error = crate::snapshot::TryReadError::from(
        crate::state::deserialize::StateRestoreError::from(original),
    );
    assert!(matches!(
        error,
        crate::snapshot::TryReadError::StateAdmission(_)
    ));
    assert_eq!(budget.reserved_bytes(), 0);
}
