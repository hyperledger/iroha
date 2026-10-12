//! Original generation graph, record wire and current/undo admission controls.

use super::*;
use crate::smartcontracts::isi::sccp::test_support::sample_generation;
use crate::{
    smartcontracts::isi::sccp::committee_storage::CommitteeStorage, state::SccpRestoreError,
};
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
    let mut record = sample_generation(1);
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
    let owner = RetainedSccpGeneration::admit(&source, &budget).unwrap();
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
    let owner = RetainedSccpGeneration::admit(&source, &measure).unwrap();
    let demand = measure.reserved_bytes();
    drop(owner);
    let budget = AllocationBudget::new(demand - 1);
    assert!(matches!(
        RetainedSccpGeneration::admit(&source, &budget),
        Err(GenerationRecordError::Admission(_))
    ));
    assert_eq!(budget.reserved_bytes(), 0);
    budget.set_limit_bytes(demand);
    let owner = RetainedSccpGeneration::admit(&source, &budget).unwrap();
    assert_eq!(budget.reserved_bytes(), demand);
    assert_eq!(&*owner, &source);
    drop(owner);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn ended_and_progress_records_do_not_mutate_retained_predecessors() {
    let source = source_with_account();
    let budget = AllocationBudget::new(1 << 20);
    let original = RetainedSccpGeneration::admit(&source, &budget).unwrap();
    let end = SccpGenerationEndV1 {
        end_height: 2,
        end_timestamp_ms: 8_000,
        next_committee_root: source.committee_root,
        successor_validity_ms: source.validity_ms,
    };
    let mut ended = original.clone();
    ended.end = Some(end);
    let mut cleared = ended.clone();
    cleared.dest_cleared_lc = Some(ended.deadline_ms + 1);
    assert_eq!(&*original, &source);
    assert_eq!(ended.end, Some(end));
    assert_eq!(ended.dest_cleared_lc, None);
    assert_eq!(cleared.dest_cleared_lc, Some(ended.deadline_ms + 1));
    assert!(std::ptr::eq(&*original, &*ended));
    assert_eq!(
        budget.reserved_bytes(),
        RetainedSccpGeneration::admission_demand(&source).unwrap()
    );
    let mut invalid = ended.clone();
    invalid.dest_cleared_lc = Some(0);
    assert!(!invalid.is_well_formed());
    drop(invalid);
    drop((original, ended, cleared));
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn snapshot_decoder_retains_original_budget_and_composes_outer_refusal() {
    let source = source_with_account();
    let hex = hex::encode(source.encode());
    let budget = AllocationBudget::new(1 << 20);
    let owner = RetainedSccpGeneration::decode_snapshot_hex(&hex, &budget).unwrap();
    assert_eq!(&*owner, &source);
    assert!(owner.belongs_to(&budget));
    assert_eq!(owner.encode(), source.encode());
    drop(owner);
    assert_eq!(budget.reserved_bytes(), 0);
    let invalid = format!("{hex}00");
    assert!(matches!(
        RetainedSccpGeneration::decode_snapshot_hex(&invalid, &budget),
        Err(GenerationRecordError::Invalid("snapshot record"))
    ));
    assert_eq!(budget.reserved_bytes(), 0);
    let outer = norito::core::DecodeBudgetContext::new(norito::DecodeLimits::new(
        usize::MAX,
        usize::MAX,
        usize::MAX,
        0,
        usize::MAX,
    ));
    let result = outer.with(|| RetainedSccpGeneration::decode_snapshot_hex(&hex, &budget));
    assert!(
        matches!(result, Err(GenerationRecordError::Account(ref error)) if error.decode_resource_error().is_some())
    );
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn current_undo_restore_moves_noncopy_owners_and_preserves_exact_envelope() {
    let budget = AllocationBudget::new(1 << 20);
    let old = sample_generation(1);
    let new = sample_generation(2);
    let map = CommitteeStorage::try_restore_admitted(budget.clone(), |current, undo| {
        undo(1, Some(RetainedSccpGeneration::admit(&old, &budget)?))?;
        undo(2, None)?;
        current(2, RetainedSccpGeneration::admit(&new, &budget)?)?;
        Ok::<_, SccpRestoreError>(())
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
    let result = CommitteeStorage::try_restore_admitted(budget.clone(), |current, undo| {
        undo(1, Some(RetainedSccpGeneration::admit(&source, &budget)?))?;
        current(1, RetainedSccpGeneration::admit(&source, &budget)?)?;
        Err::<(), _>(SccpRestoreError::Generation(
            GenerationRecordError::Invalid("snapshot record"),
        ))
    });
    assert!(matches!(
        result,
        Err(mv::storage::AdmittedBlockError::Callback(
            SccpRestoreError::Generation(GenerationRecordError::Invalid("snapshot record"))
        ))
    ));
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn child_drop_restores_current_and_undo_and_keeps_original_pool() {
    let budget = AllocationBudget::new(1 << 20);
    let map = CommitteeStorage::try_new_admitted(budget.clone()).unwrap();
    let source = source_with_account();
    map.try_with_admitted_block(|block| {
        assert!(block.allocation_budget().same_pool(&budget));
        block
            .try_insert_admitted(1, RetainedSccpGeneration::admit(&source, &budget)?)
            .map_err(|(_, e)| e)?;
        {
            let mut child = block.try_transaction_admitted()?;
            assert!(child.allocation_budget().same_pool(&budget));
            child.try_remove_admitted(1).map_err(|(_, e)| e)?;
            assert!(child.get(&1).is_none());
        }
        assert_eq!(block.get(&1).map(|v| &**v), Some(&source));
        Ok::<_, SccpRestoreError>(())
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
    let original = RetainedSccpGeneration::decode_snapshot_hex(&hex, &budget)
        .err()
        .unwrap();
    assert!(matches!(original, GenerationRecordError::Admission(_)));
    let error = crate::snapshot::TryReadError::from(
        crate::state::deserialize::StateRestoreError::Sccp(SccpRestoreError::Generation(original)),
    );
    assert!(matches!(
        error,
        crate::snapshot::TryReadError::StateSccp(SccpRestoreError::Generation(
            GenerationRecordError::Admission(_)
        ))
    ));
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn direct_snapshot_restores_lifecycle_without_copying_or_mutating_immutable_body() {
    let mut source = source_with_account();
    source.end = Some(SccpGenerationEndV1 {
        end_height: 2,
        end_timestamp_ms: 8_000,
        next_committee_root: source.committee_root,
        successor_validity_ms: source.validity_ms,
    });
    source.dest_cleared_lc = Some(source.deadline_ms + 1);
    assert!(source.is_well_formed());
    let budget = AllocationBudget::new(1 << 20);
    let original =
        RetainedSccpGeneration::decode_snapshot_hex(&hex::encode(source.encode()), &budget)
            .unwrap();
    assert_eq!(original.encode(), source.encode());
    assert_eq!(
        norito::json::to_json(&original).unwrap(),
        norito::json::to_json(&source).unwrap()
    );
    let bytes = budget.reserved_bytes();
    let mut changed = original.clone();
    changed.dest_cleared_lc = Some(source.deadline_ms + 2);
    assert!(std::ptr::eq(&*original, &*changed));
    assert_eq!(budget.reserved_bytes(), bytes);
    assert_eq!(original.dest_cleared_lc, source.dest_cleared_lc);
    assert_ne!(original, changed);
    assert_ne!(original.encode(), changed.encode());
    drop(original);
    assert_eq!(budget.reserved_bytes(), bytes);
    drop(changed);
    assert_eq!(budget.reserved_bytes(), 0);
}
