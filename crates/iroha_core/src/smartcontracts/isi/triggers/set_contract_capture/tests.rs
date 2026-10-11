//! Actual native publication owners, held encoder failures and original fixed-pool refunds.
use super::*;
use iroha_test_samples::ALICE_ID;
use std::panic::{AssertUnwindSafe, catch_unwind};
fn limits() -> LeafLimits {
    LeafLimits {
        max_tables: 1,
        max_rows: 8,
        max_payload_bytes: 65536,
        max_ordered_table_bytes: 131072,
        max_streamed_value_bytes: 131072,
    }
}
fn fixture() -> (Set, HashOf<IvmBytecode>) {
    let mut set = Set::default();
    let blob = IvmBytecode::from_compiled(vec![1, 2, 3]);
    let hash = HashOf::new(&blob);
    let action = LoadedAction {
        executable: ExecutableRef::Ivm(hash),
        repeats: Repeats::Indefinitely,
        authority: ALICE_ID.clone(),
        filter: DataEventFilter::Any,
        retry_policy: None,
        retry_state: None,
        metadata: Metadata::default(),
    };
    set.data_triggers = [("a".parse().unwrap(), action)].into_iter().collect();
    set.contracts = [(
        hash,
        IvmBytecodeEntry {
            code_hash: ivm::contract_code_hash(blob.as_ref()),
            original_contract: blob,
            count: NonZeroU64::MIN,
        },
    )]
    .into_iter()
    .collect();
    (set, hash)
}
fn freeze(block: &mut SetBlock<'_>) {
    block.begin_freeze();
    block.finish_freeze();
    block.retire_frozen_cleanup();
}
#[test]
fn committed_five_reader_owner_keeps_counter_until_encoding_and_final_probes() {
    let (set, _) = fixture();
    let pool = AllocationBudget::new(16 * 1024 * 1024);
    let mut checked = CheckedContracts::capture(&set, u64::MAX, &pool).unwrap();
    let counter = pool.reserved_bytes();
    assert!(counter > 0);
    let encoded = checked.encode(limits()).unwrap();
    assert!(pool.reserved_bytes() > counter);
    assert_eq!(checked.matches_current(), Ok(true));
    assert_eq!(encoded.table_id(), "triggers.contracts");
    assert_eq!(encoded.row_count(), 1);
    drop(encoded);
    assert_eq!(pool.reserved_bytes(), counter);
    drop(checked);
    assert_eq!(pool.reserved_bytes(), 0);
}
#[test]
fn all_five_equal_value_publications_and_foreign_targets_fail_their_original_identity() {
    for source in 0..5 {
        let (set, key) = fixture();
        let pool = AllocationBudget::new(16 * 1024 * 1024);
        let checked = CheckedContracts::capture(&set, u64::MAX, &pool).unwrap();
        match source {
            0 => {
                let original = set
                    .data_triggers
                    .view()
                    .get(&"a".parse().unwrap())
                    .unwrap()
                    .clone();
                let mut block = set.data_triggers.block();
                block.insert("a".parse().unwrap(), original);
                block.commit();
            }
            1 => {
                set.pipeline_triggers.block().commit();
            }
            2 => {
                set.time_triggers.block().commit();
            }
            3 => {
                set.by_call_triggers.block().commit();
            }
            _ => {
                let original = set.contracts.view().get(&key).unwrap().clone();
                let mut block = set.contracts.block();
                block.insert(key, original);
                block.commit();
            }
        }
        assert_eq!(checked.matches_current(), Ok(false));
        assert_eq!(checked.probes.get(), [2; 5]);
        let foreign = Set::default();
        assert!(
            !checked
                .data
                .try_matches_current(&foreign.data_triggers)
                .unwrap()
        );
        assert!(
            !checked
                .pipeline
                .try_matches_current(&foreign.pipeline_triggers)
                .unwrap()
        );
        assert!(
            !checked
                .time
                .try_matches_current(&foreign.time_triggers)
                .unwrap()
        );
        assert!(
            !checked
                .by_call
                .try_matches_current(&foreign.by_call_triggers)
                .unwrap()
        );
        assert!(
            !checked
                .contracts
                .try_matches_current(&foreign.contracts)
                .unwrap()
        );
        drop(checked);
        assert_eq!(pool.reserved_bytes(), 0);
    }
}
#[test]
fn canonical_leaf_outcome_is_held_before_changed_identity_and_unwind_refund() {
    let (set, _) = fixture();
    let pool = AllocationBudget::new(16 * 1024 * 1024);
    let mut checked = CheckedContracts::capture(&set, u64::MAX, &pool).unwrap();
    let counter = pool.reserved_bytes();
    let outcome = checked.encode(LeafLimits {
        max_payload_bytes: 0,
        ..limits()
    });
    assert!(outcome.is_err());
    assert_eq!(pool.reserved_bytes(), counter);
    set.time_triggers.block().commit();
    assert_eq!(checked.matches_current(), Ok(false));
    drop(checked);
    assert_eq!(pool.reserved_bytes(), 0);
    assert!(
        catch_unwind(AssertUnwindSafe(|| {
            let mut checked = CheckedContracts::capture(&set, u64::MAX, &pool).unwrap();
            let _outcome = checked.encode(limits()).unwrap();
            panic!("original held encoder outcome");
        }))
        .is_err()
    );
    assert_eq!(pool.reserved_bytes(), 0);
}
#[test]
fn frozen_modes_accept_the_actual_ten_targets_and_reject_every_foreign_component() {
    let (set, _) = fixture();
    let foreign = Set::default();
    let pool = AllocationBudget::new(16 * 1024 * 1024);
    for replace in [false, true] {
        let mut block = if replace {
            set.block_and_revert()
        } else {
            set.block()
        };
        assert!(FrozenContracts::retain(&block, &set).is_none());
        freeze(&mut block);
        let original = FrozenContracts::retain(&block, &set).unwrap();
        assert_eq!(
            original.data.mode(),
            if replace {
                mv::BlockMode::Replace
            } else {
                mv::BlockMode::Ordinary
            }
        );
        drop(original);
        assert!(FrozenContracts::retain(&block, &foreign).is_none());
        let result = block
            .capture_frozen_contracts_authority_table(&set, limits(), &pool, u64::MAX)
            .unwrap()
            .unwrap();
        assert_eq!(result.row_count(), 1);
        drop(result);
        assert_eq!(pool.reserved_bytes(), 0);
    }
}
#[test]
fn partial_reacquiring_and_released_set_contexts_never_allocate_or_refresh() {
    let (set, _) = fixture();
    let pool = AllocationBudget::new(16 * 1024 * 1024);
    let mut block = set.block();
    block.contracts.begin_freeze();
    block.contracts.finish_freeze();
    assert!(FrozenContracts::retain(&block, &set).is_none());
    assert_eq!(pool.peak_reserved_bytes(), 0);
    drop(block);
    let mut block = set.block();
    freeze(&mut block);
    block.publication.begin_reacquisition();
    assert!(FrozenContracts::retain(&block, &set).is_none());
    block.publication.recover_reacquisition();
    assert!(FrozenContracts::retain(&block, &set).is_some());
    mv::BlockRetirement::release_writers(&mut block);
    assert!(FrozenContracts::retain(&block, &set).is_none());
    assert_eq!(pool.peak_reserved_bytes(), 0);
}
#[test]
fn mixed_mode_and_one_foreign_derived_owner_refuse_without_semantic_index_authority() {
    let (set, _) = fixture();
    let foreign = Set::default();
    let pool = AllocationBudget::new(0);
    let mut block = set.block();
    // Replace exactly one actual context field; no new RawStorageImages implementation.
    block.fields.as_mut().unwrap().ids = BlockField::new(foreign.ids.block());
    freeze(&mut block);
    assert!(FrozenContracts::retain(&block, &set).is_none());
    assert_eq!(pool.peak_reserved_bytes(), 0);
    drop(block);
    let mut block = set.block();
    mv::BlockRetirement::release_writers(
        &mut block.fields.as_mut().unwrap().active_time_trigger_ids,
    );
    block.fields.as_mut().unwrap().active_time_trigger_ids =
        BlockField::new(set.active_time_trigger_ids.block_and_revert());
    freeze(&mut block);
    assert!(FrozenContracts::retain(&block, &set).is_none());
    assert_eq!(pool.reserved_bytes(), 0);
}
#[test]
fn all_five_independent_capture_literals_admit_exactly_and_refuse_one_below() {
    if usize::BITS != 64 {
        return;
    } // Separate native envelope controls cover32-bit.
    let (singleton, key) = fixture();
    let mut masked = Set::default();
    let mut entry = singleton.contracts.view().get(&key).unwrap().clone();
    entry.count = NonZeroU64::new(2).unwrap();
    let action = singleton
        .data_triggers
        .view()
        .get(&"a".parse().unwrap())
        .unwrap()
        .clone();
    masked.data_triggers = [
        ("a".parse().unwrap(), action.clone()),
        ("c".parse().unwrap(), action.clone()),
    ]
    .into_iter()
    .collect();
    masked.contracts = [(key, entry.clone())].into_iter().collect();
    let mut block = masked.block();
    block.data_triggers.remove("a".parse().unwrap());
    block
        .data_triggers
        .insert("b".parse().unwrap(), action.clone());
    block
        .data_triggers
        .insert("c".parse().unwrap(), action.clone());
    block.contracts.insert(key, entry);
    block.commit();
    let mut distinct = Set::default();
    let mut actions = Vec::new();
    let mut contracts = Vec::new();
    for (label, length) in [("a", 0usize), ("b", 119), ("c", 120)] {
        let bytes = IvmBytecode::from_compiled(vec![0x55; length]);
        let hash = HashOf::new(&bytes);
        let mut row = action.clone();
        row.executable = ExecutableRef::Ivm(hash);
        actions.push((label.parse().unwrap(), row));
        contracts.push((
            hash,
            IvmBytecodeEntry {
                code_hash: ivm::contract_code_hash(bytes.as_ref()),
                original_contract: bytes,
                count: NonZeroU64::MIN,
            },
        ));
    }
    distinct.data_triggers = actions.into_iter().collect();
    distinct.contracts = contracts.into_iter().collect();
    let (mut long, long_key) = fixture();
    let label: TriggerId = format!("{}z", "α".repeat(127)).parse().unwrap();
    assert_eq!(AsRef::<str>::as_ref(label.name()).len(), 255);
    long.data_triggers = [(label.clone(), action.clone())].into_iter().collect();
    let original = long.contracts.view().get(&long_key).unwrap().clone();
    let mut block = long.block();
    block.data_triggers.insert(label, action);
    block.contracts.insert(long_key, original);
    block.commit();
    // Three independent contracts: 24 cursor setups, 31 next calls (including terminals),
    // and prepare/current/reset/predecessor/encoder controls of 29/2800/5/2822/2.
    // The 0/119/120-byte contracts cross the actual compact-prefix boundary.
    assert_eq!(24_u64 * 1900 + 31 * 1114 + 29 + 2800 + 5 + 2822 + 2, 85792);
    for (source, exact, current_rows, undo_rows) in [
        (Set::default(), 63507, 0, 0),
        (singleton, 70000, 1, 0),
        (masked, 77066, 2, 3),
        (distinct, 85792, 3, 0),
        (long, 72814, 1, 1),
    ] {
        let raw = source
            .data_triggers
            .try_committed_view_nonblocking()
            .unwrap();
        assert_eq!(raw.current().len(), current_rows);
        assert_eq!(raw.undo().len(), undo_rows);
        drop(raw);
        let pool = AllocationBudget::new(16 * 1024 * 1024);
        for amount in [exact - 1, exact, exact + 1] {
            let mut checked = CheckedContracts::capture(&source, amount, &pool).unwrap();
            let outcome = checked.encode(limits());
            let current = checked.matches_current();
            assert_eq!(current, Ok(true));
            let remaining = checked.strategy.as_ref().unwrap().action_remaining();
            drop(checked);
            if amount < exact {
                assert!(matches!(
                    outcome,
                    Err(LeafError::TriggerContracts(TriggerContractError::WorkLimit))
                ));
            } else {
                assert_eq!(remaining, amount - exact);
                let snapshot = outcome.unwrap();
                assert_eq!(snapshot.table_id(), "triggers.contracts");
                assert_eq!(
                    snapshot.row_count(),
                    if current_rows == 3 {
                        3
                    } else if current_rows == 0 {
                        0
                    } else {
                        1
                    }
                );
                drop(snapshot);
            }
            assert_eq!(pool.reserved_bytes(), 0);
        }
    }
}
