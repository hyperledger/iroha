//! Actual World net-delta controls, separate from complete State-root qualification.

use super::*;
use crate::state::{World, block_field::BlockField};
use iroha_model_base::state_path::StatePath;
use mv::{cell::Cell, storage::Storage};
use std::panic::{AssertUnwindSafe, catch_unwind};

fn path(key: &str) -> StatePath {
    key.parse().expect("valid durable State path")
}

#[test]
fn world_delta_ignores_noop_touch_history_and_aborted_changes() {
    let direct_world = World::default();
    let mut direct = direct_world.block();
    let key = path("application/value");
    direct.smart_contract_state.insert(key.clone(), vec![2]);
    *direct.soradns_last_publish_ms.get_mut() = Some(12);

    let sequenced_world = World::default();
    let mut sequenced = sequenced_world.block();
    sequenced.smart_contract_state.remove(path("absent/noop"));
    {
        let mut tx = sequenced.smart_contract_state.transaction();
        tx.insert(key.clone(), vec![1]);
        tx.apply();
    }
    {
        let mut tx = sequenced.smart_contract_state.transaction();
        tx.insert(key.clone(), vec![99]);
        tx.insert(path("aborted/new"), vec![3]);
    }
    sequenced.smart_contract_state.insert(key, vec![2]);
    *sequenced.soradns_last_publish_ms.get_mut() = Some(12);
    *sequenced.soradns_history_len.get_mut() = *direct.soradns_history_len.get();
    let actual = direct.net_state_delta().unwrap();
    assert_eq!(actual.changed_values(), 2);
    assert_eq!(actual, sequenced.net_state_delta().unwrap());
    assert_eq!(
        actual.fields,
        crate::state::authority_registry::inventory_test_support::world_delta_field_count(),
        "every original World overlay field, with TriggerSet replaced by every typed trigger store"
    );
}

#[test]
fn publication_delta_retains_noop_undo_entries_but_ignores_aborted_children() {
    let world = World::default();
    let mut block = world.block();
    let semantic = block.net_state_delta().unwrap();
    let original = block.publication_state_delta().unwrap();
    {
        let mut aborted = block.smart_contract_state.transaction();
        aborted.insert(path("publication/aborted"), vec![1]);
    }
    assert_eq!(original, block.publication_state_delta().unwrap());
    block
        .smart_contract_state
        .remove(path("publication/absent"));
    assert_eq!(semantic, block.net_state_delta().unwrap());
    let touched_storage = block.publication_state_delta().unwrap();
    assert_ne!(original, touched_storage);
    let _ = block.soradns_last_publish_ms.get_mut();
    assert_eq!(semantic, block.net_state_delta().unwrap());
    assert_ne!(touched_storage, block.publication_state_delta().unwrap());
}

#[test]
fn delta_binds_actual_preimages_deletions_empty_bytes_and_physical_keys() {
    fn capture(before: Option<Vec<u8>>, after: Option<Vec<u8>>, key: &str) -> WorldNetDelta {
        let world = World::default();
        if let Some(value) = before {
            let mut setup = world.smart_contract_state.block();
            setup.insert(path(key), value);
            setup.commit();
        }
        let mut block = world.block();
        match after {
            Some(value) => {
                block.smart_contract_state.insert(path(key), value);
            }
            None => {
                block.smart_contract_state.remove(path(key));
            }
        }
        block.net_state_delta().unwrap()
    }
    let insert = capture(None, Some(vec![1]), "app/a");
    assert_eq!(insert.changed_values(), 1);
    assert_ne!(insert, capture(Some(vec![0]), Some(vec![1]), "app/a"));
    assert_ne!(insert, capture(None, Some(vec![1]), "app/b"));
    assert_ne!(insert, capture(None, Some(Vec::new()), "app/a"));
    assert_ne!(
        capture(Some(Vec::new()), None, "app/a"),
        capture(Some(Vec::new()), Some(vec![1]), "app/a")
    );
    assert_eq!(
        capture(Some(Vec::new()), Some(Vec::new()), "app/a").changed_values(),
        0
    );
    assert_eq!(capture(None, None, "app/a").changed_values(), 0);
}

#[test]
fn snapshot_skipped_authoritative_values_and_derived_indexes_are_included() {
    let world = World::default();
    let mut block = world.block();
    let empty = block.net_state_delta().unwrap();
    // This authoritative SoraDNS cell is omitted by the recovery JSON projection.
    *block.soradns_last_publish_ms.get_mut() = Some(42);
    let policy = block.net_state_delta().unwrap();
    assert_eq!(policy.changed_values(), 1);
    assert_ne!(empty, policy);
    // A derived consensus lookup index is still an execution-visible State value.
    block.contract_subject_addresses.insert(
        iroha_test_samples::ALICE_ID.clone(),
        iroha_data_model::smart_contract::ContractAddress::derive(
            &crate::state::DEFAULT_TEST_NETWORK_ID,
            &iroha_test_samples::ALICE_ID,
            1,
            iroha_model_base::topology::DataSpaceId::UNIVERSAL,
        )
        .unwrap(),
    );
    let indexed = block.net_state_delta().unwrap();
    assert_eq!(indexed.changed_values(), 2);
    assert_ne!(policy, indexed);
}

#[test]
fn untouched_state_is_explicitly_outside_the_net_delta() {
    let first = World::default();
    let second = World::default();
    {
        let mut setup = second.smart_contract_state.block();
        setup.insert(path("untouched/value"), vec![9]);
        setup.commit();
    }
    let first = first.block();
    let second = second.block();
    assert_eq!(
        first.net_state_delta().unwrap(),
        second.net_state_delta().unwrap(),
        "a net delta is not an authenticated full State root"
    );
}

#[test]
fn canonical_value_hash_stream_matches_fixed_v1_bytes_under_ambient_flags() {
    let value = (vec![1_u8, 2, 3], Some("value".to_owned()), 123_u64);
    let encoded = value.encode();
    let expected = Hash::new_from_chunks(&[
        VALUE_DOMAIN,
        &encoded,
        &(encoded.len() as u64).to_le_bytes(),
    ]);
    assert_eq!(hash_value(&value).unwrap(), expected);
    for flags in [0, norito::core::default_encode_flags()] {
        let _guard = norito::core::DecodeFlagsGuard::enter(flags);
        assert_eq!(hash_value(&value).unwrap(), expected);
    }
}

#[test]
fn fields_and_presence_are_domain_separated_and_empty_fields_are_retained() {
    let storage: Storage<u64, Vec<u8>> = [(1, vec![1])].into_iter().collect();
    let mut block = BlockField::new(storage.block());
    block.insert(1, vec![2]);
    let mut first = WorldDeltaBuilder::new();
    first.append_storage_with("a", &block, hash_value).unwrap();
    let mut other = WorldDeltaBuilder::new();
    other.append_storage_with("b", &block, hash_value).unwrap();
    assert_ne!(first.finish().unwrap(), other.finish().unwrap());
    let cell = Cell::new(1_u64);
    let block = BlockField::new(cell.block());
    let mut empty_field = WorldDeltaBuilder::new();
    empty_field
        .append_cell_with("empty", &block, hash_value)
        .unwrap();
    assert_ne!(
        empty_field.finish().unwrap(),
        WorldDeltaBuilder::new().finish().unwrap()
    );
}

#[test]
fn encoding_error_or_unwind_permanently_refuses_partial_projection() {
    let storage: Storage<u64, Vec<u8>> = Storage::new();
    let mut block = BlockField::new(storage.block());
    block.insert(1, vec![1]);
    let mut failed = WorldDeltaBuilder::new();
    assert!(
        failed
            .append_storage_with("state", &block, |_| Err("encoder failed".into()))
            .is_err()
    );
    assert!(
        failed
            .append_storage_with("state", &block, hash_value)
            .is_err()
    );
    assert!(failed.finish().is_err());
    let mut interrupted = WorldDeltaBuilder::new();
    let result = catch_unwind(AssertUnwindSafe(|| {
        let _ = interrupted.append_storage_with("state", &block, |_| panic!("encoder unwind"));
    }));
    assert!(result.is_err());
    assert!(interrupted.finish().is_err());
    let mut overflow = WorldDeltaBuilder::new();
    overflow.changed_values = u64::MAX;
    assert!(
        overflow
            .append_storage_with("state", &block, hash_value)
            .is_err()
    );
    assert!(overflow.finish().is_err());
}
