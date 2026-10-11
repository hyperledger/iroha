//! Exact pre-seal event cut, bounded preparation, rollback and path canonicality.

use super::*;
use crate::state::{State, World, WorldReadOnly};
use iroha_data_model::block::BlockHeader;

fn event(index: u8) -> EventBox {
    let mut receipt_digest = [0; 32];
    receipt_digest[0] = index;
    EventBox::Data(
        DataEvent::KagemushaLoadCommitted(KagemushaLoadCommittedV1 { receipt_digest }).into(),
    )
}
fn state() -> State {
    State::new_for_testing(
        World::default(),
        crate::kura::Kura::blank_kura_for_testing(),
        crate::query::store::LiveQueryStore::start_test(),
    )
}
fn header() -> BlockHeader {
    BlockHeader::new(2.try_into().unwrap(), None, None, 2_000, 0)
}

#[test]
fn retained_paths_bind_every_original_leaf_count_index_height_and_canonical_tail() {
    let state = state();
    let budget = AllocationBudget::new(2_000_000);
    let mut block = state.block(header());
    let mut tx = block.transaction();
    tx.world.external_event_buf.extend((1..=5).map(event));
    tx.apply();
    let tree = block
        .world
        .pending_external_events()
        .iter()
        .map(HashOf::new)
        .collect::<MerkleTree<_>>();
    let before = block.world_state_transition().unwrap();
    retain(&mut block.world, 2, &budget).unwrap();
    let after = block.world_state_transition().unwrap();
    assert_ne!(before.world_state_root, after.world_state_root);
    assert_eq!(
        before.parent_world_state_root,
        after.parent_world_state_root
    );
    assert_eq!(before.event_commitment, after.event_commitment);
    assert_eq!(after.event_commitment, tree.commitment());
    assert_eq!(budget.reserved_bytes(), 0);
    for index in 0..5 {
        let mut digest = [0; 32];
        digest[0] = u8::try_from(index + 1).unwrap();
        let selected = key(digest);
        let bytes = block.world.kagemusha_wallet_ledger.get(&selected).unwrap();
        let row: KagemushaLoadEventPathV1 = storage::decode(bytes, CAP).unwrap();
        row.validate(&selected).unwrap();
        assert_eq!(row.height(), 2);
        assert_eq!(row.receipt_digest(), &digest);
        assert_eq!(Some(row.commitment()), tree.commitment());
        assert_eq!(Some(row.proof().unwrap()), tree.get_proof(index));
        assert_eq!(storage::encode(&row).unwrap(), *bytes);
        let mut changed = row.clone();
        changed.count = NonZeroU64::new(1).unwrap();
        assert!(changed.validate(&selected).is_err());
        changed = row.clone();
        changed.index = 5;
        assert!(changed.validate(&selected).is_err());
        changed = row.clone();
        changed.height = 1;
        assert!(changed.validate(&selected).is_err());
        changed = row.clone();
        changed.siblings[usize::from(changed.depth)] = Some(HashOf::new(&event(20)));
        assert!(changed.validate(&selected).is_err());
        changed = row.clone();
        changed.depth = 33;
        assert!(changed.proof().is_err());
        assert!(changed.validate(&selected).is_err());
        changed = row;
        changed.receipt_digest[0] += 10;
        assert!(changed.validate(&key(changed.receipt_digest)).is_err());
    }
    // Exact replay produces the same rows without appending to the event cut.
    retain(&mut block.world, 2, &budget).unwrap();
    assert_eq!(block.world.pending_external_events().len(), 5);
    assert_eq!(block.world.kagemusha_wallet_ledger.iter().count(), 5);
    drop(block);
    assert_eq!(
        state
            .view()
            .world()
            .kagemusha_wallet_ledger()
            .iter()
            .count(),
        0
    );
}

#[test]
fn preparation_refusal_or_duplicate_never_inserts_a_partial_path_set() {
    let state = state();
    let mut block = state.block(header());
    let mut tx = block.transaction();
    tx.world.external_event_buf.extend([event(1), event(2)]);
    tx.apply();
    assert!(matches!(
        retain(&mut block.world, 2, &AllocationBudget::new(0)),
        Err(PreparationError::Deferred(_))
    ));
    assert_eq!(block.world.kagemusha_wallet_ledger.iter().count(), 0);
    let budget = AllocationBudget::new(2_000_000);
    let mut tx = block.transaction();
    tx.world.external_event_buf.push(event(1));
    tx.apply();
    assert!(matches!(
        retain(&mut block.world, 2, &budget),
        Err(PreparationError::Invalid(_))
    ));
    assert_eq!(block.world.kagemusha_wallet_ledger.iter().count(), 0);
    assert_eq!(budget.reserved_bytes(), 0);
    let _ = block.world.take_external_events();
    let mut tx = block.transaction();
    tx.world.external_event_buf.extend([event(1), event(2)]);
    tx.apply();
    retain(&mut block.world, 2, &budget).unwrap();
    assert_eq!(block.world.kagemusha_wallet_ledger.iter().count(), 2);
    assert!(matches!(
        retain(&mut block.world, 3, &budget),
        Err(PreparationError::Invalid(_))
    ));
    assert_eq!(block.world.kagemusha_wallet_ledger.iter().count(), 2);
    assert_eq!(budget.reserved_bytes(), 0);
}
