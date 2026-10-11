//! Restored proof lookups match the live writers and retain replacement history.

use super::*;
use crate::state::{WorldBlock, snapshot_storage};
use iroha_config::parameters::actual::LaneConfig;
use iroha_data_model::proof::{ProofId, ProofRecord, ProofStatus};
use mv::storage::{Storage, StorageReadOnly};
use norito::{
    codec::{DecodeAll, Encode},
    json,
};
use std::collections::{BTreeMap, BTreeSet};

fn id(name: &str) -> ProofId {
    ProofId {
        backend: name.into(),
        proof_hash: [41; 32],
    }
}

fn record(name: &str, status: ProofStatus) -> ProofRecord {
    ProofRecord {
        id: id(name),
        vk_ref: None,
        vk_commitment: None,
        status,
        verified_at_height: None,
        bridge: None,
    }
}

fn encoded<K: mv::Key + Encode, V: mv::Value + Encode>(store: &Storage<K, V>) -> String {
    let mut result = String::new();
    snapshot_storage::serialize(store, &mut result);
    result
}

fn restored<K, V>(store: &Storage<K, V>) -> Storage<K, V>
where
    K: mv::Key + Encode + DecodeAll,
    V: mv::Value + Encode + DecodeAll,
{
    json::from_str::<snapshot_storage::SnapshotStorage>(&encoded(store))
        .unwrap()
        .decode("proof status fixture", |_, _| true)
        .unwrap()
}

fn image(
    index: &impl StorageReadOnly<ProofStatus, BTreeSet<ProofId>>,
) -> BTreeMap<ProofStatus, BTreeSet<ProofId>> {
    index
        .iter()
        .map(|(status, ids)| (*status, ids.clone()))
        .collect()
}

fn fixture() -> Box<World> {
    let world = Box::new(World::default());
    {
        let mut block = world.block();
        let mut tx = block.transaction_without_telemetry(LaneConfig::default(), 0);
        for (name, status) in [
            ("moving", ProofStatus::Submitted),
            ("removed", ProofStatus::Verified),
            ("untouched", ProofStatus::Submitted),
            ("redundant", ProofStatus::Rejected),
            ("metadata", ProofStatus::Rejected),
        ] {
            tx.insert_proof_record(record(name, status));
        }
        tx.apply();
        block.commit();
    }
    world
}

/// Use actual canonical/index mutators as an independent reconstruction oracle.
fn change(block: &mut WorldBlock<'_>, replacement: bool) {
    let mut tx = block.transaction_without_telemetry(LaneConfig::default(), 0);
    tx.insert_proof_record(record(
        "moving",
        if replacement {
            ProofStatus::Rejected
        } else {
            ProofStatus::Verified
        },
    ));
    tx.remove_proof_record(&id("removed")).unwrap();
    tx.insert_proof_record(record("added", ProofStatus::Submitted));
    tx.insert_proof_record(record("redundant", ProofStatus::Rejected));
    let mut metadata = record("metadata", ProofStatus::Rejected);
    metadata.vk_commitment = Some([52; 32]);
    metadata.verified_at_height = Some(123);
    tx.insert_proof_record(metadata);
    assert!(tx.remove_proof_record(&id("absent")).is_none());
    tx.apply();
}

fn restart(world: &World) -> Box<World> {
    let mut result = Box::new(World::default());
    result.proofs = restored(&world.proofs);
    rebuild(&mut result);
    result
}

#[test]
fn proof_status_restore_matches_live_both_images_and_redundant_touches() {
    let live = fixture();
    let before = image(&live.proofs_by_status.view());
    {
        let mut block = live.block();
        change(&mut block, false);
        block.commit();
    }
    let authoritative = encoded(&live.proofs);
    let expected = encoded(&live.proofs_by_status);
    let mut recovered = restart(&live);
    assert_eq!(encoded(&recovered.proofs), authoritative);
    assert_eq!(encoded(&recovered.proofs_by_status), expected);
    assert_eq!(
        image(&recovered.proofs_by_status.view()),
        image(&live.proofs_by_status.view())
    );
    assert_eq!(
        recovered
            .proofs_by_status
            .snapshot()
            .revert_map()
            .get(&ProofStatus::Rejected),
        Some(&Some(BTreeSet::from([id("metadata"), id("redundant")]))),
        "redundant and metadata-only writes retain the unchanged bucket preimage"
    );
    assert!(
        recovered
            .proofs
            .snapshot()
            .revert_map()
            .contains_key(&id("absent")),
        "the original canonical tombstone survives reconstruction"
    );
    {
        let mut replacement = recovered.block_and_revert();
        assert_eq!(image(&replacement.proofs_by_status), before);
        assert_eq!(
            replacement.proofs_by_status.get(&ProofStatus::Submitted),
            Some(&BTreeSet::from([id("moving"), id("untouched")]))
        );
        change(&mut replacement, true);
        // An abandoned replacement cannot alter either persisted image.
    }
    assert_eq!(encoded(&recovered.proofs), authoritative);
    assert_eq!(encoded(&recovered.proofs_by_status), expected);
    rebuild(&mut recovered);
    assert_eq!(encoded(&recovered.proofs_by_status), expected);
    let second = restart(&recovered);
    assert_eq!(encoded(&second.proofs_by_status), expected);
    assert_eq!(image(&second.block_and_revert().proofs_by_status), before);
}

#[test]
fn proof_status_restore_survives_committed_replacement_and_second_restart() {
    let mut live = fixture();
    let before = image(&live.proofs_by_status.view());
    {
        let mut block = live.block();
        change(&mut block, false);
        block.commit();
    }
    let mut recovered = restart(&live);
    for world in [&mut live, &mut recovered] {
        let mut replacement = world.block_and_revert();
        assert_eq!(image(&replacement.proofs_by_status), before);
        change(&mut replacement, true);
        replacement.commit();
    }
    assert_eq!(encoded(&recovered.proofs), encoded(&live.proofs));
    assert_eq!(
        encoded(&recovered.proofs_by_status),
        encoded(&live.proofs_by_status)
    );
    let mut second = restart(&recovered);
    assert_eq!(
        encoded(&second.proofs_by_status),
        encoded(&live.proofs_by_status)
    );
    second.block_and_revert().commit();
    rebuild(&mut second);
    assert_eq!(image(&second.proofs_by_status.view()), before);
    assert!(second.proofs_by_status.snapshot().revert_map().is_empty());
}

#[test]
fn last_status_member_move_keeps_prior_absence_and_removed_bucket() {
    let world = Box::new(World::default());
    {
        let mut block = world.block();
        let mut tx = block.transaction_without_telemetry(LaneConfig::default(), 0);
        tx.insert_proof_record(record("only", ProofStatus::Submitted));
        tx.apply();
        block.commit();
    }
    {
        let mut block = world.block();
        let mut tx = block.transaction_without_telemetry(LaneConfig::default(), 0);
        tx.insert_proof_record(record("only", ProofStatus::Rejected));
        tx.apply();
        block.commit();
    }
    let recovered = restart(&world);
    assert_eq!(
        encoded(&recovered.proofs_by_status),
        encoded(&world.proofs_by_status)
    );
    let prior = recovered.proofs_by_status.snapshot();
    assert_eq!(prior.revert_map().get(&ProofStatus::Rejected), Some(&None));
    assert_eq!(
        prior.revert_map().get(&ProofStatus::Submitted),
        Some(&Some(BTreeSet::from([id("only")])))
    );
    assert_eq!(
        image(&recovered.block_and_revert().proofs_by_status),
        BTreeMap::from([(ProofStatus::Submitted, BTreeSet::from([id("only")]))])
    );
}

#[test]
fn actual_state_constructor_and_snapshot_restore_keep_the_live_proof_predecessor() {
    use crate::{
        kura::Kura,
        query::store::LiveQueryStore,
        state::{State, deserialize},
    };

    let live = fixture();
    let before = image(&live.proofs_by_status.view());
    {
        let mut block = live.block();
        change(&mut block, false);
        block.commit();
    }
    let canonical = encoded(&live.proofs);
    let expected = encoded(&live.proofs_by_status);
    let state = State::new_for_testing(
        *live,
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    );
    assert_eq!(encoded(&state.world.proofs), canonical);
    assert_eq!(encoded(&state.world.proofs_by_status), expected);
    let value = json::to_value(&state).unwrap();
    let recovered = deserialize::KuraSeed {
        execution_budget: state.ivm_execution_budget(),
        lane_manifests: state.lane_manifests.read().clone(),
        kura: Kura::blank_kura_for_testing(),
        query_handle: LiveQueryStore::start_test(),
        #[cfg(feature = "telemetry")]
        telemetry: crate::telemetry::StateTelemetry::default(),
    }
    .into_state_from_json(value)
    .unwrap();
    assert_eq!(encoded(&recovered.world.proofs), canonical);
    assert_eq!(encoded(&recovered.world.proofs_by_status), expected);
    assert_eq!(
        image(&recovered.world.block_and_revert().proofs_by_status),
        before
    );
}
