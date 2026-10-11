//! Exact original graph custody for current and undo beacon snapshot rows.

use super::*;
use crate::beacon::{
    FinalizedGlobalThresholdBeaconKeySessionRecordV1, GlobalThresholdBeaconSessionBindingV1,
    GlobalThresholdBeaconSessionError, global_threshold_beacon_roster_hash_v1,
    global_threshold_beacon_session_allocation_bytes_v1, prepared_session_and_signers_fixture_v1,
};
use iroha_allocation::{AllocationBudget, AllocationRefusal};
use iroha_crypto::{Algorithm, Hash, HashOf, KeyPair};
use iroha_data_model::{
    NetworkId, block::BlockHeader, consensus::GlobalThresholdBeaconDkgSessionV1,
};
use iroha_model_base::peer::PeerId;

fn rows() -> (NativeBeaconSessionSnapshot, usize, usize, usize) {
    let mut keys = (1..=4)
        .map(|marker| KeyPair::from_seed(vec![marker; 32], Algorithm::BlsNormal))
        .collect::<Vec<_>>();
    keys.sort_by(|a, b| a.public_key().cmp(b.public_key()));
    let peers = keys
        .iter()
        .map(|key| PeerId::new(key.public_key().clone()))
        .collect::<Vec<_>>();
    let network = NetworkId::from_genesis_hash(HashOf::<BlockHeader>::from_untyped_unchecked(
        Hash::prehashed([0xE1; 32]),
    ));
    let source_pool = AllocationBudget::new(64 * 1024 * 1024);
    let make = |marker: u8, generation: u64, start: u64| {
        let (session, _) = prepared_session_and_signers_fixture_v1(
            GlobalThresholdBeaconDkgSessionV1 {
                version: 1,
                network_id: network,
                session_id: [marker; 32],
                attempt_id: [marker; 32],
                authority_generation: generation,
                roster_hash: global_threshold_beacon_roster_hash_v1(&peers),
                committee_size: 4,
                threshold: 2,
                start_height: start,
                commitments_end_height: start + 1,
                deliveries_end_height: start + 2,
                acceptances_end_height: start + 3,
            },
            &source_pool,
        );
        let binding = GlobalThresholdBeaconSessionBindingV1 {
            network_id: network,
            session_id: session.session_id,
            roster_hash: session.roster_hash,
            transcript_hash: session.transcript_hash,
        };
        let demand =
            global_threshold_beacon_session_allocation_bytes_v1(session.record(), &binding)
                .unwrap();
        let retained = session.retained_allocation_bytes();
        let mut row = FinalizedGlobalThresholdBeaconKeySessionRecordV1::new(
            session.record().clone(),
            &source_pool,
        )
        .unwrap();
        row.activate(start + 4, &source_pool).unwrap();
        (row, demand, retained)
    };
    let (previous, previous_demand, previous_retained) = make(0xE2, 0, 1);
    let (current, current_demand, current_retained) = make(0xE3, 1, 11);
    let current_id = current.session.session_id;
    let previous_id = previous.session.session_id;
    (
        NativeBeaconSessionSnapshot {
            blocks: std::collections::BTreeMap::from([(current_id, current)]),
            revert: std::collections::BTreeMap::from([
                (
                    previous_id,
                    Some(mv::json::SnapshotUndoValue { value: previous }),
                ),
                (current_id, None),
            ]),
        },
        current_demand.max(current_retained + previous_demand),
        current_retained + previous_retained,
        previous_demand,
    )
}

fn original_field(map: &SnapshotJsonMap<'_>) -> *const u8 {
    match map.fields.get("global_beacon_key_sessions").unwrap() {
        SnapshotJsonField::Borrowed { raw } => raw.as_ptr(),
        SnapshotJsonField::Owned(_) => {
            panic!("restore must exercise the production borrowed source")
        }
    }
}

#[test]
fn beacon_snapshot_current_and_undo_share_only_their_original_admitted_graphs() {
    let (source, peak, retained, _) = rows();
    let field = json::to_json(&source).unwrap();
    let raw = format!("{{\"global_beacon_key_sessions\":{field}}}");
    let mut map = SnapshotJsonMap::parse(&raw, "world").unwrap();
    let pool = AllocationBudget::new(peak);
    let restored = take_native_beacon_sessions(&mut map, &pool).unwrap();
    assert!(map.is_empty());
    assert_eq!(
        json::to_json(&restored).unwrap(),
        field,
        "runtime custody adds no wire fields"
    );
    assert_eq!(pool.reserved_bytes(), retained);
    let current_id = *source.blocks.keys().next().unwrap();
    let previous_id = *source
        .revert
        .iter()
        .find(|(_, value)| value.is_some())
        .unwrap()
        .0;
    let current = restored.view().get(&current_id).unwrap().session.clone();
    let previous = restored
        .snapshot()
        .revert_map()
        .get(&previous_id)
        .unwrap()
        .as_ref()
        .unwrap()
        .session
        .clone();
    assert!(restored.view().get(&previous_id).is_none());
    assert!(
        restored
            .snapshot()
            .revert_map()
            .get(&current_id)
            .unwrap()
            .is_none()
    );
    assert!(current.belongs_to(&pool) && previous.belongs_to(&pool));
    assert_eq!(current.record(), &source.blocks[&current_id].session);
    assert_eq!(
        previous.record(),
        &source.revert[&previous_id].as_ref().unwrap().value.session
    );
    assert_eq!(
        pool.reserved_bytes(),
        retained,
        "cloning readers never duplicates the public graph"
    );
    drop(restored);
    assert_eq!(
        pool.reserved_bytes(),
        retained,
        "readers retain both current and undo originals"
    );
    drop(current);
    assert_eq!(pool.reserved_bytes(), previous.retained_allocation_bytes());
    drop(previous);
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn beacon_snapshot_second_cut_refusal_keeps_raw_source_and_refunds_partial_restore() {
    let (source, peak, retained, second_demand) = rows();
    let field = json::to_json(&source).unwrap();
    let raw = format!("{{\"global_beacon_key_sessions\":{field}}}");
    let mut map = SnapshotJsonMap::parse(&raw, "world").unwrap();
    let pointer = original_field(&map);
    let pool = AllocationBudget::new(peak - 1);
    pool.with_deferred_refund_notifications(|_| {
        let error = take_native_beacon_sessions(&mut map, &pool).err().unwrap();
        let StateRestoreError::BeaconSession(GlobalThresholdBeaconSessionError::Admission(actual)) = error else {
            panic!("second graph must preserve its actual original pool refusal")
        };
        assert!(matches!(actual, AllocationRefusal::Capacity { requested_bytes, .. } if requested_bytes == second_demand));
        assert_eq!(pool.reserved_bytes(), 0, "failed reconstruction released its first graph");
        // Defer this pool's notifications while independently reproducing the
        // exact occupied geometry. Equality includes the actual release source
        // and observation sequence, not only requested/occupied byte counts.
        let occupied = pool.try_reserve_bytes(peak - second_demand).unwrap();
        let independently_observed = pool.try_reserve_bytes(second_demand).unwrap_err();
        assert_eq!(actual, independently_observed);
        drop(occupied);
    });
    assert_eq!(original_field(&map), pointer);
    assert_eq!(
        pool.reserved_bytes(),
        0,
        "no current or undo map escaped the failed restore"
    );
    pool.set_limit_bytes(peak);
    let restored = take_native_beacon_sessions(&mut map, &pool).unwrap();
    assert!(map.is_empty());
    assert_eq!(json::to_json(&restored).unwrap(), field);
    assert_eq!(pool.reserved_bytes(), retained);
}

#[test]
fn beacon_snapshot_rejects_wrong_storage_identity_without_consuming_original_field() {
    let (mut source, peak, _, _) = rows();
    let (key, row) = source.blocks.pop_first().unwrap();
    let mut wrong = key;
    wrong[0] ^= 1;
    source.blocks.insert(wrong, row);
    let field = json::to_json(&source).unwrap();
    let raw = format!("{{\"global_beacon_key_sessions\":{field}}}");
    let mut map = SnapshotJsonMap::parse(&raw, "world").unwrap();
    let pointer = original_field(&map);
    let pool = AllocationBudget::new(peak);
    assert!(matches!(
        take_native_beacon_sessions(&mut map, &pool),
        Err(StateRestoreError::Serialization(_))
    ));
    assert_eq!(original_field(&map), pointer);
    assert_eq!(pool.reserved_bytes(), 0);
}
