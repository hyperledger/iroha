//! Reproducible native storage measurements for the §4.11 churn envelope.
//!
//! These measure canonical Norito payloads and original-pool retained allocations, not
//! allocator metadata, RSS, snapshot envelopes, permanent message history or archive files.
//! The fixture uses 31 distinct single-key Ed25519 validator accounts. Larger supported
//! account policies and indefinitely pending penalties are not bounded by these figures.

use super::{
    anchor_record::RetainedSccpAnchors,
    anchor_storage::AnchorStorage,
    committee_storage::CommitteeStorage,
    generation_record::{MemberRef, RetainedSccpGeneration},
    test_support::{authority, sample_generation},
};
use iroha_allocation::AllocationBudget;
use iroha_crypto::{Algorithm, KeyPair};
use iroha_data_model::{
    block::consensus::MAX_VALIDATORS_PER_HEIGHT,
    sccp::{
        generation::{
            SCCP_ANCHOR_CHUNK_SIZE_V1, SccpAnchorV1, SccpCommitteeGenerationV1,
            SccpGenerationCauseV1, SccpGenerationEndV1, SccpGenerationMemberV1,
        },
        params::{
            SCCP_MAX_DESTINATION_PROGRESS_CAP_MS_V1, SCCP_MAX_FORGERY_EVIDENCE_GRACE_MS_V1,
            SCCP_MAX_VALIDITY_MS_V1, SCCP_MIN_EPOCH_MS_V1, SCCP_MIN_HEARTBEAT_MS_V1,
            SccpParametersV1,
        },
    },
    sumeragi_finality::certified_result::committee_root,
};
use iroha_model_base::topology::LaneId;
use mv::storage::StorageReadOnly as _;
use norito::{codec::Encode as _, json::Value};

const DAY_MS: u64 = 86_400_000;
const CADENCE_MS: u64 = 1_000;

fn maximal_committee() -> SccpCommitteeGenerationV1 {
    let mut source = sample_generation(1);
    source.keys = (1..=MAX_VALIDATORS_PER_HEIGHT)
        .map(|index| {
            let seed = u8::try_from(index).unwrap();
            KeyPair::try_from_seed(vec![seed; 32], Algorithm::BlsNormal)
                .unwrap()
                .public_key()
                .try_to_bytes()
                .unwrap()
                .1
                .try_into()
                .unwrap()
        })
        .collect();
    source.keys.sort_unstable();
    source.committee_root = committee_root(&source.keys).unwrap();
    source.members = (1..=MAX_VALIDATORS_PER_HEIGHT)
        .map(|index| {
            Some(SccpGenerationMemberV1 {
                lane_id: LaneId::SINGLE,
                validator: authority(u8::try_from(index).unwrap()),
                activation_height: 1,
            })
        })
        .collect();
    source.validity_ms = SCCP_MAX_VALIDITY_MS_V1;
    source.grace_ms = SCCP_MAX_FORGERY_EVIDENCE_GRACE_MS_V1;
    source.progress_cap_ms = SCCP_MAX_DESTINATION_PROGRESS_CAP_MS_V1;
    source
}

fn at_generation(
    source: &mut SccpCommitteeGenerationV1,
    generation: u64,
    current: u64,
    spacing_ms: u64,
    measurement_lc: u64,
    clearance_age_ms: Option<u64>,
) {
    let start = (generation - 1) * spacing_ms;
    source.generation = generation;
    source.cause = if generation == 1 {
        SccpGenerationCauseV1::Genesis
    } else {
        SccpGenerationCauseV1::Heartbeat
    };
    source.start_timestamp_ms = start;
    source.start_lc = start;
    source.start_height = if generation == 1 {
        1
    } else {
        start / CADENCE_MS + 2
    };
    source.deadline_ms = start + source.validity_ms;
    source.liable_until_lc = source.deadline_ms + source.grace_ms;
    source.end = (generation < current).then_some(SccpGenerationEndV1 {
        end_height: (start + spacing_ms) / CADENCE_MS + 1,
        end_timestamp_ms: start + spacing_ms,
        next_committee_root: source.committee_root,
        successor_validity_ms: source.validity_ms,
    });
    source.dest_cleared_lc = clearance_age_ms
        .map(|age| start + age)
        .filter(|cleared| source.end.is_some() && *cleared <= measurement_lc);
}

fn measure_generations(window_ms: u64, rate_per_day: u64, clearance_age_ms: Option<u64>) -> Value {
    // The sum of epoch and heartbeat rate ceilings is a conservative storage population,
    // not a claim that a half-hour heartbeat trace is admitted by the transition rules.
    // Include the current generation and the inclusive oldest liability boundary.
    let count = window_ms / DAY_MS * rate_per_day + 1;
    let spacing_ms = DAY_MS / rate_per_day;
    let mut source = maximal_committee();
    at_generation(
        &mut source,
        1,
        count,
        spacing_ms,
        window_ms,
        clearance_age_ms,
    );
    // L5 may clear at the inclusive no-clearance boundary before it expires. The
    // cleared leg then retains one further grace period; it has no 90-day clamp.
    assert_eq!(source.dest_cleared_lc, clearance_age_ms);
    if let Some(cleared) = clearance_age_ms {
        source.dest_cleared_lc = None;
        assert!(source.is_liable(count, cleared));
        assert!(!source.is_liable(count, cleared + 1));
        source.dest_cleared_lc = Some(cleared);
    }
    assert!(source.is_liable(count, window_ms));
    assert!(!source.is_liable(count, window_ms + 1));
    let members = source
        .members
        .iter()
        .map(|member| {
            member.as_ref().map(|member| MemberRef {
                lane_id: member.lane_id,
                validator: &member.validator,
                activation_height: member.activation_height,
            })
        })
        .collect::<Vec<_>>();
    let demand = RetainedSccpGeneration::allocation_demand(&source.keys, &members).unwrap();
    let exact = AllocationBudget::new(demand);
    let owner = RetainedSccpGeneration::admit(&source, &exact).unwrap();
    assert_eq!(exact.reserved_bytes(), demand);
    assert!(owner.is_liable(count, window_ms));
    assert!(!owner.is_liable(count, window_ms + 1));
    assert_eq!(owner.encode(), source.encode());
    let reader = owner.clone();
    drop(owner);
    assert_eq!(exact.reserved_bytes(), demand);
    drop(reader);
    assert_eq!(exact.reserved_bytes(), 0);

    // An uncapped measurement pool measures actual demand; it is not a proposed node limit.
    let pool = AllocationBudget::new(usize::MAX);
    let table = CommitteeStorage::try_new_admitted(pool.clone()).unwrap();
    let empty_map_bytes = pool.reserved_bytes();
    for generation in 1..count {
        at_generation(
            &mut source,
            generation,
            count - 1,
            spacing_ms,
            window_ms,
            clearance_age_ms,
        );
        assert!(source.is_liable(count, window_ms));
        let owner = RetainedSccpGeneration::admit(&source, &pool).unwrap();
        let encoded = owner.encode();
        assert_eq!(encoded, source.encode());
        table
            .try_with_admitted_block(|block| {
                block
                    .try_insert_admitted(generation, owner)
                    .map_err(|(_, error)| error)
            })
            .unwrap();
    }
    let previous_snapshot = table.snapshot();
    let mut ended = previous_snapshot
        .current()
        .get(&(count - 1))
        .unwrap()
        .clone();
    assert!(ended.end.is_none());
    at_generation(
        &mut source,
        count,
        count,
        spacing_ms,
        window_ms,
        clearance_age_ms,
    );
    ended.end = Some(SccpGenerationEndV1 {
        end_height: source.start_height - 1,
        end_timestamp_ms: source.start_timestamp_ms,
        next_committee_root: source.committee_root,
        successor_validity_ms: source.validity_ms,
    });
    let successor = RetainedSccpGeneration::admit(&source, &pool).unwrap();
    table
        .try_with_admitted_block(|block| {
            block
                .try_insert_admitted(count - 1, ended)
                .map_err(|(_, error)| error)?;
            block
                .try_insert_admitted(count, successor)
                .map_err(|(_, error)| error)
        })
        .unwrap();
    let transition_with_previous_reader_bytes = pool.reserved_bytes();
    let snapshot = table.snapshot();
    assert_eq!(snapshot.current().len(), usize::try_from(count).unwrap());
    assert_eq!(snapshot.revert_map().len(), 2);
    let old_current = snapshot
        .revert_map()
        .get(&(count - 1))
        .unwrap()
        .as_ref()
        .unwrap();
    let ended_current = snapshot.current().get(&(count - 1)).unwrap();
    assert!(old_current.end.is_none());
    assert_eq!(
        ended_current.end.unwrap().end_timestamp_ms,
        source.start_timestamp_ms
    );
    assert_eq!(
        ended_current.end.unwrap().end_height + 1,
        source.start_height
    );
    assert!(std::ptr::eq(
        std::ptr::from_ref(&**old_current),
        std::ptr::from_ref(&**ended_current)
    ));
    assert_eq!(snapshot.revert_map().get(&count), Some(&None));
    assert_eq!(pool.reserved_bytes(), transition_with_previous_reader_bytes);
    drop(previous_snapshot);
    let current_and_undo_bytes = pool.reserved_bytes();
    let body_bytes = usize::try_from(count).unwrap() * demand;
    assert!(current_and_undo_bytes >= body_bytes);
    let record_payload_bytes: usize = snapshot
        .current()
        .iter()
        .map(|(_, record)| record.encode().len())
        .sum();
    let current_record_payload_bytes = source.encode().len();
    source.end = Some(SccpGenerationEndV1 {
        end_height: source.start_height,
        end_timestamp_ms: source.start_timestamp_ms,
        next_committee_root: source.committee_root,
        successor_validity_ms: source.validity_ms,
    });
    source.dest_cleared_lc = Some(source.deadline_ms);
    let ended_cleared_record_payload_bytes = source.encode().len();
    drop(snapshot);
    drop(table);
    assert_eq!(pool.reserved_bytes(), 0);
    norito::json!({
        "measurement_liability_clock_ms": window_ms,
        "clearance_age_ms": clearance_age_ms,
        "records_including_current_and_inclusive_boundary": count,
        "single_constructed_body_custody_bytes": demand,
        "current_record_norito_payload_bytes": current_record_payload_bytes,
        "ended_cleared_record_norito_payload_bytes": ended_cleared_record_payload_bytes,
        "sum_record_norito_payload_bytes_excluding_map_envelope": record_payload_bytes,
        "body_custody_bytes": body_bytes,
        "empty_map_custody_bytes": empty_map_bytes,
        "current_and_undo_map_with_bodies_custody_bytes": current_and_undo_bytes,
        "map_nodes_and_control_custody_bytes": (current_and_undo_bytes - body_bytes),
        "transition_with_previous_snapshot_reader_custody_bytes": transition_with_previous_reader_bytes,
        "previous_snapshot_retained_extra_custody_bytes": (transition_with_previous_reader_bytes - current_and_undo_bytes),
        "rotation_undo_entries": 2,
        "snapshot_reader_additional_custody_bytes": 0,
        "final_custody_bytes": (pool.reserved_bytes()),
    })
}

fn measure_anchor_roots(window_ms: u64) -> Value {
    // Ceiling covers an arbitrary retained-window/chunk alignment. Open-chunk maximum is
    // measured separately, so this is a conservative envelope, not an exact chain trace.
    let count =
        (window_ms / CADENCE_MS).div_ceil(u64::try_from(SCCP_ANCHOR_CHUNK_SIZE_V1).unwrap());
    let pool = AllocationBudget::new(usize::MAX);
    let table = AnchorStorage::try_new_admitted(pool.clone()).unwrap();
    for chunk in 0..count {
        table
            .try_with_admitted_block(|block| {
                block
                    .try_insert_admitted(chunk, [7; 32])
                    .map_err(|(_, error)| error)
            })
            .unwrap();
    }
    let custody_bytes = pool.reserved_bytes();
    let snapshot = table.snapshot();
    assert_eq!(snapshot.current().len(), usize::try_from(count).unwrap());
    assert_eq!(snapshot.revert_map().len(), 1);
    assert_eq!(pool.reserved_bytes(), custody_bytes);
    let entry_payload_bytes = (0_u64, [7_u8; 32]).encode().len();
    drop(snapshot);
    drop(table);
    assert_eq!(pool.reserved_bytes(), 0);
    norito::json!({
        "completed_chunk_roots": count,
        "key_and_root_raw_bytes_per_entry": (size_of::<u64>() + size_of::<[u8; 32]>()),
        "norito_tuple_payload_bytes_per_entry": entry_payload_bytes,
        "current_and_undo_map_custody_bytes": custody_bytes,
        "final_custody_bytes": (pool.reserved_bytes()),
    })
}

fn measure_open_chunk() -> Value {
    let anchor = SccpAnchorV1 {
        core_hash: [2; 32],
        result: [3; 32],
    };
    let source = vec![anchor; SCCP_ANCHOR_CHUNK_SIZE_V1 - 1];
    let demand = RetainedSccpAnchors::admission_demand(&source).unwrap();
    let pool = AllocationBudget::new(usize::MAX);
    let open = RetainedSccpAnchors::admit(&source, &pool).unwrap();
    assert_eq!(pool.reserved_bytes(), demand);
    assert_eq!(open.encode(), source.encode());
    let open_payload_bytes = open.encode().len();
    let reader = open.clone();
    assert_eq!(pool.reserved_bytes(), demand);
    let full_demand = open.append_demand(&pool).unwrap();
    let full = open.try_appended(anchor, &pool).unwrap();
    assert_eq!(full.as_slice().len(), SCCP_ANCHOR_CHUNK_SIZE_V1);
    assert!(RetainedSccpAnchors::admission_demand(full.as_slice()).is_err());
    assert!(full.append_demand(&pool).is_err());
    let full_payload_bytes = full.encode().len();
    let rollover_custody_bytes = pool.reserved_bytes();
    assert_eq!(rollover_custody_bytes, demand + full_demand);
    drop(open);
    assert_eq!(pool.reserved_bytes(), rollover_custody_bytes);
    drop(reader);
    assert_eq!(pool.reserved_bytes(), full_demand);
    drop(full);
    assert_eq!(pool.reserved_bytes(), 0);
    let full_raw_bytes = SCCP_ANCHOR_CHUNK_SIZE_V1 * size_of::<SccpAnchorV1>();
    assert_eq!(full_raw_bytes, 256 * 1_024);
    norito::json!({
        "maximum_stored_anchors": (source.len()),
        "maximum_stored_raw_bytes": (source.len() * size_of::<SccpAnchorV1>()),
        "maximum_stored_norito_payload_bytes": open_payload_bytes,
        "maximum_stored_custody_bytes": demand,
        "transient_complete_raw_bytes": full_raw_bytes,
        "transient_complete_norito_payload_bytes": full_payload_bytes,
        "transient_complete_custody_bytes": full_demand,
        "rollover_with_original_reader_custody_bytes": rollover_custody_bytes,
        "final_custody_bytes": (pool.reserved_bytes()),
    })
}

#[test]
fn native_maximal_churn_storage_measurement() {
    let defaults = SccpParametersV1::taira_default();
    let normal_window = defaults.committee_validity_ms + defaults.forgery_evidence_grace_ms;
    let stalled_default_window = normal_window + defaults.destination_progress_cap_ms;
    let stalled_maximum_window = SCCP_MAX_VALIDITY_MS_V1
        + SCCP_MAX_FORGERY_EVIDENCE_GRACE_MS_V1
        + SCCP_MAX_DESTINATION_PROGRESS_CAP_MS_V1;
    let late_clearance_default_window = stalled_default_window + defaults.forgery_evidence_grace_ms;
    let late_clearance_maximum_window =
        stalled_maximum_window + SCCP_MAX_FORGERY_EVIDENCE_GRACE_MS_V1;
    let default_rate = DAY_MS / SCCP_MIN_EPOCH_MS_V1 + DAY_MS / defaults.committee_heartbeat_ms;
    let maximum_rate = DAY_MS / SCCP_MIN_EPOCH_MS_V1 + DAY_MS / SCCP_MIN_HEARTBEAT_MS_V1;
    assert_eq!(stalled_maximum_window / DAY_MS, 90);
    assert_eq!(late_clearance_maximum_window / DAY_MS, 120);
    assert_eq!(late_clearance_default_window / DAY_MS, 58);
    assert_eq!(maximum_rate, 48);
    let measured = norito::json!({
        "cadence_ms": CADENCE_MS,
        "committee_seats": MAX_VALIDATORS_PER_HEIGHT,
        "ordinary_default_window_days": (normal_window / DAY_MS),
        "stalled_default_window_days": (stalled_default_window / DAY_MS),
        "default_rate_ceiling_per_day": default_rate,
        "estimated_ordinary_default_records_including_boundary": (normal_window / DAY_MS * default_rate + 1),
        "estimated_stalled_default_records_including_boundary": (stalled_default_window / DAY_MS * default_rate + 1),
        "late_clearance_default_window_days": (late_clearance_default_window / DAY_MS),
        "estimated_late_clearance_default_records_including_boundary": (late_clearance_default_window / DAY_MS * default_rate + 1),
        "maximum_rate_ceiling_per_day": maximum_rate,
        "stalled_no_clearance": {
            "window_days": (stalled_maximum_window / DAY_MS),
            "generations": (measure_generations(stalled_maximum_window, maximum_rate, None)),
            "anchor_roots": (measure_anchor_roots(stalled_maximum_window)),
        },
        "late_clearance": {
            "window_days": (late_clearance_maximum_window / DAY_MS),
            "generations": (measure_generations(late_clearance_maximum_window, maximum_rate, Some(stalled_maximum_window))),
            "anchor_roots": (measure_anchor_roots(late_clearance_maximum_window)),
        },
        "open_chunk": (measure_open_chunk()),
    });
    println!(
        "SCCP_NATIVE_STORAGE_MEASUREMENT {}",
        norito::json::to_json(&measured).unwrap()
    );
}
