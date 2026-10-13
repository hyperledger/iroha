//! Retained-generation DATA exercises deletion quotas, exact pending joins and rollback.

use super::*;
use crate::{
    smartcontracts::isi::sccp::{
        anchor_record::RetainedSccpAnchors,
        committee_storage::CommitteeFixtureStorage as _,
        test_support::{authority, blank_state, header, sample_generation_at},
    },
    state::{State, World, sccp_forgery_custody::OffenceKey},
};
use iroha_crypto::Hash;
use iroha_data_model::{
    block::consensus::{EvidencePenaltyStatus, EvidenceScope, RecordedEvidenceV1},
    sccp::generation::{
        SccpAnchorV1, SccpCommitteeGenerationV1, SccpGenerationEndV1, SccpGenerationMemberV1,
    },
    sumeragi_finality::certified_result::SccpFinalityHeaderV1,
};
use iroha_model_base::topology::LaneId;
use mv::storage::StorageReadOnly as _;

fn ended(id: u64, start: u64) -> SccpCommitteeGenerationV1 {
    let mut record = sample_generation_at(id, start);
    record.end = Some(SccpGenerationEndV1 {
        end_height: start + 1,
        end_timestamp_ms: record.start_timestamp_ms + 1,
        successor_validity_ms: record.validity_ms,
        next_committee_root: record.committee_root,
    });
    record
}

fn seeded(records: &[SccpCommitteeGenerationV1], current: u64, clock: u64, chunks: u64) -> State {
    let state = blank_state();
    let mut world = state.world.block();
    *world.sccp_committee_current.get_mut() = current;
    *world.sccp_liability_clock.get_mut() = clock;
    for record in records {
        world
            .sccp_committee_generations
            .insert(record.generation, record.clone());
    }
    for chunk in 0..chunks {
        world
            .sccp_anchor_chunks
            .try_insert_admitted(chunk, [7; 32])
            .unwrap();
    }
    *world.sccp_anchor_open.get_mut() = RetainedSccpAnchors::admit(
        &[SccpAnchorV1 {
            core_hash: [2; 32],
            result: [3; 32],
        }],
        &state.ivm_execution_budget(),
    )
    .unwrap();
    world.commit();
    state
}

// This parses retained DATA, not evidence authority; the test only inspects its exact join.
fn pending_claim(world: &mut World, generation: &SccpCommitteeGenerationV1) -> Hash {
    use crate::sumeragi::evidence::record::{parse_record, sccp_storage_claim_for_testing};
    let member = generation.members[0].as_ref().unwrap();
    let mut data = sccp_storage_claim_for_testing();
    let RecordedEvidenceV1::SccpForgery(forgery) = &mut data.evidence else {
        unreachable!()
    };
    forgery.generation = generation.generation;
    forgery.start_height = generation.start_height;
    forgery.offenders[0].lane_id = member.lane_id;
    forgery.offenders[0].validator = member.validator.clone();
    forgery.offenders[0].activation_height = member.activation_height;
    let mut fields = SccpFinalityHeaderV1::parse(&forgery.evidence.header)
        .unwrap()
        .fields();
    fields.committee_root = generation.committee_root;
    fields.generation = generation.generation;
    forgery.evidence.header = *SccpFinalityHeaderV1::from_fields(&fields)
        .unwrap()
        .as_bytes();
    data.attribution.scope = EvidenceScope::SccpGeneration {
        generation: generation.generation,
    };
    data.attribution.height = generation.start_height;
    data.attribution.authority_generation = generation.committee_root;
    let budget = world.sccp_forgery_offences.allocation_budget();
    let json = norito::json::to_json(&data).unwrap();
    let record = parse_record(&mut norito::json::Parser::new(&json), budget).unwrap();
    let id = record.sccp_evidence_id().unwrap();
    let key = OffenceKey::try_copy(
        generation.generation,
        member.lane_id,
        &member.validator,
        budget,
    )
    .unwrap();
    world
        .sccp_forgery_offences
        .try_with_admitted_block(|block| {
            block
                .try_insert_admitted(key, id)
                .map_err(|(_, error)| error)
        })
        .unwrap();
    let hash = Hash::prehashed(id);
    world.consensus_evidence.insert(hash, record);
    hash
}

#[test]
fn pruning_keeps_pending_exact_generation_until_penalty_is_applied() {
    let mut old = ended(7, 2);
    old.members[0] = Some(SccpGenerationMemberV1 {
        lane_id: LaneId::SINGLE,
        validator: authority(7),
        activation_height: 1,
    });
    let mut state = seeded(
        &[old.clone(), sample_generation_at(20, 10_000)],
        20,
        u64::MAX,
        3,
    );
    let id = pending_claim(&mut state.world, &old);
    {
        let mut block = state.block(header(30));
        let mut tx = block.transaction();
        prune(&mut tx).unwrap();
        assert!(
            store::committee_generations::contains(&*tx.world, &7),
            "pruning must retain a generation with an exact Pending SCCP penalty"
        );
        assert!(store::anchor_chunks::contains(&*tx.world, &0));
        // No retirement was authorized. Drop this unpublished component overlay;
        // committing a State block requires an actual inserted signed block.
        assert_eq!(store::committee_generations::len(&*tx.world), 2);
    }
    let mut record = state
        .world
        .consensus_evidence
        .view()
        .get(&id)
        .unwrap()
        .clone();
    record.penalty_status = EvidencePenaltyStatus::Applied { height: 30 };
    state.world.consensus_evidence.insert(id, record);
    let mut block = state.block(header(31));
    let mut tx = block.transaction();
    prune(&mut tx).unwrap();
    assert!(!store::committee_generations::contains(&*tx.world, &7));
    assert!(store::committee_generations::contains(&*tx.world, &20));
    assert!(!store::anchor_chunks::contains(&*tx.world, &0));
    assert!(
        tx.world.consensus_evidence.get(&id).is_some(),
        "evidence is permanent"
    );
    assert_eq!(
        tx.world.sccp_forgery_offences.len(),
        1,
        "offence deduplication is permanent"
    );
}

#[test]
fn pruning_preserves_inclusive_liability_pending_gaps_and_ascending_eight_limit() {
    let mut records = (1..=12)
        .map(|id| {
            let mut record = if id == 12 {
                sample_generation_at(id, id)
            } else {
                ended(id, id)
            };
            record.members[0] = Some(SccpGenerationMemberV1 {
                lane_id: LaneId::SINGLE,
                validator: authority(u8::try_from(id).expect("fixture value fits u8")),
                activation_height: 1,
            });
            record
        })
        .collect::<Vec<_>>();
    // All ended generations can clear together when one destination finally
    // reports progress. Non-genesis generations still begin after height one.
    let cleared = records[11].start_lc + records[11].validity_ms;
    for record in &mut records[..11] {
        record.dest_cleared_lc = Some(cleared);
    }
    let boundary = cleared + records[0].grace_ms;
    assert!(
        records
            .iter()
            .all(SccpCommitteeGenerationV1::is_well_formed)
    );
    let mut state = seeded(&records, 12, boundary, 0);
    pending_claim(&mut state.world, &records[1]);
    pending_claim(&mut state.world, &records[3]);
    let mut block = state.block(header(13));
    let mut tx = block.transaction();
    prune(&mut tx).unwrap();
    assert_eq!(
        store::committee_generations::len(&*tx.world),
        12,
        "the inclusive liability boundary preserves every original generation"
    );
    store::liability_clock::set(&mut tx, boundary + 1);
    tx.require_storage_admission().unwrap();
    prune(&mut tx).unwrap();
    let retained = store::committee_generations::iter(&*tx.world)
        .map(|(id, _)| *id)
        .collect::<Vec<_>>();
    assert_eq!(retained, vec![2, 4, 11, 12]);
    records.retain(|record| !retained.contains(&record.generation));
    assert_eq!(
        records
            .iter()
            .map(|record| record.generation)
            .collect::<Vec<_>>(),
        vec![1, 3, 5, 6, 7, 8, 9, 10],
        "exactly eight eligible records retire in ascending order across pending gaps"
    );
}

#[test]
fn pruning_sparse_generations_and_anchor_roots_each_stop_after_eight() {
    let mut records = (1..=12)
        .map(|n| ended(n * 2, 100_000 + n))
        .collect::<Vec<_>>();
    records.push(sample_generation_at(100, 100_100));
    let state = seeded(&records, 100, u64::MAX, 16);
    let mut block = state.block(header(200));
    let mut tx = block.transaction();
    let original_open = store::anchor_open::get(&*tx.world).as_slice().as_ptr();
    prune(&mut tx).unwrap();
    assert_eq!(
        store::committee_generations::iter(&*tx.world)
            .map(|(id, _)| *id)
            .collect::<Vec<_>>(),
        vec![18, 20, 22, 24, 100]
    );
    assert_eq!(
        store::anchor_chunks::iter(&*tx.world)
            .map(|(id, _)| *id)
            .collect::<Vec<_>>(),
        (8..16).collect::<Vec<_>>()
    );
    assert_eq!(
        store::anchor_open::get(&*tx.world).as_slice().as_ptr(),
        original_open
    );
    assert_eq!(store::anchor_open::get(&*tx.world).as_slice().len(), 1);
}

#[test]
fn pruning_anchor_boundary_uses_minimum_retained_start_and_is_strict() {
    let first = ended(7, 12_288);
    let current = sample_generation_at(20, 8_192);
    let state = seeded(&[first, current], 20, 0, 4);
    let mut block = state.block(header(21));
    let mut tx = block.transaction();
    prune(&mut tx).unwrap();
    assert!(!store::anchor_chunks::contains(&*tx.world, &0));
    assert!(
        store::anchor_chunks::contains(&*tx.world, &1),
        "pruning must retain a chunk ending at the minimum retained generation start"
    );
    assert_eq!(store::anchor_chunks::iter(&*tx.world).count(), 3);
}

#[test]
fn pruning_missing_original_evidence_refuses_before_any_deletion() {
    let mut old = ended(7, 2);
    old.members[0] = Some(SccpGenerationMemberV1 {
        lane_id: LaneId::SINGLE,
        validator: authority(7),
        activation_height: 1,
    });
    let mut state = seeded(
        &[ended(1, 1), old.clone(), sample_generation_at(20, 10_000)],
        20,
        u64::MAX,
        2,
    );
    let id = pending_claim(&mut state.world, &old);
    {
        let mut records = state.world.consensus_evidence.block();
        records.remove(id);
        records.commit();
    }
    let mut block = state.block(header(30));
    let mut tx = block.transaction();
    assert_eq!(
        prune(&mut tx),
        Err(StateStorageAdmissionError::SccpForgery(
            ForgeryStorageError::Invalid
        ))
    );
    assert_eq!(store::committee_generations::iter(&*tx.world).count(), 3);
    assert_eq!(store::anchor_chunks::iter(&*tx.world).count(), 2);
}

#[test]
fn pruning_original_map_refusal_rolls_back_and_retries() {
    let state = seeded(
        &[ended(1, 1), sample_generation_at(20, 10_000)],
        20,
        u64::MAX,
        3,
    );
    let mut block = state.block(header(30));
    let budget = state.ivm_execution_budget();
    {
        let mut tx = block.transaction();
        let occupied = budget
            .try_reserve_bytes(budget.limit_bytes() - budget.reserved_bytes())
            .unwrap();
        assert!(
            prune(&mut tx).is_err(),
            "admitted retirement must preserve the original map refusal"
        );
        drop(occupied);
    }
    assert!(store::committee_generations::contains(&block.world, &1));
    assert!(store::anchor_chunks::contains(&block.world, &0));
    // Original storage refusal is sticky for the whole failed block, not just its child.
    // Retry must acquire a new block overlay from the unchanged original State.
    drop(block);
    let mut block = state.block(header(30));
    let mut tx = block.transaction();
    prune(&mut tx).unwrap();
    assert!(!store::committee_generations::contains(&*tx.world, &1));
    assert!(!store::anchor_chunks::contains(&*tx.world, &0));
}
