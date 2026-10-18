//! DATA-only L3 gates; no fixture record authenticates a forgery or grants execution.

use super::*;
use crate::smartcontracts::isi::sccp::committee_storage::CommitteeFixtureStorage as _;
use crate::state::scalar_cell_custody::ScalarCellFixtureBlock as _;
use crate::{
    smartcontracts::isi::sccp::test_support::{authority, sample_generation_at},
    state::World,
};
use iroha_data_model::sccp::generation::{
    SccpCommitteeGenerationV1, SccpGenerationEndV1, SccpGenerationMemberV1,
};
use iroha_data_model::{
    nexus::PublicLaneValidatorStatus, sumeragi_finality::certified_result::SccpFinalityHeaderV1,
};
use iroha_model_base::{metadata::Metadata, peer::PeerId, topology::LaneId};
use iroha_primitives::numeric::Quantity;

// Mutate fixture scalar cells through their actual MV writer/publication API.
fn set_cell(cell: &mv::cell::Cell<u64, iroha_allocation::AllocationCharge>, value: u64) {
    let mut block = cell.block();
    *block.get_mut() = value;
    block.commit();
    assert_eq!(*cell.view().get(), value);
}

fn validator() -> PublicLaneValidatorRecord {
    let account = authority(0x71);
    PublicLaneValidatorRecord {
        lane_id: LaneId::SINGLE,
        validator: account.clone(),
        peer_id: PeerId::new(account.try_signatory().expect("single-key fixture").clone()),
        stake_account: account,
        total_stake: Quantity::zero(),
        self_stake: Quantity::zero(),
        metadata: Metadata::default(),
        status: PublicLaneValidatorStatus::Exited,
        activation_height: 1,
        election_exit_height: Some(2),
        deactivation_height: Some(2),
    }
}

fn generation(v: &PublicLaneValidatorRecord) -> SccpCommitteeGenerationV1 {
    let mut g = sample_generation_at(7, 2);
    g.members[0] = Some(SccpGenerationMemberV1 {
        lane_id: v.lane_id,
        validator: v.validator.clone(),
        activation_height: v.activation_height,
    });
    g.end = Some(SccpGenerationEndV1 {
        end_height: 2,
        end_timestamp_ms: g.start_timestamp_ms + 1,
        successor_validity_ms: g.validity_ms,
        next_committee_root: g.committee_root,
    });
    assert!(g.is_well_formed());
    g
}

fn worlds(g: &SccpCommitteeGenerationV1) -> (World, World) {
    let mut parent = World::new();
    parent
        .sccp_committee_generations
        .insert(g.generation, g.clone());
    set_cell(&parent.sccp_committee_current, 8);
    (parent, World::new())
}

fn check(
    parent: &World,
    current: &World,
    validator: &PublicLaneValidatorRecord,
    through: Option<u64>,
) -> Result<Option<ReleaseBlocker>, ForgeryStorageError> {
    release_blocker(
        crate::smartcontracts::isi::sccp::eligibility::Current(&parent.view()),
        &current.view(),
        validator,
        through,
        current.sccp_forgery_offences.allocation_budget(),
    )
}

fn insert_pending_claim(
    world: &mut World,
    v: &PublicLaneValidatorRecord,
    generation: &SccpCommitteeGenerationV1,
) -> Hash {
    use crate::sumeragi::evidence::record::{parse_record, sccp_storage_claim_for_testing};
    let mut data = sccp_storage_claim_for_testing();
    let RecordedEvidenceV1::SccpForgery(forgery) = &mut data.evidence else {
        unreachable!()
    };
    forgery.generation = generation.generation;
    forgery.start_height = generation.start_height;
    forgery.offenders[0].lane_id = v.lane_id;
    forgery.offenders[0].validator = v.validator.clone();
    forgery.offenders[0].activation_height = v.activation_height;
    let mut fields = SccpFinalityHeaderV1::parse(&forgery.evidence.header)
        .unwrap()
        .fields();
    fields.committee_root = generation.committee_root;
    forgery.evidence.header = *SccpFinalityHeaderV1::from_fields(&fields)
        .unwrap()
        .as_bytes();
    data.attribution.authority_generation = generation.committee_root;
    data.attribution.height = generation.start_height;
    let budget = world.sccp_forgery_offences.allocation_budget();
    let encoded = norito::json::to_json(&data).unwrap();
    let record = parse_record(&mut norito::json::Parser::new(&encoded), budget).unwrap();
    let id = record.sccp_evidence_id().unwrap();
    let key = OffenceKey::try_copy(generation.generation, v.lane_id, &v.validator, budget).unwrap();
    world
        .sccp_forgery_offences
        .try_with_admitted_block(|block| {
            block
                .try_insert_admitted(key, id)
                .map_err(|(_, error)| error)
        })
        .unwrap();
    let id = Hash::prehashed(id);
    world.consensus_evidence.insert(id, record);
    id
}

#[test]
fn liability_is_inclusive_at_h_and_clock_and_matches_captured_registration() {
    let v = validator();
    let g = generation(&v);
    let (parent, current) = worlds(&g);
    set_cell(
        &current.sccp_liability_clock,
        g.liable_until_lc + g.progress_cap_ms,
    );
    assert_eq!(
        check(&parent, &current, &v, Some(g.start_height)).unwrap(),
        Some(ReleaseBlocker::LiabilityActive)
    );
    assert_eq!(
        check(&parent, &current, &v, Some(g.start_height - 1)).unwrap(),
        None
    );
    set_cell(
        &current.sccp_liability_clock,
        g.liable_until_lc + g.progress_cap_ms + 1,
    );
    assert_eq!(check(&parent, &current, &v, None).unwrap(), None);
    for foreign in [
        PublicLaneValidatorRecord {
            activation_height: 2,
            ..v.clone()
        },
        PublicLaneValidatorRecord {
            lane_id: LaneId::new(8),
            ..v.clone()
        },
        PublicLaneValidatorRecord {
            validator: authority(0x72),
            ..v.clone()
        },
    ] {
        set_cell(&current.sccp_liability_clock, 0);
        assert_eq!(check(&parent, &current, &foreign, None).unwrap(), None);
    }
}

#[test]
fn current_generation_and_parent_clearance_cannot_be_shortened_by_block_writes() {
    let v = validator();
    let mut g = generation(&v);
    let (mut parent, mut current) = worlds(&g);
    set_cell(&parent.sccp_committee_current, 7);
    set_cell(&current.sccp_liability_clock, u64::MAX);
    assert_eq!(
        check(&parent, &current, &v, None).unwrap(),
        Some(ReleaseBlocker::LiabilityActive)
    );
    set_cell(&parent.sccp_committee_current, 8);
    let clock = g.liable_until_lc + 1;
    set_cell(&current.sccp_liability_clock, clock);
    g.dest_cleared_lc = Some(g.start_lc);
    current.sccp_committee_generations.insert(7, g.clone());
    // The executing overlay's early-clearance value does not replace the original parent.
    assert_eq!(
        check(&parent, &current, &v, None).unwrap(),
        Some(ReleaseBlocker::LiabilityActive),
        "SC20 must retain liability until original destination clearance or the progress cap"
    );
    parent.sccp_committee_generations.insert(7, g);
    assert_eq!(check(&parent, &current, &v, None).unwrap(), None);
}

#[test]
fn pending_exact_offence_survives_liability_expiry_and_only_applied_releases_it() {
    let v = validator();
    let g = generation(&v);
    let (parent, mut current) = worlds(&g);
    set_cell(&current.sccp_liability_clock, u64::MAX);
    let id = insert_pending_claim(&mut current, &v, &g);
    let pool = current.sccp_forgery_offences.allocation_budget().clone();
    let retained = pool.reserved_bytes();
    assert_eq!(
        check(&parent, &current, &v, Some(0)).unwrap(),
        Some(ReleaseBlocker::PenaltyPending),
        "SC15 must retain an unbond while its exact recorded SCCP penalty is pending"
    );
    assert_eq!(
        pool.reserved_bytes(),
        retained,
        "temporary query ownership retires"
    );
    let mut record = current.consensus_evidence.view().get(&id).unwrap().clone();
    record.penalty_status = EvidencePenaltyStatus::Applied { height: 20 };
    current.consensus_evidence.insert(id, record);
    assert_eq!(check(&parent, &current, &v, None).unwrap(), None);
    assert_eq!(pool.reserved_bytes(), retained);
}

#[test]
fn missing_record_and_exhausted_original_query_pool_never_release() {
    let v = validator();
    let g = generation(&v);
    let (parent, mut current) = worlds(&g);
    set_cell(&current.sccp_liability_clock, u64::MAX);
    let id = insert_pending_claim(&mut current, &v, &g);
    let original = current.consensus_evidence.view().get(&id).unwrap().clone();
    {
        let mut records = current.consensus_evidence.block();
        let removed = records
            .remove(id)
            .expect("the original retained fixture record exists");
        assert!(removed.shares_body(&original));
        records.commit();
    }
    assert_eq!(
        check(&parent, &current, &v, None),
        Err(ForgeryStorageError::Invalid)
    );
    current.consensus_evidence.insert(id, original);
    let pool = current.sccp_forgery_offences.allocation_budget().clone();
    let retained = pool.reserved_bytes();
    let limit = pool.limit_bytes();
    pool.set_limit_bytes(retained);
    assert!(matches!(
        check(&parent, &current, &v, None),
        Err(ForgeryStorageError::Storage(_))
    ));
    assert_eq!(pool.reserved_bytes(), retained);
    pool.set_limit_bytes(limit);
    assert_eq!(
        check(&parent, &current, &v, None).unwrap(),
        Some(ReleaseBlocker::PenaltyPending)
    );
}

#[test]
fn offence_record_with_a_foreign_generation_root_never_releases() {
    let v = validator();
    let g = generation(&v);
    let (parent, mut current) = worlds(&g);
    set_cell(&current.sccp_liability_clock, u64::MAX);
    let mut foreign = g.clone();
    foreign.committee_root[0] ^= 1;
    let id = insert_pending_claim(&mut current, &v, &foreign);
    let mut record = current.consensus_evidence.view().get(&id).unwrap().clone();
    record.penalty_status = EvidencePenaltyStatus::Applied { height: 20 };
    current.consensus_evidence.insert(id, record);
    assert_eq!(
        check(&parent, &current, &v, None),
        Err(ForgeryStorageError::Invalid)
    );
}

#[test]
fn stored_offender_must_name_the_exact_captured_signer_slot() {
    let v = validator();
    let mut g = generation(&v);
    g.members[1] = g.members[0].take();
    let (parent, mut current) = worlds(&g);
    set_cell(&current.sccp_liability_clock, u64::MAX);
    let id = insert_pending_claim(&mut current, &v, &g);
    let mut record = current.consensus_evidence.view().get(&id).unwrap().clone();
    record.penalty_status = EvidencePenaltyStatus::Applied { height: 20 };
    current.consensus_evidence.insert(id, record);
    assert_eq!(
        check(&parent, &current, &v, None),
        Err(ForgeryStorageError::Invalid)
    );
}

#[path = "reference_fixtures.rs"]
mod reference_fixtures;
