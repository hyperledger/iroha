//! Independent production-Core generator and byte drift gate for forgery_evidence_v1.json.
use super::*;
use crate::smartcontracts::isi::sccp::{
    committee_storage::CommitteeFixtureStorage as _, test_support::retained_generation_fixture,
};
use crate::state::{World, sccp_forgery_custody::OffenceKey};
use iroha_crypto::bls::consensus::{aggregate, sign};
use iroha_data_model::{
    block::{BlockHeader, consensus::RecordedEvidenceV1},
    sumeragi_finality::certified_result::SccpFinalityHeaderFieldsV1,
};
use iroha_sccp::v1::{
    evidence::{anchor_leaf, anchor_path_root},
    finality::commit_message,
};
use mv::storage::StorageReadOnly as _;
use norito::{json, json::Value};
use std::num::NonZeroU64;

#[path = "../reference_fixture_support.rs"]
mod fixture;
use fixture::{CAP, GRACE, START, UNTIL, VALIDITY, hx};

const GENERATOR: &str = "two independent generators: python3.11 scripts/sccp_reference/generate.py --write; cargo test -p iroha_core --lib sccp -- --ignored regenerate_forgery_evidence_v1";
const CONVENTION: &str = "Explicit original-observation DATA exercises Core's production E0, signature, E1-E4, anchor and permanent-offence predicates; it grants no live authority. The record row separately replays authenticated native execution and projects its retained G6 bindings.";

fn certificate(
    height: u64,
    mode: &str,
    signers: u32,
) -> (
    SccpFinalityHeaderV1,
    QcFixedV1,
    [u8; 96],
    [u8; 32],
    [u8; 32],
) {
    let keys = fixture::keys();
    let rec = fixture::generation(7, 2);
    let fields = SccpFinalityHeaderFieldsV1 {
        network_id: [0x11; 32],
        height,
        timestamp_ms: if mode == "header" { 10_001 } else { 10_000 },
        flags: 1,
        generation: 7,
        committee_root: rec.committee_root,
        ..SccpFinalityHeaderFieldsV1::default()
    };
    let header = if mode == "inactive" {
        SccpFinalityHeaderV1::inactive([0x11; 32], height, 10_000).unwrap()
    } else {
        SccpFinalityHeaderV1::from_fields(&fields).unwrap()
    };
    let qc = QcFixedV1 {
        epoch: 2,
        epoch_context: [0x88; 32],
        view: 1,
        block_hash: [if mode == "block" { 0x98 } else { 0x99 }; 32],
        result_body: [if mode == "body" { 0x67 } else { 0x66 }; 32],
        signers,
    };
    let result = outer_result(&header, &qc.result_body).0;
    let preimage = commit_preimage(&[0x77; 32], &qc, height, &result);
    let message = commit_message(&preimage);
    let digest = ConsensusDigest::from_preimage(&preimage).unwrap();
    let signature = aggregate(
        keys.iter()
            .enumerate()
            .filter(|(i, _)| signers & (1 << i) != 0)
            .map(|(_, key)| sign(key.private_key(), &digest).unwrap()),
    )
    .unwrap();
    (header, qc, signature, message, result)
}

fn name(answer: Result<SccpForgeryRuleV1>) -> &'static str {
    match answer {
        Ok(SccpForgeryRuleV1::E1) => "E1",
        Ok(SccpForgeryRuleV1::E2) => "E2",
        Ok(SccpForgeryRuleV1::E3) => "E3",
        Ok(SccpForgeryRuleV1::E4) => "E4",
        Err(ForgeryVerificationError::NotEvidence) => "NotEvidence",
        Err(ForgeryVerificationError::EvidenceExpired) => "EvidenceExpired",
        Err(ForgeryVerificationError::WitnessRequired) => "WitnessRequired",
        Err(ForgeryVerificationError::BadWitness) => "BadWitness",
        Err(error) => panic!("unexpected fixture refusal: {error:?}"),
    }
}
fn evidence_rows() -> Vec<Value> {
    let cases = [
        (
            "e0_inclusive_window",
            "A retained ended generation is still liable exactly at its capped boundary.",
            "body",
            3,
        ),
        (
            "e0_expired_window",
            "One liability-clock millisecond after the cap expires E0 before pairing.",
            "body",
            3,
        ),
        (
            "e1_before_start",
            "A valid quorum signs before the retained generation starts.",
            "body",
            1,
        ),
        (
            "e1_after_end",
            "Tenure ends before this signed future height; E1 precedes E2.",
            "body",
            5,
        ),
        (
            "e2_future",
            "A quorum signs a height not yet committed by the original observation.",
            "body",
            4,
        ),
        (
            "e3_stray_commit_completion",
            "A quorum completes stray Commit votes for a competing block that never committed.",
            "block",
            3,
        ),
        (
            "e4_false_header",
            "The original core hash carries a false X.",
            "header",
            3,
        ),
        (
            "e4_genuine_x_different_body",
            "Genuine X with a different D_body changes the certified outer result.",
            "body",
            3,
        ),
        (
            "genuine_certificate",
            "The genuine block and result are never evidence.",
            "genuine",
            3,
        ),
        (
            "genuine_other_valid_signers",
            "A different valid exact quorum for the same genuine result is never evidence.",
            "genuine",
            3,
        ),
        (
            "anchor_tip",
            "The original tip supplies its own anchor without a witness.",
            "body",
            3,
        ),
        (
            "anchor_open_chunk",
            "The original open chunk supplies height two without a witness.",
            "body",
            2,
        ),
        (
            "anchor_completed_chunk",
            "A retained completed root authenticates the original twelve-sibling witness.",
            "body",
            2,
        ),
        (
            "anchor_missing_witness",
            "A completed chunk refuses an absent witness.",
            "body",
            2,
        ),
        (
            "anchor_wrong_path",
            "A changed sibling does not reach the retained completed root.",
            "body",
            2,
        ),
        (
            "anchor_pruned_chunk",
            "A witness cannot restore a pruned authoritative root.",
            "body",
            2,
        ),
        (
            "pruned_generation",
            "A generation missing from retained state has expired.",
            "body",
            3,
        ),
        (
            "inactive_x",
            "An inactive X makes no SCCP claim.",
            "inactive",
            3,
        ),
        (
            "e4_active_at_degraded_height",
            "An ACTIVE claim differs from the original inactive result at a degraded height.",
            "genuine",
            3,
        ),
    ];
    cases.into_iter().map(|(label, description, mode, height)| {
        let signers = if label == "genuine_other_valid_signers" {11} else {7};
        let (header, qc, signature, message, result) = certificate(height, mode, signers);
        let genuine = certificate(height, "genuine", 7);
        let anchor_result = if label == "e4_active_at_degraded_height" {
            outer_result(&SccpFinalityHeaderV1::inactive([0x11;32], height,10_000).unwrap(), &[0x66;32]).0
        } else { genuine.4 };
        let anchor = SccpAnchorV1 { core_hash: [0x99;32], result: anchor_result };
        let mut path = [[4;32];12];
        let root = anchor_path_root(&anchor_leaf(height, &anchor.core_hash, &anchor.result), ((height-1)%4096) as usize, &path).unwrap();
        let completed = matches!(label,"anchor_completed_chunk"|"anchor_missing_witness"|"anchor_wrong_path"|"anchor_pruned_chunk");
        let source = if completed {"completed"} else if label == "anchor_open_chunk" {"open"} else {"tip"};
        let witness = match label { "anchor_missing_witness" => "missing", "anchor_wrong_path" => "wrong", _ => "present" };
        if witness == "wrong" { path[0][0] ^= 1; }
        let chunk_retained = label != "anchor_pruned_chunk";
        let retained = label != "pruned_generation";
        let execution_height = if completed {4098} else {4};
        let lc = UNTIL+CAP+u64::from(label == "e0_expired_window");
        let mut record = fixture::generation(7,2);
        let end_height = if label == "e1_after_end" {Some(4)} else {None};
        if let Some(end_height) = end_height { record.end = Some(iroha_data_model::sccp::generation::SccpGenerationEndV1 {
            end_height, end_timestamp_ms: 10_000, next_committee_root: record.committee_root, successor_validity_ms: VALIDITY }); }
        let mut world = World::new();
        if retained { world.sccp_committee_generations.insert(7, record); }
        let view = world.view();
        let budget = AllocationBudget::new(128 << 20);
        let answer = if !header.is_active() { Err(ForgeryVerificationError::NotEvidence) } else {
            generation_for_claim(Current(&view), &header, 8, lc).and_then(|generation| {
                assert_eq!(verify_signature(generation, Hash32([0x77;32]), &header, &qc, &signature, &budget, VerificationControl::Synchronous).unwrap(), message);
                first_mismatch(generation, execution_height, height, &qc, result, || {
                    let open = if completed {vec![]} else {vec![anchor;2]};
                    lookup_anchor(execution_height-1, anchor, &open, height,
                        chunk_retained.then_some(&root), if witness == "missing" { None } else { Some((&anchor,&path)) }).map_err(anchor_error)
                })
            })
        };
        let outcome = name(answer);
        json!({"label": (label),"description": (description),"input": {
            "header": (hx(header.as_bytes())),"qc": (hx(&qc.encode())),"aggregate_signature": (hx(&signature)),"signature_evm": (hx(&iroha_sccp::v1::committee::signature_to_evm192(&signature).unwrap())),
            "generation_retained": (retained),"current_generation": (8u64),"lc": (lc),"liable_until_lc": (UNTIL),
            "start_height": (2u64),"end_height": (end_height),"execution_height": (execution_height),
            "anchor_source": (source),"anchor_core_hash": (hx(&anchor.core_hash)),"anchor_result": (hx(&anchor.result)),
            "chunk_root": (hx(&root)),"path": (path.iter().map(|h| hx(h)).collect::<Vec<_>>()),
            "chunk_retained": (chunk_retained),"witness": (witness)},"expected": {"outcome": (outcome),"message": (hx(&message)),"result": (hx(&result)),"evidence_id": (hx(&forgery_evidence_id(header.generation(),&message,signers)))}})
    }).collect()
}
fn dedup_rows() -> Vec<Value> {
    let record = fixture::generation(7, 2);
    let retained = retained_generation_fixture(&record);
    let world = World::new();
    let mut seen = 0u32;
    [("first_signer_set",7u32),("same_signer_set",7),("different_signer_set",11)].into_iter().map(|(label,signers)| {
        let message = certificate(4,"body",signers).3;
        let id = forgery_evidence_id(7, &message, signers);
        let budget = world.sccp_forgery_offences.allocation_budget().clone();
        let selected = new_signers(&world.view(), &retained, signers, &budget).unwrap();
        let row = json!({"label": (label),"input": {"generation": (7u64),"signers": (signers),"already_recorded": (seen)},
            "expected": {"outcome": (if selected==0 {"EvidenceDuplicate"} else {"Recorded"}),"new_signers": (selected),"evidence_id": (hx(&id))}});
        for (index, member) in record.members.iter().enumerate() {
            if selected & (1 << index) != 0 {
                let member = member.as_ref().unwrap();
                let key = OffenceKey::try_copy(7,member.lane_id,&member.validator,&budget).unwrap();
                world.sccp_forgery_offences.try_with_admitted_block(|block| block.try_insert_admitted(key,id).map_err(|(_,error)|error)).unwrap();
            }
        }
        seen |= selected;
        row
    }).collect()
}
fn record_row() -> Value {
    let (chain, keys) = super::tests::active_member_chain();
    let mut evidence = super::tests::future(&chain, &keys);
    let mut qc = QcFixedV1::parse(&evidence.qc).unwrap();
    qc.signers = 7;
    evidence.qc = qc.encode();
    super::tests::resign(&mut evidence, &keys, chain.instance());
    let view = chain.state().view();
    let parent = view.native_execution_tip().unwrap();
    let generation = store::committee_generations::get(view.world(), &1).unwrap();
    let header = BlockHeader::new(
        NonZeroU64::new(parent.height() + 1).unwrap(),
        Some(parent.iroha_hash()),
        None,
        parent.creation_time_ms() + 1000,
        0,
    );
    let mut block = chain.state().block(header);
    let mut tx = block.transaction_for_callback_testing();
    execute_forgery(&evidence, &mut tx).unwrap();
    let retained = tx.world.consensus_evidence.iter().next().unwrap().1;
    let RecordedEvidenceV1::SccpForgery(record) = &retained.evidence else {
        panic!("SCCP record");
    };
    let offenders = record.offenders.iter().map(|offender| {
        let member = generation.members[offender.signer as usize].as_ref().unwrap();
        json!({"signer": (offender.signer),"lane_id": (offender.lane_id.as_u32()),"activation_height": (offender.activation_height),
            "matches_original_g6": (member.lane_id==offender.lane_id && member.validator==offender.validator && member.activation_height==offender.activation_height)})
    }).collect::<Vec<_>>();
    json!({"label": ("self_contained_g6_record"),"description": ("Authenticated native genesis and one committed successor produce a verified future claim. The retained record uses start_height, not the attacker height, and copies each original G6 binding; the projection omits chain-specific hashes."),
        "input": {"generation": (generation.generation),"start_height": (generation.start_height),"committed_height": (parent.height()),"claimed_height": (SccpFinalityHeaderV1::parse(&evidence.header).unwrap().height()),"signers": (qc.signers)},
        "expected": {"rule": (format!("{:?}",record.rule)),"offence_height": (retained.attribution.height),
            "signed_height": (SccpFinalityHeaderV1::parse(&record.evidence.header).unwrap().height()),"generation": (record.generation),
            "penalty_status": (format!("{:?}",retained.penalty_status)),
            "self_contained": (record.evidence == evidence && record.start_height == generation.start_height
                && retained.attribution.authority_generation == generation.committee_root
                && retained.sccp_evidence_id() == Some(forgery_evidence_id(record.generation, &commit_message(&commit_preimage(&chain.instance().0, &qc, SccpFinalityHeaderV1::parse(&evidence.header).unwrap().height(), &outer_result(&SccpFinalityHeaderV1::parse(&evidence.header).unwrap(), &qc.result_body).0)), qc.signers))),
            "offenders": (offenders)}})
}
fn build() -> Value {
    let generation = fixture::generation(7, 2);
    json!({"schema": ("iroha.sccp.forgery_evidence.v1"),"generator": (GENERATOR),"conventions": (CONVENTION),
        "constants": {"network_id": (hx(&[0x11;32])),"consensus_instance": (hx(&[0x77;32])),
            "committee_keys": (generation.keys.iter().map(|key| hx(key)).collect::<Vec<_>>()),
            "committee_root": (hx(&generation.committee_root)),"n": (4u64),"q": (3u64),"generation": (7u64),
            "start_lc": (START),"validity_ms": (VALIDITY),"grace_ms": (GRACE),"progress_cap_ms": (CAP)},
        "rows": (evidence_rows()),"deduplication": (dedup_rows()),"record": (record_row())})
}
#[test]
fn reference_forgery_evidence_v1_matches_committed_fixture() {
    fixture::assert_fixture("forgery_evidence_v1.json", &build());
}
#[test]
#[ignore = "explicit fixture regeneration"]
fn regenerate_forgery_evidence_v1() {
    fixture::write_fixture("forgery_evidence_v1.json", &build());
}
