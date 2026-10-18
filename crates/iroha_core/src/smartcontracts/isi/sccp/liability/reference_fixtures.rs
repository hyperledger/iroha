//! Shared liability fixture generated from the production clock, liability and State owners.
use super::*;
use crate::smartcontracts::isi::sccp::{
    generations, governance, pruning, store,
    test_support::{blank_state, header, install_generation, sample_route},
};
use iroha_data_model::{
    bridge::SccpNetworkV1,
    sccp::{
        generation::next_liability_clock_v1,
        light_client::{
            SccpLcFreezeReasonV1, SccpLcHeadV1, SccpLcParliamentFreezeV1, SccpLcPointV1,
            SccpLightClientParamsV1, SccpLightClientV1,
        },
    },
};
use norito::{json, json::Value};
#[path = "../reference_fixture_support.rs"]
mod fixture;
use fixture::{CAP, GRACE, HEARTBEAT, START, UNTIL, VALIDITY};

const GENERATOR: &str = "two independent generators: python3.11 scripts/sccp_reference/generate.py --write; cargo test -p iroha_core --lib sccp -- --ignored regenerate_liability_v1";
const CONVENTION: &str = "Times are integer milliseconds; every liability boundary is inclusive. DATA fixtures call production clock, L3, L5, pruning and P2 predicates without opening either route launch gate or manufacturing Parliament authority.";
fn clock_rows() -> Vec<Value> {
    let mut lc = 1000;
    let mut parent = 1000;
    let mut rows = Vec::new();
    for (label, now) in [
        ("ordinary_step", 2000),
        ("halt_no_committed_block", 2000),
        ("first_block_after_halt", 2000 + 30 * 86_400_000),
        ("second_resumed_block", 3000 + 30 * 86_400_000),
    ] {
        let out = next_liability_clock_v1(lc, parent, now, HEARTBEAT);
        rows.push(json!({"label": (label),"input": {"parent_lc": (lc),"parent_time": (parent),"time": (now),"heartbeat_ms": (HEARTBEAT)},"expected": {"lc": (out)}}));
        lc = out;
        parent = now;
    }
    rows.push(json!({"label": ("saturating_clock"),"input": {"parent_lc": (u64::MAX-2),"parent_time": (0u64),"time": (100u64),"heartbeat_ms": (HEARTBEAT)},
        "expected": {"lc": (next_liability_clock_v1(u64::MAX-2,0,100,HEARTBEAT))}}));
    rows
}
fn liability_rows() -> Vec<Value> {
    [("time_leg_before",8,UNTIL-1,Some(START)),("time_leg_inclusive",8,UNTIL,Some(START)),
        ("time_leg_ended",8,UNTIL+1,Some(START)),("progress_leg",8,UNTIL+1,None),
        ("progress_clearance_inclusive",8,UNTIL+GRACE,Some(UNTIL)),
        ("progress_clearance_ended",8,UNTIL+GRACE+1,Some(UNTIL)),
        ("cap_inclusive",8,UNTIL+CAP,None),("cap_ended",8,UNTIL+CAP+1,None),
        ("current_generation_never_expires",7,u64::MAX,None)].into_iter().map(|(label,current,lc,cleared)| {
            let mut generation=fixture::ended(7,2);generation.dest_cleared_lc=cleared;
            assert!(generation.is_well_formed());
            json!({"label": (label),"input": {"generation": (7u64),"current_generation": (current),"lc": (lc),"liable_until_lc": (UNTIL),
                "grace_ms": (GRACE),"progress_cap_ms": (CAP),"dest_cleared_lc": (cleared)},"expected": {"liable": (generation.is_liable(current,lc))}})
        }).collect()
}
fn clearance_rows() -> Vec<Value> {
    let deadline = START + VALIDITY;
    [("l5_missing_light_client",false,false,0),("l5_stalled_light_client",true,false,deadline-1),
        ("l5_at_deadline",true,false,deadline),("l5_past_deadline",true,false,deadline+1),
        ("l5_frozen_light_client",true,true,deadline+1)].into_iter().map(|(label,present,frozen,source)| {
            let state=blank_state();let mut block=state.block(header(4));let mut tx=block.transaction();
            install_generation(&mut tx,7,fixture::ended(7,2)).unwrap();
            store::liability_clock::set(&mut tx,UNTIL);
            let network=SccpNetworkV1::EthereumMainnet;
            store::routes::insert(&mut tx,network,sample_route(network)).unwrap();
            if present {
                let client=SccpLightClientV1 {
                    params:SccpLightClientParamsV1::defaults_for(network).unwrap(),
                    head:SccpLcHeadV1 {latest_set_id:1, latest_finalized:SccpLcPointV1 {source_height:1,block_hash:[1;32],source_time_ms:source},last_progress_taira_ms:START},
                    frozen:frozen.then_some(SccpLcFreezeReasonV1::Parliament(SccpLcParliamentFreezeV1 {proposal_id:[1;32]})),state_hash:[2;32]
                };
                store::light_clients::insert(&mut tx,network,client).unwrap();
            }
            generations::clear_destinations(&mut tx).unwrap();
            let cleared=store::committee_generations::get(&*tx.world,&7).unwrap().dest_cleared_lc;
            json!({"label": (label),"input": {"deadline_ms": (deadline),"lc": (UNTIL),"light_client_present": (present),"light_client_frozen": (frozen),"source_time_ms": (source)},
                "expected": {"dest_cleared_lc": (cleared)}})
        }).collect()
}
fn release_generation(v: &PublicLaneValidatorRecord) -> SccpCommitteeGenerationV1 {
    let mut g = fixture::ended(7, 2);
    g.members[0] = Some(SccpGenerationMemberV1 {
        lane_id: v.lane_id,
        validator: v.validator.clone(),
        activation_height: v.activation_height,
    });
    g
}
fn order_rows() -> Vec<Value> {
    [
        ("evidence_then_unbond", ["evidence", "unbond"]),
        ("unbond_then_evidence", ["unbond", "evidence"]),
    ]
    .into_iter()
    .map(|(label, steps)| {
        let v = validator();
        let g = release_generation(&v);
        let (parent, mut current) = worlds(&g);
        set_cell(&current.sccp_liability_clock, UNTIL);
        let mut outcomes = Vec::new();
        for step in steps {
            if step == "evidence" {
                let id = insert_pending_claim(&mut current, &v, &g);
                outcomes.push(format!(
                    "{:?}",
                    current
                        .consensus_evidence
                        .view()
                        .get(&id)
                        .unwrap()
                        .penalty_status
                ));
            } else {
                outcomes.push(format!(
                    "{:?}",
                    check(&parent, &current, &v, Some(g.start_height))
                        .unwrap()
                        .unwrap()
                ));
            }
        }
        let pending = generation_has_pending_penalty(
            &current.view(),
            &crate::smartcontracts::isi::sccp::test_support::retained_generation_fixture(&g),
            current.sccp_forgery_offences.allocation_budget(),
        )
        .unwrap();
        let released = check(&parent, &current, &v, Some(g.start_height))
            .unwrap()
            .is_none();
        json!({"label": (label),"input": {"lc": (UNTIL),"liable_until_lc": (UNTIL),"steps": (steps.to_vec())},
            "expected": {"outcomes": (outcomes),"stake_released": (released),"penalty_pending": (pending)}})
    })
    .collect()
}
fn pruning_rows() -> Vec<Value> {
    [("pending_generation_is_skipped",true),("applied_generation_can_retire",false)].into_iter().map(|(label,pending)| {
        let v=validator();let g=release_generation(&v);let mut state=blank_state();
        state.world.sccp_committee_generations.insert(7,g.clone());
        state.world.sccp_committee_generations.insert(9,fixture::ended(9,8));
        state.world.sccp_committee_generations.insert(20,fixture::generation(20,20));
        set_cell(&state.world.sccp_committee_current,20);set_cell(&state.world.sccp_liability_clock,u64::MAX);
        let id=insert_pending_claim(&mut state.world,&v,&g);
        if !pending {
            let mut record=state.world.consensus_evidence.view().get(&id).unwrap().clone();
            record.penalty_status=EvidencePenaltyStatus::Applied {height:30};state.world.consensus_evidence.insert(id,record);
        }
        let mut block=state.block(header(31));let mut tx=block.transaction();
        pruning::prune(&mut tx).unwrap();
        let retained=store::committee_generations::iter(&*tx.world).map(|(id,_)|*id).collect::<Vec<_>>();
        let pruned=[7u64,9,20].into_iter().filter(|id|!retained.contains(id)).collect::<Vec<_>>();
        json!({"label": (label),"input": {"current_generation": (20u64),"lc": (u64::MAX),"retained_generations": (vec![7u64,9,20]),"pending_generation": (pending.then_some(7u64))},
            "expected": {"retained_generations": (retained),"pruned_generations": (pruned)}})
    }).collect()
}
fn build() -> Value {
    json!({"schema": ("iroha.sccp.liability.v1"),"generator": (GENERATOR),"conventions": (CONVENTION),
        "constants": {"heartbeat_ms": (HEARTBEAT),"lc_slack_ms": (iroha_data_model::sccp::generation::SCCP_LC_SLACK_MS_V1),
            "start_lc": (START),"validity_ms": (VALIDITY),"grace_ms": (GRACE),"progress_cap_ms": (CAP),"liable_until_lc": (UNTIL)},
        "clock": (clock_rows()),"liability": (liability_rows()),"destination_clearance": (clearance_rows()),
        "same_block_orders": (order_rows()),"pruning": (pruning_rows()),"pin_margin": (governance::reference_pin_rows())})
}
#[test]
fn reference_liability_v1_matches_committed_fixture() {
    fixture::assert_fixture("liability_v1.json", &build());
}
#[test]
#[ignore = "explicit fixture regeneration"]
fn regenerate_liability_v1() {
    fixture::write_fixture("liability_v1.json", &build());
}
