//! P2 rows derived through the production retained-pin validator, without opening P0.
use super::*;
use crate::smartcontracts::isi::sccp::{
    store,
    test_support::{blank_state, header, install_generation, sample_pin},
};
use iroha_data_model::sccp::generation::SccpGenerationEndV1;
use norito::{json, json::Value};
#[path = "../../reference_fixture_support.rs"]
mod fixture;

/// Produce all registration-margin rows of the shared liability fixture.
pub(crate) fn rows() -> Vec<Value> {
    let now = 200_000_000u64;
    let required = now + fixture::HEARTBEAT + PIN_MARGIN_MS;
    [("p2_validity_reduction_refused", required-1), ("p2_intervening_boundary",required), ("p2_all_generations_live",required+1)]
        .into_iter().map(|(label, deadline)| {
            let mut first = fixture::generation(1,1);
            let mut second = fixture::generation(2,3);
            second.validity_ms=deadline-fixture::START;
            second.deadline_ms=deadline;
            second.liable_until_lc=second.start_lc+second.validity_ms+second.grace_ms;
            first.end=Some(SccpGenerationEndV1 { end_height:2,end_timestamp_ms:second.start_timestamp_ms,
                next_committee_root:second.committee_root,successor_validity_ms:second.validity_ms });
            let pin=sample_pin(&first);
            let deadlines=vec![first.deadline_ms,second.deadline_ms];
            let state=blank_state();let mut block=state.block(header(4));let mut tx=block.transaction();
            install_generation(&mut tx,1,first).unwrap();install_generation(&mut tx,2,second).unwrap();
            store::committee_current::set(&mut tx,2);
            let outcome=match retained_pin(&*tx.world,&pin,now,fixture::HEARTBEAT,3) {
                Ok(_) => "Accepted",
                Err(error) => { assert!(error.to_string().contains("intervening generation expires"),"{label}: {error}");"InterveningGenerationExpired" }
            };
            json!({"label": (label),"input": {"now_ms": (now),"heartbeat_ms": (fixture::HEARTBEAT),"pin_margin_ms": (PIN_MARGIN_MS),"deadlines_ms": (deadlines)},
                "expected": {"required_until_ms": (required),"outcome": (outcome)}})
        }).collect()
}
