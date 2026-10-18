//! Independent Rust derivation of the shared fast-pause component rows.
//!
//! The fixture supplies explicit effect-boundary inputs, never Parliament authority.
//! Production draw/eligibility refusal is separately recorded. Every expected value comes
//! from the current Core consumer or the native SCCP destination implementation.
use super::*;
use crate::smartcontracts::isi::sccp::{
    governance, hold,
    test_support::{
        authority, blank_state, header, sample_fast_pause, sample_fast_pause_round,
        sample_pause_panel, sample_route,
    },
};
use iroha_data_model::{
    governance::GovernanceAnchorV1,
    sccp::governance::{
        SccpGovernanceActionV1, SccpGovernanceProposalV1, SccpSetDestinationPausedActionV1,
        SccpSetFastPauseSuspendedActionV1, SccpSetTairaPausedActionV1,
    },
};
use iroha_sccp::v1::{
    control::{ControlLeafV1, control_leaf, control_leaf_preimage},
    hashes::to_hex,
};
use norito::{json, json::Value};

#[path = "../../../../../../../iroha_sccp/tests/reference_support/python_json.rs"]
mod python_json;

const NETWORK: SccpNetworkV1 = SccpNetworkV1::EthereumMainnet;
const T0: u64 = 8_000;

fn number(v: &Value, key: &str) -> u64 {
    v[key].as_u64().unwrap()
}
fn string<'a>(v: &'a Value, key: &str) -> &'a str {
    v[key].as_str().unwrap()
}
fn indices(v: &Value, key: &str) -> Vec<usize> {
    v[key]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_u64().unwrap() as usize)
        .collect()
}
fn hex(bytes: &[u8]) -> String {
    format!("0x{}", to_hex(bytes))
}
fn anchor(v: &Value) -> GovernanceAnchorV1 {
    GovernanceAnchorV1 {
        height: number(v, "height"),
        position: number(v, "position") as u32,
        timestamp_ms: number(v, "timestamp_ms"),
    }
}
fn role(v: &Value) -> SccpPanelRoleV1 {
    if string(v, "role") == "Primary" {
        SccpPanelRoleV1::Primary
    } else {
        SccpPanelRoleV1::Backup
    }
}
fn setup(tx: &mut StateTransaction<'_, '_>, activation: SccpRouteActivationV1, k: u32) {
    let mut parameters = SccpParametersV1::taira_default();
    parameters.enabled = true;
    parameters.fast_pause_panel_seats = k;
    store::parameters::set(tx, Some(parameters));
    let mut route = sample_route(NETWORK);
    route.revisions.get_mut(&1).unwrap().activation = activation;
    store::routes::insert(tx, NETWORK, route).unwrap();
}
fn panel(
    tx: &StateTransaction<'_, '_>,
    k: usize,
    accepted: &[usize],
    sequence: u64,
) -> RetainedSccpPausePanel {
    let mut panel = sample_pause_panel(1);
    panel.drawn.truncate(3 * k);
    panel.accepted = accepted.iter().map(|i| panel.drawn[*i].clone()).collect();
    panel.panel_seq = sequence;
    RetainedSccpPausePanel::admit(&panel, tx.sccp_evidence_preparation_budget()).unwrap()
}
fn round(
    tx: &StateTransaction<'_, '_>,
    panel: &PausePanelBody,
    role: SccpPanelRoleV1,
    members: &[usize],
    head: u64,
    window: (u64, u64),
    sequence: u64,
) -> RetainedSccpFastPauseRound {
    let mut round = sample_fast_pause_round(1);
    round.panel_id = if role == SccpPanelRoleV1::Primary {
        panel.primary_id
    } else {
        panel.backup_id
    };
    round.panel_seq = sequence;
    round.head = head;
    round.opened_at_ms = window.0;
    round.closes_at_ms = window.1;
    round.certify_due = true;
    round.endorsers = members
        .iter()
        .map(|index| {
            (
                panel.drawn[*index].clone(),
                SccpFastPauseEndorsementV1 {
                    incident_digest: [9; 32],
                    recorded_at_height: 2,
                },
            )
        })
        .collect();
    RetainedSccpFastPauseRound::admit(&round, tx.sccp_evidence_preparation_budget()).unwrap()
}
fn snapshot(world: &impl WorldReadOnly, time: u64) -> Value {
    let route = store::routes::get(world, &NETWORK).unwrap();
    let revision = &route.revisions[&1];
    let fast_destination = hold::fast_destination(world, NETWORK, 1, time);
    json!({"activation":(format!("{:?}",revision.activation)),
        "destination_parliament_paused":(revision.destination_paused),
        "fast_until_ms":(store::fast_pauses::get(world,&NETWORK).map_or(0,|p|p.until_ms)),
        "fast_taira_held":(hold::fast_taira(world,NETWORK,Some(time))),
        "fast_destination_held":fast_destination,
        "taira_held":(hold::taira(world,NETWORK,1,Some(time))),
        "destination_held":(revision.destination_paused || fast_destination),
        "fast_hold_head":(store::governance_revision(world,&SccpGovernanceSubjectV1::FastHold(NETWORK))),
        "rounds":(store::fast_pause_rounds::iter(world).count()),
        "next_control_nonce":(revision.next_control_nonce),
        "suspended_until_ms":(store::fast_pause_suspended_until_ms::get(world,&NETWORK).copied().unwrap_or(0))})
}
fn state_expected(inputs: &Value) -> Value {
    let state = blank_state();
    let mut block = state.block(header(2));
    let k = number(inputs, "panel_seats") as usize;
    let quorum = (2 * k + 2) / 3;
    {
        let mut tx = block.transaction();
        let activation = if string(inputs, "activation") == "InboundOnly" {
            SccpRouteActivationV1::InboundOnly
        } else {
            SccpRouteActivationV1::Bidirectional
        };
        setup(&mut tx, activation, k as u32);
        tx.apply();
    }
    let mut snapshots = Vec::new();
    for op in inputs["operations"].as_array().unwrap() {
        let time = number(op, "time_ms");
        block._curr_block.creation_time_ms = time;
        match string(op, "kind") {
            "parliament_pause" | "parliament_resume" | "suspend" => {
                let mut tx = block.transaction();
                let kind = string(op, "kind");
                let actions = if kind == "suspend" {
                    vec![SccpGovernanceActionV1::SetFastPauseSuspended(
                        SccpSetFastPauseSuspendedActionV1 {
                            network: NETWORK,
                            duration_ms: number(op, "duration_ms"),
                        },
                    )]
                } else {
                    let paused = kind == "parliament_pause";
                    vec![
                        SccpGovernanceActionV1::SetTairaPaused(SccpSetTairaPausedActionV1 {
                            network: NETWORK,
                            paused,
                        }),
                        SccpGovernanceActionV1::SetDestinationPaused(
                            SccpSetDestinationPausedActionV1 {
                                network: NETWORK,
                                revision: 1,
                                paused,
                            },
                        ),
                    ]
                };
                let mut proposal = SccpGovernanceProposalV1 {
                    network_id: *tx.network_id(),
                    base_revisions: Vec::new(),
                    actions,
                };
                proposal.base_revisions = proposal
                    .subjects()
                    .into_iter()
                    .map(|s| (s, store::governance_revision(&*tx.world, &s)).into())
                    .collect();
                governance::enact(
                    &mut tx,
                    [0x43; 32],
                    [0x45; 32],
                    anchor(&op["s0"]),
                    &proposal,
                )
                .unwrap();
                tx.apply();
            }
            "fast_enact" => {
                block._curr_block.height = std::num::NonZeroU64::new(number(op, "height")).unwrap();
                let role = role(op);
                let head = store::governance_revision(
                    &block.world,
                    &SccpGovernanceSubjectV1::FastHold(NETWORK),
                );
                // Explicit component facts exercise the same post-Parliament recheck;
                // they do not construct an eligibility capability or a CertifiedPause.
                let (endorsement_root, incident_root, endorsement_count) = {
                    let tx = block.transaction();
                    let panel = panel(&tx, k, &(0..3 * k).collect::<Vec<_>>(), 1);
                    let start = if role == SccpPanelRoleV1::Primary {
                        0
                    } else {
                        k
                    };
                    let members = (start..start + quorum).collect::<Vec<_>>();
                    let round = store::fast_pause_rounds::get(&*tx.world, &(NETWORK, role))
                        .cloned()
                        .unwrap_or_else(|| {
                            round(
                                &tx,
                                &panel,
                                role,
                                &members,
                                head,
                                (
                                    number(op, "round_opened_at_ms"),
                                    number(op, "round_closes_at_ms"),
                                ),
                                1,
                            )
                        });
                    assert_eq!(round.opened_at_ms, number(op, "round_opened_at_ms"));
                    assert_eq!(round.closes_at_ms, number(op, "round_closes_at_ms"));
                    let (selected, count) =
                        recheck(&*tx.world, &panel, &round, NETWORK, role, time, u32::MAX).unwrap();
                    let (endorsements, incidents) = roots(&round, &selected, count).unwrap();
                    (endorsements, incidents, count)
                };
                let certificate = SccpFastPauseCertificateV1 {
                    network_id: *block.network_id(),
                    network: NETWORK,
                    panel_id: if role == SccpPanelRoleV1::Primary {
                        [3; 32]
                    } else {
                        [4; 32]
                    },
                    panel_role: role,
                    panel_seq: 1,
                    head,
                    endorsement_root,
                    endorsement_count,
                    quorum: quorum as u32,
                    incident_root,
                    effect_preimage_hash: SccpFastPauseCertificateV1::effect_hash(
                        *block.network_id(),
                        NETWORK,
                        head,
                    ),
                    certified_at_height: number(op, "height"),
                    certified_at_ms: time,
                };
                apply_enactment::<()>(&mut block, certificate, number(op, "position") as u32)
                    .unwrap();
            }
            "seed_rounds" => {
                let mut tx = block.transaction();
                let panel = panel(&tx, k, &(0..3 * k).collect::<Vec<_>>(), 1);
                for (role, members) in [
                    (
                        SccpPanelRoleV1::Primary,
                        (0..if k == 5 { 2 } else { quorum }).collect::<Vec<_>>(),
                    ),
                    (SccpPanelRoleV1::Backup, (k..k + quorum).collect()),
                ] {
                    let round = round(&tx, &panel, role, &members, 0, (time, time + 1_800_000), 1);
                    let result = recheck(&*tx.world, &panel, &round, NETWORK, role, time, u32::MAX);
                    if role == SccpPanelRoleV1::Primary && k == 5 {
                        assert_eq!(result, Err(NoResult::InsufficientEligibleEndorsements));
                    } else {
                        assert_eq!(result.unwrap().1, quorum as u32);
                    }
                    store::fast_pause_rounds::insert(&mut tx, (NETWORK, role), round).unwrap();
                }
                tx.apply();
            }
            "observe" => {}
            other => panic!("unknown operation {other}"),
        }
        snapshots.push(snapshot(&block.world, time));
    }
    json!({"snapshots":snapshots})
}
fn expected(row: &Value) -> Value {
    let input = &row["inputs"];
    if string(row, "category") == "state" {
        return state_expected(input);
    }
    let state = blank_state();
    let mut block = state.block(header(2));
    let mut tx = block.transaction();
    let k = input["panel_seats"].as_u64().unwrap_or(9) as usize;
    setup(&mut tx, SccpRouteActivationV1::Bidirectional, k as u32);
    match string(row, "category") {
        "certification" => {
            let panel = panel(
                &tx,
                k,
                &(0..3 * k).collect::<Vec<_>>(),
                number(input, "panel_seq"),
            );
            let round = round(
                &tx,
                &panel,
                role(input),
                &indices(input, "endorsers"),
                number(input, "round_head"),
                (1_000, number(input, "closes")),
                number(input, "round_seq"),
            );
            store::set_governance_revision(
                &mut tx,
                SccpGovernanceSubjectV1::FastHold(NETWORK),
                number(input, "head"),
            );
            let suspended = number(input, "suspended_until");
            if suspended != 0 {
                store::fast_pause_suspended_until_ms::insert(&mut tx, NETWORK, suspended).unwrap();
            }
            let result = recheck(
                &*tx.world,
                &panel,
                &round,
                NETWORK,
                role(input),
                number(input, "time"),
                number(input, "eligible") as u32,
            );
            match result {
                Ok((_, count)) => json!({"outcome":"Certified","endorsement_count":count}),
                Err(e) => json!({"outcome":(format!("{e:?}")),"endorsement_count":0}),
            }
        }
        "seats" => {
            let panel = panel(&tx, 9, &indices(input, "accepted"), 1);
            let owners = seats(
                &panel,
                9,
                number(input, "time_ms"),
                number(input, "eligible") as u32,
            )
            .unwrap();
            let member = &panel.drawn[number(input, "member") as usize];
            json!({"owners":(owners[..18].to_vec()),"primary_member_counts":(counts(&panel,&owners,SccpPanelRoleV1::Primary,9,number(input,"eligible") as u32,member))})
        }
        "endorsement" => {
            let panel = panel(&tx, 9, &(0..27).collect::<Vec<_>>(), 1);
            let existing = indices(input, "existing_endorsers");
            if !existing.is_empty() {
                let round = round(
                    &tx,
                    &panel,
                    SccpPanelRoleV1::Primary,
                    &existing,
                    0,
                    (1_000, 9_000),
                    1,
                );
                store::fast_pause_rounds::insert(
                    &mut tx,
                    (NETWORK, SccpPanelRoleV1::Primary),
                    round,
                )
                .unwrap();
            }
            let member = number(input, "member") as usize;
            let outside = authority(99);
            let account = panel.drawn.get(member).unwrap_or(&outside);
            let instruction = EndorseSccpFastPauseV1 {
                network_id: *tx.network_id(),
                network: NETWORK,
                panel_id: panel.primary_id,
                head: 0,
                incident_digest: [9; 32],
            };
            let result = check_current_endorsement(
                &*tx.world,
                account,
                &instruction,
                T0,
                &panel,
                SccpPanelRoleV1::Primary,
                u32::MAX,
            );
            let outcome = match result {
                Ok(()) => "Accepted",
                Err(e) if e.to_string().contains("duplicate") => "DuplicateEndorsement",
                Err(e) if e.to_string().contains("eligible seat") => "NotEligibleSeat",
                Err(e) => panic!("unexpected refusal {e}"),
            };
            json!({"outcome":outcome})
        }
        "renewal" => {
            let mut pause = sample_fast_pause(1);
            pause.until_ms = number(input, "until_ms");
            let retained = super::super::super::pause_record::RetainedSccpFastPause::admit(
                &pause,
                tx.sccp_evidence_preparation_budget(),
            )
            .unwrap();
            store::fast_pauses::insert(&mut tx, NETWORK, retained).unwrap();
            let result = conditions(
                &*tx.world,
                NETWORK,
                0,
                number(input, "time_ms"),
                store::parameters::get(&*tx.world).as_ref().unwrap(),
            );
            json!({"outcome":(match result {Ok(())=>"Ready".to_owned(),Err(e)=>format!("{e:?}")})})
        }
        "boundary" => {
            let panel = panel(&tx, 9, &[], 1);
            let eligibility = parliament_iface::pause_eligibility(&*tx.world, &panel, T0).is_ok();
            drop(tx);
            let draw = parliament_iface::pause_draw(&block.world, [1; 32], 1, [2; 32], 9).is_ok();
            json!({"draw_available":draw,"eligibility_available":eligibility,"binding_ballot_available":(parliament_iface::parliament_binding_ballot_available())})
        }
        other => panic!("unknown category {other}"),
    }
}

fn inputs() -> Value {
    norito::json::from_str(r#"{
  "constants": {
    "destination_t0_ms": 1800000000000,
    "hold_ms": 864000000,
    "max_fast_pause_ms": 2592000000,
    "panel_quorum": 6,
    "panel_seats": 9,
    "renew_lead_ms": 86400000,
    "t0_ms": 8000
  },
  "controls": [
    {
      "destination_word": "0x0000000000000000000000002222222222222222222222222222222222222222",
      "fields": {
        "certificate_id": "0x5555555555555555555555555555555555555555555555555555555555555555",
        "control_nonce": 1,
        "effect_hash": "0x6666666666666666666666666666666666666666666666666666666666666666",
        "fast_pause_until_ms": 1799999999000,
        "parliament_paused": 0,
        "route_revision": 1,
        "track": 2
      },
      "id": "ethereum-mainnet_late_track2",
      "network": "ethereum-mainnet",
      "network_id": "0x1111111111111111111111111111111111111111111111111111111111111111",
      "now_ms": 1800000000000,
      "previous_control_nonce": 0
    },
    {
      "destination_word": "0x0000000000000000000000002222222222222222222222222222222222222222",
      "fields": {
        "certificate_id": "0x5555555555555555555555555555555555555555555555555555555555555555",
        "control_nonce": 1,
        "effect_hash": "0x6666666666666666666666666666666666666666666666666666666666666666",
        "fast_pause_until_ms": 1802592001000,
        "parliament_paused": 0,
        "route_revision": 1,
        "track": 2
      },
      "id": "ethereum-mainnet_max_fast_pause_clamp",
      "network": "ethereum-mainnet",
      "network_id": "0x1111111111111111111111111111111111111111111111111111111111111111",
      "now_ms": 1800000000000,
      "previous_control_nonce": 0
    },
    {
      "destination_word": "0x0000000000000000000000002222222222222222222222222222222222222222",
      "fields": {
        "certificate_id": "0x5555555555555555555555555555555555555555555555555555555555555555",
        "control_nonce": 1,
        "effect_hash": "0x6666666666666666666666666666666666666666666666666666666666666666",
        "fast_pause_until_ms": 1799999999000,
        "parliament_paused": 1,
        "route_revision": 1,
        "track": 2
      },
      "id": "ethereum-mainnet_parliament_survives_expiry",
      "network": "ethereum-mainnet",
      "network_id": "0x1111111111111111111111111111111111111111111111111111111111111111",
      "now_ms": 1800000000000,
      "previous_control_nonce": 0
    },
    {
      "destination_word": "0x0000000000000000000000002222222222222222222222222222222222222222",
      "fields": {
        "certificate_id": "0x5555555555555555555555555555555555555555555555555555555555555555",
        "control_nonce": 1,
        "effect_hash": "0x6666666666666666666666666666666666666666666666666666666666666666",
        "fast_pause_until_ms": 1800000030000,
        "parliament_paused": 0,
        "route_revision": 1,
        "track": 2
      },
      "id": "ethereum-mainnet_stale_control_nonce",
      "network": "ethereum-mainnet",
      "network_id": "0x1111111111111111111111111111111111111111111111111111111111111111",
      "now_ms": 1800000000000,
      "previous_control_nonce": 1
    },
    {
      "destination_word": "0x3535353535353535353535353535353535353535353535353535353535353535",
      "fields": {
        "certificate_id": "0x5555555555555555555555555555555555555555555555555555555555555555",
        "control_nonce": 1,
        "effect_hash": "0x6666666666666666666666666666666666666666666666666666666666666666",
        "fast_pause_until_ms": 1799999999000,
        "parliament_paused": 0,
        "route_revision": 1,
        "track": 2
      },
      "id": "ton-mainnet_late_track2",
      "network": "ton-mainnet",
      "network_id": "0x1111111111111111111111111111111111111111111111111111111111111111",
      "now_ms": 1800000000000,
      "previous_control_nonce": 0
    },
    {
      "destination_word": "0x3535353535353535353535353535353535353535353535353535353535353535",
      "fields": {
        "certificate_id": "0x5555555555555555555555555555555555555555555555555555555555555555",
        "control_nonce": 1,
        "effect_hash": "0x6666666666666666666666666666666666666666666666666666666666666666",
        "fast_pause_until_ms": 1802592001000,
        "parliament_paused": 0,
        "route_revision": 1,
        "track": 2
      },
      "id": "ton-mainnet_max_fast_pause_clamp",
      "network": "ton-mainnet",
      "network_id": "0x1111111111111111111111111111111111111111111111111111111111111111",
      "now_ms": 1800000000000,
      "previous_control_nonce": 0
    },
    {
      "destination_word": "0x3535353535353535353535353535353535353535353535353535353535353535",
      "fields": {
        "certificate_id": "0x5555555555555555555555555555555555555555555555555555555555555555",
        "control_nonce": 1,
        "effect_hash": "0x6666666666666666666666666666666666666666666666666666666666666666",
        "fast_pause_until_ms": 1799999999000,
        "parliament_paused": 1,
        "route_revision": 1,
        "track": 2
      },
      "id": "ton-mainnet_parliament_survives_expiry",
      "network": "ton-mainnet",
      "network_id": "0x1111111111111111111111111111111111111111111111111111111111111111",
      "now_ms": 1800000000000,
      "previous_control_nonce": 0
    },
    {
      "destination_word": "0x3535353535353535353535353535353535353535353535353535353535353535",
      "fields": {
        "certificate_id": "0x5555555555555555555555555555555555555555555555555555555555555555",
        "control_nonce": 1,
        "effect_hash": "0x6666666666666666666666666666666666666666666666666666666666666666",
        "fast_pause_until_ms": 1800000030000,
        "parliament_paused": 0,
        "route_revision": 1,
        "track": 2
      },
      "id": "ton-mainnet_stale_control_nonce",
      "network": "ton-mainnet",
      "network_id": "0x1111111111111111111111111111111111111111111111111111111111111111",
      "now_ms": 1800000000000,
      "previous_control_nonce": 1
    }
  ],
  "conventions": {
    "authority_boundary": "Component inputs only: Parliament authenticates certificate_id, effect_hash and casting-open s0; panel draw order and eligibility masks are supplied DATA. No genuine ballot, citizen draw or eligibility capability is fabricated; production launch gates remain false.",
    "clock": "Taira inputs are milliseconds; destination now_ms is a whole second times 1000.",
    "indices": "Zero-based original draw indices; panel_seats is 5 or 9, with equally sized primary, backup and reserve partitions."
  },
  "generator": "Independent Python scripts/sccp_reference/vectors_fast_pause.py and Rust iroha_core fast_pause::certification::reference_fixtures write this file byte for byte.",
  "rows": [
    {
      "category": "state",
      "description": "A Parliament pause survives a later fast pause and its blockless expiry.",
      "id": "parliament_pause_fast_pause_lapse",
      "inputs": {
        "activation": "Bidirectional",
        "operations": [
          {
            "certificate_id": "0x4343434343434343434343434343434343434343434343434343434343434343",
            "effect_hash": "0x4545454545454545454545454545454545454545454545454545454545454545",
            "kind": "parliament_pause",
            "s0": {
              "height": 1,
              "position": 0,
              "timestamp_ms": 1000
            },
            "time_ms": 8000
          },
          {
            "height": 2,
            "kind": "fast_enact",
            "position": 5,
            "role": "Primary",
            "round_closes_at_ms": 1808000,
            "round_opened_at_ms": 8000,
            "time_ms": 8000
          },
          {
            "kind": "observe",
            "time_ms": 864008000
          }
        ],
        "panel_seats": 9
      }
    },
    {
      "category": "state",
      "description": "A round certified against the unchanged FastHold head before Parliament pauses is enacted afterward; lapse preserves Parliament's pause.",
      "id": "certify_before_parliament_pause",
      "inputs": {
        "activation": "Bidirectional",
        "operations": [
          {
            "kind": "seed_rounds",
            "time_ms": 8000
          },
          {
            "certificate_id": "0x4343434343434343434343434343434343434343434343434343434343434343",
            "effect_hash": "0x4545454545454545454545454545454545454545454545454545454545454545",
            "kind": "parliament_pause",
            "s0": {
              "height": 1,
              "position": 0,
              "timestamp_ms": 1000
            },
            "time_ms": 8000
          },
          {
            "height": 2,
            "kind": "fast_enact",
            "position": 5,
            "role": "Primary",
            "round_closes_at_ms": 1808000,
            "round_opened_at_ms": 8000,
            "time_ms": 8000
          },
          {
            "kind": "observe",
            "time_ms": 864008000
          }
        ],
        "panel_seats": 9
      }
    },
    {
      "category": "state",
      "description": "Authenticated s0 after the fast enactment clears both parts; timestamp is not an ordering substitute.",
      "id": "lift_after_enactment",
      "inputs": {
        "activation": "Bidirectional",
        "operations": [
          {
            "height": 2,
            "kind": "fast_enact",
            "position": 5,
            "role": "Primary",
            "round_closes_at_ms": 1808000,
            "round_opened_at_ms": 8000,
            "time_ms": 8000
          },
          {
            "certificate_id": "0x4343434343434343434343434343434343434343434343434343434343434343",
            "effect_hash": "0x4545454545454545454545454545454545454545454545454545454545454545",
            "kind": "parliament_resume",
            "s0": {
              "height": 2,
              "position": 6,
              "timestamp_ms": 1000
            },
            "time_ms": 8000
          }
        ],
        "panel_seats": 9
      }
    },
    {
      "category": "state",
      "description": "Authenticated s0 before the fast enactment retains both parts.",
      "id": "lift_before_enactment",
      "inputs": {
        "activation": "Bidirectional",
        "operations": [
          {
            "height": 2,
            "kind": "fast_enact",
            "position": 5,
            "role": "Primary",
            "round_closes_at_ms": 1808000,
            "round_opened_at_ms": 8000,
            "time_ms": 8000
          },
          {
            "certificate_id": "0x4343434343434343434343434343434343434343434343434343434343434343",
            "effect_hash": "0x4545454545454545454545454545454545454545454545454545454545454545",
            "kind": "parliament_resume",
            "s0": {
              "height": 1,
              "position": 99,
              "timestamp_ms": 1000
            },
            "time_ms": 8000
          }
        ],
        "panel_seats": 9
      }
    },
    {
      "category": "state",
      "description": "A ballot opened at position 2 cannot lift a pause enacted at position 5 of that same block.",
      "id": "same_block_open_2_enact_5",
      "inputs": {
        "activation": "Bidirectional",
        "operations": [
          {
            "height": 2,
            "kind": "fast_enact",
            "position": 5,
            "role": "Primary",
            "round_closes_at_ms": 1808000,
            "round_opened_at_ms": 8000,
            "time_ms": 8000
          },
          {
            "certificate_id": "0x4343434343434343434343434343434343434343434343434343434343434343",
            "effect_hash": "0x4545454545454545454545454545454545454545454545454545454545454545",
            "kind": "parliament_resume",
            "s0": {
              "height": 2,
              "position": 2,
              "timestamp_ms": 1000
            },
            "time_ms": 8000
          }
        ],
        "panel_seats": 9
      }
    },
    {
      "category": "state",
      "description": "Parliament pauses, a resume ballot opens, fast pause enacts, and that older resume leaves the Taira part holding settlement.",
      "id": "older_resume_keeps_settlement_held",
      "inputs": {
        "activation": "Bidirectional",
        "operations": [
          {
            "certificate_id": "0x4343434343434343434343434343434343434343434343434343434343434343",
            "effect_hash": "0x4545454545454545454545454545454545454545454545454545454545454545",
            "kind": "parliament_pause",
            "s0": {
              "height": 1,
              "position": 0,
              "timestamp_ms": 1000
            },
            "time_ms": 8000
          },
          {
            "height": 2,
            "kind": "fast_enact",
            "position": 5,
            "role": "Primary",
            "round_closes_at_ms": 1808000,
            "round_opened_at_ms": 8000,
            "time_ms": 8000
          },
          {
            "certificate_id": "0x4343434343434343434343434343434343434343434343434343434343434343",
            "effect_hash": "0x4545454545454545454545454545454545454545454545454545454545454545",
            "kind": "parliament_resume",
            "s0": {
              "height": 2,
              "position": 2,
              "timestamp_ms": 1000
            },
            "time_ms": 8000
          }
        ],
        "panel_seats": 9
      }
    },
    {
      "category": "state",
      "description": "The common Taira hold predicate holds settlement and refunds even for InboundOnly.",
      "id": "inbound_only_settlement_and_refunds_held",
      "inputs": {
        "activation": "InboundOnly",
        "operations": [
          {
            "height": 2,
            "kind": "fast_enact",
            "position": 5,
            "role": "Primary",
            "round_closes_at_ms": 1808000,
            "round_opened_at_ms": 8000,
            "time_ms": 8000
          }
        ],
        "panel_seats": 9
      }
    },
    {
      "category": "state",
      "description": "A renewal opens exactly at until minus renew lead and enacts before lapse; an s0 between enactments cannot lift the renewed hold.",
      "id": "renew_at_lead_then_old_lift",
      "inputs": {
        "activation": "Bidirectional",
        "operations": [
          {
            "height": 2,
            "kind": "fast_enact",
            "position": 5,
            "role": "Primary",
            "round_closes_at_ms": 1808000,
            "round_opened_at_ms": 8000,
            "time_ms": 8000
          },
          {
            "height": 3,
            "kind": "fast_enact",
            "position": 5,
            "role": "Primary",
            "round_closes_at_ms": 779408000,
            "round_opened_at_ms": 777608000,
            "time_ms": 777608000
          },
          {
            "certificate_id": "0x4343434343434343434343434343434343434343434343434343434343434343",
            "effect_hash": "0x4545454545454545454545454545454545454545454545454545454545454545",
            "kind": "parliament_resume",
            "s0": {
              "height": 2,
              "position": 6,
              "timestamp_ms": 1000
            },
            "time_ms": 777608000
          }
        ],
        "panel_seats": 9
      }
    },
    {
      "category": "state",
      "description": "Three primary members remain silent; a quorate backup effect deletes both panel rounds.",
      "id": "backup_decides_deletes_both_rounds",
      "inputs": {
        "activation": "Bidirectional",
        "operations": [
          {
            "kind": "seed_rounds",
            "time_ms": 8000
          },
          {
            "height": 2,
            "kind": "fast_enact",
            "position": 5,
            "role": "Backup",
            "round_closes_at_ms": 1808000,
            "round_opened_at_ms": 8000,
            "time_ms": 8000
          }
        ],
        "panel_seats": 5
      }
    },
    {
      "category": "state",
      "description": "Authenticated suspension duration starts at its own enactment and preserves existing pause parts.",
      "id": "suspension_counts_from_enactment",
      "inputs": {
        "activation": "Bidirectional",
        "operations": [
          {
            "height": 2,
            "kind": "fast_enact",
            "position": 5,
            "role": "Primary",
            "round_closes_at_ms": 1808000,
            "round_opened_at_ms": 8000,
            "time_ms": 8000
          },
          {
            "certificate_id": "0x4343434343434343434343434343434343434343434343434343434343434343",
            "duration_ms": 30000,
            "effect_hash": "0x4545454545454545454545454545454545454545454545454545454545454545",
            "kind": "suspend",
            "s0": {
              "height": 1,
              "position": 0,
              "timestamp_ms": 1000
            },
            "time_ms": 9000
          }
        ],
        "panel_seats": 9
      }
    },
    {
      "category": "certification",
      "description": "Quorum is insufficient once the first post-halt block is at or after closes_at_ms.",
      "id": "quorum_next_block_after_close",
      "inputs": {
        "closes": 9000,
        "eligible": 134217727,
        "endorsers": [
          0,
          1,
          2,
          3,
          4,
          5
        ],
        "head": 0,
        "panel_seats": 9,
        "panel_seq": 1,
        "role": "Primary",
        "round_head": 0,
        "round_seq": 1,
        "suspended_until": 0,
        "time": 9001
      }
    },
    {
      "category": "certification",
      "description": "An eligibility observation after an earlier Parliament suspension no longer counts that citizen.",
      "id": "endorser_suspended_earlier_same_pass",
      "inputs": {
        "closes": 9000,
        "eligible": 134217726,
        "endorsers": [
          0,
          1,
          2,
          3,
          4,
          5
        ],
        "head": 0,
        "panel_seats": 9,
        "panel_seq": 1,
        "role": "Primary",
        "round_head": 0,
        "round_seq": 1,
        "suspended_until": 0,
        "time": 8000
      }
    },
    {
      "category": "certification",
      "description": "An earlier authenticated SetFastPauseSuspended enactment makes this round NoResult.",
      "id": "fast_pause_suspended_earlier_same_pass",
      "inputs": {
        "closes": 9000,
        "eligible": 134217727,
        "endorsers": [
          0,
          1,
          2,
          3,
          4,
          5
        ],
        "head": 0,
        "panel_seats": 9,
        "panel_seq": 1,
        "role": "Primary",
        "round_head": 0,
        "round_seq": 1,
        "suspended_until": 38000,
        "time": 8000
      }
    },
    {
      "category": "certification",
      "description": "A replacement draw invalidates the original panel sequence.",
      "id": "new_draw_between_quorum_and_certification",
      "inputs": {
        "closes": 9000,
        "eligible": 134217727,
        "endorsers": [
          0,
          1,
          2,
          3,
          4,
          5
        ],
        "head": 0,
        "panel_seats": 9,
        "panel_seq": 2,
        "role": "Primary",
        "round_head": 0,
        "round_seq": 1,
        "suspended_until": 0,
        "time": 8000
      }
    },
    {
      "category": "certification",
      "description": "An endorsement of the previous FastHold head cannot certify after another enactment.",
      "id": "stale_fast_hold_head",
      "inputs": {
        "closes": 9000,
        "eligible": 134217727,
        "endorsers": [
          0,
          1,
          2,
          3,
          4,
          5
        ],
        "head": 1,
        "panel_seats": 9,
        "panel_seq": 1,
        "role": "Primary",
        "round_head": 0,
        "round_seq": 1,
        "suspended_until": 0,
        "time": 8000
      }
    },
    {
      "category": "certification",
      "description": "Three silent primary members of a five-seat panel leave fewer than the four required endorsements.",
      "id": "primary_three_silent",
      "inputs": {
        "closes": 9000,
        "eligible": 134217727,
        "endorsers": [
          0,
          1
        ],
        "head": 0,
        "panel_seats": 5,
        "panel_seq": 1,
        "role": "Primary",
        "round_head": 0,
        "round_seq": 1,
        "suspended_until": 0,
        "time": 8000
      }
    },
    {
      "category": "certification",
      "description": "Four backup members of a five-seat panel independently reach quorum while three primaries are silent.",
      "id": "backup_quorum",
      "inputs": {
        "closes": 9000,
        "eligible": 134217727,
        "endorsers": [
          5,
          6,
          7,
          8
        ],
        "head": 0,
        "panel_seats": 5,
        "panel_seq": 1,
        "role": "Backup",
        "round_head": 0,
        "round_seq": 1,
        "suspended_until": 0,
        "time": 8000
      }
    },
    {
      "category": "seats",
      "description": "Original draw indices are identities; replacement consumes accepted eligible reserves once, primary then backup.",
      "id": "seat_replacement_at_deadline",
      "inputs": {
        "accept_until_ms": 2000,
        "accepted": [
          1,
          9,
          18,
          19,
          20,
          21,
          22,
          23,
          24,
          25,
          26
        ],
        "drawn_count": 27,
        "eligible": 133693439,
        "member": 18,
        "time_ms": 2000
      }
    },
    {
      "category": "seats",
      "description": "Original draw indices are identities; replacement consumes accepted eligible reserves once, primary then backup.",
      "id": "reserve_exhaustion",
      "inputs": {
        "accept_until_ms": 2000,
        "accepted": [
          18
        ],
        "drawn_count": 27,
        "eligible": 134217727,
        "member": 18,
        "time_ms": 2000
      }
    },
    {
      "category": "seats",
      "description": "Original draw indices are identities; replacement consumes accepted eligible reserves once, primary then backup.",
      "id": "reserve_premature_endorsement",
      "inputs": {
        "accept_until_ms": 2000,
        "accepted": [
          18
        ],
        "drawn_count": 27,
        "eligible": 134217727,
        "member": 18,
        "time_ms": 1999
      }
    },
    {
      "category": "endorsement",
      "description": "Member and duplicate checks consume a previously authenticated eligibility observation; no observation is synthesized in production.",
      "id": "non_member_endorsement",
      "inputs": {
        "existing_endorsers": [],
        "member": 27
      }
    },
    {
      "category": "endorsement",
      "description": "Member and duplicate checks consume a previously authenticated eligibility observation; no observation is synthesized in production.",
      "id": "duplicate_endorsement",
      "inputs": {
        "existing_endorsers": [
          0
        ],
        "member": 0
      }
    },
    {
      "category": "endorsement",
      "description": "Member and duplicate checks consume a previously authenticated eligibility observation; no observation is synthesized in production.",
      "id": "member_first_endorsement",
      "inputs": {
        "existing_endorsers": [],
        "member": 0
      }
    },
    {
      "category": "renewal",
      "description": "Renewal opens at the exact lead boundary, with no empty block required.",
      "id": "renewal_boundary_before",
      "inputs": {
        "time_ms": 777607999,
        "until_ms": 864008000
      }
    },
    {
      "category": "renewal",
      "description": "Renewal opens at the exact lead boundary, with no empty block required.",
      "id": "renewal_boundary_at",
      "inputs": {
        "time_ms": 777608000,
        "until_ms": 864008000
      }
    },
    {
      "category": "boundary",
      "description": "Current public draw and eligibility producers refuse; seeded component facts confer no authority.",
      "id": "parliament_authority_unavailable",
      "inputs": {
        "panel_seq": 1
      }
    }
  ],
  "schema": "iroha.sccp.fast_pause.v1"
}"#).unwrap()
}

fn bytes32(v: &Value, key: &str) -> [u8; 32] {
    let text = string(v, key).strip_prefix("0x").unwrap();
    let mut bytes = [0; 32];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[index * 2..index * 2 + 2], 16).unwrap();
    }
    bytes
}
fn control_expected(
    row: &Value,
    fields: &ControlLeafV1,
    leaf: [u8; 32],
    network: SccpNetworkV1,
) -> Value {
    use iroha_crypto::{
        Algorithm, KeyPair,
        bls::consensus::{aggregate, sign_preimage},
    };
    use iroha_sccp::v1::{
        committee::committee_root,
        destination::{
            BlockRefV1, CertificateSourceV1, ControlProofV1, DeploymentV1, Destination,
            DestinationFlavor, TairaCertificateV1,
        },
        finality::{
            FLAG_ACTIVE, QcFixedV1, SccpFinalityHeaderFieldsV1, SccpFinalityHeaderV1,
            commit_preimage, outer_result,
        },
        hashes::history_leaf,
    };
    let mut pairs = (1..=4)
        .map(|i| KeyPair::try_from_seed(vec![i; 32], Algorithm::BlsNormal).unwrap())
        .collect::<Vec<_>>();
    pairs.sort_by_key(|p| <[u8; 48]>::try_from(p.public_key().try_to_bytes().unwrap().1).unwrap());
    let keys: Vec<[u8; 48]> = pairs
        .iter()
        .map(|p| p.public_key().try_to_bytes().unwrap().1.try_into().unwrap())
        .collect();
    let root = committee_root(&keys).unwrap();
    let network_id = bytes32(row, "network_id");
    let now = number(row, "now_ms");
    let header = SccpFinalityHeaderV1::from_fields(&SccpFinalityHeaderFieldsV1 {
        network_id,
        height: 1,
        timestamp_ms: now,
        flags: FLAG_ACTIVE,
        message_count: 1,
        sccp_root: leaf,
        history_size: 1,
        history_root: history_leaf(1, &leaf, 1),
        generation: 1,
        committee_root: root,
        ..SccpFinalityHeaderFieldsV1::default()
    })
    .unwrap();
    let qc = QcFixedV1 {
        epoch: 1,
        epoch_context: [0x31; 32],
        view: 0,
        block_hash: [0x32; 32],
        result_body: [0x33; 32],
        signers: 7,
    };
    let result = outer_result(&header, &qc.result_body);
    let preimage = commit_preimage(&[0x77; 32], &qc, 1, &result.0);
    let signature = aggregate(
        pairs[..3]
            .iter()
            .map(|p| sign_preimage(p.private_key(), &preimage).unwrap()),
    )
    .unwrap();
    let certificate = TairaCertificateV1::new(&qc, &header, &signature, &keys).unwrap();
    let flavor = if network == SccpNetworkV1::TonMainnet {
        DestinationFlavor::Ton
    } else {
        DestinationFlavor::Evm
    };
    let mut destination = Destination::new(DeploymentV1 {
        flavor,
        taira_network_id: network_id,
        consensus_instance: [0x77; 32],
        network,
        destination_word: bytes32(row, "destination_word"),
        route_revision: 1,
        max_wrapped_supply: 1_000_000,
        pin_generation: 1,
        pin_root: root,
        pin_start_height: 1,
        pin_until_ms: now + 1_000_000,
        pin_keys: Some(keys),
    })
    .unwrap();
    let proof = ControlProofV1 {
        control_nonce: fields.control_nonce,
        track: fields.track,
        parliament_paused: fields.parliament_paused,
        fast_pause_until_ms: fields.fast_pause_until_ms,
        certificate_id: fields.certificate_id,
        effect_hash: fields.effect_hash,
        leaf_index: 0,
        path: Vec::new(),
        block: BlockRefV1 {
            height: 1,
            sccp_root: leaf,
            message_count: 1,
            history_index: 0,
            history_path: Vec::new(),
        },
    };
    if number(row, "previous_control_nonce") != 0 {
        assert_eq!(number(row, "previous_control_nonce"), fields.control_nonce);
        destination
            .apply_control(CertificateSourceV1::Inline(&certificate), &proof, now)
            .unwrap();
    }
    let outcome =
        match destination.apply_control(CertificateSourceV1::Inline(&certificate), &proof, now) {
            Ok(_) => "Applied".to_owned(),
            Err(error) => format!("{error:?}"),
        };
    json!({"outcome":outcome,"applied_until_ms":(destination.state().fast_pause_until_ms),"minting_paused":(destination.minting_paused(now))})
}
fn build() -> Value {
    let mut document = inputs();
    for row in document.get_mut("rows").unwrap().as_array_mut().unwrap() {
        let derived = expected(row);
        row.as_object_mut()
            .unwrap()
            .insert("expected".into(), derived);
    }
    for row in document
        .get_mut("controls")
        .unwrap()
        .as_array_mut()
        .unwrap()
    {
        let f = &row["fields"];
        let fields = ControlLeafV1 {
            route_revision: number(f, "route_revision") as u32,
            control_nonce: number(f, "control_nonce"),
            track: number(f, "track") as u8,
            parliament_paused: number(f, "parliament_paused") as u8,
            fast_pause_until_ms: number(f, "fast_pause_until_ms"),
            certificate_id: bytes32(f, "certificate_id"),
            effect_hash: bytes32(f, "effect_hash"),
        };
        let network = if string(row, "network") == "ton-mainnet" {
            SccpNetworkV1::TonMainnet
        } else {
            SccpNetworkV1::EthereumMainnet
        };
        let leaf = control_leaf(
            &bytes32(row, "network_id"),
            network,
            &bytes32(row, "destination_word"),
            &fields,
        )
        .unwrap();
        let preimage = control_leaf_preimage(
            &bytes32(row, "network_id"),
            network,
            &bytes32(row, "destination_word"),
            &fields,
        )
        .unwrap();
        let expected = control_expected(row, &fields, leaf, network);
        let map = row.as_object_mut().unwrap();
        map.insert("leaf".into(), json!(hex(&leaf)));
        map.insert("preimage".into(), json!(hex(&preimage)));
        map.insert("expected".into(), expected);
    }
    document
}
fn path() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/sccp/fast_pause_v1.json")
}
#[test]
fn reference_fast_pause_v1_matches_committed_fixture() {
    let generated = build();
    let committed = std::fs::read_to_string(path()).unwrap();
    let parsed: Value = norito::json::from_str(&committed).unwrap();
    assert_eq!(python_json::first_difference(&generated, &parsed), None);
    assert_eq!(python_json::render(&generated), committed);
}
#[test]
#[ignore = "explicit shared fixture regeneration"]
fn regenerate_fast_pause_v1() {
    std::fs::write(path(), python_json::render(&build())).unwrap();
}
