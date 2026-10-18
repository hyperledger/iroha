//! Browser kernels generated from the compiled native arithmetic relation.

use super::{
    race::{
        RaceSimulationErrorV1, apply_race_dnf_v1, initial_race_state_v1, race_result_v1,
        step_race_v1,
    },
    race_air::{FIXED_PREFIX, RaceAirV1},
};
use iroha_data_model::execution_proofs::{RaceInputFrameV1, RaceReplayV1, RaceTrackV1};
use sha2::{Digest, Sha256};
use std::fmt::Write as _;

/// Export the closed `RaceV1` track/player catalog as an integer-only JSON program.
///
/// This is a presentation runtime export, not an installable verifier program. Native proof
/// admission always selects a compiled, immutable relation. All arithmetic is within 2^50,
/// allowing exact JavaScript integer evaluation without 32-bit bitwise coercions.
#[must_use]
pub fn export_race_kernels_json_v1() -> String {
    let sources = [
        ("race.rs", include_bytes!("race.rs").as_slice()),
        (
            "environment.rs",
            include_bytes!("environment.rs").as_slice(),
        ),
        (
            "environment_air.rs",
            include_bytes!("environment_air.rs").as_slice(),
        ),
        (
            "integer_air.rs",
            include_bytes!("integer_air.rs").as_slice(),
        ),
        ("race_air.rs", include_bytes!("race_air.rs").as_slice()),
    ];
    let mut output = String::from("{\"version\":1,\"sources\":{");
    for (index, (name, bytes)) in sources.iter().enumerate() {
        if index != 0 {
            output.push(',');
        }
        write!(output, "\"{name}\":\"{:x}\"", Sha256::digest(bytes)).expect("string write");
    }
    let profile_sources = super::proof::RACE_PROFILE_SOURCES_V1
        .iter()
        .map(|(name, bytes)| ((*name).to_owned(), format!("{:x}", Sha256::digest(bytes))))
        .collect::<std::collections::BTreeMap<_, _>>();
    let environment = [RaceTrackV1::NeonTokyo, RaceTrackV1::Harbor, RaceTrackV1::Sakura].into_iter().map(|track| {
        use super::environment as env;
        norito::json!({"length_mm":(track.length_mm()),"centers":(env::centers(track).to_vec()),"kinds":(env::kinds(track).to_vec()),"laterals":(env::laterals(track).to_vec()),"rain_pattern":(env::rain_pattern(track).to_vec()),"wind_pattern":(env::WIND_PATTERN.to_vec()),"rain_ticks":(env::WEATHER_TICKS),"wind_ticks":(env::WIND_TICKS),"wind_strength":(env::wind_strength(track)),"oil_half_length":(env::OIL_HALF_LENGTH),"oil_half_width":(env::OIL_HALF_WIDTH),"tree_radius":1400,"sign_radius":1300,"tree_speed_loss":600,"sign_speed_loss":260,"tree_push":1800})
    }).collect::<Vec<_>>();
    write!(
        output,
        "}},\"rules_hash\":\"{}\",\"profile_id\":\"{}\",\"profile_sources\":{},\"fixed_prefix\":{FIXED_PREFIX},\"environment\":{},\"kernels\":[",
        super::race_rules_hash_v1(), super::race_profile_id_v1(),
        norito::json::to_json(&profile_sources).expect("native verifier source inventory"),
        norito::json::to_json(&environment).expect("native environment catalog")
    )
    .expect("string write");
    let mut first = true;
    for (track_id, track) in [
        RaceTrackV1::NeonTokyo,
        RaceTrackV1::Harbor,
        RaceTrackV1::Sakura,
    ]
    .into_iter()
    .enumerate()
    {
        for players in 2..=8 {
            if !first {
                output.push(',');
            }
            first = false;
            let mut replay = RaceReplayV1 {
                track,
                player_count: players,
                frames: vec![],
                dnf_events: vec![],
            };
            let initial = initial_race_state_v1(track, players).expect("compiled catalog");
            let compiled = RaceAirV1::compile(&replay, &initial, None);
            let (nodes, outputs) = compiled.air.export_graph(
                &compiled
                    .outputs
                    .iter()
                    .flatten()
                    .chain(compiled.events.iter().flatten())
                    .copied()
                    .collect::<Vec<_>>(),
            );
            let events = &outputs[7 * usize::from(players)..];
            let outputs = &outputs[..7 * usize::from(players)];
            let control_table = (0..64)
                .map(|control| {
                    replay.frames = vec![RaceInputFrameV1 {
                        tick: 0,
                        controls: vec![control; usize::from(players)],
                    }];
                    let fixed = RaceAirV1::fixed_row(&replay, 0, 2, None);
                    [
                        fixed[FIXED_PREFIX],
                        fixed[FIXED_PREFIX + 1],
                        fixed[FIXED_PREFIX + 2],
                    ]
                })
                .collect::<Vec<_>>();
            write!(output,"{{\"track\":{track_id},\"player_count\":{players},\"input_count\":{},\"fixed_count\":{},\"control_table\":{control_table:?},\"nodes\":{nodes:?},\"outputs\":{outputs:?},\"events\":{events:?}}}",7*usize::from(players),FIXED_PREFIX+4*usize::from(players)).expect("string write");
        }
    }
    output.push_str("]}\n");
    output
}

/// Generate all 21 native reference transcripts, snapshots and terminal outcomes for browser parity.
///
/// Inputs intentionally cause early contacts, drift, boost exhaustion and consensus removals.
/// Eight-car cases continue to the 5,400-tick bound; smaller grids end in technical wins.
/// Snapshots include current-boundary removals before that tick's controls are applied.
///
/// # Errors
/// Returns the native simulation error if this fixed qualification corpus is no longer admissible.
pub fn export_race_parity_json_v1() -> Result<norito::json::Value, RaceSimulationErrorV1> {
    use norito::json;
    let mut fixtures = Vec::new();
    for (track_id, track) in [
        RaceTrackV1::NeonTokyo,
        RaceTrackV1::Harbor,
        RaceTrackV1::Sakura,
    ]
    .into_iter()
    .enumerate()
    {
        for players in 2..=8 {
            let mut state = initial_race_state_v1(track, players)?;
            let mut inputs = Vec::new();
            let mut checkpoints = Vec::new();
            let mut dnf_events = Vec::new();
            loop {
                let removed = match (players, state.tick) {
                    (2 | 8, 1200) | (3..=7, 300) => vec![players - 1],
                    (3..=7, 600) => (1..players - 1).collect(),
                    _ => vec![],
                };
                if !removed.is_empty() {
                    apply_race_dnf_v1(&mut state, &removed)?;
                    dnf_events.push(json!({"tick":(state.tick),"slots":removed}));
                }
                let terminal = state.tick == 5400
                    || state.tick % 6 == 0
                        && (state
                            .cars
                            .iter()
                            .all(|car| car.finish_tick.is_some() || car.dnf_tick.is_some())
                            || state
                                .cars
                                .iter()
                                .filter(|car| car.dnf_tick.is_none())
                                .count()
                                < 2);
                if state.tick % 300 == 0 || [1, 6, 30, 60, 90].contains(&state.tick) || terminal {
                    let cars = state.cars.iter().map(|car| json!({
                        "progress_mm":(car.progress_mm),"lateral_mm":(car.lateral_mm),
                        "speed_mm_per_tick":(car.speed_mm_per_tick),"lateral_velocity_mm_per_tick":(car.lateral_velocity_mm_per_tick),
                        "boost_energy":(car.boost_energy),"finish_tick":(car.finish_tick),"dnf_tick":(car.dnf_tick),
                    })).collect::<Vec<_>>();
                    checkpoints.push(json!({"tick":(state.tick),"cars":cars}));
                }
                if terminal {
                    break;
                }
                let controls = state
                    .cars
                    .iter()
                    .enumerate()
                    .map(|(slot, car)| {
                        if car.dnf_tick.is_some() {
                            return 0;
                        }
                        let target = if slot % 2 == 0 { -1600 } else { 1600 };
                        let steer = if state.tick < 90 {
                            if slot % 2 == 0 { 8 } else { 4 }
                        } else if car.lateral_mm + car.lateral_velocity_mm_per_tick * 8
                            > target + 150
                        {
                            4
                        } else if car.lateral_mm + car.lateral_velocity_mm_per_tick * 8
                            < target - 150
                        {
                            8
                        } else {
                            0
                        };
                        1 | 16
                            | steer
                            | if (state.tick + slot as u32 * 11) % 90 < 25 {
                                32
                            } else {
                                0
                            }
                    })
                    .collect::<Vec<u16>>();
                let frame = RaceInputFrameV1 {
                    tick: (state.tick),
                    controls: controls.clone(),
                };
                inputs.push(controls);
                step_race_v1(&mut state, &frame)?;
            }
            let result = race_result_v1(&state)?;
            let standings = result.standings.iter().map(|car| json!({
                "slot":(car.slot),"finish_tick":(car.finish_tick),"dnf_tick":(car.dnf_tick),"progress_mm":(car.progress_mm),
            })).collect::<Vec<_>>();
            fixtures.push(json!({
                "trackId":track_id,"players":players,"inputs":inputs,"checkpoints":checkpoints,"dnfEvents":dnf_events,
                "result":{"ticks":(result.ticks),"standings":standings,"winners":(result.winners)},
            }));
        }
    }
    Ok(json!({
        "rulesHash":(super::race_rules_hash_v1().to_string()),
        "generator":"Native Iroha RaceV1 reference, canonical in-tree export; snapshots after current-tick consensus DNF phase before controls",
        "kernelSha256":(format!("{:x}",Sha256::digest(include_bytes!("race.rs")))),
        "fixtures":fixtures,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn complete_closed_catalog_exports_valid_json() {
        let text = export_race_kernels_json_v1();
        let json: norito::json::Value = norito::json::from_str(&text).expect("JSON export");
        assert_eq!(
            json.get("kernels")
                .and_then(norito::json::Value::as_array)
                .expect("kernels")
                .len(),
            21
        );
        let profile_sources = json
            .get("profile_sources")
            .and_then(norito::json::Value::as_object)
            .expect("complete verifier provenance");
        assert_eq!(
            profile_sources.len(),
            super::super::proof::RACE_PROFILE_SOURCES_V1.len()
        );
        for (name, bytes) in super::super::proof::RACE_PROFILE_SOURCES_V1 {
            assert_eq!(
                profile_sources
                    .get(*name)
                    .and_then(norito::json::Value::as_str),
                Some(format!("{:x}", Sha256::digest(bytes)).as_str()),
                "profile source {name} must come from the actual committed inventory",
            );
        }
    }
    #[test]
    fn native_reference_corpus_covers_every_grid_and_full_duration() {
        let value = export_race_parity_json_v1().expect("native reference export");
        let fixtures = value.get("fixtures").unwrap().as_array().unwrap();
        assert_eq!(fixtures.len(), 21);
        for fixture in fixtures {
            let players = fixture.get("players").unwrap().as_u64().unwrap();
            let inputs = fixture.get("inputs").unwrap().as_array().unwrap();
            assert_eq!(
                inputs.len(),
                if players == 8 {
                    5400
                } else if players == 2 {
                    1200
                } else {
                    600
                }
            );
            assert!(
                fixture
                    .get("result")
                    .unwrap()
                    .get("winners")
                    .unwrap()
                    .as_array()
                    .is_some_and(|slots| !slots.is_empty())
            );
        }
    }
}
