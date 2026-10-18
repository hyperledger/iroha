//! Browser programs sliced from the compiled Touring S1 whole-tick arithmetic relation.
//!
//! This export installs no verifier and makes no profile-admission or security claim. State
//! outputs come from the native relation; contact outputs retain its exact pre-movement object
//! predicates. The browser must select the distinct class, rules and profile identities together.

use super::super::integer_air::{Source, Value};
use super::{
    admission::classed_race_rules_hash_v1,
    environment as env,
    proof::{CLASSED_RACE_PROFILE_SOURCES_V1, classed_race_profile_id_v1},
    race_air::{ClassedRaceAirV1, FIXED_PER_CAR, FIXED_PREFIX, STATE_WIDTH, car_values},
    reference::{
        ClassedRaceSimulationErrorV1, apply_classed_race_dnf_v1, classed_race_is_terminal_v1,
        classed_race_result_v1, initial_classed_race_state_v1, replay_classed_race_v1,
        step_classed_race_v1,
    },
    rules::{
        BATCH_TICKS, LAPS, MAX_TICKS, class_performance_v1, classed_track_curvature_v1,
        classed_track_length_v1,
    },
};
use iroha_data_model::classed_race_v1::{
    ClassedRaceClassV1, ClassedRaceInputFrameV1, ClassedRaceReplayV1, ClassedRaceStateV1,
    ClassedRaceTrackV1,
};
use norito::{json, json::Value as Json};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

const CLASS: ClassedRaceClassV1 = ClassedRaceClassV1::TouringS1;
const TRACKS: [ClassedRaceTrackV1; 3] = [
    ClassedRaceTrackV1::NeonTokyo,
    ClassedRaceTrackV1::Harbor,
    ClassedRaceTrackV1::Sakura,
];

fn source_hashes() -> BTreeMap<&'static str, String> {
    [
        ("reference.rs", include_bytes!("reference.rs").as_slice()),
        ("rules.rs", include_bytes!("rules.rs").as_slice()),
        (
            "environment.rs",
            include_bytes!("environment.rs").as_slice(),
        ),
        (
            "environment_air.rs",
            include_bytes!("environment_air.rs").as_slice(),
        ),
        ("race_air.rs", include_bytes!("race_air.rs").as_slice()),
        (
            "integer_air.rs",
            include_bytes!("../integer_air.rs").as_slice(),
        ),
    ]
    .into_iter()
    .map(|(name, bytes)| (name, format!("{:x}", Sha256::digest(bytes))))
    .collect()
}

fn grid_graph(
    track: ClassedRaceTrackV1,
    players: u8,
) -> Result<ClassedRaceAirV1, ClassedRaceSimulationErrorV1> {
    // The public fixed-row producer, rather than a second control decoder, supplies all 64
    // table rows. The backward slice drops first/final/checkpoint constraint-only witnesses.
    let replay = ClassedRaceReplayV1 {
        version: 1,
        class_id: CLASS,
        track,
        player_count: players,
        frames: (0_u16..64)
            .map(|control| ClassedRaceInputFrameV1 {
                tick: u32::from(control),
                controls: vec![control; usize::from(players)],
            })
            .collect(),
        dnf_events: vec![],
    };
    let final_state = replay_classed_race_v1(&replay)?;
    ClassedRaceAirV1::compile(&replay, &final_state, None)
}

fn controls_table(graph: &ClassedRaceAirV1) -> Result<Vec<[i64; 3]>, ClassedRaceSimulationErrorV1> {
    (0..64)
        .map(|control| {
            let fixed = graph.fixed_row(control, 128)?;
            Ok([
                fixed[FIXED_PREFIX],
                fixed[FIXED_PREFIX + 1],
                fixed[FIXED_PREFIX + 2],
            ])
        })
        .collect()
}

fn environment_catalog() -> Vec<Json> {
    TRACKS
        .into_iter()
        .map(|track| {
            json!({
                "length_mm": (classed_track_length_v1(track)),
                "curvature": (classed_track_curvature_v1(track).to_vec()),
                "centers": (env::centers(track).to_vec()), "kinds": (env::kinds(track).to_vec()),
                "laterals": (env::laterals(track).to_vec()),
                "rain_pattern": (env::rain_pattern(track).to_vec()),
                "wind_pattern": (env::WIND_PATTERN.to_vec()),
                "rain_ticks": (env::WEATHER_TICKS), "wind_ticks": (env::WIND_TICKS),
                "wind_strength": (env::wind_strength(track)),
                "oil_half_length": (env::OIL_HALF_LENGTH), "oil_half_width": (env::OIL_HALF_WIDTH),
                "tree_radius": 1400, "sign_radius": 1300,
                "tree_speed_loss": 600, "sign_speed_loss": 260, "tree_push": 1800,
            })
        })
        .collect()
}

/// Export all three tracks and all two-to-eight-player Touring S1 grids.
///
/// Nodes use the native integer export's opcodes 0..8 and operand kinds 0..3. Values remain
/// strictly inside 2^50, so JavaScript evaluates them exactly using Number arithmetic, truncating
/// division, and no 32-bit bitwise coercions. State fields use the native seven-column order.
/// `events` contains `[running && oil, running && solid_hit, kind]` per permanent slot; kind is
/// inspected only when a contact predicate is true. `initial_inputs` is the exact native grid.
///
/// # Errors
/// Returns a native simulation error if the closed class/grid control corpus becomes invalid.
pub fn export_classed_race_kernels_json_v1() -> Result<Json, ClassedRaceSimulationErrorV1> {
    let mut kernels = Vec::new();
    for (track_id, track) in TRACKS.into_iter().enumerate() {
        for players in 2..=8 {
            let graph = grid_graph(track, players)?;
            let (nodes, output_refs) = graph.air.export_graph(
                &graph
                    .outputs
                    .iter()
                    .flatten()
                    .chain(graph.events.iter().flatten())
                    .copied()
                    .collect::<Vec<_>>(),
            );
            let state_end = STATE_WIDTH * usize::from(players);
            let initial = initial_classed_race_state_v1(CLASS, track, players)?;
            kernels.push(json!({
                "track": track_id, "player_count": players,
                "input_count": state_end,
                "fixed_count": (FIXED_PREFIX + FIXED_PER_CAR * usize::from(players)),
                "initial_inputs": (initial.cars.iter().flat_map(car_values).collect::<Vec<_>>()),
                "control_table": (controls_table(&graph)?.iter().map(|row| row.to_vec()).collect::<Vec<_>>()),
                "nodes": nodes, "outputs": (output_refs[..state_end].iter().map(|row| row.to_vec()).collect::<Vec<_>>()),
                "events": (output_refs[state_end..].iter().map(|row| row.to_vec()).collect::<Vec<_>>()),
            }));
        }
    }
    let spec = class_performance_v1(CLASS);
    let profile_sources = CLASSED_RACE_PROFILE_SOURCES_V1
        .iter()
        .map(|(name, bytes)| ((*name).to_owned(), format!("{:x}", Sha256::digest(bytes))))
        .collect::<BTreeMap<_, _>>();
    Ok(json!({
        "version": 1, "computation": "ClassedRaceV1", "class_id": CLASS,
        "rules_hash": (classed_race_rules_hash_v1().to_string()),
        "profile_id": (classed_race_profile_id_v1().to_string()),
        "profile_sources": profile_sources, "sources": (source_hashes()),
        "fixed_prefix": FIXED_PREFIX, "state_width": STATE_WIDTH,
        "max_ticks": MAX_TICKS, "batch_ticks": BATCH_TICKS, "laps": LAPS,
        "performance": {
            "acceleration": (spec.acceleration), "normal_speed": (spec.normal_speed),
            "boost_speed": (spec.boost_speed), "brake": (spec.brake), "coast": (spec.coast),
            "steering": (spec.steering), "drift_steering": (spec.drift_steering),
            "boost_capacity": (spec.boost_capacity), "boost_cost": (spec.boost_cost),
            "boost_recharge": (spec.boost_recharge), "offroad_penalty": (spec.offroad_penalty),
            "contact_penalty": (spec.contact_penalty),
        },
        "environment": (environment_catalog()), "kernels": kernels,
    }))
}

fn snapshot(state: &ClassedRaceStateV1) -> Json {
    json!({"tick": (state.tick), "cars": (state.cars.clone())})
}

fn state_checksum(state: &ClassedRaceStateV1) -> String {
    // An export-only diagnostic checksum, not the ledger's Norito/Poseidon state commitment.
    let mut digest = Sha256::new();
    digest.update(state.tick.to_le_bytes());
    for car in &state.cars {
        for value in car_values(car) {
            digest.update(value.to_le_bytes());
        }
    }
    format!("{:x}", digest.finalize())
}

fn reference_fixture(
    track_id: usize,
    track: ClassedRaceTrackV1,
    players: u8,
) -> Result<Json, ClassedRaceSimulationErrorV1> {
    let mut state = initial_classed_race_state_v1(CLASS, track, players)?;
    let mut inputs = Vec::new();
    let mut checkpoints = Vec::new();
    let mut dnf_events = Vec::new();
    let mut state_hashes = Vec::new();
    loop {
        let removed = match (players, state.tick) {
            (2, 1200) | (3..=7, 300) | (8, 5394) => vec![players - 1],
            (3..=7, 600) => (1..players - 1).collect(),
            _ => vec![],
        };
        if !removed.is_empty() {
            apply_classed_race_dnf_v1(&mut state, &removed)?;
            dnf_events.push(json!({"tick": (state.tick), "slots": removed}));
        }
        let terminal = classed_race_is_terminal_v1(&state)?;
        state_hashes.push(state_checksum(&state));
        if state.tick % 300 == 0 || [1, 6, 30, 60, 90, 5394].contains(&state.tick) || terminal {
            checkpoints.push(snapshot(&state));
        }
        if terminal {
            break;
        }
        let controls = state
            .cars
            .iter()
            .enumerate()
            .map(|(slot, car)| {
                // Two parked eligible keys keep every eight-car corpus at the full duration even
                // if all moving cars finish; the final batch also covers an actual native removal.
                if car.dnf_tick.is_some() || players == 8 && slot >= 6 {
                    return 0;
                }
                let slot = u32::try_from(slot).expect("at most eight car slots fit u32");
                let target = if slot % 2 == 0 { -1600 } else { 1600 };
                let steer = if state.tick < 90 {
                    if slot % 2 == 0 { 8 } else { 4 }
                } else if car.lateral_mm + car.lateral_velocity_mm_per_tick * 8 > target + 150 {
                    4
                } else if car.lateral_mm + car.lateral_velocity_mm_per_tick * 8 < target - 150 {
                    8
                } else {
                    0
                };
                1 | 16
                    | steer
                    | if (state.tick + slot * 11) % 90 < 25 {
                        32
                    } else {
                        0
                    }
            })
            .collect::<Vec<u16>>();
        inputs.push(controls.clone());
        let tick = state.tick;
        step_classed_race_v1(&mut state, &ClassedRaceInputFrameV1 { tick, controls })?;
    }
    Ok(json!({
        "trackId": track_id, "players": players, "inputs": inputs,
        "checkpoints": checkpoints, "dnfEvents": dnf_events, "state_hashes": state_hashes,
        "result": (classed_race_result_v1(&state)?),
    }))
}

fn value_integer(value: Value, row: &[i64], fixed: &[i64]) -> i64 {
    match value.source {
        Source::Column(index) => row[index],
        Source::Constant(value) => value,
        Source::Fixed(index) => fixed[index],
        Source::Next(_) => unreachable!("compiled output cannot reference a future witness"),
    }
}

fn transition_fixture(
    graph: &ClassedRaceAirV1,
    table: &[[i64; 3]],
    name: &str,
    state: &ClassedRaceStateV1,
    control: u16,
) -> Result<Json, ClassedRaceSimulationErrorV1> {
    let mut controls = vec![0; state.cars.len()];
    controls[0] = control;
    let (rain, wind) = env::weather(state.track, state.tick);
    let mut fixed = vec![
        i64::from(state.tick),
        1,
        i64::from(state.tick == 0),
        1,
        0,
        0,
        i64::from(state.tick.is_multiple_of(BATCH_TICKS)),
        rain,
        wind,
    ];
    for &control in &controls {
        fixed.extend(table[usize::from(control)]);
        fixed.push(0);
    }
    let row = graph.air.witness(
        &state.cars.iter().flat_map(car_values).collect::<Vec<_>>(),
        &fixed,
    );
    let mut after = state.clone();
    step_classed_race_v1(
        &mut after,
        &ClassedRaceInputFrameV1 {
            tick: state.tick,
            controls: controls.clone(),
        },
    )?;
    let actual = graph
        .outputs
        .iter()
        .flatten()
        .map(|value| value_integer(*value, &row, &fixed))
        .collect::<Vec<_>>();
    let expected = after.cars.iter().flat_map(car_values).collect::<Vec<_>>();
    if actual != expected {
        return Err(ClassedRaceSimulationErrorV1::StateBounds);
    }
    let events = graph
        .events
        .iter()
        .map(|car| car.map(|value| value_integer(value, &row, &fixed)).to_vec())
        .collect::<Vec<_>>();
    Ok(
        json!({"name": name, "before": state, "controls": controls, "after": after, "events": events}),
    )
}

fn environment_transitions() -> Result<Vec<Json>, ClassedRaceSimulationErrorV1> {
    let mut fixtures = Vec::new();
    for track in TRACKS {
        let graph = grid_graph(track, 8)?;
        let table = controls_table(&graph)?;
        for wet in [0, 1] {
            // Each track supplies both weather states and nonzero wind from its real schedule.
            let tick = (1..1200)
                .find(|tick| {
                    let weather = env::weather(track, *tick);
                    weather.0 == wet && weather.1 != 0
                })
                .ok_or(ClassedRaceSimulationErrorV1::StateBounds)?;
            for cell in 0..12 {
                let center = env::centers(track)[cell];
                let x = env::laterals(track)[cell];
                let kind = env::kinds(track)[cell];
                let radius = if kind == env::TREE { 1400 } else { 1300 };
                let cases = if kind == env::OIL {
                    vec![
                        ("inside", 0, 0, false),
                        ("length-edge", -9000, 0, false),
                        ("outside-length", -9001, 0, false),
                        ("width-edge", 0, 1400, false),
                        ("outside-width", 0, 1401, false),
                        ("inactive", 0, 0, true),
                    ]
                } else {
                    vec![
                        ("crossing", -500, 0, false),
                        ("before-crossing", -4000, 0, false),
                        ("center", 0, 0, false),
                        ("past", 1, 0, false),
                        ("radius-edge", -500, radius, false),
                        ("inactive", -500, 0, true),
                    ]
                };
                for (name, offset, lateral_offset, inactive) in cases {
                    let mut state = initial_classed_race_state_v1(CLASS, track, 8)?;
                    state.tick = tick;
                    let car = &mut state.cars[0];
                    car.progress_mm = center + offset;
                    car.lateral_mm = i32::try_from(x + lateral_offset)
                        .expect("fixed object-edge fixture fits i32");
                    car.speed_mm_per_tick = 2400;
                    car.dnf_tick = inactive.then_some(tick);
                    fixtures.push(transition_fixture(&graph, &table, name, &state, 49)?);
                }
            }
            // Reserved input bits have no export entry; every legal bit combination is exercised
            // against a real native state in each track/weather regime.
            for control in 0..64 {
                let mut state = initial_classed_race_state_v1(CLASS, track, 8)?;
                state.tick = tick;
                state.cars[0].speed_mm_per_tick = 2500;
                state.cars[0].lateral_velocity_mm_per_tick = -319;
                state.cars[0].boost_energy = 24;
                fixtures.push(transition_fixture(
                    &graph,
                    &table,
                    "all-controls-low-energy",
                    &state,
                    control,
                )?);
            }
        }
    }
    Ok(fixtures)
}

/// Export native reference parity for 21 grids, full-duration eight-car races and object edges.
///
/// Every per-tick checksum follows current-boundary DNF application and precedes that tick's
/// controls. It hashes tick as little-endian u32, then seven little-endian i64 values per car in
/// native column order. These checksums are diagnostic, not on-chain state commitments.
/// `transitions` additionally contains full native before/after states and exact AIR event outputs.
///
/// # Errors
/// Returns an error if native reference execution or any whole-tick graph comparison fails.
pub fn export_classed_race_parity_json_v1() -> Result<Json, ClassedRaceSimulationErrorV1> {
    let mut fixtures = Vec::new();
    for (track_id, track) in TRACKS.into_iter().enumerate() {
        for players in 2..=8 {
            fixtures.push(reference_fixture(track_id, track, players)?);
        }
    }
    Ok(json!({
        "version": 1, "computation": "ClassedRaceV1", "class_id": CLASS,
        "rulesHash": (classed_race_rules_hash_v1().to_string()),
        "profileId": (classed_race_profile_id_v1().to_string()),
        "kernelSha256": (format!("{:x}", Sha256::digest(include_bytes!("reference.rs")))),
        "generator": "Native ClassedRaceV1/TouringS1 reference and whole-tick AIR; no stock fallback",
        "fixtures": fixtures, "transitions": (environment_transitions()?),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn closed_classed_export_has_exact_native_source_identity_and_all_grids() {
        let value = export_classed_race_kernels_json_v1().unwrap();
        assert_eq!(value["computation"].as_str(), Some("ClassedRaceV1"));
        assert_eq!(value["fixed_prefix"].as_u64(), Some(9));
        let kernels = value["kernels"].as_array().unwrap();
        assert_eq!(kernels.len(), 21);
        for (index, kernel) in kernels.iter().enumerate() {
            let players = index % 7 + 2;
            assert_eq!(kernel["track"].as_u64(), Some((index / 7) as u64));
            assert_eq!(kernel["player_count"].as_u64(), Some(players as u64));
            assert_eq!(kernel["control_table"].as_array().unwrap().len(), 64);
            assert_eq!(kernel["outputs"].as_array().unwrap().len(), players * 7);
            assert_eq!(kernel["events"].as_array().unwrap().len(), players * 3);
            assert_eq!(
                kernel["initial_inputs"].as_array().unwrap().len(),
                players * 7
            );
        }
        for (name, bytes) in CLASSED_RACE_PROFILE_SOURCES_V1 {
            assert_eq!(
                value["profile_sources"][*name].as_str(),
                Some(format!("{:x}", Sha256::digest(bytes)).as_str())
            );
        }
    }

    #[test]
    fn native_corpus_covers_full_duration_weather_objects_controls_and_inactive_cars() {
        let value = export_classed_race_parity_json_v1().unwrap();
        let fixtures = value["fixtures"].as_array().unwrap();
        assert_eq!(fixtures.len(), 21);
        for fixture in fixtures {
            let players = fixture["players"].as_u64().unwrap();
            let ticks = fixture["inputs"].as_array().unwrap().len();
            assert_eq!(
                ticks,
                if players == 8 {
                    5400
                } else if players == 2 {
                    1200
                } else {
                    600
                }
            );
            assert_eq!(fixture["state_hashes"].as_array().unwrap().len(), ticks + 1);
            assert_eq!(fixture["result"]["terminal"].as_bool(), Some(true));
        }
        let transitions = value["transitions"].as_array().unwrap();
        assert_eq!(transitions.len(), 3 * 2 * (12 * 6 + 64));
        let mut seen = [false; 3];
        for fixture in transitions {
            let event = fixture["events"].as_array().unwrap()[0].as_array().unwrap();
            if fixture["name"].as_str() == Some("inactive") {
                assert_eq!(event[0].as_i64(), Some(0));
                assert_eq!(event[1].as_i64(), Some(0));
            }
            if event[0].as_i64() == Some(1) || event[1].as_i64() == Some(1) {
                seen[usize::try_from(event[2].as_u64().unwrap()).unwrap()] = true;
            }
        }
        assert_eq!(seen, [true; 3]);
    }
}
