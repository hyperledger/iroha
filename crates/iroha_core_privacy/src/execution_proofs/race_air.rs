//! Complete `RaceV1` integer transition relation for the native transparent proof driver.

#[cfg(test)]
use super::integer_air::Source;
use super::{
    integer_air::{IntegerAirV1, Value},
    race::initial_race_state_v1,
};
use iroha_data_model::execution_proofs::{RaceCarStateV1, RaceReplayV1, RaceStateV1};

pub(super) const FIXED_PREFIX: usize = 9;
pub(super) const FIXED_PER_CAR: usize = 4;
pub(super) const STATE_WIDTH: usize = 7;

/// Closed transition graph; one row contains one complete tick, including ordered contacts.
pub(super) struct RaceAirV1 {
    pub(super) air: IntegerAirV1,
    pub(super) outputs: Vec<[Value; STATE_WIDTH]>,
    pub(super) events: Vec<[Value; 3]>,
}

pub(super) fn car_values(car: &RaceCarStateV1) -> [i64; STATE_WIDTH] {
    [
        car.progress_mm,
        i64::from(car.lateral_mm),
        i64::from(car.speed_mm_per_tick),
        i64::from(car.lateral_velocity_mm_per_tick),
        i64::from(car.boost_energy),
        i64::from(car.finish_tick.unwrap_or(0)),
        car.dnf_tick.map_or(0, |tick| i64::from(tick) + 1),
    ]
}

impl RaceAirV1 {
    pub(super) fn compile(
        replay: &RaceReplayV1,
        final_state: &RaceStateV1,
        checkpoint: Option<&RaceStateV1>,
    ) -> Self {
        let mut a = IntegerAirV1::default();
        let players = usize::from(replay.player_count);
        let finish = replay.track.length_mm() * 3;
        let length = replay.track.length_mm();
        let inputs = (0..players)
            .map(|_| {
                [
                    a.input(-12_000, finish),
                    a.input(-16_200, 16_200),
                    a.input(0, 3_000),
                    a.input(-320, 320),
                    a.input(0, 1_000),
                    a.input(0, 5_400),
                    a.input(0, 5_401),
                ]
            })
            .collect::<Vec<_>>();
        let tick = Value::fixed(0, 0, 16_383);
        let enabled = Value::fixed(1, 0, 1);
        let first = Value::fixed(2, 0, 1);
        let transition = Value::fixed(3, 0, 1);
        let final_row = Value::fixed(4, 0, 1);
        let checkpoint_row = Value::fixed(5, 0, 1);
        let batch_start_enabled = Value::fixed(6, 0, 1);
        let zero = Value::constant(0);
        let one = Value::constant(1);
        let grid = initial_race_state_v1(replay.track, replay.player_count)
            .expect("validated player count");
        for (slot, car) in inputs.iter().enumerate() {
            for (value, expected) in car.iter().zip(car_values(&grid.cars[slot])) {
                a.gated_equate(first, *value, Value::constant(expected));
            }
            if let Some(checkpoint) = checkpoint {
                for (value, expected) in car.iter().zip(car_values(&checkpoint.cars[slot])) {
                    a.gated_equate(checkpoint_row, *value, Value::constant(expected));
                }
            }
        }
        let mut outputs = inputs.clone();
        let mut events = Vec::with_capacity(players);
        let mut active = Vec::with_capacity(players);
        let mut any_active = zero;
        let mut alive_count = zero;
        for (slot, car) in inputs.iter().enumerate() {
            let base = FIXED_PREFIX + slot * FIXED_PER_CAR;
            let acceleration = Value::fixed(base, -100, 40);
            let steer = Value::fixed(base + 1, -28, 28);
            let boost_requested = Value::fixed(base + 2, 0, 1);
            let dnf_event = Value::fixed(base + 3, 0, 1);
            let unfinished = a.less(car[5], one);
            let present = a.less(car[6], one);
            let remove = a.and(present, dnf_event);
            let dnf_tick = a.add_constant(tick, 1);
            let dnf = a.select(remove, dnf_tick, car[6]);
            let still_present = a.less(dnf, one);
            alive_count = a.add(alive_count, still_present);
            let racing = a.and(unfinished, still_present);
            any_active = a.or(any_active, racing);
            let running = a.and(racing, enabled);
            active.push(running);

            let insufficient = a.less(car[4], Value::constant(25));
            let enough = a.not(insufficient);
            let boosting = a.and(boost_requested, enough);
            let drained = a.sub_constant(car[4], 25);
            let recharged = a.add_constant(car[4], 4);
            let replenished = a.minimum(recharged, Value::constant(1_000));
            let energy = a.select(boosting, drained, replenished);
            let top = a.select(boosting, Value::constant(3_000), Value::constant(2_400));
            let accelerated = a.add(car[2], acceleration);
            let positive = a.maximum(accelerated, zero);
            let mut speed = a.minimum(positive, top);
            let [vx, oil] = super::environment_air::lateral_velocity(
                &mut a,
                replay.track,
                Value::fixed(7, 0, 1),
                car[0],
                car[1],
                car[3],
                steer,
            );

            // Shift by one track length, so division is unsigned even on the staggered grid.
            let shifted = a.add_constant(car[0], length);
            let (_, wrapped) = a.divmod_unsigned(shifted, length);
            let scaled = a.mul_constant(wrapped, 12);
            let (segment, _) = a.divmod_unsigned(scaled, length);
            let table = replay.track.curvature().map(i64::from);
            let curvature = a.lookup(segment, &table);
            let curve_speed = a.mul(curvature, speed);
            let curve_force = a.divide(curve_speed, 120);
            let wind_force = a.mul(Value::fixed(8, -32, 32), speed);
            let wind_force = a.divide(wind_force, 2400);
            let force = a.add(curve_force, wind_force);
            let steered = a.add(car[1], vx);
            let displaced = a.add(steered, force);
            let x = a.clamp(displaced, -9_000, 9_000);
            let abs_x = a.absolute(x);
            let offroad = a.less(Value::constant(6_000), abs_x);
            let slowed = a.sub_constant(speed, 90);
            let slowed = a.maximum(slowed, zero);
            speed = a.select(offroad, slowed, speed);
            let progress = a.add(car[0], speed);
            let [x, speed, solid_hit, kind] =
                super::environment_air::impact(&mut a, replay.track, car[0], progress, x, speed);
            events.push([a.and(running, oil), a.and(running, solid_hit), kind]);
            outputs[slot] = [
                a.select(running, progress, car[0]),
                a.select(running, x, car[1]),
                a.select(running, speed, car[2]),
                a.select(running, vx, car[3]),
                a.select(running, energy, car[4]),
                car[5],
                dnf,
            ];
        }
        // Extra frames after all cars stopped are forbidden, even if their state would be unchanged.
        a.gated_equate(batch_start_enabled, any_active, one);
        if players >= 2 {
            let below_quorum = a.less(alive_count, Value::constant(2));
            a.gated_equate(batch_start_enabled, below_quorum, zero);
        }
        for i in 0..players {
            for j in i + 1..players {
                let longitudinal = a.sub(outputs[i][0], outputs[j][0]);
                let longitudinal = a.absolute(longitudinal);
                let near = a.less(longitudinal, Value::constant(3_600));
                let lateral = a.sub(outputs[i][1], outputs[j][1]);
                let separation = a.absolute(lateral);
                let touching = a.less(separation, Value::constant(1_800));
                let both = a.and(active[i], active[j]);
                let contact = a.and(near, touching);
                let contact = a.and(both, contact);
                // Clamp before unsigned division: the unused noncontact branch must remain bounded too.
                let overlap = a.sub(Value::constant(1_800), separation);
                let overlap = a.maximum(overlap, zero);
                let rounded = a.add_constant(overlap, 1);
                let push = a.divide(rounded, 2);
                let left_is_greater = a.less(outputs[j][1], outputs[i][1]);
                let negative = a.mul_constant(push, -1);
                let delta = a.select(left_is_greater, push, negative);
                let ax = a.add(outputs[i][1], delta);
                let bx = a.sub(outputs[j][1], delta);
                outputs[i][1] = a.select(contact, ax, outputs[i][1]);
                outputs[j][1] = a.select(contact, bx, outputs[j][1]);
                // Every car can move by at most 900 mm in each of its seven pair visits.
                outputs[i][1].low = -16_200;
                outputs[i][1].high = 16_200;
                outputs[j][1].low = -16_200;
                outputs[j][1].high = 16_200;
                for slot in [i, j] {
                    let slowed = a.sub_constant(outputs[slot][2], 120);
                    let slowed = a.maximum(slowed, zero);
                    outputs[slot][2] = a.select(contact, slowed, outputs[slot][2]);
                }
            }
        }
        for (slot, car) in outputs.iter_mut().enumerate() {
            let before_finish = a.less(car[0], Value::constant(finish));
            let crossed = a.not(before_finish);
            let crossed = a.and(crossed, active[slot]);
            car[0] = a.select(crossed, Value::constant(finish), car[0]);
            let completed_tick = a.add_constant(tick, 1);
            car[5] = a.select(crossed, completed_tick, car[5]);
            for (value, input) in car.iter().zip(inputs[slot]) {
                a.gated_equate(transition, *value, IntegerAirV1::next(input));
            }
            for (value, expected) in car.iter().zip(car_values(&final_state.cars[slot])) {
                a.gated_equate(final_row, *value, Value::constant(expected));
            }
        }
        Self {
            air: a,
            outputs,
            events,
        }
    }

    pub(super) fn fixed_row(
        replay: &RaceReplayV1,
        row: usize,
        size: usize,
        checkpoint_tick: Option<u32>,
    ) -> Vec<i64> {
        let mut fixed = vec![
            row as i64,
            i64::from(row < replay.frames.len()),
            i64::from(row == 0),
            i64::from(row + 1 < size),
            i64::from(row == replay.frames.len()),
            i64::from(checkpoint_tick == Some(row as u32)),
            i64::from(row < replay.frames.len() && row % 6 == 0),
        ];
        let (rain, wind) = super::environment::weather(replay.track, row.min(5400) as u32);
        fixed.extend([rain, wind]);
        for slot in 0..usize::from(replay.player_count) {
            let control = replay
                .frames
                .get(row)
                .map_or(0, |frame| frame.controls[slot]);
            let acceleration = if control & 2 != 0 {
                -100
            } else if control & 1 != 0 {
                40
            } else {
                -12
            };
            let steer = (i64::from(control & 8 != 0) - i64::from(control & 4 != 0))
                * if control & 16 != 0 { 28 } else { 18 };
            let dnf = replay
                .dnf_events
                .iter()
                .find(|event| event.tick == row as u32)
                .is_some_and(|event| event.slots.contains(&(slot as u8)));
            fixed.extend([
                acceleration,
                steer,
                i64::from(control & 32 != 0),
                i64::from(dnf),
            ]);
        }
        fixed
    }

    #[cfg(test)]
    pub(super) fn next_inputs(&self, row: &[i64]) -> Vec<i64> {
        self.outputs
            .iter()
            .flat_map(|car| car.iter())
            .map(|value| match value.source {
                Source::Column(i) => row[i],
                Source::Constant(v) => v,
                _ => unreachable!("output is a witness value"),
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::super::{
        integer_air::field,
        race::{apply_race_dnf_v1, step_race_v1},
    };
    use super::*;
    use iroha_data_model::execution_proofs::{RaceDnfEventV1, RaceInputFrameV1, RaceTrackV1};
    #[test]
    fn arithmetic_trace_matches_every_reference_transition() {
        for track in [
            RaceTrackV1::NeonTokyo,
            RaceTrackV1::Harbor,
            RaceTrackV1::Sakura,
        ] {
            let mut replay = RaceReplayV1 {
                track,
                player_count: 8,
                frames: vec![],
                dnf_events: vec![RaceDnfEventV1 {
                    tick: 31,
                    slots: vec![3],
                }],
            };
            let mut reference = initial_race_state_v1(track, 8).expect("grid");
            for tick in 0..90 {
                let controls = (0..8)
                    .map(|slot| ((tick * 13 + slot * 19) % 64) as u16)
                    .collect();
                let frame = RaceInputFrameV1 { tick, controls };
                if tick == 31 {
                    apply_race_dnf_v1(&mut reference, &[3]).expect("dnf");
                }
                step_race_v1(&mut reference, &frame).expect("step");
                replay.frames.push(frame);
            }
            let compiled = RaceAirV1::compile(&replay, &reference, None);
            let mut state = initial_race_state_v1(track, 8).expect("grid");
            let mut inputs = state.cars.iter().flat_map(car_values).collect::<Vec<_>>();
            for row_index in 0..90 {
                let fixed = RaceAirV1::fixed_row(&replay, row_index, 128, None);
                let row = compiled.air.witness(&inputs, &fixed);
                inputs = compiled.next_inputs(&row);
                if row_index == 31 {
                    apply_race_dnf_v1(&mut state, &[3]).expect("dnf");
                }
                step_race_v1(&mut state, &replay.frames[row_index]).expect("step");
                assert_eq!(
                    inputs,
                    state.cars.iter().flat_map(car_values).collect::<Vec<_>>(),
                    "track {track:?}, tick {row_index}"
                );
                let fields = row.iter().copied().map(field).collect::<Vec<_>>();
                let next_fixed = RaceAirV1::fixed_row(&replay, row_index + 1, 128, None);
                let next = compiled
                    .air
                    .witness(&inputs, &next_fixed)
                    .into_iter()
                    .map(field)
                    .collect::<Vec<_>>();
                assert!(
                    compiled
                        .air
                        .residues(
                            &fields,
                            &next,
                            &fixed.into_iter().map(field).collect::<Vec<_>>()
                        )
                        .iter()
                        .all(|r| *r == field(0)),
                    "all constraints at row {row_index}"
                );
            }
            eprintln!(
                "{track:?} AIR columns={} constraints={}",
                compiled.air.width(),
                compiled.air.constraint_count()
            );
            assert!(compiled.air.width() < 16_000);
        }
    }

    #[test]
    fn full_duration_contacts_curvature_and_removal_match_reference() {
        let track = RaceTrackV1::Harbor;
        let mut replay = RaceReplayV1 {
            track,
            player_count: 8,
            frames: vec![],
            dnf_events: vec![RaceDnfEventV1 {
                tick: 1200,
                slots: vec![7],
            }],
        };
        let mut reference = initial_race_state_v1(track, 8).expect("grid");
        let mut expected = Vec::with_capacity(5401);
        for tick in 0..5400 {
            if tick == 1200 {
                apply_race_dnf_v1(&mut reference, &[7]).expect("removal");
            }
            let controls = reference
                .cars
                .iter()
                .enumerate()
                .map(|(slot, car)| {
                    if car.dnf_tick.is_some() {
                        return 0;
                    }
                    let target = if slot % 2 == 0 { -1600 } else { 1600 };
                    let steer = if tick < 90 {
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
                        | if (tick + slot as u32 * 11) % 90 < 25 {
                            32
                        } else {
                            0
                        }
                })
                .collect();
            let frame = RaceInputFrameV1 { tick, controls };
            step_race_v1(&mut reference, &frame).expect("reference tick");
            replay.frames.push(frame);
            expected.push(
                reference
                    .cars
                    .iter()
                    .flat_map(car_values)
                    .collect::<Vec<_>>(),
            );
        }
        expected.push(
            reference
                .cars
                .iter()
                .flat_map(car_values)
                .collect::<Vec<_>>(),
        );
        let compiled = RaceAirV1::compile(&replay, &reference, None);
        let mut inputs = initial_race_state_v1(track, 8)
            .expect("grid")
            .cars
            .iter()
            .flat_map(car_values)
            .collect::<Vec<_>>();
        for (row_index, expected) in expected.iter().enumerate() {
            let fixed = RaceAirV1::fixed_row(&replay, row_index, 8192, None);
            let row = compiled.air.witness(&inputs, &fixed);
            inputs = compiled.next_inputs(&row);
            assert_eq!(&inputs, expected, "complete transition at tick {row_index}");
            let fields = row.iter().copied().map(field).collect::<Vec<_>>();
            let next_fixed = RaceAirV1::fixed_row(&replay, row_index + 1, 8192, None);
            let next = compiled
                .air
                .witness(&inputs, &next_fixed)
                .into_iter()
                .map(field)
                .collect::<Vec<_>>();
            assert!(
                compiled
                    .air
                    .residues(
                        &fields,
                        &next,
                        &fixed.into_iter().map(field).collect::<Vec<_>>()
                    )
                    .iter()
                    .all(|residue| *residue == field(0)),
                "complete AIR at tick {row_index}"
            );
        }
    }
}
