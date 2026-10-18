//! `ClassedRaceV1` complete tick graph with explicit bounded inputs.
//!
//! The compiled class selects all performance constants before witness construction. This graph
//! is a separate source identity; it never changes the retained stock relation. Fixed rows are
//! derived from canonical public replay data, not witness-selected controls or class parameters.
//! TODO: integrate the narrow proof schedule, profile, history verifier and browser exporter;
//! arithmetic witness/residue tests alone do not qualify a cryptographic execution profile.

#[cfg(test)]
use super::super::integer_air::Source;
use super::super::integer_air::{IntegerAirV1, Value};
use super::{
    environment, environment_air,
    reference::{
        ClassedRaceSimulationErrorV1, classed_race_is_terminal_v1, initial_classed_race_state_v1,
    },
    rules::*,
};
use iroha_data_model::classed_race_v1::{
    ClassedRaceCarStateV1, ClassedRaceReplayV1, ClassedRaceStateV1,
};

pub(super) const FIXED_PREFIX: usize = 9;
pub(super) const FIXED_PER_CAR: usize = 4;
pub(super) const STATE_WIDTH: usize = 7;

/// Closed transition graph; one row contains one complete tick, including ordered contacts.
pub(super) struct ClassedRaceAirV1 {
    pub(super) air: IntegerAirV1,
    pub(super) outputs: Vec<[Value; STATE_WIDTH]>,
    /// Per-slot [running oil contact, running solid hit, pre-movement cell kind].
    /// Kind is consumed only when a contact predicate is set.
    pub(super) events: Vec<[Value; 3]>,
    replay: ClassedRaceReplayV1,
    checkpoint_tick: Option<u32>,
}

pub(super) fn car_values(car: &ClassedRaceCarStateV1) -> [i64; STATE_WIDTH] {
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

/// Constrain the input range with an exact unsigned remainder, not interval annotations alone.
fn bounded_input(a: &mut IntegerAirV1, low: i64, high: i64) -> Value {
    let value = a.input(low, high);
    let shifted = a.sub_constant(value, low);
    let (quotient, remainder) = a.divmod_unsigned(shifted, high - low + 1);
    a.equate(quotient, Value::constant(0));
    a.equate(remainder, shifted);
    value
}

fn validate_replay_shape(replay: &ClassedRaceReplayV1) -> Result<(), ClassedRaceSimulationErrorV1> {
    if replay.version != 1 {
        return Err(ClassedRaceSimulationErrorV1::Version);
    }
    if !(1..=MAX_PLAYERS).contains(&replay.player_count) {
        return Err(ClassedRaceSimulationErrorV1::PlayerCount);
    }
    if replay.frames.len() > MAX_TICKS as usize {
        return Err(ClassedRaceSimulationErrorV1::Terminal);
    }
    for (tick, frame) in replay.frames.iter().enumerate() {
        if frame.tick as usize != tick {
            return Err(ClassedRaceSimulationErrorV1::TickSequence);
        }
        if frame.controls.len() != usize::from(replay.player_count) {
            return Err(ClassedRaceSimulationErrorV1::ControlCount);
        }
        if frame
            .controls
            .iter()
            .any(|control| control & !CONTROL_MASK != 0)
        {
            return Err(ClassedRaceSimulationErrorV1::ControlBits);
        }
    }
    if replay.dnf_events.len() > usize::from(MAX_PLAYERS)
        || replay
            .dnf_events
            .windows(2)
            .any(|pair| pair[0].tick >= pair[1].tick)
    {
        return Err(ClassedRaceSimulationErrorV1::DnfSequence);
    }
    let mut removed = [false; MAX_PLAYERS as usize];
    for event in &replay.dnf_events {
        if event.tick as usize > replay.frames.len()
            || event.slots.is_empty()
            || event.slots.len() > usize::from(replay.player_count)
            || event.slots.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err(ClassedRaceSimulationErrorV1::DnfSequence);
        }
        for &slot in &event.slots {
            if slot >= replay.player_count || removed[usize::from(slot)] {
                return Err(ClassedRaceSimulationErrorV1::DnfSequence);
            }
            removed[usize::from(slot)] = true;
        }
    }
    Ok(())
}

pub(super) fn validate_public_inputs(
    replay: &ClassedRaceReplayV1,
    final_state: &ClassedRaceStateV1,
    checkpoint: Option<&ClassedRaceStateV1>,
) -> Result<(), ClassedRaceSimulationErrorV1> {
    validate_replay_shape(replay)?;
    classed_race_is_terminal_v1(final_state)?;
    if final_state.class_id != replay.class_id
        || final_state.track != replay.track
        || final_state.tick as usize != replay.frames.len()
        || final_state.cars.len() != usize::from(replay.player_count)
    {
        return Err(ClassedRaceSimulationErrorV1::StateBounds);
    }
    if let Some(checkpoint) = checkpoint {
        classed_race_is_terminal_v1(checkpoint)?;
        if checkpoint.class_id != replay.class_id
            || checkpoint.track != replay.track
            || checkpoint.tick > final_state.tick
            || checkpoint.cars.len() != final_state.cars.len()
        {
            return Err(ClassedRaceSimulationErrorV1::StateBounds);
        }
    }
    Ok(())
}

impl ClassedRaceAirV1 {
    pub(super) fn compile(
        replay: &ClassedRaceReplayV1,
        final_state: &ClassedRaceStateV1,
        checkpoint: Option<&ClassedRaceStateV1>,
    ) -> Result<Self, ClassedRaceSimulationErrorV1> {
        validate_public_inputs(replay, final_state, checkpoint)?;
        let spec = class_performance_v1(replay.class_id);
        let mut a = IntegerAirV1::default();
        let players = usize::from(replay.player_count);
        let finish = classed_track_length_v1(replay.track) * LAPS;
        let length = classed_track_length_v1(replay.track);
        let inputs = (0..players)
            .map(|_| {
                [
                    bounded_input(&mut a, MIN_PROGRESS, finish),
                    bounded_input(
                        &mut a,
                        -i64::from(STATE_LATERAL_LIMIT),
                        i64::from(STATE_LATERAL_LIMIT),
                    ),
                    bounded_input(&mut a, 0, spec.boost_speed),
                    bounded_input(&mut a, -LATERAL_SPEED_LIMIT, LATERAL_SPEED_LIMIT),
                    bounded_input(&mut a, 0, i64::from(spec.boost_capacity)),
                    bounded_input(&mut a, 0, i64::from(MAX_TICKS)),
                    bounded_input(&mut a, 0, i64::from(MAX_TICKS) + 1),
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
        let grid =
            initial_classed_race_state_v1(replay.class_id, replay.track, replay.player_count)?;
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
        let mut active = Vec::with_capacity(players);
        let mut events = Vec::with_capacity(players);
        let mut any_active = zero;
        let mut alive_count = zero;
        for (slot, car) in inputs.iter().enumerate() {
            let base = FIXED_PREFIX + slot * FIXED_PER_CAR;
            let acceleration = Value::fixed(base, -spec.brake, spec.acceleration);
            let steer = Value::fixed(base + 1, -spec.drift_steering, spec.drift_steering);
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

            let insufficient = a.less(car[4], Value::constant(i64::from(spec.boost_cost)));
            let enough = a.not(insufficient);
            let boosting = a.and(boost_requested, enough);
            let drained = a.sub_constant(car[4], i64::from(spec.boost_cost));
            let recharged = a.add_constant(car[4], i64::from(spec.boost_recharge));
            let replenished = a.minimum(recharged, Value::constant(i64::from(spec.boost_capacity)));
            let energy = a.select(boosting, drained, replenished);
            let top = a.select(
                boosting,
                Value::constant(spec.boost_speed),
                Value::constant(spec.normal_speed),
            );
            let accelerated = a.add(car[2], acceleration);
            let positive = a.maximum(accelerated, zero);
            let mut speed = a.minimum(positive, top);
            let [vx, oil] = environment_air::lateral_velocity(
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
            let table = classed_track_curvature_v1(replay.track);
            let curvature = a.lookup(segment, &table);
            let curve_speed = a.mul(curvature, speed);
            let curve_force = a.divide(curve_speed, 120);
            let wind_speed = a.mul(Value::fixed(8, -32, 32), speed);
            let wind_force = a.divide(wind_speed, 2_400);
            let force = a.add(curve_force, wind_force);
            let steered = a.add(car[1], vx);
            let displaced = a.add(steered, force);
            let x = a.clamp(displaced, -MOVE_LATERAL_LIMIT, MOVE_LATERAL_LIMIT);
            let abs_x = a.absolute(x);
            let offroad = a.less(Value::constant(ROAD_HALF_WIDTH), abs_x);
            let slowed = a.sub_constant(speed, spec.offroad_penalty);
            let slowed = a.maximum(slowed, zero);
            speed = a.select(offroad, slowed, speed);
            let progress = a.add(car[0], speed);
            let [x, speed, solid_hit, kind] =
                environment_air::impact(&mut a, replay.track, car[0], progress, x, speed);
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
                let near = a.less(longitudinal, Value::constant(CONTACT_DISTANCE));
                let lateral = a.sub(outputs[i][1], outputs[j][1]);
                let separation = a.absolute(lateral);
                let touching = a.less(separation, Value::constant(CONTACT_WIDTH));
                let both = a.and(active[i], active[j]);
                let contact = a.and(near, touching);
                let contact = a.and(both, contact);
                // Clamp before unsigned division: the unused noncontact branch must remain bounded too.
                let overlap = a.sub(Value::constant(CONTACT_WIDTH), separation);
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
                outputs[i][1].low = -i64::from(STATE_LATERAL_LIMIT);
                outputs[i][1].high = i64::from(STATE_LATERAL_LIMIT);
                outputs[j][1].low = -i64::from(STATE_LATERAL_LIMIT);
                outputs[j][1].high = i64::from(STATE_LATERAL_LIMIT);
                for slot in [i, j] {
                    let slowed = a.sub_constant(outputs[slot][2], spec.contact_penalty);
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
        Ok(Self {
            air: a,
            outputs,
            events,
            replay: replay.clone(),
            checkpoint_tick: checkpoint.map(|state| state.tick),
        })
    }

    pub(super) fn fixed_row(
        &self,
        row: usize,
        size: usize,
    ) -> Result<Vec<i64>, ClassedRaceSimulationErrorV1> {
        let replay = &self.replay;
        let checkpoint_tick = self.checkpoint_tick;
        if size < replay.frames.len() + 2 || !size.is_power_of_two() || size > 8192 || row >= size {
            return Err(ClassedRaceSimulationErrorV1::TickSequence);
        }
        let spec = class_performance_v1(replay.class_id);
        let (rain, wind) = environment::weather(replay.track, (row as u32).min(MAX_TICKS));
        let mut fixed = vec![
            row as i64,
            i64::from(row < replay.frames.len()),
            i64::from(row == 0),
            i64::from(row + 1 < size),
            i64::from(row == replay.frames.len()),
            i64::from(checkpoint_tick == Some(row as u32)),
            i64::from(row < replay.frames.len() && row % BATCH_TICKS as usize == 0),
            rain,
            wind,
        ];
        for slot in 0..usize::from(replay.player_count) {
            let control = replay
                .frames
                .get(row)
                .map_or(0, |frame| frame.controls[slot]);
            let acceleration = if control & 2 != 0 {
                -spec.brake
            } else if control & 1 != 0 {
                spec.acceleration
            } else {
                -spec.coast
            };
            let steer = (i64::from(control & 8 != 0) - i64::from(control & 4 != 0))
                * if control & 16 != 0 {
                    spec.drift_steering
                } else {
                    spec.steering
                };
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
        Ok(fixed)
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
    use super::super::super::integer_air::field;
    use super::super::reference::{
        apply_classed_race_dnf_v1, replay_classed_race_v1, step_classed_race_v1,
    };
    use super::*;
    use iroha_data_model::classed_race_v1::{
        ClassedRaceClassV1, ClassedRaceDnfEventV1, ClassedRaceInputFrameV1, ClassedRaceTrackV1,
    };

    fn replay(track: ClassedRaceTrackV1, count: u8, ticks: u32) -> ClassedRaceReplayV1 {
        ClassedRaceReplayV1 {
            version: 1,
            class_id: ClassedRaceClassV1::TouringS1,
            track,
            player_count: count,
            frames: (0..ticks)
                .map(|tick| ClassedRaceInputFrameV1 {
                    tick,
                    controls: (0..count)
                        .map(|slot| ((tick * 13 + u32::from(slot) * 19) % 64) as u16)
                        .collect(),
                })
                .collect(),
            dnf_events: vec![],
        }
    }

    fn verify_trace(replay: &ClassedRaceReplayV1) {
        let final_state = replay_classed_race_v1(replay).expect("valid reference replay");
        let mut reference =
            initial_classed_race_state_v1(replay.class_id, replay.track, replay.player_count)
                .unwrap();
        let checkpoint = if replay.frames.len() >= 6 {
            let mut prefix = replay.clone();
            prefix.frames.truncate(6);
            prefix.dnf_events.retain(|event| event.tick < 6);
            Some(replay_classed_race_v1(&prefix).unwrap())
        } else {
            None
        };
        let graph = ClassedRaceAirV1::compile(replay, &final_state, checkpoint.as_ref()).unwrap();
        let size = (replay.frames.len() + 2).next_power_of_two();
        let mut input = reference
            .cars
            .iter()
            .flat_map(car_values)
            .collect::<Vec<_>>();
        for tick in 0..size {
            let fixed = graph.fixed_row(tick, size).unwrap();
            let row = graph.air.witness(&input, &fixed);
            if let Some(event) = replay
                .dnf_events
                .iter()
                .find(|event| event.tick as usize == tick)
            {
                apply_classed_race_dnf_v1(&mut reference, &event.slots).unwrap();
            }
            if let Some(frame) = replay.frames.get(tick) {
                step_classed_race_v1(&mut reference, frame).unwrap();
            }
            let next_input = graph.next_inputs(&row);
            assert_eq!(
                next_input,
                reference
                    .cars
                    .iter()
                    .flat_map(car_values)
                    .collect::<Vec<_>>(),
                "class/track/grid {:?}/{:?}/{}, row {tick}",
                replay.class_id,
                replay.track,
                replay.player_count
            );
            let next_fixed = graph.fixed_row((tick + 1).min(size - 1), size).unwrap();
            let next = graph
                .air
                .witness(&next_input, &next_fixed)
                .into_iter()
                .map(field)
                .collect::<Vec<_>>();
            let fields = row.iter().copied().map(field).collect::<Vec<_>>();
            let fixed_fields = fixed.into_iter().map(field).collect::<Vec<_>>();
            assert!(
                graph
                    .air
                    .residues(&fields, &next, &fixed_fields)
                    .iter()
                    .all(|value| *value == field(0)),
                "all equations at row {tick}"
            );
            // Corrupt an actual state-producing column while holding the next state fixed.
            let Source::Column(speed) = graph.outputs[0][2].source else {
                panic!("state output column");
            };
            let mut altered = fields.clone();
            altered[speed] = altered[speed].add(field(1));
            assert!(
                graph
                    .air
                    .residues(&altered, &next, &fixed_fields)
                    .iter()
                    .any(|value| *value != field(0)),
                "altered speed must violate equations at row {tick}"
            );
            input = next_input;
        }
        eprintln!(
            "ClassedRaceV1 {:?}/{} columns={} constraints={} rows={size}",
            replay.track,
            replay.player_count,
            graph.air.width(),
            graph.air.constraint_count()
        );
    }

    #[test]
    fn all_class_tracks_and_rosters_match_reference_through_padding() {
        for track in [
            ClassedRaceTrackV1::NeonTokyo,
            ClassedRaceTrackV1::Harbor,
            ClassedRaceTrackV1::Sakura,
        ] {
            for count in 1..=8 {
                let mut data = replay(track, count, 90);
                if count >= 3 {
                    data.dnf_events.push(ClassedRaceDnfEventV1 {
                        tick: 31,
                        slots: vec![count - 1],
                    });
                }
                verify_trace(&data);
            }
        }
    }

    #[test]
    fn terminal_removals_are_preserved_through_every_padding_row() {
        let mut data = replay(ClassedRaceTrackV1::Harbor, 2, 6);
        data.dnf_events.push(ClassedRaceDnfEventV1 {
            tick: 6,
            slots: vec![0, 1],
        });
        verify_trace(&data);
    }

    #[test]
    fn all_performance_extrema_and_contacts_match_the_reference() {
        let data = replay(ClassedRaceTrackV1::Harbor, 8, 1);
        let final_state = replay_classed_race_v1(&data).unwrap();
        let graph = ClassedRaceAirV1::compile(&data, &final_state, None).unwrap();
        for mask in 0..=63 {
            let mut state = initial_classed_race_state_v1(data.class_id, data.track, 8).unwrap();
            state.tick = 101;
            for (slot, car) in state.cars.iter_mut().enumerate() {
                car.progress_mm = classed_track_length_v1(data.track) * 5 / 12 + slot as i64 * 10;
                car.lateral_mm = match slot {
                    0 => -STATE_LATERAL_LIMIT,
                    1 => STATE_LATERAL_LIMIT,
                    2 => -6000,
                    3 => 6000,
                    _ => slot as i32 - 5,
                };
                car.lateral_velocity_mm_per_tick = if slot % 2 == 0 { -320 } else { 320 };
                car.speed_mm_per_tick = [0, 1, 100, 2639, 2640, 2999, 3299, 3300][slot];
                car.boost_energy = [0, 1, 24, 25, 26, 996, 999, 1000][slot];
            }
            let input = state.cars.iter().flat_map(car_values).collect::<Vec<_>>();
            let control = ClassedRaceInputFrameV1 {
                tick: state.tick,
                controls: vec![mask; 8],
            };
            step_classed_race_v1(&mut state, &control).unwrap();
            // Deliberately test an isolated intermediate transition, without initial/final gates.
            let spec = class_performance_v1(data.class_id);
            let accel = if mask & 2 != 0 {
                -spec.brake
            } else if mask & 1 != 0 {
                spec.acceleration
            } else {
                -spec.coast
            };
            let steer = (i64::from(mask & 8 != 0) - i64::from(mask & 4 != 0))
                * if mask & 16 != 0 {
                    spec.drift_steering
                } else {
                    spec.steering
                };
            let (rain, wind) = environment::weather(data.track, 101);
            let mut fixed = vec![101, 1, 0, 0, 0, 0, 0, rain, wind];
            for _ in 0..8 {
                fixed.extend([accel, steer, i64::from(mask & 32 != 0), 0]);
            }
            let row = graph.air.witness(&input, &fixed);
            assert_eq!(
                graph.next_inputs(&row),
                state.cars.iter().flat_map(car_values).collect::<Vec<_>>(),
                "control {mask}"
            );
            let fields = row.into_iter().map(field).collect::<Vec<_>>();
            assert!(
                graph
                    .air
                    .residues(
                        &fields,
                        &fields,
                        &fixed.into_iter().map(field).collect::<Vec<_>>()
                    )
                    .iter()
                    .all(|value| *value == field(0)),
                "extrema equations for control {mask}"
            );
        }
    }

    #[test]
    fn finish_crossing_and_inactive_cars_match_the_exact_reference() {
        let data = replay(ClassedRaceTrackV1::Sakura, 4, 1);
        let final_state = replay_classed_race_v1(&data).unwrap();
        let graph = ClassedRaceAirV1::compile(&data, &final_state, None).unwrap();
        let mut state = initial_classed_race_state_v1(data.class_id, data.track, 4).unwrap();
        state.tick = 101;
        let finish = classed_track_length_v1(data.track) * LAPS;
        for car in &mut state.cars {
            car.progress_mm = finish - 1;
            car.speed_mm_per_tick = 3300;
        }
        state.cars[0].progress_mm = finish;
        state.cars[0].finish_tick = Some(100);
        state.cars[0].dnf_tick = Some(101);
        state.cars[1].dnf_tick = Some(99);
        let before = state.clone();
        let input = state.cars.iter().flat_map(car_values).collect::<Vec<_>>();
        let frame = ClassedRaceInputFrameV1 {
            tick: 101,
            controls: vec![63; 4],
        };
        step_classed_race_v1(&mut state, &frame).unwrap();
        assert_eq!(
            state.cars[0], before.cars[0],
            "finished/forfeited car is frozen"
        );
        assert_eq!(
            state.cars[1], before.cars[1],
            "unfinished forfeited car is frozen"
        );
        assert_eq!(state.cars[2].finish_tick, Some(102));
        assert_eq!(state.cars[3].finish_tick, Some(102));
        let (rain, wind) = environment::weather(data.track, 101);
        let mut fixed = vec![101, 1, 0, 0, 0, 0, 0, rain, wind];
        // Simultaneous brake+throttle prioritizes brake; opposing steering cancels.
        for _ in 0..4 {
            fixed.extend([-100, 0, 1, 0]);
        }
        let row = graph.air.witness(&input, &fixed);
        assert_eq!(
            graph.next_inputs(&row),
            state.cars.iter().flat_map(car_values).collect::<Vec<_>>()
        );
        let fields = row.into_iter().map(field).collect::<Vec<_>>();
        assert!(
            graph
                .air
                .residues(
                    &fields,
                    &fields,
                    &fixed.into_iter().map(field).collect::<Vec<_>>()
                )
                .iter()
                .all(|value| *value == field(0))
        );
    }

    #[test]
    fn malformed_public_controls_events_and_state_are_rejected_before_compilation() {
        let data = replay(ClassedRaceTrackV1::Sakura, 2, 6);
        let final_state = replay_classed_race_v1(&data).unwrap();
        let mut bad = data.clone();
        bad.frames[2].controls[0] = 64;
        assert!(matches!(
            ClassedRaceAirV1::compile(&bad, &final_state, None),
            Err(ClassedRaceSimulationErrorV1::ControlBits)
        ));
        bad = data.clone();
        bad.frames[2].controls.clear();
        assert!(matches!(
            ClassedRaceAirV1::compile(&bad, &final_state, None),
            Err(ClassedRaceSimulationErrorV1::ControlCount)
        ));
        bad = data.clone();
        bad.frames[2].tick = 4;
        assert!(matches!(
            ClassedRaceAirV1::compile(&bad, &final_state, None),
            Err(ClassedRaceSimulationErrorV1::TickSequence)
        ));
        bad = data.clone();
        bad.dnf_events = vec![
            ClassedRaceDnfEventV1 {
                tick: 1,
                slots: vec![0],
            },
            ClassedRaceDnfEventV1 {
                tick: 2,
                slots: vec![0],
            },
        ];
        assert!(matches!(
            ClassedRaceAirV1::compile(&bad, &final_state, None),
            Err(ClassedRaceSimulationErrorV1::DnfSequence)
        ));
        bad = data.clone();
        bad.version = 2;
        assert!(matches!(
            ClassedRaceAirV1::compile(&bad, &final_state, None),
            Err(ClassedRaceSimulationErrorV1::Version)
        ));
        let mut wrong = final_state.clone();
        wrong.track = ClassedRaceTrackV1::Harbor;
        assert!(matches!(
            ClassedRaceAirV1::compile(&data, &wrong, None),
            Err(ClassedRaceSimulationErrorV1::StateBounds)
        ));
        wrong = final_state.clone();
        wrong.cars[0].speed_mm_per_tick = 3301;
        assert!(matches!(
            ClassedRaceAirV1::compile(&data, &wrong, None),
            Err(ClassedRaceSimulationErrorV1::StateBounds)
        ));
        let graph = ClassedRaceAirV1::compile(&data, &final_state, None).unwrap();
        assert!(graph.fixed_row(0, 7).is_err());
        assert!(graph.fixed_row(8, 8).is_err());
        assert!(graph.fixed_row(0, 16384).is_err());
    }

    #[test]
    fn annotated_input_bounds_are_actual_polynomial_constraints() {
        let mut air = IntegerAirV1::default();
        bounded_input(&mut air, -15300, 15300);
        for value in [-15301, -15300, 0, 15300, 15301] {
            let row = air
                .witness(&[value], &[])
                .into_iter()
                .map(field)
                .collect::<Vec<_>>();
            let valid = air
                .residues(&row, &row, &[])
                .iter()
                .all(|value| *value == field(0));
            assert_eq!(valid, (-15300..=15300).contains(&value), "value {value}");
        }
    }
}
