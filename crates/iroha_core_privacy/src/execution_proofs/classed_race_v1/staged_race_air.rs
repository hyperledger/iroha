//! Narrow `ClassedRaceV1` microcycle graph with constrained producer and tick-boundary ranges.
//!
//! This source is separate from all retained stock profiles. Arithmetic tests do not qualify a
//! STARK proof, generated browser simulator, resource admission or production profile.
//!
//! Each public tick executes a boundary row, six rows per car, every ordered pair,
//! and one finish row per car. The state is carried between rows; fixed selectors bind
//! the exact schedule. No prover-chosen opcode or indirect memory access is accepted.
//! `RANGE_SCHEDULE.md` establishes the integer induction between the explicit range checks.

use super::super::integer_air::{IntegerAirV1, PackedIntegerAirV1, Value, field};
use super::{
    environment, environment_air,
    race_air::{car_values, validate_public_inputs},
    reference::{ClassedRaceSimulationErrorV1, initial_classed_race_state_v1},
    rules::*,
};
use crate::privacy_engines::transparent_stark::GoldilocksFieldV1 as F;
use iroha_data_model::classed_race_v1::{ClassedRaceReplayV1, ClassedRaceStateV1};

// |trunc(curve * 3300 / 120)| + |trunc(wind * 3300 / 2400)| <= 82 + 44.
const MOVEMENT_FORCE_LIMIT: i64 = 126;
const STAGES: usize = 9;
const BOUNDARY: usize = 0;
const DRIVE: usize = 1;
const CURVE: usize = 2;
const MOVE: usize = 3;
const CONTACT: usize = 4;
const FINISH: usize = 5;
const GRIP: usize = 6;
const IMPACT: usize = 7;
const ENVIRONMENT: usize = 8;
// tick,enabled,first,transition,final,checkpoint,batch-boundary,rain,wind, nine stage selectors,
// left-slot selectors, right-slot selectors, DNF selectors, acceleration/steer/boost.
const SELECTORS: usize = 9;
const SLOT_PREFIX: usize = SELECTORS + STAGES;

pub(super) struct StagedClassedRaceAirV1 {
    players: usize,
    pub(super) packed: PackedIntegerAirV1,
    outputs: Vec<[Value; 18]>,
    stages: Vec<(usize, Option<usize>, Option<usize>)>,
    grid: Vec<i64>,
    final_state: Vec<i64>,
    checkpoint: Option<Vec<i64>>,
    replay: ClassedRaceReplayV1,
    checkpoint_tick: Option<u32>,
}
fn constrain_range(a: &mut IntegerAirV1, value: Value, low: i64, high: i64) {
    // These endpoints are proved by the remainder equations below. Normalizing the
    // graph metadata is not a claim that an arbitrary witness already satisfies them.
    let bounded = Value { low, high, ..value };
    let shifted = a.sub_constant(bounded, low);
    let (quotient, remainder) = a.divmod_unsigned(shifted, high - low + 1);
    a.equate(quotient, Value::constant(0));
    a.equate(remainder, shifted);
}
fn make_stage(stage: usize, replay: &ClassedRaceReplayV1) -> (IntegerAirV1, [Value; 18]) {
    let mut a = IntegerAirV1::default();
    let spec = class_performance_v1(replay.class_id);
    let finish = classed_track_length_v1(replay.track) * LAPS;
    let length = classed_track_length_v1(replay.track);
    let mut car = || {
        [
            a.input(MIN_PROGRESS, finish + spec.boost_speed),
            a.input(
                -i64::from(STATE_LATERAL_LIMIT),
                i64::from(STATE_LATERAL_LIMIT),
            ),
            a.input(0, spec.boost_speed),
            a.input(-LATERAL_SPEED_LIMIT, LATERAL_SPEED_LIMIT),
            a.input(0, i64::from(spec.boost_capacity)),
            a.input(0, i64::from(MAX_TICKS)),
            a.input(0, i64::from(MAX_TICKS) + 1),
        ]
    };
    let left = car();
    let right = car();
    let running = a.input(0, 1);
    let running_right = a.input(0, 1);
    let relative = a.input(-length, length);
    let kind = a.input(0, 2);
    let object_x = a.input(-7_400, 7_400);
    let force = a.input(-MOVEMENT_FORCE_LIMIT, MOVEMENT_FORCE_LIMIT);
    // All 20 inputs occupy the same ordinary bank and are equated to carried state in
    // residues(). Initial state, exact producer equations and FINISH range checks establish
    // their bounds; running flags have independent Boolean/zero-test equations there.
    // Do not interleave auxiliaries with inputs or treat this stage as a standalone relation.
    let mut x = left;
    let mut y = right;
    let mut scratch = [relative, kind, object_x, force];
    let zero = Value::constant(0);
    let one = Value::constant(1);
    let control = SLOT_PREFIX + 3 * usize::from(replay.player_count);
    let acceleration = Value::fixed(control, -spec.brake, spec.acceleration);
    let steer = Value::fixed(control + 1, -spec.drift_steering, spec.drift_steering);
    let boost = Value::fixed(control + 2, 0, 1);
    if stage == DRIVE {
        let insufficient = a.less(left[4], Value::constant(i64::from(spec.boost_cost)));
        let enough = a.not(insufficient);
        let boosting = a.and(boost, enough);
        let drained = a.sub_constant(left[4], i64::from(spec.boost_cost));
        let recharged = a.add_constant(left[4], i64::from(spec.boost_recharge));
        let replenished = a.minimum(recharged, Value::constant(i64::from(spec.boost_capacity)));
        let energy = a.select(boosting, drained, replenished);
        let top = a.select(
            boosting,
            Value::constant(spec.boost_speed),
            Value::constant(spec.normal_speed),
        );
        let accelerated = a.add(left[2], acceleration);
        let positive = a.maximum(accelerated, zero);
        let speed = a.minimum(positive, top);
        x[2] = a.select(running, speed, left[2]);
        x[4] = a.select(running, energy, left[4]);
    } else if stage == ENVIRONMENT {
        scratch[..3].copy_from_slice(&environment_air::geometry(&mut a, replay.track, left[0]));
        constrain_range(&mut a, scratch[0], -length, length);
        constrain_range(&mut a, scratch[1], 0, 2);
        constrain_range(&mut a, scratch[2], -7_400, 7_400);
    } else if stage == GRIP {
        let [vx, _] = environment_air::lateral_velocity_from_geometry(
            &mut a,
            Value::fixed(7, 0, 1),
            [relative, kind, object_x],
            left[1],
            left[3],
            steer,
        );
        x[3] = a.select(running, vx, left[3]);
    } else if stage == CURVE {
        let shifted = a.add_constant(left[0], length);
        let (_, wrapped) = a.divmod_unsigned(shifted, length);
        let scaled = a.mul_constant(wrapped, 12);
        let (segment, _) = a.divmod_unsigned(scaled, length);
        let curvature = a.lookup(segment, &classed_track_curvature_v1(replay.track));
        let curve_speed = a.mul(curvature, left[2]);
        let curve_force = a.divide(curve_speed, 120);
        let wind_speed = a.mul(Value::fixed(8, -32, 32), left[2]);
        let wind_force = a.divide(wind_speed, 2_400);
        let force = a.add(curve_force, wind_force);
        scratch[3] = a.select(running, force, zero);
        constrain_range(
            &mut a,
            scratch[3],
            -MOVEMENT_FORCE_LIMIT,
            MOVEMENT_FORCE_LIMIT,
        );
    } else if stage == MOVE {
        let steered = a.add(left[1], left[3]);
        let displaced = a.add(steered, force);
        let lateral = a.clamp(displaced, -MOVE_LATERAL_LIMIT, MOVE_LATERAL_LIMIT);
        let absolute = a.absolute(lateral);
        let offroad = a.less(Value::constant(ROAD_HALF_WIDTH), absolute);
        let slowed = a.sub_constant(left[2], spec.offroad_penalty);
        let slowed = a.maximum(slowed, zero);
        let speed = a.select(offroad, slowed, left[2]);
        let progress = a.add(left[0], speed);
        x[0] = a.select(running, progress, left[0]);
        x[1] = a.select(running, lateral, left[1]);
        x[2] = a.select(running, speed, left[2]);
    } else if stage == IMPACT {
        let [lateral, speed, _, _] = environment_air::impact_from_geometry(
            &mut a,
            [relative, kind, object_x],
            left[2],
            left[1],
            left[2],
        );
        x[1] = a.select(running, lateral, left[1]);
        x[2] = a.select(running, speed, left[2]);
    } else if stage == CONTACT {
        let delta = a.sub(left[0], right[0]);
        let delta = a.absolute(delta);
        let near = a.less(delta, Value::constant(CONTACT_DISTANCE));
        let lateral = a.sub(left[1], right[1]);
        let separation = a.absolute(lateral);
        let touching = a.less(separation, Value::constant(CONTACT_WIDTH));
        let both = a.and(running, running_right);
        let contact = a.and(near, touching);
        let contact = a.and(both, contact);
        let overlap = a.sub(Value::constant(CONTACT_WIDTH), separation);
        let overlap = a.maximum(overlap, zero);
        let rounded = a.add_constant(overlap, 1);
        let push = a.divide(rounded, 2);
        let greater = a.less(right[1], left[1]);
        let negative = a.mul_constant(push, -1);
        let delta = a.select(greater, push, negative);
        let ax = a.add(left[1], delta);
        let bx = a.sub(right[1], delta);
        x[1] = a.select(contact, ax, left[1]);
        y[1] = a.select(contact, bx, right[1]);
        for car in [&mut x, &mut y] {
            let slowed = a.sub_constant(car[2], spec.contact_penalty);
            let slowed = a.maximum(slowed, zero);
            car[2] = a.select(contact, slowed, car[2]);
        }
    } else if stage == FINISH {
        let before = a.less(left[0], Value::constant(finish));
        let crossed = a.not(before);
        let crossed = a.and(crossed, running);
        x[0] = a.select(crossed, Value::constant(finish), left[0]);
        let tick = a.add(Value::fixed(0, 0, i64::from(MAX_TICKS)), one);
        x[5] = a.select(crossed, tick, left[5]);
        // Every car has this row, including ghosts and padding. Its seven output fields
        // receive exact canonical state bounds once per tick. Intermediate bounds follow
        // the fixed schedule's induction documented in RANGE_SCHEDULE.md.
        for (value, (low, high)) in x.into_iter().zip([
            (MIN_PROGRESS, finish),
            (
                -i64::from(STATE_LATERAL_LIMIT),
                i64::from(STATE_LATERAL_LIMIT),
            ),
            (0, spec.boost_speed),
            (-LATERAL_SPEED_LIMIT, LATERAL_SPEED_LIMIT),
            (0, i64::from(spec.boost_capacity)),
            (0, i64::from(MAX_TICKS)),
            (0, i64::from(MAX_TICKS) + 1),
        ]) {
            constrain_range(&mut a, value, low, high);
        }
    }
    let mut outputs = [zero; 18];
    outputs[..7].copy_from_slice(&x);
    outputs[7..14].copy_from_slice(&y);
    outputs[14..18].copy_from_slice(&scratch);
    (a, outputs)
}
/// All inversions used by witness generation are of bounded public tick/count integers.
/// Cache them once; the verifier evaluates their field equations without using this table.
fn inverse_small(value: i64) -> F {
    static INVERSES: std::sync::OnceLock<Vec<F>> = std::sync::OnceLock::new();
    INVERSES.get_or_init(|| {
        (0..=i64::from(MAX_TICKS) + 1)
            .map(|value| {
                if value == 0 {
                    F::ZERO
                } else {
                    field(value).inv().expect("nonzero small integer")
                }
            })
            .collect()
    })[value as usize]
}
impl StagedClassedRaceAirV1 {
    pub(super) fn compile(
        replay: &ClassedRaceReplayV1,
        final_state: &ClassedRaceStateV1,
        checkpoint: Option<&ClassedRaceStateV1>,
    ) -> Result<Self, ClassedRaceSimulationErrorV1> {
        validate_public_inputs(replay, final_state, checkpoint)?;
        let players = usize::from(replay.player_count);
        let mut programs = vec![];
        let mut outputs = vec![];
        for stage in 0..STAGES {
            let (program, output) = make_stage(stage, replay);
            programs.push(program);
            outputs.push(output);
        }
        let mut stages = vec![(BOUNDARY, None, None)];
        for slot in 0..players {
            for stage in [ENVIRONMENT, GRIP, DRIVE, CURVE, MOVE, IMPACT] {
                stages.push((stage, Some(slot), None));
            }
        }
        for left in 0..players {
            for right in left + 1..players {
                stages.push((CONTACT, Some(left), Some(right)));
            }
        }
        for slot in 0..players {
            stages.push((FINISH, Some(slot), None));
        }
        Ok(Self {
            players,
            packed: PackedIntegerAirV1::new(programs),
            outputs,
            stages,
            grid: initial_classed_race_state_v1(
                replay.class_id,
                replay.track,
                replay.player_count,
            )?
            .cars
            .iter()
            .flat_map(car_values)
            .collect(),
            final_state: final_state.cars.iter().flat_map(car_values).collect(),
            checkpoint: checkpoint.map(|state| state.cars.iter().flat_map(car_values).collect()),
            replay: replay.clone(),
            checkpoint_tick: checkpoint.map(|state| state.tick),
        })
    }
    pub(super) fn rows_per_tick(&self) -> usize {
        self.stages.len()
    }
    pub(super) fn trace_size(&self) -> usize {
        ((self.replay.frames.len() + 1) * self.rows_per_tick() + 1)
            .next_power_of_two()
            .max(8192)
    }
    fn carry_width(&self) -> usize {
        7 * self.players + 4
    }
    fn bank_start(&self) -> usize {
        self.carry_width() + 5 * self.players + 4
    }
    pub(super) fn width(&self) -> usize {
        self.bank_start() + self.packed.width()
    }
    pub(super) fn fixed_width(&self) -> usize {
        SLOT_PREFIX + 3 * self.players + 3
    }
    pub(super) fn fixed_row(
        &self,
        row: usize,
        size: usize,
    ) -> Result<Vec<i64>, ClassedRaceSimulationErrorV1> {
        if size != self.trace_size() || row >= size {
            return Err(ClassedRaceSimulationErrorV1::TickSequence);
        }
        let replay = &self.replay;
        let checkpoint = self.checkpoint_tick;
        let spec = class_performance_v1(replay.class_id);
        let phases = self.rows_per_tick();
        let tick = row / phases;
        let phase = row % phases;
        let (stage, left, right) = self.stages[phase];
        let final_row = (replay.frames.len() + 1) * phases;
        let (rain, wind) = environment::weather(replay.track, tick.min(MAX_TICKS as usize) as u32);
        let mut fixed = vec![
            tick.min(MAX_TICKS as usize) as i64,
            i64::from(tick < replay.frames.len()),
            i64::from(row == 0),
            i64::from(row + 1 < size),
            i64::from(row == final_row),
            i64::from(checkpoint.is_some_and(|tick| row == tick as usize * phases)),
            i64::from(phase == 0 && tick < replay.frames.len() && tick % BATCH_TICKS as usize == 0),
            rain,
            wind,
        ];
        fixed.extend((0..STAGES).map(|index| i64::from(index == stage)));
        fixed.extend((0..self.players).map(|slot| i64::from(left == Some(slot))));
        fixed.extend((0..self.players).map(|slot| i64::from(right == Some(slot))));
        fixed.extend((0..self.players).map(|slot| {
            i64::from(
                phase == 0
                    && replay.dnf_events.iter().any(|event| {
                        event.tick as usize == tick && event.slots.contains(&(slot as u8))
                    }),
            )
        }));
        let control = left
            .and_then(|slot| replay.frames.get(tick).map(|frame| frame.controls[slot]))
            .unwrap_or(0);
        fixed.extend([
            if control & 2 != 0 {
                -spec.brake
            } else if control & 1 != 0 {
                spec.acceleration
            } else {
                -spec.coast
            },
            (i64::from(control & 8 != 0) - i64::from(control & 4 != 0))
                * if control & 16 != 0 {
                    spec.drift_steering
                } else {
                    spec.steering
                },
            i64::from(control & 32 != 0),
        ]);
        Ok(fixed)
    }
    pub(super) fn initial_carry(&self) -> Vec<i64> {
        let mut carry = self.grid.clone();
        carry.extend([0; 4]);
        carry
    }
    pub(super) fn witness(&self, carry: &[i64], fixed: &[i64]) -> (Vec<F>, Vec<i64>) {
        let stage = (0..STAGES)
            .find(|stage| fixed[SELECTORS + stage] == 1)
            .expect("fixed stage");
        let left = (0..self.players).find(|slot| fixed[SLOT_PREFIX + slot] == 1);
        let right = (0..self.players).find(|slot| fixed[SLOT_PREFIX + self.players + slot] == 1);
        let mut inputs = vec![0; 20];
        for (offset, slot) in [(0, left), (7, right)] {
            if let Some(slot) = slot {
                inputs[offset..offset + 7].copy_from_slice(&carry[slot * 7..slot * 7 + 7]);
            }
        }
        let running = |slot: usize| {
            i64::from(carry[slot * 7 + 5] == 0 && carry[slot * 7 + 6] == 0 && fixed[1] == 1)
        };
        inputs[14] = left.map_or(0, running);
        inputs[15] = right.map_or(0, running);
        inputs[16..20].copy_from_slice(&carry[7 * self.players..7 * self.players + 4]);
        let packed = self.packed.witness(stage, &inputs, fixed);
        let mut row = carry.iter().copied().map(field).collect::<Vec<_>>();
        let mut post_alive = 0;
        let mut post_running = 0;
        for slot in 0..self.players {
            let finish = field(carry[slot * 7 + 5]);
            let dnf = field(carry[slot * 7 + 6]);
            let alive = i64::from(dnf == F::ZERO);
            let unfinished = i64::from(finish == F::ZERO);
            row.extend([
                field(alive),
                if dnf == F::ZERO {
                    F::ZERO
                } else {
                    inverse_small(carry[slot * 7 + 6])
                },
                field(unfinished),
                if finish == F::ZERO {
                    F::ZERO
                } else {
                    inverse_small(carry[slot * 7 + 5])
                },
                field(running(slot)),
            ]);
            let remains = alive * (1 - fixed[SLOT_PREFIX + 2 * self.players + slot]);
            post_alive += remains;
            post_running += remains * unfinished;
        }
        // One inverse proves at least one racing car exists on an enabled batch boundary.
        let quorum = field(post_alive).mul(field(post_alive - 1));
        row.extend([
            field(post_alive),
            field(post_running),
            if post_running == 0 {
                F::ZERO
            } else {
                inverse_small(post_running)
            },
            if quorum == F::ZERO {
                F::ZERO
            } else {
                inverse_small(post_alive * (post_alive - 1))
            },
        ]);
        row.extend(packed.iter().copied().map(field));
        let mut next = carry.to_vec();
        for (offset, slot) in [(0, left), (7, right)] {
            if let Some(slot) = slot {
                for i in 0..7 {
                    next[slot * 7 + i] = self.packed.read_integer(
                        stage,
                        self.outputs[stage][offset + i],
                        &packed,
                        fixed,
                    );
                }
            }
        }
        for index in 0..4 {
            next[7 * self.players + index] =
                self.packed
                    .read_integer(stage, self.outputs[stage][14 + index], &packed, fixed);
        }
        if stage == BOUNDARY {
            for slot in 0..self.players {
                if fixed[SLOT_PREFIX + 2 * self.players + slot] == 1 && carry[slot * 7 + 6] == 0 {
                    next[slot * 7 + 6] = fixed[0] + 1;
                }
            }
        }
        (row, next)
    }
    pub(super) fn residues(&self, current: &[F], next: &[F], fixed: &[F]) -> Vec<F> {
        let bank = &current[self.bank_start()..];
        let stages = &fixed[SELECTORS..SELECTORS + STAGES];
        let mut out = self.packed.residues(bank, fixed, stages);
        let mut selected = [F::ZERO; 20];
        let mut post_alive = F::ZERO;
        let mut post_running = F::ZERO;
        for slot in 0..self.players {
            let car = &current[slot * 7..slot * 7 + 7];
            let flag = self.carry_width() + 5 * slot;
            let alive = current[flag];
            let alive_inverse = current[flag + 1];
            let unfinished = current[flag + 2];
            let finish_inverse = current[flag + 3];
            let running = current[flag + 4];
            out.extend([
                alive.mul(alive.sub(F::ONE)),
                car[6].mul(alive),
                car[6].mul(alive_inverse).sub(F::ONE.sub(alive)),
                unfinished.mul(unfinished.sub(F::ONE)),
                car[5].mul(unfinished),
                car[5].mul(finish_inverse).sub(F::ONE.sub(unfinished)),
                running.sub(fixed[1].mul(alive).mul(unfinished)),
            ]);
            let left = fixed[SLOT_PREFIX + slot];
            let right = fixed[SLOT_PREFIX + self.players + slot];
            let event = fixed[SLOT_PREFIX + 2 * self.players + slot];
            for i in 0..7 {
                selected[i] = selected[i].add(left.mul(car[i]));
                selected[7 + i] = selected[7 + i].add(right.mul(car[i]));
            }
            selected[14] = selected[14].add(left.mul(running));
            selected[15] = selected[15].add(right.mul(running));
            let remains = alive.mul(F::ONE.sub(event));
            post_alive = post_alive.add(remains);
            post_running = post_running.add(remains.mul(unfinished));
            for i in 0..7 {
                let mut delta = F::ZERO;
                for stage in 0..STAGES {
                    let l = self.packed.read(stage, self.outputs[stage][i], bank, fixed);
                    let r = self
                        .packed
                        .read(stage, self.outputs[stage][7 + i], bank, fixed);
                    delta = delta.add(
                        stages[stage].mul(left.mul(l.sub(car[i])).add(right.mul(r.sub(car[i])))),
                    );
                }
                if i == 6 {
                    delta = delta.add(event.mul(alive).mul(fixed[0].add(F::ONE).sub(car[6])));
                }
                out.push(fixed[3].mul(next[slot * 7 + i].sub(car[i]).sub(delta)));
                out.push(fixed[2].mul(car[i].sub(field(self.grid[slot * 7 + i]))));
                out.push(fixed[4].mul(car[i].sub(field(self.final_state[slot * 7 + i]))));
                if let Some(checkpoint) = &self.checkpoint {
                    out.push(fixed[5].mul(car[i].sub(field(checkpoint[slot * 7 + i]))));
                }
            }
        }
        selected[16..20].copy_from_slice(&current[7 * self.players..7 * self.players + 4]);
        // Every stage has the same first 20 ordinary-bank input columns.
        for (input, expected) in bank[..20].iter().zip(selected) {
            out.push(input.sub(expected));
        }
        for index in 0..4 {
            let mut expected = F::ZERO;
            for stage in 0..STAGES {
                expected = expected.add(stages[stage].mul(self.packed.read(
                    stage,
                    self.outputs[stage][14 + index],
                    bank,
                    fixed,
                )));
            }
            out.push(fixed[3].mul(next[7 * self.players + index].sub(expected)));
            out.push(fixed[2].mul(current[7 * self.players + index]));
        }
        let counts = self.carry_width() + 5 * self.players;
        let alive_count = current[counts];
        let running_count = current[counts + 1];
        out.push(alive_count.sub(post_alive));
        out.push(running_count.sub(post_running));
        out.push(fixed[6].mul(running_count.mul(current[counts + 2]).sub(F::ONE)));
        if self.players >= 2 {
            out.push(
                fixed[6].mul(
                    alive_count
                        .mul(alive_count.sub(F::ONE))
                        .mul(current[counts + 3])
                        .sub(F::ONE),
                ),
            );
        }
        out
    }
    pub(super) fn constraint_count(&self) -> usize {
        let zero = vec![F::ZERO; self.width()];
        let fixed = vec![F::ZERO; self.fixed_width()];
        self.residues(&zero, &zero, &fixed).len()
    }
}

#[cfg(test)]
mod tests {
    use super::super::reference::{apply_classed_race_dnf_v1, step_classed_race_v1};
    use super::*;
    use iroha_data_model::classed_race_v1::{
        ClassedRaceClassV1, ClassedRaceDnfEventV1, ClassedRaceInputFrameV1, ClassedRaceTrackV1,
    };

    fn replay(track: ClassedRaceTrackV1, players: u8, ticks: u32) -> ClassedRaceReplayV1 {
        ClassedRaceReplayV1 {
            version: 1,
            class_id: ClassedRaceClassV1::TouringS1,
            track,
            player_count: players,
            frames: (0..ticks)
                .map(|tick| ClassedRaceInputFrameV1 {
                    tick,
                    controls: (0..players)
                        .map(|slot| ((tick * 17 + u32::from(slot) * 11) % 64) as u16)
                        .collect(),
                })
                .collect(),
            dnf_events: vec![],
        }
    }

    fn check_trace(data: &ClassedRaceReplayV1, checkpoint_tick: Option<u32>) {
        let mut state =
            initial_classed_race_state_v1(data.class_id, data.track, data.player_count).unwrap();
        let mut expected = vec![state.clone()];
        for frame in &data.frames {
            if let Some(event) = data
                .dnf_events
                .iter()
                .find(|event| event.tick == state.tick)
            {
                apply_classed_race_dnf_v1(&mut state, &event.slots).unwrap();
            }
            step_classed_race_v1(&mut state, frame).unwrap();
            expected.push(state.clone());
        }
        if let Some(event) = data
            .dnf_events
            .iter()
            .find(|event| event.tick == state.tick)
        {
            apply_classed_race_dnf_v1(&mut state, &event.slots).unwrap();
        }
        let checkpoint = checkpoint_tick.map(|tick| &expected[tick as usize]);
        let graph = StagedClassedRaceAirV1::compile(data, &state, checkpoint).unwrap();
        let mut carry = graph.initial_carry();
        let size = graph.trace_size();
        let mut previous: Option<(Vec<F>, Vec<F>)> = None;
        for index in 0..size {
            let tick = index / graph.rows_per_tick();
            if index % graph.rows_per_tick() == 0 && tick < expected.len() {
                assert_eq!(
                    &carry[..7 * graph.players],
                    &expected[tick]
                        .cars
                        .iter()
                        .flat_map(car_values)
                        .collect::<Vec<_>>(),
                    "{:?}/{} tick {tick}",
                    data.track,
                    graph.players
                );
            }
            let fixed = graph.fixed_row(index, size).unwrap();
            let (row, next) = graph.witness(&carry, &fixed);
            if let Some((prior, prior_fixed)) = previous.take() {
                assert!(
                    graph
                        .residues(&prior, &row, &prior_fixed)
                        .iter()
                        .all(|r| *r == F::ZERO),
                    "{:?}/{} row {}",
                    data.track,
                    graph.players,
                    index - 1
                );
            }
            previous = Some((row, fixed.into_iter().map(field).collect()));
            carry = next;
        }
        let (last, fixed) = previous.unwrap();
        assert!(
            graph
                .residues(&last, &last, &fixed)
                .iter()
                .all(|r| *r == F::ZERO)
        );
        assert_eq!(
            &carry[..7 * graph.players],
            &state.cars.iter().flat_map(car_values).collect::<Vec<_>>()
        );
        eprintln!(
            "classed narrow {:?}/{} ticks={} rows={} rows/tick={} columns={} constraints={}",
            data.track,
            graph.players,
            data.frames.len(),
            size,
            graph.rows_per_tick(),
            graph.width(),
            graph.constraint_count()
        );
    }

    #[test]
    fn every_track_and_roster_matches_reference_through_terminal_and_padding() {
        for track in [
            ClassedRaceTrackV1::NeonTokyo,
            ClassedRaceTrackV1::Harbor,
            ClassedRaceTrackV1::Sakura,
        ] {
            for players in 1..=8 {
                let mut data = replay(track, players, 90);
                if players >= 3 {
                    data.dnf_events.push(ClassedRaceDnfEventV1 {
                        tick: 31,
                        slots: vec![players - 1],
                    });
                }
                data.dnf_events.push(ClassedRaceDnfEventV1 {
                    tick: 90,
                    slots: (0..if players >= 3 { players - 1 } else { players }).collect(),
                });
                check_trace(&data, Some(30));
            }
        }
        let mut technical = replay(ClassedRaceTrackV1::Harbor, 2, 6);
        technical.dnf_events.push(ClassedRaceDnfEventV1 {
            tick: 6,
            slots: vec![1],
        });
        check_trace(&technical, Some(6));
    }

    #[test]
    fn full_three_track_eight_car_duration_has_exact_narrow_residues() {
        for track in [
            ClassedRaceTrackV1::NeonTokyo,
            ClassedRaceTrackV1::Harbor,
            ClassedRaceTrackV1::Sakura,
        ] {
            let mut data = replay(track, 8, MAX_TICKS);
            data.dnf_events.push(ClassedRaceDnfEventV1 {
                tick: 1200,
                slots: vec![7],
            });
            check_trace(&data, Some(1200));
        }
    }

    #[test]
    fn full_integer_inputs_and_carried_state_are_constrained() {
        let data = replay(ClassedRaceTrackV1::Harbor, 8, 0);
        let state = initial_classed_race_state_v1(data.class_id, data.track, 8).unwrap();
        let graph = StagedClassedRaceAirV1::compile(&data, &state, None).unwrap();
        let mut fixed = graph.fixed_row(1, graph.trace_size()).unwrap();
        fixed[1] = 1;
        let carry = graph.initial_carry();
        let (row, next_carry) = graph.witness(&carry, &fixed);
        let (next, _) = graph.witness(&next_carry, &fixed);
        let fixed_fields = fixed.iter().copied().map(field).collect::<Vec<_>>();
        assert!(
            graph
                .residues(&row, &next, &fixed_fields)
                .iter()
                .all(|r| *r == F::ZERO)
        );
        for column in 0..graph.carry_width() {
            let mut changed = row.clone();
            changed[column] = changed[column].add(F::ONE);
            assert!(
                graph
                    .residues(&changed, &next, &fixed_fields)
                    .iter()
                    .any(|r| *r != F::ZERO),
                "unbound carry column {column}"
            );
        }
        // Recompute every auxiliary at the actual seven-field range-check row. Keep the
        // car inactive so clamping cannot repair a forged field before its range is tested.
        let (program, _) = make_stage(FINISH, &data);
        for (index, bad) in [
            (0, MIN_PROGRESS - 1),
            (0, classed_track_length_v1(data.track) * LAPS + 1),
            (1, -15_301),
            (1, 15_301),
            (2, -1),
            (2, 3_301),
            (3, -321),
            (3, 321),
            (4, -1),
            (4, 1_001),
            (5, -1),
            (5, 5_401),
            (6, -1),
            (6, 5_402),
        ] {
            let mut inputs = vec![0; 20];
            inputs[index] = bad;
            let row = program
                .witness(&inputs, &fixed)
                .into_iter()
                .map(field)
                .collect::<Vec<_>>();
            assert!(
                program
                    .residues(&row, &row, &fixed_fields)
                    .iter()
                    .any(|r| *r != F::ZERO),
                "accepted invalid FINISH field {index}={bad}"
            );
        }
    }

    #[test]
    fn forged_car_and_scratch_cannot_cross_their_producer_transition() {
        let data = replay(ClassedRaceTrackV1::Harbor, 8, 1);
        let mut state = initial_classed_race_state_v1(data.class_id, data.track, 8).unwrap();
        step_classed_race_v1(&mut state, &data.frames[0]).unwrap();
        let graph = StagedClassedRaceAirV1::compile(&data, &state, None).unwrap();
        let mut carry = graph.initial_carry();
        for index in 0..graph.rows_per_tick() {
            let fixed = graph.fixed_row(index, graph.trace_size()).unwrap();
            let (row, next_carry) = graph.witness(&carry, &fixed);
            let next_fixed = graph.fixed_row(index + 1, graph.trace_size()).unwrap();
            let (next, _) = graph.witness(&next_carry, &next_fixed);
            let fixed_fields = fixed.iter().copied().map(field).collect::<Vec<_>>();
            assert!(
                graph
                    .residues(&row, &next, &fixed_fields)
                    .iter()
                    .all(|r| *r == F::ZERO)
            );
            let columns = if fixed[SELECTORS + ENVIRONMENT] == 1 {
                (7 * graph.players..7 * graph.players + 3).collect::<Vec<_>>()
            } else if fixed[SELECTORS + CURVE] == 1 {
                vec![7 * graph.players + 3]
            } else if fixed[SELECTORS + DRIVE] == 1 {
                let slot = (0..graph.players)
                    .find(|slot| fixed[SLOT_PREFIX + slot] == 1)
                    .unwrap();
                vec![7 * slot + 2, 7 * slot + 4]
            } else {
                vec![]
            };
            for column in columns {
                // Change a consumer's carried operand and regenerate its entire arithmetic
                // bank, flags, and following state. The preceding producer must still reject
                // this coherent forged consumer, including changes remaining inside the range.
                for forged in [next_carry[column] + 1, next_carry[column] - 1] {
                    let mut changed = next_carry.clone();
                    changed[column] = forged;
                    let (changed_row, _) = graph.witness(&changed, &next_fixed);
                    assert!(
                        graph
                            .residues(&row, &changed_row, &fixed_fields)
                            .iter()
                            .any(|r| *r != F::ZERO),
                        "forged operand {column} crossed producer row {index}"
                    );
                }
            }
            carry = next_carry;
        }
    }

    #[test]
    fn producer_range_schedule_preserves_full_duration_row_geometry() {
        for (track, eight_car_width) in [
            (ClassedRaceTrackV1::NeonTokyo, 406),
            (ClassedRaceTrackV1::Harbor, 409),
            (ClassedRaceTrackV1::Sakura, 405),
        ] {
            for players in 1..=8 {
                let data = replay(track, players, MAX_TICKS);
                let mut state =
                    initial_classed_race_state_v1(data.class_id, track, players).unwrap();
                state.tick = MAX_TICKS;
                let graph = StagedClassedRaceAirV1::compile(&data, &state, None).unwrap();
                let players = usize::from(players);
                assert_eq!(graph.width(), eight_car_width - 12 * (8 - players));
                assert_eq!(
                    graph.rows_per_tick(),
                    1 + 7 * players + players * (players - 1) / 2
                );
                if players == 8 {
                    assert_eq!(graph.rows_per_tick(), 85);
                    assert_eq!(graph.trace_size(), 524_288);
                }
            }
        }
    }

    #[test]
    fn immutable_public_context_rejects_malformed_shapes_and_row_geometry() {
        let mut data = replay(ClassedRaceTrackV1::Harbor, 2, 0);
        let state = initial_classed_race_state_v1(data.class_id, data.track, 2).unwrap();
        let graph = StagedClassedRaceAirV1::compile(&data, &state, Some(&state)).unwrap();
        let before = graph.fixed_row(0, graph.trace_size()).unwrap();
        data.dnf_events.push(ClassedRaceDnfEventV1 {
            tick: 0,
            slots: vec![1],
        });
        assert_eq!(graph.fixed_row(0, graph.trace_size()).unwrap(), before);
        assert!(
            graph
                .fixed_row(graph.trace_size(), graph.trace_size())
                .is_err()
        );
        assert!(graph.fixed_row(0, graph.trace_size() * 2).is_err());
        data.dnf_events.push(ClassedRaceDnfEventV1 {
            tick: 0,
            slots: vec![0],
        });
        assert!(StagedClassedRaceAirV1::compile(&data, &state, None).is_err());
        let mut bad = replay(ClassedRaceTrackV1::Harbor, 2, 1);
        bad.frames[0].controls[0] = 64;
        assert!(StagedClassedRaceAirV1::compile(&bad, &state, None).is_err());
        let mut checkpoint = state.clone();
        checkpoint.track = ClassedRaceTrackV1::Sakura;
        assert!(
            StagedClassedRaceAirV1::compile(
                &replay(ClassedRaceTrackV1::Harbor, 2, 0),
                &state,
                Some(&checkpoint)
            )
            .is_err()
        );
    }

    fn check_isolated_tick(state: ClassedRaceStateV1, controls: Vec<u16>) {
        use super::super::race_air::ClassedRaceAirV1;
        let tick = state.tick;
        let mut data = replay(state.track, state.cars.len() as u8, tick + 1);
        data.frames[tick as usize].controls = controls;
        let mut expected = state.clone();
        step_classed_race_v1(&mut expected, &data.frames[tick as usize]).unwrap();
        let graph = StagedClassedRaceAirV1::compile(&data, &expected, None).unwrap();
        let mut carry = state.cars.iter().flat_map(car_values).collect::<Vec<_>>();
        carry.extend([0; 4]);
        let first = tick as usize * graph.rows_per_tick();
        for index in first..first + graph.rows_per_tick() {
            let fixed = graph.fixed_row(index, graph.trace_size()).unwrap();
            let (row, next_carry) = graph.witness(&carry, &fixed);
            let next_fixed = graph.fixed_row(index + 1, graph.trace_size()).unwrap();
            let (next_row, _) = graph.witness(&next_carry, &next_fixed);
            assert!(
                graph
                    .residues(
                        &row,
                        &next_row,
                        &fixed.into_iter().map(field).collect::<Vec<_>>()
                    )
                    .iter()
                    .all(|r| *r == F::ZERO),
                "isolated microcycle {index}"
            );
            carry = next_carry;
        }
        let expected_values = expected
            .cars
            .iter()
            .flat_map(car_values)
            .collect::<Vec<_>>();
        assert_eq!(&carry[..7 * graph.players], &expected_values);
        // A separately compiled whole-tick graph must derive precisely the same state.
        // These are intermediate-state tests, so genesis/final gates are outside this row.
        let whole = ClassedRaceAirV1::compile(&data, &expected, None).unwrap();
        let fixed = whole
            .fixed_row(tick as usize, (data.frames.len() + 2).next_power_of_two())
            .unwrap();
        let input = state.cars.iter().flat_map(car_values).collect::<Vec<_>>();
        let row = whole.air.witness(&input, &fixed);
        assert_eq!(whole.next_inputs(&row), expected_values);
    }

    #[test]
    fn all_controls_curve_extrema_contacts_and_finish_ghosts_match_both_graphs() {
        for mask in 0..=63 {
            for segment in [5, 9] {
                let mut state = initial_classed_race_state_v1(
                    ClassedRaceClassV1::TouringS1,
                    ClassedRaceTrackV1::Harbor,
                    8,
                )
                .unwrap();
                state.tick = 101;
                for (slot, car) in state.cars.iter_mut().enumerate() {
                    car.progress_mm =
                        classed_track_length_v1(state.track) * segment / 12 + slot as i64 * 9;
                    car.lateral_mm = [-15_300, 15_300, -6000, 6000, -1, 0, 1, 2][slot];
                    car.speed_mm_per_tick = [0, 3300, 3299, 2640, 2639, 100, 1, 3300][slot];
                    car.boost_energy = [0, 24, 25, 1000, 999, 1, 26, 25][slot];
                    car.lateral_velocity_mm_per_tick = if slot % 2 == 0 { -320 } else { 320 };
                }
                check_isolated_tick(state, vec![mask; 8]);
            }
        }
        let mut state = initial_classed_race_state_v1(
            ClassedRaceClassV1::TouringS1,
            ClassedRaceTrackV1::Harbor,
            8,
        )
        .unwrap();
        state.tick = 101;
        let finish = classed_track_length_v1(state.track) * LAPS;
        for (slot, car) in state.cars.iter_mut().enumerate() {
            car.progress_mm = finish - 1000 - slot as i64;
            car.lateral_mm = slot as i32;
            car.speed_mm_per_tick = 3300;
        }
        state.cars[1].progress_mm = finish;
        state.cars[1].finish_tick = Some(100);
        state.cars[2].dnf_tick = Some(100);
        state.cars[3].progress_mm = finish;
        state.cars[3].finish_tick = Some(99);
        state.cars[3].dnf_tick = Some(100);
        check_isolated_tick(state, vec![33; 8]);
    }

    #[test]
    fn weather_object_edges_and_touring_speed_match_both_graphs() {
        for track in [
            ClassedRaceTrackV1::NeonTokyo,
            ClassedRaceTrackV1::Harbor,
            ClassedRaceTrackV1::Sakura,
        ] {
            // Every public weather boundary, including both maximum wind signs.
            for tick in [89, 90, 179, 180, 299, 300, 539, 540, 599, 600, 899, 900] {
                let mut state =
                    initial_classed_race_state_v1(ClassedRaceClassV1::TouringS1, track, 8).unwrap();
                state.tick = tick;
                for (slot, car) in state.cars.iter_mut().enumerate() {
                    let cell = slot % 12;
                    car.progress_mm = environment::centers(track)[cell] - 1_500;
                    car.lateral_mm = environment::laterals(track)[cell] as i32;
                    car.speed_mm_per_tick = 3_300;
                    car.lateral_velocity_mm_per_tick = if slot % 2 == 0 { -320 } else { 320 };
                }
                check_isolated_tick(state, vec![33 | 16 | 4; 8]);
            }
            for cell in 0..12 {
                for offset in [-9_001, -9_000, -1, 0, 9_000, 9_001] {
                    let mut state =
                        initial_classed_race_state_v1(ClassedRaceClassV1::TouringS1, track, 8)
                            .unwrap();
                    state.tick = environment::rain_pattern(track)
                        .iter()
                        .position(|rain| *rain == 1)
                        .unwrap() as u32
                        * environment::WEATHER_TICKS
                        + 1;
                    for (slot, car) in state.cars.iter_mut().enumerate() {
                        car.progress_mm = environment::centers(track)[cell] + offset;
                        car.lateral_mm = (environment::laterals(track)[cell]
                            + [-1_401, -1_400, -1_300, 0, 1_299, 1_300, 1_400, 1_401][slot])
                            as i32;
                        car.speed_mm_per_tick = 3_300;
                        car.lateral_velocity_mm_per_tick = 0;
                    }
                    // A removed car at the same object must remain frozen while others hit it.
                    state.cars[7].dnf_tick = Some(state.tick - 1);
                    check_isolated_tick(state, vec![33; 8]);
                }
            }
        }
    }

    #[test]
    fn actual_weather_fixed_columns_cannot_be_changed_without_rechecking_equations() {
        let mut state = initial_classed_race_state_v1(
            ClassedRaceClassV1::TouringS1,
            ClassedRaceTrackV1::Harbor,
            2,
        )
        .unwrap();
        state.tick = 540;
        state.cars[0].speed_mm_per_tick = 3_300;
        state.cars[0].lateral_velocity_mm_per_tick = 100;
        let mut data = replay(state.track, 2, state.tick + 1);
        data.frames[state.tick as usize].controls = vec![33 | 8, 0];
        let mut expected = state.clone();
        step_classed_race_v1(&mut expected, &data.frames[state.tick as usize]).unwrap();
        let graph = StagedClassedRaceAirV1::compile(&data, &expected, None).unwrap();
        let mut carry = state.cars.iter().flat_map(car_values).collect::<Vec<_>>();
        carry.extend([0; 4]);
        let first = state.tick as usize * graph.rows_per_tick();
        for index in first..first + graph.rows_per_tick() {
            let fixed = graph.fixed_row(index, graph.trace_size()).unwrap();
            assert_eq!((fixed[7], fixed[8]), (1, -32));
            let (row, next_carry) = graph.witness(&carry, &fixed);
            let next_fixed = graph.fixed_row(index + 1, graph.trace_size()).unwrap();
            let (next, _) = graph.witness(&next_carry, &next_fixed);
            for (stage, column, changed) in [(GRIP, 7, 0), (CURVE, 8, 32)] {
                if fixed[SELECTORS + stage] == 1 && fixed[SLOT_PREFIX] == 1 {
                    let mut altered = fixed.iter().copied().map(field).collect::<Vec<_>>();
                    altered[column] = field(changed);
                    assert!(
                        graph
                            .residues(&row, &next, &altered)
                            .iter()
                            .any(|r| *r != F::ZERO)
                    );
                }
            }
            carry = next_carry;
        }
    }

    #[test]
    fn packed_relation_degree_is_at_most_four_on_independent_lines() {
        let data = replay(ClassedRaceTrackV1::Harbor, 8, 0);
        let state = initial_classed_race_state_v1(data.class_id, data.track, 8).unwrap();
        let graph = StagedClassedRaceAirV1::compile(&data, &state, Some(&state)).unwrap();
        for seed in [1, 17, 93] {
            let mut samples = (0..6)
                .map(|t| {
                    let line = |length: usize, salt: i64| {
                        (0..length)
                            .map(|i| {
                                field((i as i64 * 19 + salt + seed) * t + (i as i64 * 7 + salt * 3))
                            })
                            .collect::<Vec<_>>()
                    };
                    graph.residues(
                        &line(graph.width(), 3),
                        &line(graph.width(), 5),
                        &line(graph.fixed_width(), 7),
                    )
                })
                .collect::<Vec<_>>();
            for _ in 0..5 {
                samples = samples
                    .windows(2)
                    .map(|pair| {
                        pair[1]
                            .iter()
                            .zip(&pair[0])
                            .map(|(a, b)| a.sub(*b))
                            .collect()
                    })
                    .collect();
            }
            assert!(
                samples[0].iter().all(|r| *r == F::ZERO),
                "degree exceeds four"
            );
        }
    }
}
