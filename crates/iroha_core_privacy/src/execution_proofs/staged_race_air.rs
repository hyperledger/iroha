//! Narrow microcycle `RaceV1` AIR with shared range-check banks.
//!
//! Each public tick executes a boundary row, six rows per car, every ordered pair,
//! and one finish row per car. The state is carried between rows; fixed selectors bind
//! the exact schedule. No prover-chosen opcode or indirect memory access is accepted.

use super::{
    integer_air::{IntegerAirV1, PackedIntegerAirV1, Value, field},
    race::initial_race_state_v1,
    race_air::car_values,
};
use crate::privacy_engines::transparent_stark::GoldilocksFieldV1 as F;
use iroha_data_model::execution_proofs::{RaceReplayV1, RaceStateV1};

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
// tick,enabled,first,transition,final,checkpoint,batch-boundary, six stage selectors,
// left-slot selectors, right-slot selectors, DNF selectors, acceleration/steer/boost.
const SELECTORS: usize = 9;
const SLOT_PREFIX: usize = SELECTORS + STAGES;

pub(super) struct StagedRaceAirV1 {
    players: usize,
    pub(super) packed: PackedIntegerAirV1,
    outputs: Vec<[Value; 18]>,
    stages: Vec<(usize, Option<usize>, Option<usize>)>,
    grid: Vec<i64>,
    final_state: Vec<i64>,
    checkpoint: Option<Vec<i64>>,
}
fn make_stage(stage: usize, replay: &RaceReplayV1) -> (IntegerAirV1, [Value; 18]) {
    let mut a = IntegerAirV1::default();
    let finish = replay.track.length_mm() * 3;
    let length = replay.track.length_mm();
    let mut car = || {
        [
            a.input(-12_000, finish + 3_000),
            a.input(-16_200, 16_200),
            a.input(0, 3_000),
            a.input(-320, 320),
            a.input(0, 1_000),
            a.input(0, 5_400),
            a.input(0, 5_401),
        ]
    };
    let left = car();
    let right = car();
    let running = a.input(0, 1);
    let running_right = a.input(0, 1);
    let relative = a.input(-2_400_000, 2_400_000);
    let kind = a.input(0, 2);
    let object_x = a.input(-7_400, 7_400);
    let force = a.input(-115, 115);
    let mut x = left;
    let mut y = right;
    let mut scratch = [relative, kind, object_x, force];
    let zero = Value::constant(0);
    let one = Value::constant(1);
    let control = SLOT_PREFIX + 3 * usize::from(replay.player_count);
    let acceleration = Value::fixed(control, -100, 40);
    let steer = Value::fixed(control + 1, -28, 28);
    let boost = Value::fixed(control + 2, 0, 1);
    if stage == DRIVE {
        let insufficient = a.less(left[4], Value::constant(25));
        let enough = a.not(insufficient);
        let boosting = a.and(boost, enough);
        let drained = a.sub_constant(left[4], 25);
        let recharged = a.add_constant(left[4], 4);
        let replenished = a.minimum(recharged, Value::constant(1_000));
        let energy = a.select(boosting, drained, replenished);
        let top = a.select(boosting, Value::constant(3_000), Value::constant(2_400));
        let accelerated = a.add(left[2], acceleration);
        let positive = a.maximum(accelerated, zero);
        let speed = a.minimum(positive, top);
        x[2] = a.select(running, speed, left[2]);
        x[4] = a.select(running, energy, left[4]);
    } else if stage == ENVIRONMENT {
        scratch[..3].copy_from_slice(&super::environment_air::geometry(
            &mut a,
            replay.track,
            left[0],
        ));
    } else if stage == GRIP {
        let [vx, _] = super::environment_air::lateral_velocity_from_geometry(
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
        let curvature = a.lookup(segment, &replay.track.curvature().map(i64::from));
        let curve_speed = a.mul(curvature, left[2]);
        let curve_force = a.divide(curve_speed, 120);
        let wind_force = a.mul(Value::fixed(8, -32, 32), left[2]);
        let wind_force = a.divide(wind_force, 2400);
        let force = a.add(curve_force, wind_force);
        scratch[3] = a.select(running, force, zero);
    } else if stage == MOVE {
        let steered = a.add(left[1], left[3]);
        let displaced = a.add(steered, force);
        let lateral = a.clamp(displaced, -9_000, 9_000);
        let absolute = a.absolute(lateral);
        let offroad = a.less(Value::constant(6_000), absolute);
        let slowed = a.sub_constant(left[2], 90);
        let slowed = a.maximum(slowed, zero);
        let speed = a.select(offroad, slowed, left[2]);
        let progress = a.add(left[0], speed);
        x[0] = a.select(running, progress, left[0]);
        x[1] = a.select(running, lateral, left[1]);
        x[2] = a.select(running, speed, left[2]);
    } else if stage == IMPACT {
        let [lateral, speed, _, _] = super::environment_air::impact_from_geometry(
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
        let near = a.less(delta, Value::constant(3_600));
        let lateral = a.sub(left[1], right[1]);
        let separation = a.absolute(lateral);
        let touching = a.less(separation, Value::constant(1_800));
        let both = a.and(running, running_right);
        let contact = a.and(near, touching);
        let contact = a.and(both, contact);
        let overlap = a.sub(Value::constant(1_800), separation);
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
            let slowed = a.sub_constant(car[2], 120);
            let slowed = a.maximum(slowed, zero);
            car[2] = a.select(contact, slowed, car[2]);
        }
    } else if stage == FINISH {
        let before = a.less(left[0], Value::constant(finish));
        let crossed = a.not(before);
        let crossed = a.and(crossed, running);
        x[0] = a.select(crossed, Value::constant(finish), left[0]);
        let tick = a.add(Value::fixed(0, 0, 5_400), one);
        x[5] = a.select(crossed, tick, left[5]);
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
        (0..=5_401)
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
impl StagedRaceAirV1 {
    pub(super) fn compile(
        replay: &RaceReplayV1,
        final_state: &RaceStateV1,
        checkpoint: Option<&RaceStateV1>,
    ) -> Self {
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
        Self {
            players,
            packed: PackedIntegerAirV1::new(programs),
            outputs,
            stages,
            grid: initial_race_state_v1(replay.track, replay.player_count)
                .expect("catalog")
                .cars
                .iter()
                .flat_map(car_values)
                .collect(),
            final_state: final_state.cars.iter().flat_map(car_values).collect(),
            checkpoint: checkpoint.map(|state| state.cars.iter().flat_map(car_values).collect()),
        }
    }
    pub(super) fn rows_per_tick(&self) -> usize {
        self.stages.len()
    }
    pub(super) fn trace_size(&self, replay: &RaceReplayV1) -> usize {
        ((replay.frames.len() + 1) * self.rows_per_tick() + 1)
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
        replay: &RaceReplayV1,
        row: usize,
        size: usize,
        checkpoint: Option<u32>,
    ) -> Vec<i64> {
        let phases = self.rows_per_tick();
        let tick = row / phases;
        let phase = row % phases;
        let (stage, left, right) = self.stages[phase];
        let final_row = (replay.frames.len() + 1) * phases;
        let mut fixed = vec![
            tick.min(5_400) as i64,
            i64::from(tick < replay.frames.len()),
            i64::from(row == 0),
            i64::from(row + 1 < size),
            i64::from(row == final_row),
            i64::from(checkpoint.is_some_and(|tick| row == tick as usize * phases)),
            i64::from(phase == 0 && tick < replay.frames.len() && tick % 6 == 0),
        ];
        let (rain, wind) = super::environment::weather(replay.track, tick.min(5_400) as u32);
        fixed.extend([rain, wind]);
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
                -100
            } else if control & 1 != 0 {
                40
            } else {
                -12
            },
            (i64::from(control & 8 != 0) - i64::from(control & 4 != 0))
                * if control & 16 != 0 { 28 } else { 18 },
            i64::from(control & 32 != 0),
        ]);
        fixed
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
        // All stages have the same first 20 normal-bank input columns.
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
    use super::super::race::{apply_race_dnf_v1, step_race_v1};
    use super::*;
    use iroha_data_model::execution_proofs::{RaceDnfEventV1, RaceInputFrameV1, RaceTrackV1};
    #[test]
    fn narrow_microcycles_match_reference_and_all_residues() {
        for track in [
            RaceTrackV1::NeonTokyo,
            RaceTrackV1::Harbor,
            RaceTrackV1::Sakura,
        ] {
            for players in [2_u8, 8] {
                let mut replay = RaceReplayV1 {
                    track,
                    player_count: players,
                    frames: vec![],
                    dnf_events: vec![RaceDnfEventV1 {
                        tick: 120,
                        slots: (0..players).collect(),
                    }],
                };
                let mut reference = initial_race_state_v1(track, players).expect("grid");
                let mut expected = vec![reference.clone()];
                for tick in 0..120 {
                    let frame = RaceInputFrameV1 {
                        tick,
                        controls: (0..players)
                            .map(|slot| ((tick * 13 + u32::from(slot) * 19) % 64) as u16)
                            .collect(),
                    };
                    step_race_v1(&mut reference, &frame).expect("step");
                    expected.push(reference.clone());
                    replay.frames.push(frame);
                }
                apply_race_dnf_v1(&mut reference, &(0..players).collect::<Vec<_>>())
                    .expect("terminal dnf");
                let compiled = StagedRaceAirV1::compile(&replay, &reference, Some(&expected[60]));
                println!(
                    "narrow players={players} track={track:?} width={} constraints={} rows/tick={}",
                    compiled.width(),
                    compiled.constraint_count(),
                    compiled.rows_per_tick()
                );
                let size = compiled.trace_size(&replay);
                let mut carry = compiled.initial_carry();
                for row_index in 0..size {
                    let fixed = compiled.fixed_row(&replay, row_index, size, Some(60));
                    let (row, next) = compiled.witness(&carry, &fixed);
                    if row_index % compiled.rows_per_tick() == 0
                        && row_index / compiled.rows_per_tick() <= 120
                    {
                        assert_eq!(
                            &carry[..7 * usize::from(players)],
                            &expected[row_index / compiled.rows_per_tick()]
                                .cars
                                .iter()
                                .flat_map(car_values)
                                .collect::<Vec<_>>()
                        );
                    }
                    let next_fixed = compiled.fixed_row(&replay, row_index + 1, size, Some(60));
                    let (next_row, _) = compiled.witness(&next, &next_fixed);
                    let residues = compiled.residues(
                        &row,
                        &next_row,
                        &fixed.iter().copied().map(field).collect::<Vec<_>>(),
                    );
                    assert!(
                        residues.iter().all(|value| *value == F::ZERO),
                        "residue row={row_index} positions={:?}",
                        residues
                            .iter()
                            .enumerate()
                            .filter(|(_, v)| **v != F::ZERO)
                            .collect::<Vec<_>>()
                    );
                    carry = next;
                }
                assert_eq!(
                    &carry[..7 * usize::from(players)],
                    &reference
                        .cars
                        .iter()
                        .flat_map(car_values)
                        .collect::<Vec<_>>()
                );
            }
        }
    }
    #[test]
    fn packed_relation_remains_degree_four() {
        let replay = RaceReplayV1 {
            track: RaceTrackV1::Harbor,
            player_count: 8,
            frames: vec![],
            dnf_events: vec![],
        };
        let state = initial_race_state_v1(replay.track, 8).expect("grid");
        let air = StagedRaceAirV1::compile(&replay, &state, Some(&state));
        let mut lines = Vec::new();
        for t in 0..6 {
            let line = |length: usize, salt: i64| {
                (0..length)
                    .map(|i| field((i as i64 * 19 + salt) * t + (i as i64 * 7 + salt * 3)))
                    .collect::<Vec<_>>()
            };
            lines.push(air.residues(
                &line(air.width(), 3),
                &line(air.width(), 5),
                &line(air.fixed_width(), 7),
            ));
        }
        for _ in 0..5 {
            lines = lines
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
            lines[0].iter().all(|r| *r == F::ZERO),
            "degree exceeds four"
        );
    }
}

#[cfg(test)]
mod full_duration_tests {
    use super::super::race::{apply_race_dnf_v1, step_race_v1};
    use super::*;
    use iroha_data_model::execution_proofs::{RaceDnfEventV1, RaceInputFrameV1, RaceTrackV1};
    #[test]
    fn all_three_full_duration_eight_car_microcycle_traces_match_reference() {
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
                    tick: 1200,
                    slots: vec![7],
                }],
            };
            let mut reference = initial_race_state_v1(track, 8).expect("grid");
            let mut expected = vec![
                reference
                    .cars
                    .iter()
                    .flat_map(car_values)
                    .collect::<Vec<_>>(),
            ];
            let mut checkpoint = None;
            for tick in 0..5400 {
                if tick == 1200 {
                    checkpoint = Some(reference.clone());
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
                expected.push(reference.cars.iter().flat_map(car_values).collect());
            }
            let compiled = StagedRaceAirV1::compile(&replay, &reference, checkpoint.as_ref());
            let size = compiled.trace_size(&replay);
            assert_eq!(size, 1 << 19);
            let mut carry = compiled.initial_carry();
            let mut previous: Option<(Vec<F>, Vec<F>)> = None;
            for row_index in 0..size {
                if row_index % compiled.rows_per_tick() == 0
                    && row_index / compiled.rows_per_tick() <= 5400
                {
                    assert_eq!(
                        &carry[..56],
                        &expected[row_index / compiled.rows_per_tick()],
                        "{track:?} tick boundary {row_index}"
                    );
                }
                let fixed = compiled.fixed_row(&replay, row_index, size, Some(1200));
                let (row, next) = compiled.witness(&carry, &fixed);
                if let Some((prior, prior_fixed)) = previous.take() {
                    assert!(
                        compiled
                            .residues(&prior, &row, &prior_fixed)
                            .iter()
                            .all(|r| *r == F::ZERO),
                        "{track:?} microcycle {}",
                        row_index - 1
                    );
                }
                previous = Some((row, fixed.into_iter().map(field).collect()));
                carry = next;
            }
            let (last, fixed) = previous.expect("last row");
            assert!(
                compiled
                    .residues(&last, &last, &fixed)
                    .iter()
                    .all(|r| *r == F::ZERO)
            );
            assert_eq!(&carry[..56], expected.last().expect("final"));
            println!(
                "complete narrow {track:?}: 5400 ticks, {size} rows, {} columns, all residues zero",
                compiled.width()
            );
        }
    }
}
