//! Exact bounded integer reference for Touring S1; no proof or admission is substituted here.
use super::{environment, rules::*};
use iroha_data_model::classed_race_v1::{
    ClassedRaceCarStateV1, ClassedRaceClassV1, ClassedRaceInputFrameV1, ClassedRaceReplayV1,
    ClassedRaceResultV1, ClassedRaceStandingV1, ClassedRaceStateV1, ClassedRaceTrackV1,
};
use thiserror::Error;

/// Invalid simulation input; errors never partially mutate a caller's state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum ClassedRaceSimulationErrorV1 {
    /// Unsupported replay generation.
    #[error("classed replay version must be one")]
    Version,
    /// Outside the bounded practice/multiplayer grid range.
    #[error("classed racing requires one to eight cars")]
    PlayerCount,
    /// Input is missing or adds a permanent slot.
    #[error("classed input does not match the roster")]
    ControlCount,
    /// Reserved control bits are not meaningful input.
    #[error("classed input contains reserved control bits")]
    ControlBits,
    /// Frame/event tick is absent, repeated or out of sequence.
    #[error("classed replay tick sequence is not canonical")]
    TickSequence,
    /// A removal set is empty, repeated, unsorted or references an absent slot.
    #[error("classed removal sequence is not canonical")]
    DnfSequence,
    /// No further ticks are admitted at a terminal boundary.
    #[error("classed race is terminal or exceeds its duration bound")]
    Terminal,
    /// Caller-supplied state is outside the exact integer/state-machine bounds.
    #[error("classed state is outside its bounded domain")]
    StateBounds,
    /// Checked host arithmetic or a narrowing conversion exceeded its range.
    #[error("classed integer operation overflowed")]
    ArithmeticOverflow,
}

/// Immutable two-column grid; skin, kit price and per-car tuning cannot alter it.
///
/// # Errors
/// Returns `PlayerCount` unless the grid contains one to eight cars.
pub fn initial_classed_race_state_v1(
    class_id: ClassedRaceClassV1,
    track: ClassedRaceTrackV1,
    player_count: u8,
) -> Result<ClassedRaceStateV1, ClassedRaceSimulationErrorV1> {
    if !(1..=MAX_PLAYERS).contains(&player_count) {
        return Err(ClassedRaceSimulationErrorV1::PlayerCount);
    }
    let spec = class_performance_v1(class_id);
    Ok(ClassedRaceStateV1 {
        tick: 0,
        class_id,
        track,
        cars: (0..player_count)
            .map(|slot| ClassedRaceCarStateV1 {
                progress_mm: -i64::from(slot / 2) * 4_000,
                lateral_mm: if slot % 2 == 0 { -1_800 } else { 1_800 },
                speed_mm_per_tick: 0,
                lateral_velocity_mm_per_tick: 0,
                boost_energy: spec.boost_capacity,
                finish_tick: None,
                dnf_tick: None,
            })
            .collect(),
    })
}

fn validate(state: &ClassedRaceStateV1) -> Result<(), ClassedRaceSimulationErrorV1> {
    if state.cars.is_empty() || state.cars.len() > usize::from(MAX_PLAYERS) {
        return Err(ClassedRaceSimulationErrorV1::PlayerCount);
    }
    let spec = class_performance_v1(state.class_id);
    let finish = classed_track_length_v1(state.track) * LAPS;
    if state.tick > MAX_TICKS || state.cars.iter().any(|car| {
        !(MIN_PROGRESS..=finish).contains(&car.progress_mm)
            || !(-STATE_LATERAL_LIMIT..=STATE_LATERAL_LIMIT).contains(&car.lateral_mm)
            || !(0..=spec.boost_speed).contains(&i64::from(car.speed_mm_per_tick))
            || !(-LATERAL_SPEED_LIMIT..=LATERAL_SPEED_LIMIT)
                .contains(&i64::from(car.lateral_velocity_mm_per_tick))
            || car.boost_energy > spec.boost_capacity
            || car
                .finish_tick
                .is_some_and(|tick| tick == 0 || tick > state.tick)
            || (car.finish_tick.is_some() != (car.progress_mm == finish))
            || car.dnf_tick.is_some_and(|tick| tick > state.tick)
            || matches!((car.finish_tick, car.dnf_tick), (Some(finish), Some(dnf)) if finish > dnf)
    }) {
        return Err(ClassedRaceSimulationErrorV1::StateBounds);
    }
    Ok(())
}

fn terminal(state: &ClassedRaceStateV1) -> bool {
    state.tick == MAX_TICKS
        || state.tick % BATCH_TICKS == 0
            && (state
                .cars
                .iter()
                .all(|car| car.finish_tick.is_some() || car.dnf_tick.is_some())
                || state.cars.len() >= 2
                    && state
                        .cars
                        .iter()
                        .filter(|car| car.dnf_tick.is_none())
                        .count()
                        < 2)
}

/// Return the canonical batch-aligned termination predicate after validating the state.
///
/// # Errors
/// Returns `PlayerCount` or `StateBounds` when the supplied state is outside
/// the admitted roster, tick or car-state bounds.
pub fn classed_race_is_terminal_v1(
    state: &ClassedRaceStateV1,
) -> Result<bool, ClassedRaceSimulationErrorV1> {
    validate(state)?;
    Ok(terminal(state))
}

fn narrow(value: i64) -> Result<i32, ClassedRaceSimulationErrorV1> {
    i32::try_from(value).map_err(|_| ClassedRaceSimulationErrorV1::ArithmeticOverflow)
}

/// Advance one tick with truncation toward zero and canonical ascending pair contacts.
///
/// The validated public state bounds make every i64 intermediate smaller than 2^27.
/// Checked addition/conversion and a staged copy additionally make failures atomic.
///
/// # Errors
/// Rejects invalid state, terminal races, nonsequential ticks, mismatched
/// control counts or reserved control bits. Arithmetic overflow and invalid
/// successor state also fail; the original state remains unchanged.
pub fn step_classed_race_v1(
    state: &mut ClassedRaceStateV1,
    frame: &ClassedRaceInputFrameV1,
) -> Result<(), ClassedRaceSimulationErrorV1> {
    validate(state)?;
    if terminal(state) {
        return Err(ClassedRaceSimulationErrorV1::Terminal);
    }
    if frame.tick != state.tick {
        return Err(ClassedRaceSimulationErrorV1::TickSequence);
    }
    if frame.controls.len() != state.cars.len() {
        return Err(ClassedRaceSimulationErrorV1::ControlCount);
    }
    if frame
        .controls
        .iter()
        .any(|control| control & !CONTROL_MASK != 0)
    {
        return Err(ClassedRaceSimulationErrorV1::ControlBits);
    }
    let spec = class_performance_v1(state.class_id);
    let length = classed_track_length_v1(state.track);
    let curves = classed_track_curvature_v1(state.track);
    let mut next = state.clone();
    for (car, control) in next.cars.iter_mut().zip(&frame.controls) {
        if car.finish_tick.is_some() || car.dnf_tick.is_some() {
            continue;
        }
        let boost = control & 32 != 0 && car.boost_energy >= spec.boost_cost;
        car.boost_energy = if boost {
            car.boost_energy - spec.boost_cost
        } else {
            car.boost_energy
                .checked_add(spec.boost_recharge)
                .ok_or(ClassedRaceSimulationErrorV1::ArithmeticOverflow)?
                .min(spec.boost_capacity)
        };
        let maximum = if boost {
            spec.boost_speed
        } else {
            spec.normal_speed
        };
        let acceleration = if control & 2 != 0 {
            -spec.brake
        } else if control & 1 != 0 {
            spec.acceleration
        } else {
            -spec.coast
        };
        car.speed_mm_per_tick =
            narrow((i64::from(car.speed_mm_per_tick) + acceleration).clamp(0, maximum))?;
        let steer = i64::from(control & 8 != 0) - i64::from(control & 4 != 0);
        let force = if control & 16 != 0 {
            spec.drift_steering
        } else {
            spec.steering
        };
        let old_progress = car.progress_mm;
        let vx = environment::lateral_velocity(
            state.track,
            state.tick,
            old_progress,
            car.lateral_mm,
            car.lateral_velocity_mm_per_tick,
            narrow(steer * force)?,
        );
        car.lateral_velocity_mm_per_tick = vx;
        let segment = usize::try_from(car.progress_mm.rem_euclid(length) * 12 / length)
            .map_err(|_| ClassedRaceSimulationErrorV1::ArithmeticOverflow)?;
        let curvature = *curves
            .get(segment)
            .ok_or(ClassedRaceSimulationErrorV1::StateBounds)?;
        let wind = environment::weather(state.track, state.tick).1;
        let speed = i64::from(car.speed_mm_per_tick);
        let lateral = (i64::from(car.lateral_mm)
            + i64::from(vx)
            + curvature * speed / 120
            + wind * speed / 2_400)
            .clamp(-MOVE_LATERAL_LIMIT, MOVE_LATERAL_LIMIT);
        car.lateral_mm = narrow(lateral)?;
        if lateral.abs() > ROAD_HALF_WIDTH {
            car.speed_mm_per_tick =
                narrow((i64::from(car.speed_mm_per_tick) - spec.offroad_penalty).max(0))?;
        }
        car.progress_mm = car
            .progress_mm
            .checked_add(i64::from(car.speed_mm_per_tick))
            .ok_or(ClassedRaceSimulationErrorV1::ArithmeticOverflow)?;
        (car.lateral_mm, car.speed_mm_per_tick) = environment::impact(
            state.track,
            old_progress,
            car.progress_mm,
            car.lateral_mm,
            car.speed_mm_per_tick,
        );
    }
    for left_slot in 0..next.cars.len() {
        for right_slot in left_slot + 1..next.cars.len() {
            let (left, right) = next.cars.split_at_mut(right_slot);
            let a = &mut left[left_slot];
            let b = &mut right[0];
            if a.finish_tick.is_some()
                || b.finish_tick.is_some()
                || a.dnf_tick.is_some()
                || b.dnf_tick.is_some()
                || (a.progress_mm - b.progress_mm).abs() >= CONTACT_DISTANCE
                || (i64::from(a.lateral_mm) - i64::from(b.lateral_mm)).abs() >= CONTACT_WIDTH
            {
                continue;
            }
            let push =
                (CONTACT_WIDTH - (i64::from(a.lateral_mm) - i64::from(b.lateral_mm)).abs() + 1) / 2;
            let direction = if a.lateral_mm <= b.lateral_mm { -1 } else { 1 };
            a.lateral_mm = narrow(i64::from(a.lateral_mm) + direction * push)?;
            b.lateral_mm = narrow(i64::from(b.lateral_mm) - direction * push)?;
            a.speed_mm_per_tick =
                narrow((i64::from(a.speed_mm_per_tick) - spec.contact_penalty).max(0))?;
            b.speed_mm_per_tick =
                narrow((i64::from(b.speed_mm_per_tick) - spec.contact_penalty).max(0))?;
        }
    }
    next.tick = next
        .tick
        .checked_add(1)
        .ok_or(ClassedRaceSimulationErrorV1::ArithmeticOverflow)?;
    let finish = length * LAPS;
    for car in &mut next.cars {
        if car.finish_tick.is_none() && car.dnf_tick.is_none() && car.progress_mm >= finish {
            car.progress_mm = finish;
            car.finish_tick = Some(next.tick);
        }
    }
    validate(&next)?;
    *state = next;
    Ok(())
}

/// Apply a unique ascending consensus removal set; preserve earlier finishes and reject repeats.
///
/// # Errors
/// Rejects invalid state or an empty, oversized, unsorted, repeated or
/// out-of-roster removal set, including slots already removed.
pub fn apply_classed_race_dnf_v1(
    state: &mut ClassedRaceStateV1,
    slots: &[u8],
) -> Result<(), ClassedRaceSimulationErrorV1> {
    validate(state)?;
    if slots.is_empty()
        || slots.len() > state.cars.len()
        || slots.windows(2).any(|pair| pair[0] >= pair[1])
        || slots.iter().any(|slot| {
            usize::from(*slot) >= state.cars.len()
                || state.cars[usize::from(*slot)].dnf_tick.is_some()
        })
    {
        return Err(ClassedRaceSimulationErrorV1::DnfSequence);
    }
    for slot in slots {
        state.cars[usize::from(*slot)].dnf_tick = Some(state.tick);
    }
    Ok(())
}

/// Replay from the exact grid, rejecting noncanonical events and any tick after termination.
///
/// # Errors
/// Rejects unsupported versions, invalid player counts, excessive duration,
/// noncanonical frame or removal sequences, and invalid controls. State-bound
/// and arithmetic failures from individual replay steps are propagated.
pub fn replay_classed_race_v1(
    replay: &ClassedRaceReplayV1,
) -> Result<ClassedRaceStateV1, ClassedRaceSimulationErrorV1> {
    if replay.version != 1 {
        return Err(ClassedRaceSimulationErrorV1::Version);
    }
    if replay.frames.len() > MAX_TICKS as usize {
        return Err(ClassedRaceSimulationErrorV1::Terminal);
    }
    if replay.dnf_events.len() > usize::from(MAX_PLAYERS) {
        return Err(ClassedRaceSimulationErrorV1::DnfSequence);
    }
    let mut state =
        initial_classed_race_state_v1(replay.class_id, replay.track, replay.player_count)?;
    if replay
        .dnf_events
        .windows(2)
        .any(|pair| pair[0].tick >= pair[1].tick)
        || replay
            .dnf_events
            .iter()
            .any(|event| event.tick > replay.frames.len() as u32)
    {
        return Err(ClassedRaceSimulationErrorV1::TickSequence);
    }
    let mut events = replay.dnf_events.iter().peekable();
    for frame in &replay.frames {
        if events.peek().is_some_and(|event| event.tick == state.tick) {
            if let Some(event) = events.next() {
                apply_classed_race_dnf_v1(&mut state, &event.slots)?;
            }
        }
        step_classed_race_v1(&mut state, frame)?;
    }
    if let Some(event) = events.next() {
        apply_classed_race_dnf_v1(&mut state, &event.slots)?;
    }
    Ok(state)
}

/// Derive a terminal result; prefixes have display standings but never a payout winner list.
///
/// # Errors
/// Returns `PlayerCount` or `StateBounds` when the supplied state is invalid.
pub fn classed_race_result_v1(
    state: &ClassedRaceStateV1,
) -> Result<ClassedRaceResultV1, ClassedRaceSimulationErrorV1> {
    validate(state)?;
    let mut standings: Vec<_> = state
        .cars
        .iter()
        .enumerate()
        .map(|(slot, car)| ClassedRaceStandingV1 {
            slot: slot as u8,
            finish_tick: car.finish_tick,
            dnf_tick: car.dnf_tick,
            progress_mm: car.progress_mm,
        })
        .collect();
    standings.sort_by(|a, b| {
        // Eligibility precedes every finish/distance comparison: an input key can
        // forfeit after physically finishing, which preserves history but loses prizes.
        a.dnf_tick
            .is_some()
            .cmp(&b.dnf_tick.is_some())
            .then_with(|| match (a.finish_tick, b.finish_tick) {
                (Some(x), Some(y)) => x.cmp(&y).then(a.slot.cmp(&b.slot)),
                (Some(_), None) => std::cmp::Ordering::Less,
                (None, Some(_)) => std::cmp::Ordering::Greater,
                (None, None) => b.progress_mm.cmp(&a.progress_mm).then(a.slot.cmp(&b.slot)),
            })
    });
    let is_terminal = terminal(state);
    let mut winners = Vec::new();
    if is_terminal {
        let eligible: Vec<_> = standings
            .iter()
            .filter(|car| car.dnf_tick.is_none())
            .collect();
        if let Some(earliest) = eligible.first().and_then(|car| car.finish_tick) {
            winners.extend(
                eligible
                    .iter()
                    .filter(|car| car.finish_tick == Some(earliest))
                    .map(|car| car.slot),
            );
        } else if eligible.len() == 1 {
            winners.push(eligible[0].slot);
        } else if state.tick == MAX_TICKS {
            if let Some(leader) = eligible.first() {
                winners.extend(
                    eligible
                        .iter()
                        .filter(|car| car.progress_mm == leader.progress_mm)
                        .map(|car| car.slot),
                );
            }
        }
    }
    winners.sort_unstable();
    Ok(ClassedRaceResultV1 {
        class_id: state.class_id,
        track: state.track,
        ticks: state.tick,
        terminal: is_terminal,
        standings,
        winners,
    })
}
