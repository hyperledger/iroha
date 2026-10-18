//! Exact integer `RaceV1` reference simulation shared by trace generation and replay tools.

use iroha_data_model::execution_proofs::{
    RACE_CONTROL_MASK_V1, RACE_LAPS_V1, RACE_MAX_PLAYERS_V1, RACE_MAX_TICKS_V1, RaceCarStateV1,
    RaceInputFrameV1, RaceReplayV1, RaceResultV1, RaceStandingV1, RaceStateV1, RaceTrackV1,
};
use thiserror::Error;

/// Invalid replay structure or simulation state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum RaceSimulationErrorV1 {
    /// Player count is outside the fixed catalog bound.
    #[error("race requires between one and eight players")]
    PlayerCount,
    /// Controls do not contain exactly one mask per participant.
    #[error("race input frame does not match the participant count")]
    ControlCount,
    /// Reserved control bits were set.
    #[error("race controls contain reserved bits")]
    ControlBits,
    /// Frame sequence differs from the current state tick.
    #[error("race frame tick is not consecutive")]
    TickSequence,
    /// The run has already reached its fixed terminal boundary.
    #[error("race is already terminal")]
    Terminal,
    /// A supplied state falls outside the reachable integer bounds.
    #[error("race state is outside the bounded simulation domain")]
    StateBounds,
}

/// Create the immutable two-column staggered starting grid.
pub fn initial_race_state_v1(
    track: RaceTrackV1,
    player_count: u8,
) -> Result<RaceStateV1, RaceSimulationErrorV1> {
    if !(1..=RACE_MAX_PLAYERS_V1).contains(&player_count) {
        return Err(RaceSimulationErrorV1::PlayerCount);
    }
    Ok(RaceStateV1 {
        tick: 0,
        track,
        cars: (0..player_count)
            .map(|slot| RaceCarStateV1 {
                progress_mm: -i64::from(slot / 2) * 4_000,
                lateral_mm: if slot % 2 == 0 { -1_800 } else { 1_800 },
                speed_mm_per_tick: 0,
                lateral_velocity_mm_per_tick: 0,
                boost_energy: 1_000,
                finish_tick: None,
                dnf_tick: None,
            })
            .collect(),
    })
}

fn validate_state_v1(state: &RaceStateV1) -> Result<(), RaceSimulationErrorV1> {
    if state.cars.is_empty() || state.cars.len() > usize::from(RACE_MAX_PLAYERS_V1) {
        return Err(RaceSimulationErrorV1::PlayerCount);
    }
    let finish = state.track.length_mm() * i64::from(RACE_LAPS_V1);
    if state.tick > RACE_MAX_TICKS_V1
        || state.cars.iter().any(|car| {
            !(-12_000..=finish).contains(&car.progress_mm)
                || !(-16_200..=16_200).contains(&car.lateral_mm)
                || !(0..=3_000).contains(&car.speed_mm_per_tick)
                || !(-320..=320).contains(&car.lateral_velocity_mm_per_tick)
                || car.boost_energy > 1_000
                || car
                    .finish_tick
                    .is_some_and(|tick| tick == 0 || tick > state.tick)
                || (car.finish_tick.is_some() && car.progress_mm != finish)
                || car.dnf_tick.is_some_and(|tick| tick > state.tick)
        })
    {
        return Err(RaceSimulationErrorV1::StateBounds);
    }
    Ok(())
}

/// Advance one exact tick. Rust integer division truncates toward zero, including negative values.
pub fn step_race_v1(
    state: &mut RaceStateV1,
    frame: &RaceInputFrameV1,
) -> Result<(), RaceSimulationErrorV1> {
    validate_state_v1(state)?;
    if state.tick == RACE_MAX_TICKS_V1
        || (state.tick % 6 == 0
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
                        < 2))
    {
        return Err(RaceSimulationErrorV1::Terminal);
    }
    if frame.tick != state.tick {
        return Err(RaceSimulationErrorV1::TickSequence);
    }
    if frame.controls.len() != state.cars.len() {
        return Err(RaceSimulationErrorV1::ControlCount);
    }
    if frame
        .controls
        .iter()
        .any(|control| control & !RACE_CONTROL_MASK_V1 != 0)
    {
        return Err(RaceSimulationErrorV1::ControlBits);
    }
    let length = state.track.length_mm();
    let curves = state.track.curvature();
    let (_, wind) = super::environment::weather(state.track, state.tick);
    for (car, control) in state.cars.iter_mut().zip(&frame.controls) {
        if car.finish_tick.is_some() || car.dnf_tick.is_some() {
            continue;
        }
        let boost = control & 32 != 0 && car.boost_energy >= 25;
        car.boost_energy = if boost {
            car.boost_energy - 25
        } else {
            (car.boost_energy + 4).min(1_000)
        };
        let maximum_speed = if boost { 3_000 } else { 2_400 };
        let acceleration = if control & 2 != 0 {
            -100
        } else if control & 1 != 0 {
            40
        } else {
            -12
        };
        car.speed_mm_per_tick = (car.speed_mm_per_tick + acceleration).clamp(0, maximum_speed);
        let steer = i32::from(control & 8 != 0) - i32::from(control & 4 != 0);
        let steering_force = if control & 16 != 0 { 28 } else { 18 };
        car.lateral_velocity_mm_per_tick = super::environment::lateral_velocity(
            state.track,
            state.tick,
            car.progress_mm,
            car.lateral_mm,
            car.lateral_velocity_mm_per_tick,
            steer * steering_force,
        );
        let segment = usize::try_from(car.progress_mm.rem_euclid(length) * 12 / length)
            .map_err(|_| RaceSimulationErrorV1::StateBounds)?;
        let curvature_force = curves[segment] * car.speed_mm_per_tick / 120
            + (wind as i32 * car.speed_mm_per_tick / 2400);
        car.lateral_mm = (car.lateral_mm + car.lateral_velocity_mm_per_tick + curvature_force)
            .clamp(-9_000, 9_000);
        if car.lateral_mm.abs() > 6_000 {
            car.speed_mm_per_tick = (car.speed_mm_per_tick - 90).max(0);
        }
        let old_progress = car.progress_mm;
        car.progress_mm += i64::from(car.speed_mm_per_tick);
        (car.lateral_mm, car.speed_mm_per_tick) = super::environment::impact(
            state.track,
            old_progress,
            car.progress_mm,
            car.lateral_mm,
            car.speed_mm_per_tick,
        );
    }
    // Every pair observes effects of the preceding pairs in this exact slot order.
    for left_slot in 0..state.cars.len() {
        for right_slot in left_slot + 1..state.cars.len() {
            let (left, right) = state.cars.split_at_mut(right_slot);
            let a = &mut left[left_slot];
            let b = &mut right[0];
            if a.finish_tick.is_some()
                || b.finish_tick.is_some()
                || a.dnf_tick.is_some()
                || b.dnf_tick.is_some()
                || (a.progress_mm - b.progress_mm).abs() >= 3_600
                || (a.lateral_mm - b.lateral_mm).abs() >= 1_800
            {
                continue;
            }
            let push = (1_800 - (a.lateral_mm - b.lateral_mm).abs() + 1) / 2;
            if a.lateral_mm <= b.lateral_mm {
                a.lateral_mm -= push;
                b.lateral_mm += push;
            } else {
                a.lateral_mm += push;
                b.lateral_mm -= push;
            }
            a.speed_mm_per_tick = (a.speed_mm_per_tick - 120).max(0);
            b.speed_mm_per_tick = (b.speed_mm_per_tick - 120).max(0);
        }
    }
    state.tick += 1;
    let finish = length * i64::from(RACE_LAPS_V1);
    for car in &mut state.cars {
        if car.finish_tick.is_none() && car.dnf_tick.is_none() && car.progress_mm >= finish {
            car.progress_mm = finish;
            car.finish_tick = Some(state.tick);
        }
    }
    Ok(())
}

/// Apply a unique ascending list of consensus-authorized removals atomically.
/// Already-finished cars retain their finish; repeated removals are invalid.
pub fn apply_race_dnf_v1(
    state: &mut RaceStateV1,
    slots: &[u8],
) -> Result<(), RaceSimulationErrorV1> {
    validate_state_v1(state)?;
    if slots.is_empty()
        || slots.windows(2).any(|pair| pair[0] >= pair[1])
        || slots.iter().any(|slot| {
            usize::from(*slot) >= state.cars.len()
                || state.cars[usize::from(*slot)].dnf_tick.is_some()
        })
    {
        return Err(RaceSimulationErrorV1::StateBounds);
    }
    for slot in slots {
        let car = &mut state.cars[usize::from(*slot)];
        car.dnf_tick = Some(state.tick);
    }
    Ok(())
}

/// Replay a complete or prefix transcript with strict frame and integer-domain validation.
pub fn replay_race_v1(replay: &RaceReplayV1) -> Result<RaceStateV1, RaceSimulationErrorV1> {
    if replay.frames.len() > RACE_MAX_TICKS_V1 as usize {
        return Err(RaceSimulationErrorV1::Terminal);
    }
    let mut state = initial_race_state_v1(replay.track, replay.player_count)?;
    if replay
        .dnf_events
        .windows(2)
        .any(|pair| pair[0].tick >= pair[1].tick)
        || replay
            .dnf_events
            .iter()
            .any(|event| event.tick > replay.frames.len() as u32)
    {
        return Err(RaceSimulationErrorV1::TickSequence);
    }
    let mut events = replay.dnf_events.iter().peekable();
    for frame in &replay.frames {
        if events.peek().is_some_and(|event| event.tick == state.tick) {
            apply_race_dnf_v1(&mut state, &events.next().expect("peeked event").slots)?;
        }
        step_race_v1(&mut state, frame)?;
    }
    if let Some(event) = events.next() {
        apply_race_dnf_v1(&mut state, &event.slots)?;
    }
    Ok(state)
}

/// Derive standings and every tied winner without allowing a display tie-break to redirect prizes.
pub fn race_result_v1(state: &RaceStateV1) -> Result<RaceResultV1, RaceSimulationErrorV1> {
    validate_state_v1(state)?;
    let mut standings: Vec<_> = state
        .cars
        .iter()
        .enumerate()
        .map(|(slot, car)| RaceStandingV1 {
            slot: slot as u8,
            finish_tick: car.finish_tick,
            dnf_tick: car.dnf_tick,
            progress_mm: car.progress_mm,
        })
        .collect();
    standings.sort_by(|a, b| {
        a.dnf_tick
            .is_some()
            .cmp(&b.dnf_tick.is_some())
            .then_with(|| match (a.finish_tick, b.finish_tick) {
                (Some(a_tick), Some(b_tick)) => a_tick.cmp(&b_tick),
                (Some(_), None) => std::cmp::Ordering::Less,
                (None, Some(_)) => std::cmp::Ordering::Greater,
                (None, None) => b.progress_mm.cmp(&a.progress_mm),
            })
            .then(a.slot.cmp(&b.slot))
    });
    let eligible = standings
        .iter()
        .take_while(|standing| standing.dnf_tick.is_none())
        .collect::<Vec<_>>();
    let mut winners = Vec::new();
    if let Some(leader) = eligible.first() {
        if let Some(earliest) = leader.finish_tick {
            winners.extend(
                eligible
                    .iter()
                    .filter(|standing| standing.finish_tick == Some(earliest))
                    .map(|standing| standing.slot),
            );
        } else if state.cars.len() >= 2 && state.tick % 6 == 0 {
            if eligible.len() == 1 {
                winners.push(leader.slot);
            } else if state.tick == RACE_MAX_TICKS_V1 {
                winners.extend(
                    eligible
                        .iter()
                        .filter(|standing| standing.progress_mm == leader.progress_mm)
                        .map(|standing| standing.slot),
                );
            }
        }
    }
    Ok(RaceResultV1 {
        ticks: state.tick,
        standings,
        winners,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dnf_removes_contact_and_excludes_a_previously_finished_racer() {
        let mut state = initial_race_state_v1(RaceTrackV1::NeonTokyo, 3).expect("grid");
        state.cars[0].lateral_mm = 0;
        state.cars[1].lateral_mm = 0;
        apply_race_dnf_v1(&mut state, &[0]).expect("remove");
        let removed = state.cars[0];
        step_race_v1(
            &mut state,
            &RaceInputFrameV1 {
                tick: 0,
                controls: vec![1, 1, 0],
            },
        )
        .expect("tick");
        assert_eq!(state.cars[0], removed);
        assert_eq!(state.cars[1].lateral_mm, 0);
        state.cars[1].progress_mm = 6_000_000;
        state.cars[1].finish_tick = Some(1);
        apply_race_dnf_v1(&mut state, &[1]).expect("finished car retained");
        assert_eq!(state.cars[1].dnf_tick, Some(1));
        assert!(race_result_v1(&state).expect("result").winners.is_empty());
    }

    #[test]
    fn consensus_quorum_loss_has_provable_technical_outcome() {
        let mut state = initial_race_state_v1(RaceTrackV1::NeonTokyo, 2).expect("grid");
        apply_race_dnf_v1(&mut state, &[0]).expect("consensus removal");
        assert_eq!(
            race_result_v1(&state).expect("technical result").winners,
            vec![1]
        );
        assert_eq!(
            step_race_v1(
                &mut state,
                &RaceInputFrameV1 {
                    tick: 0,
                    controls: vec![0, 1]
                }
            ),
            Err(RaceSimulationErrorV1::Terminal)
        );
        apply_race_dnf_v1(&mut state, &[1]).expect("second removal");
        assert!(
            race_result_v1(&state)
                .expect("refund outcome")
                .winners
                .is_empty()
        );
        let mut finished = initial_race_state_v1(RaceTrackV1::NeonTokyo, 2).expect("grid");
        finished.tick = 6;
        finished.cars[0].finish_tick = Some(4);
        finished.cars[0].progress_mm = 6_000_000;
        apply_race_dnf_v1(&mut finished, &[0]).expect("finished input key removed");
        assert_eq!(finished.cars[0].dnf_tick, Some(6));
        assert_eq!(
            race_result_v1(&finished)
                .expect("sole eligible racer wins despite earlier forfeited finish")
                .winners,
            vec![1]
        );
    }

    #[test]
    fn timeout_rewards_exact_eligible_distance_ties_and_only_all_forfeit_refunds() {
        let mut state = initial_race_state_v1(RaceTrackV1::NeonTokyo, 4).expect("grid");
        state.tick = RACE_MAX_TICKS_V1 - 6;
        for (car, progress) in state.cars.iter_mut().zip([50, 120, 120, 999]) {
            car.progress_mm = progress;
        }
        apply_race_dnf_v1(&mut state, &[3]).expect("removed former distance leader");
        assert!(
            race_result_v1(&state)
                .expect("nonterminal prefix")
                .winners
                .is_empty()
        );
        state.tick = RACE_MAX_TICKS_V1;
        let result = race_result_v1(&state).expect("timeout outcome");
        assert_eq!(result.winners, vec![1, 2]);
        assert_eq!(
            result
                .standings
                .iter()
                .map(|standing| standing.slot)
                .collect::<Vec<_>>(),
            vec![1, 2, 0, 3]
        );
        apply_race_dnf_v1(&mut state, &[0, 1, 2]).expect("all input keys removed");
        assert!(
            race_result_v1(&state)
                .expect("all forfeit refund")
                .winners
                .is_empty()
        );
        state.cars[0].progress_mm = 6_000_000;
        state.cars[0].finish_tick = Some(RACE_MAX_TICKS_V1 - 1);
        assert!(
            race_result_v1(&state)
                .expect("prior finish is history, not eligibility")
                .winners
                .is_empty()
        );
    }

    #[test]
    fn grid_and_first_tick_are_exact() {
        let mut state = initial_race_state_v1(RaceTrackV1::NeonTokyo, 8).expect("grid");
        assert_eq!(state.cars[7].progress_mm, -12_000);
        step_race_v1(
            &mut state,
            &RaceInputFrameV1 {
                tick: 0,
                controls: vec![1; 8],
            },
        )
        .expect("tick");
        assert_eq!(state.cars[0].progress_mm, 40);
        assert_eq!(state.cars[0].speed_mm_per_tick, 40);
        assert_eq!(state.cars[0].lateral_mm, -1_800);
        assert_eq!(state.tick, 1);
    }

    #[test]
    fn invalid_inputs_leave_state_unchanged() {
        let mut state = initial_race_state_v1(RaceTrackV1::Sakura, 2).expect("grid");
        let before = state.clone();
        assert_eq!(
            step_race_v1(
                &mut state,
                &RaceInputFrameV1 {
                    tick: 0,
                    controls: vec![64, 1]
                }
            ),
            Err(RaceSimulationErrorV1::ControlBits)
        );
        assert_eq!(state, before);
        assert_eq!(
            step_race_v1(
                &mut state,
                &RaceInputFrameV1 {
                    tick: 1,
                    controls: vec![1, 1]
                }
            ),
            Err(RaceSimulationErrorV1::TickSequence)
        );
        assert_eq!(state, before);
    }

    #[test]
    fn contacts_have_deterministic_tie_direction() {
        let mut state = initial_race_state_v1(RaceTrackV1::NeonTokyo, 2).expect("grid");
        state.cars[0].lateral_mm = 0;
        state.cars[1].lateral_mm = 0;
        step_race_v1(
            &mut state,
            &RaceInputFrameV1 {
                tick: 0,
                controls: vec![1, 1],
            },
        )
        .expect("tick");
        assert_eq!(state.cars[0].lateral_mm, -900);
        assert_eq!(state.cars[1].lateral_mm, 900);
        assert_eq!(state.cars[0].speed_mm_per_tick, 0);
    }

    #[test]
    fn curvature_and_negative_division_are_exact() {
        let mut state = initial_race_state_v1(RaceTrackV1::NeonTokyo, 1).expect("grid");
        state.cars[0].progress_mm = 400_000;
        state.cars[0].speed_mm_per_tick = 1_200;
        state.cars[0].lateral_velocity_mm_per_tick = -3;
        step_race_v1(
            &mut state,
            &RaceInputFrameV1 {
                tick: 0,
                controls: vec![4],
            },
        )
        .expect("tick");
        assert_eq!(state.cars[0].lateral_velocity_mm_per_tick, -18);
        assert_eq!(state.cars[0].lateral_mm, -1_799);
    }

    #[test]
    fn tied_finishers_share_win_and_are_frozen() {
        let mut state = initial_race_state_v1(RaceTrackV1::NeonTokyo, 3).expect("grid");
        for car in &mut state.cars[..2] {
            car.progress_mm = 5_999_990;
        }
        step_race_v1(
            &mut state,
            &RaceInputFrameV1 {
                tick: 0,
                controls: vec![1, 1, 0],
            },
        )
        .expect("finish");
        assert_eq!(race_result_v1(&state).expect("result").winners, vec![0, 1]);
        let first = state.cars[0];
        step_race_v1(
            &mut state,
            &RaceInputFrameV1 {
                tick: 1,
                controls: vec![63, 63, 0],
            },
        )
        .expect("continue");
        assert_eq!(state.cars[0], first);
    }
}

#[cfg(test)]
mod eligibility_tests {
    use super::*;
    use iroha_data_model::execution_proofs::{RACE_LAPS_V1, RaceTrackV1};

    fn state() -> RaceStateV1 {
        let mut state =
            super::initial_race_state_v1(RaceTrackV1::Harbor, 4).expect("canonical grid");
        state.tick = 24;
        state
    }

    fn finish(state: &mut RaceStateV1, slot: usize, tick: u32) {
        state.cars[slot].progress_mm = state.track.length_mm() * i64::from(RACE_LAPS_V1);
        state.cars[slot].finish_tick = Some(tick);
    }

    #[test]
    fn a_late_forfeit_loses_its_prior_finish_to_every_eligible_racer() {
        let mut state = state();
        finish(&mut state, 0, 6);
        state.cars[0].dnf_tick = Some(12);
        state.cars[1].dnf_tick = Some(18);
        state.cars[2].dnf_tick = Some(18);
        let corrected = race_result_v1(&state).unwrap();
        assert_eq!(corrected.winners, [3]);
        assert_eq!(corrected.standings[0].slot, 3);
        assert_eq!(corrected.standings[1].finish_tick, Some(6));
    }

    #[test]
    fn all_forfeit_refunds_even_when_one_or_every_car_previously_finished() {
        for finished in 1..=4 {
            let mut state = state();
            for slot in 0..finished {
                finish(&mut state, slot, 6 + slot as u32);
            }
            for car in &mut state.cars {
                car.dnf_tick = Some(24);
            }
            assert!(race_result_v1(&state).unwrap().winners.is_empty());
        }
    }

    #[test]
    fn eligible_finish_ties_exclude_an_earlier_forfeited_finisher() {
        let mut state = state();
        finish(&mut state, 0, 6);
        finish(&mut state, 1, 12);
        finish(&mut state, 2, 12);
        state.cars[0].dnf_tick = Some(18);
        let result = race_result_v1(&state).unwrap();
        assert_eq!(result.winners, [1, 2]);
        assert_eq!(
            result.standings.iter().map(|r| r.slot).collect::<Vec<_>>(),
            [1, 2, 3, 0]
        );
    }

    #[test]
    fn timeout_uses_only_eligible_distance_ties_after_a_prior_finish_forfeits() {
        let mut state = state();
        state.tick = RACE_MAX_TICKS_V1;
        finish(&mut state, 0, 6);
        state.cars[0].dnf_tick = Some(12);
        state.cars[1].progress_mm = 400_000;
        state.cars[2].progress_mm = 400_000;
        state.cars[3].progress_mm = 399_999;
        assert_eq!(race_result_v1(&state).unwrap().winners, [1, 2]);
    }

    #[test]
    fn frozen_validation_and_unfinished_nonterminal_outcomes_remain_strict() {
        let mut state = state();
        assert!(race_result_v1(&state).unwrap().winners.is_empty());
        state.cars[0].dnf_tick = Some(state.tick + 1);
        assert!(race_result_v1(&state).is_err());
    }
}
