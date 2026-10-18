//! Frozen Touring S1 track objects and public weather; independent of the stock profile.

use super::rules::classed_track_length_v1;
use iroha_data_model::classed_race_v1::ClassedRaceTrackV1;

pub(super) const TREE: i64 = 0;
pub(super) const SIGN: i64 = 1;
pub(super) const OIL: i64 = 2;
pub(super) const WIND_PATTERN: [i64; 8] = [0, 1, 2, 1, 0, -1, -2, -1];
pub(super) const OIL_HALF_LENGTH: i64 = 9_000;
pub(super) const OIL_HALF_WIDTH: i64 = 1_400;
pub(super) const WEATHER_TICKS: u32 = 300;
pub(super) const WIND_TICKS: u32 = 90;

pub(super) fn kinds(track: ClassedRaceTrackV1) -> [i64; 12] {
    match track {
        ClassedRaceTrackV1::NeonTokyo => [0, 1, 0, 2, 0, 1, 2, 0, 1, 0, 2, 1],
        ClassedRaceTrackV1::Harbor => [1, 2, 0, 1, 0, 2, 1, 0, 2, 1, 0, 2],
        ClassedRaceTrackV1::Sakura => [0, 0, 2, 1, 0, 2, 0, 1, 0, 2, 0, 1],
    }
}
pub(super) fn laterals(track: ClassedRaceTrackV1) -> [i64; 12] {
    let types = kinds(track);
    std::array::from_fn(|cell| {
        let magnitude = match types[cell] {
            TREE => 7_400,
            SIGN => 5_600,
            _ => 1_800,
        };
        if cell % 2 == 0 { -magnitude } else { magnitude }
    })
}
pub(super) fn centers(track: ClassedRaceTrackV1) -> [i64; 12] {
    std::array::from_fn(|cell| {
        let cell = i64::try_from(cell).expect("twelve track cells fit i64");
        (2 * cell + 1) * classed_track_length_v1(track) / 24
    })
}
pub(super) fn rain_pattern(track: ClassedRaceTrackV1) -> [i64; 4] {
    match track {
        ClassedRaceTrackV1::NeonTokyo => [0, 0, 1, 0],
        ClassedRaceTrackV1::Harbor => [0, 1, 1, 0],
        ClassedRaceTrackV1::Sakura => [0, 0, 0, 1],
    }
}
pub(super) fn wind_strength(track: ClassedRaceTrackV1) -> i64 {
    match track {
        ClassedRaceTrackV1::NeonTokyo => 4,
        ClassedRaceTrackV1::Harbor => 16,
        ClassedRaceTrackV1::Sakura => 8,
    }
}
pub(super) fn weather(track: ClassedRaceTrackV1, tick: u32) -> (i64, i64) {
    (
        rain_pattern(track)[((tick / WEATHER_TICKS) % 4) as usize],
        WIND_PATTERN[((tick / WIND_TICKS) % 8) as usize] * wind_strength(track),
    )
}
pub(super) fn object(track: ClassedRaceTrackV1, progress: i64) -> (i64, i64, i64, i64) {
    let wrapped = progress.rem_euclid(classed_track_length_v1(track));
    let cell = usize::try_from(wrapped * 12 / classed_track_length_v1(track))
        .expect("wrapped track position selects one of twelve cells");
    (
        wrapped,
        centers(track)[cell],
        kinds(track)[cell],
        laterals(track)[cell],
    )
}
pub(super) fn oil(track: ClassedRaceTrackV1, progress: i64, lateral: i32) -> bool {
    let (wrapped, center, kind, x) = object(track, progress);
    kind == OIL
        && (wrapped - center).abs() <= OIL_HALF_LENGTH
        && (i64::from(lateral) - x).abs() <= OIL_HALF_WIDTH
}
pub(super) fn lateral_velocity(
    track: ClassedRaceTrackV1,
    tick: u32,
    progress: i64,
    lateral: i32,
    velocity: i32,
    steer: i32,
) -> i32 {
    let rain = weather(track, tick).0 != 0;
    let oil = oil(track, progress, lateral);
    let steer = if rain { steer * 3 / 4 } else { steer };
    let steer = if oil { steer / 2 } else { steer };
    let velocity = if rain || oil {
        (velocity + steer) * 15 / 16
    } else {
        (velocity + steer) * 7 / 8
    };
    let limit = if rain { 280 } else { 320 };
    velocity.clamp(-limit, limit)
}
/// Crossing a solid object's center applies once; backward/zero movement cannot retrigger it.
pub(super) fn impact(
    track: ClassedRaceTrackV1,
    old_progress: i64,
    progress: i64,
    lateral: i32,
    speed: i32,
) -> (i32, i32) {
    let (wrapped, center, kind, x) = object(track, old_progress);
    let radius = if kind == TREE { 1_400 } else { 1_300 };
    if kind == OIL
        || wrapped >= center
        || wrapped + (progress - old_progress) < center
        || (i64::from(lateral) - x).abs() >= radius
    {
        return (lateral, speed);
    }
    if kind == TREE {
        let pushed = x + if i64::from(lateral) > x {
            1_800
        } else {
            -1_800
        };
        (
            i32::try_from(pushed.clamp(-9_000, 9_000)).expect("clamped lateral position fits i32"),
            (speed - 600).max(0),
        )
    } else {
        (lateral, (speed - 260).max(0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn solids_use_swept_crossing_and_exact_contact_edges_without_retrigger() {
        for track in [
            ClassedRaceTrackV1::NeonTokyo,
            ClassedRaceTrackV1::Harbor,
            ClassedRaceTrackV1::Sakura,
        ] {
            for cell in 0..12 {
                let center = centers(track)[cell];
                let x = i32::try_from(laterals(track)[cell]).expect("fixed track lateral fits i32");
                let kind = kinds(track)[cell];
                if kind == OIL {
                    continue;
                }
                let radius = if kind == TREE { 1400 } else { 1300 };
                assert_eq!(impact(track, center - 500, center - 1, x, 1000), (x, 1000));
                assert_eq!(impact(track, center, center + 1000, x, 1000), (x, 1000));
                assert_eq!(
                    impact(track, center - 500, center + 500, x + radius, 1000),
                    (x + radius, 1000)
                );
                let hit = impact(track, center - 500, center + 500, x, 1000);
                assert_eq!(hit.1, if kind == TREE { 400 } else { 740 });
                if kind == TREE {
                    assert_ne!(hit.0, x);
                }
            }
        }
    }
    #[test]
    fn wind_never_moves_a_parked_car_and_inactive_cars_ignore_objects() {
        use super::super::reference::{initial_classed_race_state_v1, step_classed_race_v1};
        use iroha_data_model::classed_race_v1::ClassedRaceClassV1;
        use iroha_data_model::classed_race_v1::ClassedRaceInputFrameV1;
        for track in [
            ClassedRaceTrackV1::NeonTokyo,
            ClassedRaceTrackV1::Harbor,
            ClassedRaceTrackV1::Sakura,
        ] {
            let mut state =
                initial_classed_race_state_v1(ClassedRaceClassV1::TouringS1, track, 2).unwrap();
            for tick in 0..1200 {
                step_classed_race_v1(
                    &mut state,
                    &ClassedRaceInputFrameV1 {
                        tick,
                        controls: vec![0, 0],
                    },
                )
                .unwrap();
                assert_eq!(state.cars[0].lateral_mm, -1800);
                assert_eq!(state.cars[1].lateral_mm, 1800);
            }
        }
    }

    #[test]
    fn frozen_centers_and_wrapped_progress_keep_exact_cell_boundaries() {
        for (track, expected_centers, extreme_positions) in [
            (
                ClassedRaceTrackV1::NeonTokyo,
                [
                    83_333, 250_000, 416_666, 583_333, 750_000, 916_666, 1_083_333, 1_250_000,
                    1_416_666, 1_583_333, 1_750_000, 1_916_666,
                ],
                [(i64::MIN, 1_224_192, 7), (i64::MAX, 775_807, 4)],
            ),
            (
                ClassedRaceTrackV1::Harbor,
                [
                    100_000, 300_000, 500_000, 700_000, 900_000, 1_100_000, 1_300_000, 1_500_000,
                    1_700_000, 1_900_000, 2_100_000, 2_300_000,
                ],
                [(i64::MIN, 424_192, 2), (i64::MAX, 1_975_807, 9)],
            ),
            (
                ClassedRaceTrackV1::Sakura,
                [
                    75_000, 225_000, 375_000, 525_000, 675_000, 825_000, 975_000, 1_125_000,
                    1_275_000, 1_425_000, 1_575_000, 1_725_000,
                ],
                [(i64::MIN, 1_024_192, 6), (i64::MAX, 775_807, 5)],
            ),
        ] {
            assert_eq!(centers(track), expected_centers);
            let length = classed_track_length_v1(track);
            let positions = [
                (-length - 1, length - 1, 11),
                (-length, 0, 0),
                (-1, length - 1, 11),
                (0, 0, 0),
                (length - 1, length - 1, 11),
                (length, 0, 0),
                (length + 1, 1, 0),
            ];
            for (progress, wrapped, cell) in positions.into_iter().chain(extreme_positions) {
                assert_eq!(
                    object(track, progress),
                    (
                        wrapped,
                        expected_centers[cell],
                        kinds(track)[cell],
                        laterals(track)[cell]
                    ),
                );
            }
        }
    }
}
