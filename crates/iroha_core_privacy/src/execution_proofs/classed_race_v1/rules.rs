//! Frozen integer constants for the Touring S1 spec class.
use iroha_data_model::classed_race_v1::{ClassedRaceClassV1, ClassedRaceTrackV1};

pub(super) const MAX_PLAYERS: u8 = 8;
pub(super) const MAX_TICKS: u32 = 5_400;
pub(super) const BATCH_TICKS: u32 = 6;
pub(super) const LAPS: i64 = 3;
pub(super) const CONTROL_MASK: u16 = 63;
pub(super) const MIN_PROGRESS: i64 = -12_000;
pub(super) const MOVE_LATERAL_LIMIT: i64 = 9_000;
// A car is clamped to 9000 before at most seven contacts, each pushing at most 900.
pub(super) const STATE_LATERAL_LIMIT: i32 = 15_300;
pub(super) const LATERAL_SPEED_LIMIT: i64 = 320;
pub(super) const ROAD_HALF_WIDTH: i64 = 6_000;
pub(super) const CONTACT_DISTANCE: i64 = 3_600;
pub(super) const CONTACT_WIDTH: i64 = 1_800;

/// Exact compiled spec values. Callers select a closed class, never this structure as input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClassPerformanceV1 {
    /// Positive throttle increment in millimetres per tick per tick.
    pub acceleration: i64,
    /// Maximum non-boosted forward displacement per tick.
    pub normal_speed: i64,
    /// Maximum boosted forward displacement per tick.
    pub boost_speed: i64,
    /// Brake decrement; braking takes precedence over throttle.
    pub brake: i64,
    /// Coasting decrement when neither brake nor throttle is pressed.
    pub coast: i64,
    /// Normal steering force before weather/oil adjustments and velocity damping.
    pub steering: i64,
    /// Drift steering force before weather/oil adjustments and velocity damping.
    pub drift_steering: i64,
    /// Maximum boost energy and the starting reserve.
    pub boost_capacity: u16,
    /// Energy consumed by an effective boost tick.
    pub boost_cost: u16,
    /// Energy restored when boost is ineffective or not requested.
    pub boost_recharge: u16,
    /// Forward-speed decrement after leaving the road.
    pub offroad_penalty: i64,
    /// Forward-speed decrement for each ordered contact.
    pub contact_penalty: i64,
}

/// One immutable kit gives every entrant the same 10% acceleration/speed improvement.
#[must_use]
pub const fn class_performance_v1(class: ClassedRaceClassV1) -> ClassPerformanceV1 {
    match class {
        ClassedRaceClassV1::TouringS1 => ClassPerformanceV1 {
            acceleration: 44,
            normal_speed: 2_640,
            boost_speed: 3_300,
            brake: 100,
            coast: 12,
            steering: 18,
            drift_steering: 28,
            boost_capacity: 1_000,
            boost_cost: 25,
            boost_recharge: 4,
            offroad_penalty: 90,
            contact_penalty: 120,
        },
    }
}

/// Track lengths copied into this new version rather than changing the retained `RaceV1` catalog.
#[must_use]
pub const fn classed_track_length_v1(track: ClassedRaceTrackV1) -> i64 {
    match track {
        ClassedRaceTrackV1::NeonTokyo => 2_000_000,
        ClassedRaceTrackV1::Harbor => 2_400_000,
        ClassedRaceTrackV1::Sakura => 1_800_000,
    }
}

/// Twelve immutable curvature cells, selected with Euclidean wrapped pre-movement progress.
#[must_use]
pub const fn classed_track_curvature_v1(track: ClassedRaceTrackV1) -> [i64; 12] {
    match track {
        ClassedRaceTrackV1::NeonTokyo => [0, 1, 2, 1, 0, -1, -2, -1, 0, 2, -2, 0],
        ClassedRaceTrackV1::Harbor => [0, -2, -2, 0, 1, 3, 1, 0, -1, -3, -1, 0],
        ClassedRaceTrackV1::Sakura => [0, 1, 1, 0, -2, -1, 0, 2, 3, 1, -2, 0],
    }
}

/// Human-readable immutable rules identity; a future profile must also commit the executable source.
pub const CLASS_RULES_V1: &str = "ClassedRaceV1/TouringS1:ticks=30:max=5400:batch=6:players=1..8:multiplayer=2..8:laps=3:accel=44:normal=2640:boost=3300:brake=100:coast=12:steer=18:drift=28:energy=1000/cost25/recharge4:grip=rain?trunc(steer*3/4):steer,then-oil?trunc(steer/2):steer:vx=rain-or-oil?trunc((vx+steer)*15/16):trunc((vx+steer)*7/8),clamp-rain280-else320:curve=pre-progress,12cells,trunc(curve*speed/120):wind=trunc(public-weather-wind*speed/2400):x=clamp9000:roadHalf=6000:offroad=-90:environment=12-cell-center-floor((2i+1)*length/24),sample-old-progress:tree=radius1400,loss600,push1800-clamp9000:sign=radius1300,loss260:oil=half-length9000,half-width1400:solids=swept-crossing-before-ordered-contacts:rain=public300tick4table:wind=public90tick8table0,1,2,1,0,-1,-2,-1:Tokyo=rain0010,wind4,kinds010201201021:Harbor=rain0110,wind16,kinds120102102102:Sakura=rain0001,wind8,kinds002102010201:object-x=alternate-negative-positive,tree7400,sign5600,oil1800:contact=ordered-i-j,dp<3600,dx<1800,ceil-half-push,lower-x-or-slot-goes-left,speed-120:finish=after-contacts,clamp3laps:dnf=before-tick,freeze-and-ghost,retain-finish-history-but-disqualify:terminal=batch-boundary(all-done-or-less-than-two-keys),or5400:winners=terminal-only,eligible-earliest-finish-ties,else-sole-survivor,else-timeout-eligible-distance-ties,else-all-forfeit-refund:class=one-global-spec,no-stacking";
