//! Time event and filter
use core::{ops::Range, time::Duration};

use derive_more::Constructor;
use getset::Getters;
use iroha_data_model_derive::model;

pub use self::model::*;
use super::*;

#[model]
pub mod model {
    use super::*;

    /// Special event that is emitted when `WSV` is ready for handling time-triggers
    ///
    /// Contains time interval which is used to identify time-triggers to be executed
    #[derive(
        Debug,
        Clone,
        Copy,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Getters,
        Decode,
        Encode,
        Deserialize,
        Serialize,
        IntoSchema,
    )]
    #[getset(get = "pub")]
    #[ffi_type]
    pub struct TimeEvent {
        /// Previous block timestamp and consensus durations estimation.
        /// `None` if it's first block commit
        pub prev_interval: Option<TimeInterval>,
        /// Current block timestamp and consensus durations estimation
        pub interval: TimeInterval,
    }

    /// Filter time-events and allow only the ones within the given time interval.
    #[derive(
        Debug,
        Clone,
        Copy,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Constructor,
        Decode,
        Encode,
        Deserialize,
        Serialize,
        IntoSchema,
    )]
    #[serde(transparent)]
    #[repr(transparent)]
    pub struct TimeEventFilter(pub(super) ExecutionTime);

    /// Trigger execution time
    #[derive(
        Debug,
        Clone,
        Copy,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Decode,
        Encode,
        Deserialize,
        Serialize,
        IntoSchema,
    )]
    pub enum ExecutionTime {
        /// Execute right before block commit
        PreCommit,
        /// Execute with some schedule
        Schedule(Schedule),
    }

    /// Schedule of the trigger
    #[derive(
        Debug,
        Clone,
        Copy,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Decode,
        Encode,
        Deserialize,
        Serialize,
        IntoSchema,
    )]
    pub struct Schedule {
        /// The first execution time
        pub start: Duration,
        /// If some, the period between cyclic executions
        pub period: Option<Duration>,
    }

    /// Time interval in which `TimeAction` should appear
    #[derive(
        Debug,
        Clone,
        Copy,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Getters,
        Decode,
        Encode,
        Deserialize,
        Serialize,
        IntoSchema,
    )]
    // TODO: Figure out how to serialize duration
    // #[getset(get = "pub")]
    #[ffi_type]
    pub struct TimeInterval {
        /// The start of a time interval
        pub since: Duration,
        /// The length of a time interval
        pub length: Duration,
    }
}

#[cfg(feature = "transparent_api")]
impl Filter for TimeEventFilter {
    type Event = TimeEvent;

    /// Isn't useful for time-triggers
    fn matches(&self, event: &TimeEvent) -> bool {
        self.count_matches(event) > 0
    }

    fn count_matches(&self, event: &TimeEvent) -> u32 {
        match &self.0 {
            ExecutionTime::PreCommit => 1,
            ExecutionTime::Schedule(schedule) => {
                let current_interval = event.prev_interval.map_or(event.interval, |prev| {
                    let estimation = event.interval.since + event.interval.length;
                    let prev_estimation = prev.since + prev.length;

                    TimeInterval {
                        since: prev_estimation,
                        length: estimation.saturating_sub(prev_estimation),
                    }
                });

                count_matches_in_interval(schedule, &current_interval)
            }
        }
    }

    fn mintable(&self) -> bool {
        !matches!(
            self.0,
            ExecutionTime::Schedule(Schedule { period: None, .. })
        )
    }
}

/// Count something with the `schedule` within the `interval`
#[cfg(feature = "transparent_api")]
fn count_matches_in_interval(schedule: &Schedule, interval: &TimeInterval) -> u32 {
    schedule.period.map_or_else(
        || u32::from(Range::from(*interval).contains(&schedule.start)),
        |period| {
            #[allow(clippy::integer_division)]
            let k = interval.since.saturating_sub(schedule.start).as_millis() / period.as_millis();
            let start = schedule.start + multiply_duration_by_u128(period, k);
            let range = Range::from(*interval);
            (0..)
                .map(|i| start + period * i)
                .skip_while(|time| *time < interval.since)
                .take_while(|time| range.contains(time))
                .count()
                .try_into()
                .expect("Overflow. The schedule is too frequent relative to the interval length")
        },
    )
}

/// Multiply `duration` by `n`
///
/// Usage of this function allows to operate with much longer time *intervals*
/// with much less *periods* than just `impl Mul<u32> for Duration` does
///
/// # Panics
/// Panics if resulting number in seconds can't be represented as `u64`
#[cfg(feature = "transparent_api")]
fn multiply_duration_by_u128(duration: Duration, n: u128) -> Duration {
    if let Ok(n) = u32::try_from(n) {
        return duration * n;
    }

    let new_ms = duration.as_millis() * n;
    if let Ok(ms) = u64::try_from(new_ms) {
        return Duration::from_millis(ms);
    }

    #[allow(clippy::integer_division)]
    let new_secs = u64::try_from(new_ms / 1000)
        .expect("Overflow. Resulting number in seconds can't be represented as `u64`");
    Duration::from_secs(new_secs)
}

impl Schedule {
    /// Create new `Schedule` starting at `start` and without period
    #[must_use]
    #[inline]
    pub const fn starting_at(start: Duration) -> Self {
        Self {
            start,
            period: None,
        }
    }

    /// Add `period` to `self`
    #[must_use]
    #[inline]
    pub const fn with_period(mut self, period: Duration) -> Self {
        self.period = Some(period);
        self
    }
}

impl TimeInterval {
    /// Getter for `since`
    pub fn since(&self) -> &Duration {
        &self.since
    }

    /// Getter for `length`
    pub fn length(&self) -> &Duration {
        &self.length
    }
}

impl From<TimeInterval> for Range<Duration> {
    #[inline]
    fn from(interval: TimeInterval) -> Self {
        interval.since..interval.since + interval.length
    }
}

/// Exports common structs and enums from this module.
pub mod prelude {
    pub use super::{
        ExecutionTime, Schedule as TimeSchedule, TimeEvent, TimeEventFilter, TimeInterval,
    };
}

#[cfg(test)]
#[cfg(feature = "transparent_api")]
mod tests {
    use super::*;

    /// Tests for `count_matches_in_interval()`
    mod count_matches_in_interval {
        use super::*;

        /// Sample timestamp
        const TIMESTAMP: u64 = 1_647_443_386;

        #[test]
        fn test_no_period_before_left_border() {
            // ----|-----[-----)-------
            //     p    i1     i2

            let schedule = Schedule::starting_at(Duration::from_secs(TIMESTAMP - 5));
            let since = Duration::from_secs(TIMESTAMP);
            let length = Duration::from_secs(10);
            let interval = TimeInterval { since, length };
            assert_eq!(count_matches_in_interval(&schedule, &interval), 0);
        }

        #[test]
        fn test_no_period_on_left_border() {
            //     |
            // ----[---------)------
            //   p, i1      i2

            let schedule = Schedule::starting_at(Duration::from_secs(TIMESTAMP));
            let since = Duration::from_secs(TIMESTAMP);
            let length = Duration::from_secs(10);
            let interval = TimeInterval { since, length };
            assert_eq!(count_matches_in_interval(&schedule, &interval), 1);
        }

        #[test]
        fn test_no_period_inside() {
            // ----[------|-----)----
            //     i1     p    i2

            let schedule = Schedule::starting_at(Duration::from_secs(TIMESTAMP + 5));
            let since = Duration::from_secs(TIMESTAMP);
            let length = Duration::from_secs(10);
            let interval = TimeInterval { since, length };
            assert_eq!(count_matches_in_interval(&schedule, &interval), 1);
        }

        #[test]
        fn test_no_period_on_right_border() {
            //               |
            // ----[---------)------
            //    i1      i2, p

            let schedule = Schedule::starting_at(Duration::from_secs(TIMESTAMP + 10));
            let since = Duration::from_secs(TIMESTAMP);
            let length = Duration::from_secs(10);
            let interval = TimeInterval { since, length };
            assert_eq!(count_matches_in_interval(&schedule, &interval), 0);
        }

        #[test]
        fn test_jump_over_inside() {
            // ----[------|-----)----*----
            //     i1     p    i2

            let schedule = Schedule::starting_at(Duration::from_secs(TIMESTAMP + 5))
                .with_period(Duration::from_secs(30));
            let since = Duration::from_secs(TIMESTAMP);
            let length = Duration::from_secs(10);
            let interval = TimeInterval { since, length };
            assert_eq!(count_matches_in_interval(&schedule, &interval), 1);
        }

        #[test]
        fn test_jump_over_outside() {
            // ----|------[-----)----*----
            //     p     i1    i2

            let schedule = Schedule::starting_at(Duration::from_secs(TIMESTAMP))
                .with_period(Duration::from_secs(10));
            let since = Duration::from_secs(TIMESTAMP + 35);
            let length = Duration::from_secs(4);
            let interval = TimeInterval { since, length };
            assert_eq!(count_matches_in_interval(&schedule, &interval), 0);
        }

        #[test]
        fn test_interval_on_the_left() {
            // ----[----)----|-----*-----*----
            //     i1   i2   p

            let schedule = Schedule::starting_at(Duration::from_secs(TIMESTAMP))
                .with_period(Duration::from_secs(6));
            let since = Duration::from_secs(TIMESTAMP - 10);
            let length = Duration::from_secs(4);
            let interval = TimeInterval { since, length };
            assert_eq!(count_matches_in_interval(&schedule, &interval), 0);
        }

        #[test]
        fn test_schedule_starts_at_the_middle() {
            // ----[------|----*----*----*--)-*----
            //     i1     p                i2

            let schedule = Schedule::starting_at(Duration::from_secs(TIMESTAMP))
                .with_period(Duration::from_secs(6));
            let since = Duration::from_secs(TIMESTAMP - 10);
            let length = Duration::from_secs(30);
            let interval = TimeInterval { since, length };
            assert_eq!(count_matches_in_interval(&schedule, &interval), 4);
        }

        #[test]
        fn test_interval_on_the_right() {
            // ----|----*--[----*----*----*----*----)----*----
            //     p      i1                       i2

            let schedule = Schedule::starting_at(Duration::from_secs(TIMESTAMP))
                .with_period(Duration::from_millis(600));
            let since = Duration::from_secs(TIMESTAMP + 3) + Duration::from_millis(500);
            let length = Duration::from_secs(2);
            let interval = TimeInterval { since, length };
            assert_eq!(count_matches_in_interval(&schedule, &interval), 4);
        }

        #[test]
        fn test_only_left_border() {
            //             *
            // ----|-------[----)--*-------*--
            //     p      i1   i2

            let schedule = Schedule::starting_at(Duration::from_secs(TIMESTAMP - 10))
                .with_period(Duration::from_secs(10));
            let since = Duration::from_secs(TIMESTAMP);
            let length = Duration::from_secs(5);
            let interval = TimeInterval { since, length };
            assert_eq!(count_matches_in_interval(&schedule, &interval), 1);
        }

        #[test]
        fn test_only_right_border_inside() {
            //               *
            // ----[----|----)----*----*----
            //     i1   p    i2

            let schedule = Schedule::starting_at(Duration::from_secs(TIMESTAMP))
                .with_period(Duration::from_secs(5));
            let since = Duration::from_secs(TIMESTAMP - 10);
            let length = Duration::from_secs(15);
            let interval = TimeInterval { since, length };
            assert_eq!(count_matches_in_interval(&schedule, &interval), 1);
        }

        #[test]
        fn test_only_right_border_outside() {
            //              *
            // ----|---[----)--------*----
            //     p   i1   i2

            let schedule = Schedule::starting_at(Duration::from_secs(TIMESTAMP - 10))
                .with_period(Duration::from_secs(15));
            let since = Duration::from_secs(TIMESTAMP);
            let length = Duration::from_secs(5);
            let interval = TimeInterval { since, length };
            assert_eq!(count_matches_in_interval(&schedule, &interval), 0);
        }

        #[test]
        fn test_matches_right_border_and_ignores_left() {
            //     |             *
            // ----[-*-*-*-*-*-*-)-*-*-*
            //   p, i1           i2

            let schedule = Schedule::starting_at(Duration::from_secs(TIMESTAMP))
                .with_period(Duration::from_secs(1));
            let since = Duration::from_secs(TIMESTAMP);
            let length = Duration::from_secs(7);
            let interval = TimeInterval { since, length };
            assert_eq!(count_matches_in_interval(&schedule, &interval), 7);
        }
    }
}
