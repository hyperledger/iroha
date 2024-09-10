//! Time event and filter
use core::time::Duration;
#[cfg(feature = "std")]
use std::time::SystemTime;

use derive_more::Constructor;
use getset::Getters;
use iroha_data_model_derive::model;

pub use self::model::*;
use super::*;

#[model]
mod model {
    use super::*;

    /// Special event that is emitted when state is ready for handling time-triggers
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
    pub struct TimeEventFilter(pub ExecutionTime);

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
        pub start_ms: u64,
        /// If some, the period between cyclic executions
        pub period_ms: Option<u64>,
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
        Decode,
        Encode,
        Deserialize,
        Serialize,
        IntoSchema,
    )]
    // TODO: Figure out how to serialize duration
    #[ffi_type]
    pub struct TimeInterval {
        /// The start of a time interval
        pub since_ms: u64,
        /// The length of a time interval
        pub length_ms: u64,
    }
}

#[cfg(feature = "transparent_api")]
impl EventFilter for TimeEventFilter {
    type Event = TimeEvent;

    /// Isn't useful for time-triggers
    fn matches(&self, event: &TimeEvent) -> bool {
        self.count_matches(event) > 0
    }

    fn count_matches(&self, event: &TimeEvent) -> u32 {
        match &self.0 {
            ExecutionTime::PreCommit => 1,
            ExecutionTime::Schedule(schedule) => {
                // Prevent matching in the future it will be handled by the next block
                if schedule.start() > event.interval.since() {
                    return 0;
                }

                let current_interval = event.prev_interval.map_or(event.interval, |prev| {
                    // Case 1:
                    // ----|-----[--[--)--)-----
                    //     s    p1 c1  p2 c2
                    //
                    // Schedule start was before previous block (p1).
                    // In this case we only care about interval [p2, c2)
                    // Because everything up to p2 (excluding) was processed in the previous blocks.
                    //
                    // Case 2:
                    // ---------[-|-[--)--)-----
                    //         p1 s c1 p2 c2
                    //
                    // ---------[--)--|--[--)---
                    //          p1 p2 s  c1 c2
                    //
                    // Schedule start is between previous block (p1) and current block (c1).
                    // In this case we care about either interval [s, c2) if (s) is in [p1, p2) or [p2, c2) if (s) is after (p2).
                    // Because in the previous block [p1, p2) event won't match since (s) was in the future.
                    //
                    // Case 3:
                    // ---------[--[-|-)--)-----
                    //         p1  c1 s p2 c2
                    //
                    // Schedule start is after current block (c1).
                    // In this case event won't match and it will be handled in the next block.
                    let since = if prev.contains(schedule.start()) {
                        schedule.start()
                    } else {
                        prev.since() + prev.length()
                    };
                    let estimation = event.interval.since() + event.interval.length();
                    let length = estimation
                        .duration_since(since)
                        .unwrap_or_else(|_| Duration::from_secs(0));

                    TimeInterval::new(since, length)
                });

                count_matches_in_interval(schedule, &current_interval)
            }
        }
    }

    fn mintable(&self) -> bool {
        !matches!(
            self.0,
            ExecutionTime::Schedule(Schedule {
                period_ms: None,
                ..
            })
        )
    }
}

/// Count something with the `schedule` within the `interval`
#[cfg(feature = "transparent_api")]
fn count_matches_in_interval(schedule: &Schedule, interval: &TimeInterval) -> u32 {
    schedule.period().map_or_else(
        || u32::from(interval.contains(schedule.start())),
        |period| {
            #[allow(clippy::integer_division)]
            let k = interval
                .since()
                .duration_since(schedule.start())
                .unwrap_or_else(|_| Duration::from_secs(0))
                .as_millis()
                / period.as_millis();
            let start = schedule.start() + multiply_duration_by_u128(period, k);
            (0..)
                .map(|i| start + period * i)
                .skip_while(|time| *time < interval.since())
                .take_while(|time| interval.contains(*time))
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
    /// Create new [`Schedule`] starting at `start` and without period
    #[must_use]
    #[inline]
    #[cfg(feature = "std")]
    pub fn starting_at(start: SystemTime) -> Self {
        Self {
            start_ms: start
                .duration_since(SystemTime::UNIX_EPOCH)
                .expect("INTERNAL BUG: Failed to get the current system time")
                .as_millis()
                .try_into()
                .expect("INTERNAL BUG: Unix timestamp exceedes u64::MAX"),
            period_ms: None,
        }
    }

    /// Add `period` to `self`
    #[must_use]
    #[inline]
    pub fn with_period(mut self, period: Duration) -> Self {
        self.period_ms = Some(
            period
                .as_millis()
                .try_into()
                .expect("INTERNAL BUG: Unix timestamp exceedes u64::MAX"),
        );
        self
    }

    /// Instant of the first execution
    #[cfg(feature = "std")]
    pub fn start(&self) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_millis(self.start_ms)
    }

    /// Period of repeated executions
    pub fn period(&self) -> Option<Duration> {
        self.period_ms.map(Duration::from_millis)
    }
}

impl TimeInterval {
    /// Create new [`Self`]
    #[cfg(feature = "std")]
    pub fn new(since: SystemTime, length: Duration) -> Self {
        Self {
            since_ms: since
                .duration_since(SystemTime::UNIX_EPOCH)
                .expect("INTERNAL BUG: Failed to get the current system time")
                .as_millis()
                .try_into()
                .expect("INTERNAL BUG: Unix timestamp exceedes u64::MAX"),
            length_ms: length
                .as_millis()
                .try_into()
                .expect("INTERNAL BUG: Unix timestamp exceedes u64::MAX"),
        }
    }

    /// Instant of the previous execution
    #[cfg(feature = "std")]
    pub fn since(&self) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_millis(self.since_ms)
    }

    /// Time since the previous execution
    pub fn length(&self) -> Duration {
        Duration::from_millis(self.length_ms)
    }

    /// Checks whether interval contains given timestamp
    #[cfg(feature = "std")]
    pub fn contains(&self, time: SystemTime) -> bool {
        let since = self.since();
        since <= time && time < since + self.length()
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

    /// Sample timestamp
    fn sample_timestamp() -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(1_647_443_386)
    }

    /// Tests for `count_matches_in_interval()`
    mod count_matches_in_interval {
        use super::*;

        #[test]
        fn test_no_period_before_left_border() {
            // ----|-----[-----)-------
            //     p    i1     i2

            let schedule = Schedule::starting_at(sample_timestamp() - Duration::from_secs(5));
            let since = sample_timestamp();
            let length = Duration::from_secs(10);
            let interval = TimeInterval::new(since, length);
            assert_eq!(count_matches_in_interval(&schedule, &interval), 0);
        }

        #[test]
        fn test_no_period_on_left_border() {
            //     |
            // ----[---------)------
            //   p, i1      i2

            let schedule = Schedule::starting_at(sample_timestamp());
            let since = sample_timestamp();
            let length = Duration::from_secs(10);
            let interval = TimeInterval::new(since, length);
            assert_eq!(count_matches_in_interval(&schedule, &interval), 1);
        }

        #[test]
        fn test_no_period_inside() {
            // ----[------|-----)----
            //     i1     p    i2

            let schedule = Schedule::starting_at(sample_timestamp() + Duration::from_secs(5));
            let since = sample_timestamp();
            let length = Duration::from_secs(10);
            let interval = TimeInterval::new(since, length);
            assert_eq!(count_matches_in_interval(&schedule, &interval), 1);
        }

        #[test]
        fn test_no_period_on_right_border() {
            //               |
            // ----[---------)------
            //    i1      i2, p

            let schedule = Schedule::starting_at(sample_timestamp() + Duration::from_secs(10));
            let since = sample_timestamp();
            let length = Duration::from_secs(10);
            let interval = TimeInterval::new(since, length);
            assert_eq!(count_matches_in_interval(&schedule, &interval), 0);
        }

        #[test]
        fn test_jump_over_inside() {
            // ----[------|-----)----*----
            //     i1     p    i2

            let schedule = Schedule::starting_at(sample_timestamp() + Duration::from_secs(5))
                .with_period(Duration::from_secs(30));
            let since = sample_timestamp();
            let length = Duration::from_secs(10);
            let interval = TimeInterval::new(since, length);
            assert_eq!(count_matches_in_interval(&schedule, &interval), 1);
        }

        #[test]
        fn test_jump_over_outside() {
            // ----|------[-----)----*----
            //     p     i1    i2

            let schedule =
                Schedule::starting_at(sample_timestamp()).with_period(Duration::from_secs(10));
            let since = SystemTime::UNIX_EPOCH + Duration::from_secs(35);
            let length = Duration::from_secs(4);
            let interval = TimeInterval::new(since, length);
            assert_eq!(count_matches_in_interval(&schedule, &interval), 0);
        }

        #[test]
        fn test_interval_on_the_left() {
            // ----[----)----|-----*-----*----
            //     i1   i2   p

            let schedule =
                Schedule::starting_at(sample_timestamp()).with_period(Duration::from_secs(6));
            let since = sample_timestamp() - Duration::from_secs(10);
            let length = Duration::from_secs(4);
            let interval = TimeInterval::new(since, length);
            assert_eq!(count_matches_in_interval(&schedule, &interval), 0);
        }

        #[test]
        fn test_schedule_starts_at_the_middle() {
            // ----[------|----*----*----*--)-*----
            //     i1     p                i2

            let schedule =
                Schedule::starting_at(sample_timestamp()).with_period(Duration::from_secs(6));
            let since = sample_timestamp() - Duration::from_secs(10);
            let length = Duration::from_secs(30);
            let interval = TimeInterval::new(since, length);
            assert_eq!(count_matches_in_interval(&schedule, &interval), 4);
        }

        #[test]
        fn test_interval_on_the_right() {
            // ----|----*--[----*----*----*----*----)----*----
            //     p      i1                       i2

            let schedule =
                Schedule::starting_at(sample_timestamp()).with_period(Duration::from_millis(600));
            let since = sample_timestamp() + Duration::from_secs(3) + Duration::from_millis(500);
            let length = Duration::from_secs(2);
            let interval = TimeInterval::new(since, length);
            assert_eq!(count_matches_in_interval(&schedule, &interval), 4);
        }

        #[test]
        fn test_only_left_border() {
            //             *
            // ----|-------[----)--*-------*--
            //     p      i1   i2

            let schedule = Schedule::starting_at(sample_timestamp() - Duration::from_secs(10))
                .with_period(Duration::from_secs(10));
            let since = sample_timestamp();
            let length = Duration::from_secs(5);
            let interval = TimeInterval::new(since, length);
            assert_eq!(count_matches_in_interval(&schedule, &interval), 1);
        }

        #[test]
        fn test_only_right_border_inside() {
            //               *
            // ----[----|----)----*----*----
            //     i1   p    i2

            let schedule =
                Schedule::starting_at(sample_timestamp()).with_period(Duration::from_secs(5));
            let since = sample_timestamp() - Duration::from_secs(10);
            let length = Duration::from_secs(15);
            let interval = TimeInterval::new(since, length);
            assert_eq!(count_matches_in_interval(&schedule, &interval), 1);
        }

        #[test]
        fn test_only_right_border_outside() {
            //              *
            // ----|---[----)--------*----
            //     p   i1   i2

            let schedule = Schedule::starting_at(sample_timestamp() - Duration::from_secs(10))
                .with_period(Duration::from_secs(15));
            let since = sample_timestamp();
            let length = Duration::from_secs(5);
            let interval = TimeInterval::new(since, length);
            assert_eq!(count_matches_in_interval(&schedule, &interval), 0);
        }

        #[test]
        fn test_matches_right_border_and_ignores_left() {
            //     |             *
            // ----[-*-*-*-*-*-*-)-*-*-*
            //   p, i1           i2

            let schedule =
                Schedule::starting_at(sample_timestamp()).with_period(Duration::from_secs(1));
            let since = sample_timestamp();
            let length = Duration::from_secs(7);
            let interval = TimeInterval::new(since, length);
            assert_eq!(count_matches_in_interval(&schedule, &interval), 7);
        }
    }

    // Tests for [`TimeEventFilter`]
    mod time_event_filter {
        use super::*;

        #[test]
        fn test_schedule_start_before_prev_interval() {
            //
            // ----|---[--*--)--*--[--*--)----
            //     s   p1    p2   c1    c2

            let schedule =
                Schedule::starting_at(sample_timestamp()).with_period(Duration::from_secs(10));
            let filter = TimeEventFilter(ExecutionTime::Schedule(schedule));

            let since = sample_timestamp() + Duration::from_secs(5);
            let length = Duration::from_secs(10);
            let prev_interval = TimeInterval::new(since, length);

            let since = sample_timestamp() + Duration::from_secs(25);
            let length = Duration::from_secs(10);
            let interval = TimeInterval::new(since, length);

            let event = TimeEvent {
                prev_interval: Some(prev_interval),
                interval,
            };

            assert_eq!(filter.count_matches(&event), 2);
        }

        #[test]
        fn test_schedule_start_inside_prev_interval() {
            //
            // -------[--|--)--*--[--*--)----
            //        p1 s  p2   c1    c2

            let schedule = Schedule::starting_at(sample_timestamp() + Duration::from_secs(5))
                .with_period(Duration::from_secs(10));
            let filter = TimeEventFilter(ExecutionTime::Schedule(schedule));

            let since = sample_timestamp();
            let length = Duration::from_secs(10);
            let prev_interval = TimeInterval::new(since, length);

            let since = sample_timestamp() + Duration::from_secs(20);
            let length = Duration::from_secs(10);
            let interval = TimeInterval::new(since, length);

            let event = TimeEvent {
                prev_interval: Some(prev_interval),
                interval,
            };

            assert_eq!(filter.count_matches(&event), 3);
        }

        #[test]
        fn test_schedule_start_between_intervals() {
            //
            // -------[----)--|--[--*--)----
            //        p1   p2 s  c1    c2

            let schedule = Schedule::starting_at(sample_timestamp() + Duration::from_secs(15))
                .with_period(Duration::from_secs(10));
            let filter = TimeEventFilter(ExecutionTime::Schedule(schedule));

            let since = sample_timestamp();
            let length = Duration::from_secs(10);
            let prev_interval = TimeInterval::new(since, length);

            let since = sample_timestamp() + Duration::from_secs(20);
            let length = Duration::from_secs(10);
            let interval = TimeInterval::new(since, length);

            let event = TimeEvent {
                prev_interval: Some(prev_interval),
                interval,
            };

            assert_eq!(filter.count_matches(&event), 2);
        }

        #[test]
        fn test_schedule_start_inside_current_interval() {
            //
            // -------[----)----[--|--)----
            //        p1   p2   c1 s  c2

            let schedule = Schedule::starting_at(sample_timestamp() + Duration::from_secs(25))
                .with_period(Duration::from_secs(10));
            let filter = TimeEventFilter(ExecutionTime::Schedule(schedule));

            let since = sample_timestamp();
            let length = Duration::from_secs(10);
            let prev_interval = TimeInterval::new(since, length);

            let since = sample_timestamp() + Duration::from_secs(20);
            let length = Duration::from_secs(10);
            let interval = TimeInterval::new(since, length);

            let event = TimeEvent {
                prev_interval: Some(prev_interval),
                interval,
            };

            assert_eq!(filter.count_matches(&event), 0);
        }

        #[test]
        fn test_schedule_start_after_current_interval() {
            //
            // -------[----)----[----)--|--
            //        p1   p2   c1   c2 s

            let schedule = Schedule::starting_at(sample_timestamp() + Duration::from_secs(35))
                .with_period(Duration::from_secs(10));
            let filter = TimeEventFilter(ExecutionTime::Schedule(schedule));

            let since = sample_timestamp();
            let length = Duration::from_secs(10);
            let prev_interval = TimeInterval::new(since, length);

            let since = sample_timestamp() + Duration::from_secs(20);
            let length = Duration::from_secs(10);
            let interval = TimeInterval::new(since, length);

            let event = TimeEvent {
                prev_interval: Some(prev_interval),
                interval,
            };

            assert_eq!(filter.count_matches(&event), 0);
        }
    }
}
