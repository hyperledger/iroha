//! Time event and filter

use core::{ops::Range, time::Duration};

use super::*;

/// Special event that is emitted when `WSV` is ready for handling time-triggers
///
/// Contains time interval which is used to identify time-triggers to be executed
#[derive(Debug, Clone, Copy, PartialEq, Eq, Decode, Encode, IntoSchema)]
pub struct Event {
    /// Previous block timestamp and consensus durations estimation.
    /// `None` if it's first block commit
    pub prev_interval: Option<Interval>,
    /// Current block timestamp and consensus durations estimation
    pub interval: Interval,
}

impl Event {
    /// Construct `Event` with `prev_interval` and `interval`
    pub fn new(prev_interval: Option<Interval>, interval: Interval) -> Self {
        Self {
            prev_interval,
            interval,
        }
    }
}

/// Filters time-events and allows only ones which time interval contains
#[derive(
    Debug,
    PartialOrd,
    Ord,
    PartialEq,
    Eq,
    Clone,
    Copy,
    Decode,
    Encode,
    IntoSchema,
    Hash,
    Serialize,
    Deserialize,
)]
pub struct EventFilter(pub Schedule);

impl EventFilter {
    /// Compute how much times trigger with `self` as filter should be executed on `event`
    pub fn count_matches(&self, event: &Event) -> u32 {
        let current_interval = event.prev_interval.map_or(event.interval, |prev| {
            let estimation = event.interval.since + event.interval.length;
            let prev_estimation = prev.since + prev.length;
            Interval::new(prev_estimation, estimation.saturating_sub(prev_estimation))
        });

        Self::count_matches_in_interval(&self.0, &current_interval)
    }

    /// Count something with the `schedule` within the `interval`
    #[allow(clippy::expect_used)]
    fn count_matches_in_interval(schedule: &Schedule, interval: &Interval) -> u32 {
        schedule.cycle.map_or_else(
            || u32::from(Range::from(*interval).contains(&schedule.start)),
            |cycle| {
                (0..)
                    .map(|i| schedule.start + cycle * i)
                    .skip_while(|time| *time < interval.since)
                    .take_while(|time| Range::from(*interval).contains(time))
                    .count()
                    .try_into()
                    .expect(
                        "Overflow. The schedule is too frequent relative to the interval length",
                    )
            },
        )
    }
}

/// Schedule of the trigger
#[derive(
    Debug,
    Clone,
    Copy,
    PartialOrd,
    Ord,
    PartialEq,
    Eq,
    Encode,
    Decode,
    Serialize,
    Deserialize,
    IntoSchema,
    Hash,
)]
pub struct Schedule {
    /// The first execution time
    pub start: Duration,
    /// If some, the period between cyclic executions
    pub cycle: Option<Duration>,
}

impl Schedule {
    /// Create new `Schedule` with `start` and `cycle`
    pub fn new(start: Duration, cycle: Option<Duration>) -> Self {
        Self { start, cycle }
    }
}

/// Time interval in which `TimeAction` should appear
#[derive(
    Debug,
    Copy,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    Serialize,
    Deserialize,
    IntoSchema,
    Hash,
)]
pub struct Interval {
    /// Since which time interval is measured
    pub since: Duration,
    /// Length of time interval
    pub length: Duration,
}

impl Interval {
    /// Construct `Interval` with `since` and `step`
    pub fn new(since: Duration, length: Duration) -> Self {
        Self { since, length }
    }
}

impl From<Interval> for Range<Duration> {
    fn from(interval: Interval) -> Self {
        interval.since..interval.since + interval.length
    }
}

/// Exports common structs and enums from this module.
pub mod prelude {
    pub use super::{
        Event as TimeEvent, EventFilter as TimeEventFilter, Interval as TimeInterval,
        Schedule as TimeSchedule,
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Tests for `EventFilter::count_matches_in_interval()`
    mod count_matches_in_interval {
        use super::*;

        /// Sample timestamp
        const TIMESTAMP: u64 = 1_647_443_386;

        #[test]
        fn test_no_cycle_before_left_border() {
            // ----|-----[-----)-------
            //     p    i1     i2

            let schedule = Schedule::new(Duration::from_secs(TIMESTAMP - 5), None);
            let interval = Interval::new(Duration::from_secs(TIMESTAMP), Duration::from_secs(10));
            assert_eq!(
                EventFilter::count_matches_in_interval(&schedule, &interval),
                0
            );
        }

        #[test]
        fn test_no_cycle_on_left_border() {
            //     |
            // ----[---------)------
            //    p,i1      i2

            let schedule = Schedule::new(Duration::from_secs(TIMESTAMP), None);
            let interval = Interval::new(Duration::from_secs(TIMESTAMP), Duration::from_secs(10));
            assert_eq!(
                EventFilter::count_matches_in_interval(&schedule, &interval),
                1
            );
        }

        #[test]
        fn test_no_cycle_inside() {
            // ----[------|-----)----
            //     i1     p    i2

            let schedule = Schedule::new(Duration::from_secs(TIMESTAMP + 5), None);
            let interval = Interval::new(Duration::from_secs(TIMESTAMP), Duration::from_secs(10));
            assert_eq!(
                EventFilter::count_matches_in_interval(&schedule, &interval),
                1
            );
        }

        #[test]
        fn test_jump_over_inside() {
            // ----[------|-----)----*----
            //     i1     p    i2

            let schedule = Schedule::new(
                Duration::from_secs(TIMESTAMP + 5),
                Some(Duration::from_secs(30)),
            );
            let interval = Interval::new(Duration::from_secs(TIMESTAMP), Duration::from_secs(10));
            assert_eq!(
                EventFilter::count_matches_in_interval(&schedule, &interval),
                1
            );
        }

        #[test]
        fn test_jump_over_outside() {
            // ----|------[-----)----*----
            //     p     i1    i2

            let schedule = Schedule::new(
                Duration::from_secs(TIMESTAMP),
                Some(Duration::from_secs(10)),
            );
            let interval =
                Interval::new(Duration::from_secs(TIMESTAMP + 35), Duration::from_secs(4));
            assert_eq!(
                EventFilter::count_matches_in_interval(&schedule, &interval),
                0
            );
        }

        #[test]
        fn test_interval_on_the_left() {
            // ----[----)----|-----*-----*----
            //     i1   i2   p

            let schedule =
                Schedule::new(Duration::from_secs(TIMESTAMP), Some(Duration::from_secs(6)));
            let interval =
                Interval::new(Duration::from_secs(TIMESTAMP - 10), Duration::from_secs(4));
            assert_eq!(
                EventFilter::count_matches_in_interval(&schedule, &interval),
                0
            );
        }

        #[test]
        fn test_schedule_starts_at_the_middle() {
            // ----[------|----*----*----*--)-*----
            //     i1     p                i2

            let schedule =
                Schedule::new(Duration::from_secs(TIMESTAMP), Some(Duration::from_secs(6)));
            let interval =
                Interval::new(Duration::from_secs(TIMESTAMP - 10), Duration::from_secs(30));
            assert_eq!(
                EventFilter::count_matches_in_interval(&schedule, &interval),
                4
            );
        }

        #[test]
        fn test_interval_on_the_right() {
            // ----|----*--[----*----*----*----*----)----*----
            //     p      i1                       i2

            let schedule = Schedule::new(
                Duration::from_secs(TIMESTAMP),
                Some(Duration::from_millis(600)),
            );
            let interval = Interval::new(
                Duration::from_secs(TIMESTAMP + 3) + Duration::from_millis(500),
                Duration::from_secs(2),
            );
            assert_eq!(
                EventFilter::count_matches_in_interval(&schedule, &interval),
                4
            );
        }

        #[test]
        fn test_only_left_border() {
            //             *
            // ----|-------[----)--*-------*--
            //     p      i1   i2

            let schedule = Schedule::new(
                Duration::from_secs(TIMESTAMP - 10),
                Some(Duration::from_secs(10)),
            );
            let interval = Interval::new(Duration::from_secs(TIMESTAMP), Duration::from_secs(5));
            assert_eq!(
                EventFilter::count_matches_in_interval(&schedule, &interval),
                1
            );
        }

        #[test]
        fn test_only_right_border_inside() {
            //               *
            // ----[----|----)----*----*----
            //     i1   p    i2

            let schedule =
                Schedule::new(Duration::from_secs(TIMESTAMP), Some(Duration::from_secs(5)));
            let interval =
                Interval::new(Duration::from_secs(TIMESTAMP - 10), Duration::from_secs(15));
            assert_eq!(
                EventFilter::count_matches_in_interval(&schedule, &interval),
                1
            );
        }

        #[test]
        fn test_only_right_border_outside() {
            //              *
            // ----|---[----)--------*----
            //     p   i1   i2

            let schedule = Schedule::new(
                Duration::from_secs(TIMESTAMP - 10),
                Some(Duration::from_secs(15)),
            );
            let interval = Interval::new(Duration::from_secs(TIMESTAMP), Duration::from_secs(5));
            assert_eq!(
                EventFilter::count_matches_in_interval(&schedule, &interval),
                0
            );
        }

        #[test]
        fn test_matches_right_border_and_ignores_left() {
            //     |             *
            // ----[-*-*-*-*-*-*-)-*-*-*
            //   p, i1           i2

            let schedule =
                Schedule::new(Duration::from_secs(TIMESTAMP), Some(Duration::from_secs(1)));
            let interval = Interval::new(Duration::from_secs(TIMESTAMP), Duration::from_secs(7));
            assert_eq!(
                EventFilter::count_matches_in_interval(&schedule, &interval),
                7
            );
        }
    }
}
