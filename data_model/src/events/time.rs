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
    pub const fn new(prev_interval: Option<Interval>, interval: Interval) -> Self {
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
pub struct EventFilter(pub ExecutionTime);

impl Filter for EventFilter {
    type EventType = Event;

    /// Isn't useful for time-triggers
    fn matches(&self, event: &Event) -> bool {
        self.count_matches(event) > 0
    }

    fn count_matches(&self, event: &Event) -> u32 {
        match &self.0 {
            ExecutionTime::PreCommit => 1,
            ExecutionTime::Schedule(schedule) => {
                let current_interval = event.prev_interval.map_or(event.interval, |prev| {
                    let estimation = event.interval.since + event.interval.length;
                    let prev_estimation = prev.since + prev.length;
                    Interval::new(prev_estimation, estimation.saturating_sub(prev_estimation))
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
#[allow(clippy::expect_used)]
fn count_matches_in_interval(schedule: &Schedule, interval: &Interval) -> u32 {
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
#[allow(clippy::expect_used, clippy::integer_division)]
fn multiply_duration_by_u128(duration: Duration, n: u128) -> Duration {
    if let Ok(n) = u32::try_from(n) {
        return duration * n;
    }

    let new_ms = duration.as_millis() * n;
    if let Ok(ms) = u64::try_from(new_ms) {
        return Duration::from_millis(ms);
    }

    let new_secs = u64::try_from(new_ms / 1000)
        .expect("Overflow. Resulting number in seconds can't be represented as `u64`");
    Duration::from_secs(new_secs)
}

/// Trigger execution time
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
    pub period: Option<Duration>,
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
    #[inline]
    pub const fn new(since: Duration, length: Duration) -> Self {
        Self { since, length }
    }
}

impl From<Interval> for Range<Duration> {
    #[inline]
    fn from(interval: Interval) -> Self {
        interval.since..interval.since + interval.length
    }
}

/// Exports common structs and enums from this module.
pub mod prelude {
    pub use super::{
        Event as TimeEvent, EventFilter as TimeEventFilter, ExecutionTime,
        Interval as TimeInterval, Schedule as TimeSchedule,
    };
}

#[cfg(test)]
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
            let interval = Interval::new(Duration::from_secs(TIMESTAMP), Duration::from_secs(10));
            assert_eq!(count_matches_in_interval(&schedule, &interval), 0);
        }

        #[test]
        fn test_no_period_on_left_border() {
            //     |
            // ----[---------)------
            //   p, i1      i2

            let schedule = Schedule::starting_at(Duration::from_secs(TIMESTAMP));
            let interval = Interval::new(Duration::from_secs(TIMESTAMP), Duration::from_secs(10));
            assert_eq!(count_matches_in_interval(&schedule, &interval), 1);
        }

        #[test]
        fn test_no_period_inside() {
            // ----[------|-----)----
            //     i1     p    i2

            let schedule = Schedule::starting_at(Duration::from_secs(TIMESTAMP + 5));
            let interval = Interval::new(Duration::from_secs(TIMESTAMP), Duration::from_secs(10));
            assert_eq!(count_matches_in_interval(&schedule, &interval), 1);
        }

        #[test]
        fn test_no_period_on_right_border() {
            //               |
            // ----[---------)------
            //    i1      i2, p

            let schedule = Schedule::starting_at(Duration::from_secs(TIMESTAMP + 10));
            let interval = Interval::new(Duration::from_secs(TIMESTAMP), Duration::from_secs(10));
            assert_eq!(count_matches_in_interval(&schedule, &interval), 0);
        }

        #[test]
        fn test_jump_over_inside() {
            // ----[------|-----)----*----
            //     i1     p    i2

            let schedule = Schedule::starting_at(Duration::from_secs(TIMESTAMP + 5))
                .with_period(Duration::from_secs(30));
            let interval = Interval::new(Duration::from_secs(TIMESTAMP), Duration::from_secs(10));
            assert_eq!(count_matches_in_interval(&schedule, &interval), 1);
        }

        #[test]
        fn test_jump_over_outside() {
            // ----|------[-----)----*----
            //     p     i1    i2

            let schedule = Schedule::starting_at(Duration::from_secs(TIMESTAMP))
                .with_period(Duration::from_secs(10));
            let interval =
                Interval::new(Duration::from_secs(TIMESTAMP + 35), Duration::from_secs(4));
            assert_eq!(count_matches_in_interval(&schedule, &interval), 0);
        }

        #[test]
        fn test_interval_on_the_left() {
            // ----[----)----|-----*-----*----
            //     i1   i2   p

            let schedule = Schedule::starting_at(Duration::from_secs(TIMESTAMP))
                .with_period(Duration::from_secs(6));
            let interval =
                Interval::new(Duration::from_secs(TIMESTAMP - 10), Duration::from_secs(4));
            assert_eq!(count_matches_in_interval(&schedule, &interval), 0);
        }

        #[test]
        fn test_schedule_starts_at_the_middle() {
            // ----[------|----*----*----*--)-*----
            //     i1     p                i2

            let schedule = Schedule::starting_at(Duration::from_secs(TIMESTAMP))
                .with_period(Duration::from_secs(6));
            let interval =
                Interval::new(Duration::from_secs(TIMESTAMP - 10), Duration::from_secs(30));
            assert_eq!(count_matches_in_interval(&schedule, &interval), 4);
        }

        #[test]
        fn test_interval_on_the_right() {
            // ----|----*--[----*----*----*----*----)----*----
            //     p      i1                       i2

            let schedule = Schedule::starting_at(Duration::from_secs(TIMESTAMP))
                .with_period(Duration::from_millis(600));
            let interval = Interval::new(
                Duration::from_secs(TIMESTAMP + 3) + Duration::from_millis(500),
                Duration::from_secs(2),
            );
            assert_eq!(count_matches_in_interval(&schedule, &interval), 4);
        }

        #[test]
        fn test_only_left_border() {
            //             *
            // ----|-------[----)--*-------*--
            //     p      i1   i2

            let schedule = Schedule::starting_at(Duration::from_secs(TIMESTAMP - 10))
                .with_period(Duration::from_secs(10));
            let interval = Interval::new(Duration::from_secs(TIMESTAMP), Duration::from_secs(5));
            assert_eq!(count_matches_in_interval(&schedule, &interval), 1);
        }

        #[test]
        fn test_only_right_border_inside() {
            //               *
            // ----[----|----)----*----*----
            //     i1   p    i2

            let schedule = Schedule::starting_at(Duration::from_secs(TIMESTAMP))
                .with_period(Duration::from_secs(5));
            let interval =
                Interval::new(Duration::from_secs(TIMESTAMP - 10), Duration::from_secs(15));
            assert_eq!(count_matches_in_interval(&schedule, &interval), 1);
        }

        #[test]
        fn test_only_right_border_outside() {
            //              *
            // ----|---[----)--------*----
            //     p   i1   i2

            let schedule = Schedule::starting_at(Duration::from_secs(TIMESTAMP - 10))
                .with_period(Duration::from_secs(15));
            let interval = Interval::new(Duration::from_secs(TIMESTAMP), Duration::from_secs(5));
            assert_eq!(count_matches_in_interval(&schedule, &interval), 0);
        }

        #[test]
        fn test_matches_right_border_and_ignores_left() {
            //     |             *
            // ----[-*-*-*-*-*-*-)-*-*-*
            //   p, i1           i2

            let schedule = Schedule::starting_at(Duration::from_secs(TIMESTAMP))
                .with_period(Duration::from_secs(1));
            let interval = Interval::new(Duration::from_secs(TIMESTAMP), Duration::from_secs(7));
            assert_eq!(count_matches_in_interval(&schedule, &interval), 7);
        }
    }
}
