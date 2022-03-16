//! Time event and filter

use core::{cmp::Ordering, ops::Range, time::Duration};

use super::*;

/// Special event that is emitted when `WSV` is ready for handling time-triggers
///
/// Contains time interval which is used to identify time-triggers to be executed
#[derive(Debug, Clone, Copy, PartialEq, Eq, Decode, Encode, IntoSchema)]
pub struct Event {
    /// Previous block timestamp and consensus durations estimation
    pub prev_interval: Interval,
    /// Current block timestamp and consensus durations estimation
    pub interval: Interval,
}

impl Event {
    /// Construct `Event` with `prev_interval` and `interval`
    pub fn new(prev_interval: Interval, interval: Interval) -> Self {
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
pub struct EventFilter(pub Reoccurs);

impl EventFilter {
    /// Compute how much times trigger with `self` as filter should be executed on `event`
    pub fn count_matches(&self, event: &Event) -> u32 {
        match &self.0 {
            Reoccurs::Periodically(periodicity) => {
                let mut res = Self::count_matches_in_interval(periodicity, &event.interval);

                let previous_estimation = event.prev_interval.since + event.prev_interval.length;

                // Counting matching points between estimated timestamp and the real one
                match event.interval.since.cmp(&previous_estimation) {
                    Ordering::Greater => {
                        let length = event.interval.since - previous_estimation;
                        let forgotten_count = Self::count_matches_in_interval(
                            periodicity,
                            &Interval::new(previous_estimation, length),
                        );
                        res += forgotten_count;
                    }
                    Ordering::Less => {
                        let length = previous_estimation - event.interval.since;
                        let twice_counted_count = Self::count_matches_in_interval(
                            periodicity,
                            &Interval::new(event.interval.since, length),
                        );
                        res -= twice_counted_count;
                    }
                    Ordering::Equal => (),
                }

                res
            }
            Reoccurs::ExactlyAt(time) => Range::from(event.interval).contains(time) as u32,
        }
    }

    /// Count how much thing with set `reoccurrence` should happen in time `interval`
    #[allow(clippy::expect_used, clippy::integer_division)]
    fn count_matches_in_interval(periodicity: &Periodicity, interval: &Interval) -> u32 {
        // p -- periodicity start point
        // i1 -- interval left border
        // i2 -- interval right border
        //
        // Case:
        // ------(-------)-----|-------
        //       i1     i2     p
        if interval.since + interval.length < periodicity.start {
            return 0;
        }

        // Normalizing values so that we can use the same math for the next cases
        //
        // Case 1:
        // -----(---------|------)-----
        //      i1        p     i2
        //
        // Case 2:
        // -----|----(----------)-----
        //      p    i1        i2
        let (normalized_since, normalized_length) = if interval.since > periodicity.start {
            (interval.since - periodicity.start, interval.length)
        } else {
            let diff = periodicity.start - interval.since;
            (Duration::ZERO, interval.length - diff)
        };

        // The first desired point inside `interval`
        let start = periodicity.period_length
            * u32::try_from(normalized_since.as_millis() / periodicity.period_length.as_millis())
                .expect(
                    "Time filter periodicity has a very small period length \
                and/or it has been set very long time ago",
                )
            + periodicity.period_length;
        if start > normalized_since + normalized_length {
            return 0;
        }

        let diff = start - normalized_since;
        1_u32
            + u32::try_from(
                (normalized_length - diff).as_millis() / periodicity.period_length.as_millis(),
            )
            .expect(
                "Time filter periodicity has a very small period length \
            and/or previous block was committed very long time ago",
            )
    }
}

/// Enumeration of possible recurrence schemes
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
pub enum Reoccurs {
    /// Occurs periodically
    Periodically(Periodicity),
    /// Occurs once exactly on set time
    ExactlyAt(Duration),
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

/// Represents endless periodicity that starts at some `start` point of time
/// and reoccurs every `period_length` time
///
/// Looks similar to `Interval` but has different semantics
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
pub struct Periodicity {
    /// Period registration time
    pub start: Duration,
    /// Length of time interval
    pub period_length: Duration,
}

impl Periodicity {
    /// Construct `Periodicity` with `start` and `period_length`
    pub fn new(start: Duration, period_length: Duration) -> Self {
        Self {
            start,
            period_length,
        }
    }
}

/// Exports common structs and enums from this module.
pub mod prelude {
    pub use super::{
        Event as TimeEvent, EventFilter as TimeEventFilter, Interval as TimeInterval,
        Periodicity as TimePeriodicity, Reoccurs,
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
        fn test_jump_over_inside() {
            // ----(------|-----)----*----
            //     i1     p    i2

            let periodicity =
                Periodicity::new(Duration::from_secs(TIMESTAMP + 5), Duration::from_secs(30));
            let interval = Interval::new(Duration::from_secs(TIMESTAMP), Duration::from_secs(10));
            assert_eq!(
                EventFilter::count_matches_in_interval(&periodicity, &interval),
                0
            );
        }

        #[test]
        fn test_jump_over_outside() {
            // ----|------(-----)----*----
            //     p     i1    i2

            let periodicity =
                Periodicity::new(Duration::from_secs(TIMESTAMP), Duration::from_secs(10));
            let interval =
                Interval::new(Duration::from_secs(TIMESTAMP + 35), Duration::from_secs(4));
            assert_eq!(
                EventFilter::count_matches_in_interval(&periodicity, &interval),
                0
            );
        }

        #[test]
        fn test_interval_on_the_left() {
            // ----(----)----|-----*-----*----
            //     i1   i2   p

            let periodicity =
                Periodicity::new(Duration::from_secs(TIMESTAMP), Duration::from_secs(6));
            let interval =
                Interval::new(Duration::from_secs(TIMESTAMP - 10), Duration::from_secs(4));
            assert_eq!(
                EventFilter::count_matches_in_interval(&periodicity, &interval),
                0
            );
        }

        #[test]
        fn test_periodicy_starts_at_the_middle() {
            // ----(------|----*----*----*--)-*----
            //     i1     p                i2

            let periodicity =
                Periodicity::new(Duration::from_secs(TIMESTAMP), Duration::from_secs(6));
            let interval =
                Interval::new(Duration::from_secs(TIMESTAMP - 10), Duration::from_secs(30));
            assert_eq!(
                EventFilter::count_matches_in_interval(&periodicity, &interval),
                3
            );
        }

        #[test]
        fn test_interval_on_the_right() {
            // ----|----*--(----*----*----*----*----)----*----
            //     p      i1                       i2

            let periodicity =
                Periodicity::new(Duration::from_secs(TIMESTAMP), Duration::from_millis(600));
            let interval = Interval::new(
                Duration::from_secs(TIMESTAMP + 3) + Duration::from_millis(500),
                Duration::from_secs(2),
            );
            assert_eq!(
                EventFilter::count_matches_in_interval(&periodicity, &interval),
                4
            );
        }

        #[test]
        fn test_only_right_border_inside() {
            //               *
            // ----(----|----)----*----*----
            //     i1   p    i2

            let periodicity =
                Periodicity::new(Duration::from_secs(TIMESTAMP), Duration::from_secs(5));
            let interval =
                Interval::new(Duration::from_secs(TIMESTAMP - 10), Duration::from_secs(15));
            assert_eq!(
                EventFilter::count_matches_in_interval(&periodicity, &interval),
                1
            );
        }

        #[test]
        fn test_only_left_border() {
            //             *
            // ----|-------(----)--*-------*--
            //     p      i1   i2

            let periodicity =
                Periodicity::new(Duration::from_secs(TIMESTAMP - 10), Duration::from_secs(10));
            let interval = Interval::new(Duration::from_secs(TIMESTAMP), Duration::from_secs(5));
            assert_eq!(
                EventFilter::count_matches_in_interval(&periodicity, &interval),
                0
            );
        }

        #[test]
        fn test_only_right_border_outside() {
            //              *
            // ----|---(----)--------*----
            //     p   i1   i2

            let periodicity =
                Periodicity::new(Duration::from_secs(TIMESTAMP - 10), Duration::from_secs(5));
            let interval = Interval::new(Duration::from_secs(TIMESTAMP), Duration::from_secs(5));
            assert_eq!(
                EventFilter::count_matches_in_interval(&periodicity, &interval),
                1
            );
        }

        #[test]
        fn test_matches_right_border_and_ignores_left() {
            //     |             *
            // ----(-*-*-*-*-*-*-)-*-*-*
            //   p, i1           i2

            let periodicity =
                Periodicity::new(Duration::from_secs(TIMESTAMP), Duration::from_secs(1));
            let interval = Interval::new(Duration::from_secs(TIMESTAMP), Duration::from_secs(7));
            assert_eq!(
                EventFilter::count_matches_in_interval(&periodicity, &interval),
                7
            );
        }
    }
}
