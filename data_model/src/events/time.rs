//! Time event and filter

use std::{ops::Range, time::Duration};

use super::*;

/// Special event that is emitted when `WSV` is ready for handling time-triggers
///
/// Contains time interval which is used to identify time-triggers to be executed
#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, IntoSchema)]
pub struct Event(pub Interval);

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
pub struct EventFilter(pub Occurrence);

impl EventFilter {
    /// Check if `event` matches filter
    ///
    /// Returns `true`, if `event` matches filter and `false` if not
    pub fn matches(&self, event: &Event) -> bool {
        match &self.0 {
            Occurrence::Every(interval) => {
                let time = interval.since + interval.length;
                Range::from(event.0).contains(&time)
            }
            Occurrence::ExactlyAt(time) => Range::from(event.0).contains(time),
        }
    }
}

/// Enumeration of possible occurrence schemes
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
pub enum Occurrence {
    /// Occurs every set time
    Every(Interval),
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

/// Exports common structs and enums from this module.
pub mod prelude {
    pub use super::{
        Event as TimeEvent, EventFilter as TimeEventFilter, Interval as TimeInterval, Occurrence,
    };
}
