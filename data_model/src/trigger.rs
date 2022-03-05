//! Structures traits and impls related to `Trigger`s.

#[cfg(not(feature = "std"))]
use alloc::{format, string::String, vec::Vec};
use core::{cmp::Ordering, time::Duration};

use iroha_macro::FromVariant;
use iroha_schema::IntoSchema;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

use crate::{
    metadata::Metadata, prelude::EventFilter, transaction::Executable, Identifiable, Name,
    ParseError,
};

/// Type which is used for registering a `Trigger`.
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Decode, Encode, Deserialize, Serialize, IntoSchema,
)]
pub struct Trigger {
    /// [`Id`] of the [`Trigger`].
    pub id: Id,
    /// Action to be performed when the trigger matches.
    pub action: Action,
    /// Metadata of this account as a key-value store.
    pub metadata: Metadata,
}

impl Trigger {
    /// Construct trigger, given name action and signatories.
    ///
    /// # Errors
    /// - Name is malformed
    pub fn new(name: &str, action: Action) -> Result<Self, ParseError> {
        let id = Id {
            name: Name::new(name)?,
        };
        Ok(Trigger {
            id,
            action,
            metadata: Metadata::new(),
        })
    }
}

/// Action to be performed when the trigger matches
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Decode,
    Encode,
    Deserialize,
    Serialize,
    IntoSchema,
    FromVariant,
)]
pub enum Action {
    /// Event based action
    EventBased(EventAction),
    /// Time based action
    TimeBased(TimeAction),
}

/// Trait to get `executable` and `technical_account` field to be able to execute action
pub trait ExecutionInfo {
    /// Returns action executable
    fn executable(&self) -> &Executable;

    /// Returns action technical account
    fn technical_account(&self) -> &super::account::Id;
}

/// Designed to differentiate between oneshot and unlimited event
/// triggers. If the trigger must be run a limited number of times,
/// it's the end-user's responsibility to either unregister the
/// `Unlimited` variant.
///
/// # Considerations
///
/// The granularity might not be sufficient to run an action exactly
/// `n` times. In order to ensure that it is even possible to run the
/// triggers without gaps, the `Executable` wrapped in the action must
/// be run before any of the ISIs are pushed into the queue of the
/// next block.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize, IntoSchema)]
pub struct EventAction {
    /// The executable linked to this action
    pub executable: Executable,
    /// The repeating scheme of the action. It's kept as part of the
    /// action and not inside the [`Trigger`] type, so that further
    /// sanity checking can be done.
    pub repeats: Repeats,
    /// Technical account linked to this trigger. The technical
    /// account must already exist in order for `Register<Trigger>` to
    /// work.
    pub technical_account: super::account::Id,
    /// Event filter to identify events on which this action should be performed.
    pub filter: EventFilter,
}

impl EventAction {
    /// Construct an action given `executable`, `repeats`, `technical_account` and `filter`.
    pub fn new(
        executable: impl Into<Executable>,
        repeats: impl Into<Repeats>,
        technical_account: super::account::Id,
        filter: EventFilter,
    ) -> EventAction {
        EventAction {
            executable: executable.into(),
            repeats: repeats.into(),
            // TODO: At this point the technical account is meaningless.
            technical_account,
            filter,
        }
    }
}

impl PartialOrd for EventAction {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for EventAction {
    fn cmp(&self, other: &Self) -> Ordering {
        // Exclude the executable. When debugging and replacing
        // the trigger, its position in Hash and Tree maps should
        // not change depending on the content.
        match self.repeats.cmp(&other.repeats) {
            Ordering::Equal => self.technical_account.cmp(&other.technical_account),
            ord => ord,
        }
    }
}

impl ExecutionInfo for EventAction {
    fn executable(&self) -> &Executable {
        &self.executable
    }

    fn technical_account(&self) -> &super::account::Id {
        &self.technical_account
    }
}

/// Action that happens every set time or exactly at set time.
/// If the trigger must be run every time interval, that's the end-user
/// responsibility to unregister it
///
/// # Considerations
///
/// It's not guaranteed that this action execution will be done in exactly the same time,
/// which is specified, but it's gonna be as close as possible.
/// Is'
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize, IntoSchema)]
pub struct TimeAction {
    /// The executable linked to this action
    pub executable: Executable,
    /// Technical account linked to this trigger. The technical
    /// account must already exist in order for `Register<Trigger>` to
    /// work.
    pub technical_account: super::account::Id,
    /// Time of this trigger appearance
    pub appears: Appears,
}

impl TimeAction {
    /// Construct an action given `executable`, `repeats`, `technical_account` and `appears`.
    pub fn new(
        executable: Executable,
        technical_account: super::account::Id,
        appears: Appears,
    ) -> Self {
        Self {
            executable,
            technical_account,
            appears,
        }
    }
}

impl PartialOrd for TimeAction {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for TimeAction {
    fn cmp(&self, other: &Self) -> Ordering {
        // Exclude the executable. When debugging and replacing
        // the trigger, its position in Hash and Tree maps should
        // not change depending on the content.
        match self.appears.cmp(&other.appears) {
            Ordering::Equal => self.technical_account.cmp(&other.technical_account),
            ord => ord,
        }
    }
}

impl ExecutionInfo for TimeAction {
    fn executable(&self) -> &Executable {
        &self.executable
    }

    fn technical_account(&self) -> &super::account::Id {
        &self.technical_account
    }
}

/// Enumeration of possible appearance schemes.
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
)]
pub enum Appears {
    /// Appear every set time
    Every(Interval),
    /// Appear once exactly on set time
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
)]
pub struct Interval {
    /// Since which time interval is measured. Initially should be action registration time.
    /// Updated every action execution.
    pub since: Duration,
    /// Step of interval or interval length
    pub step: Duration,
    /// How much time to repeat interval
    pub repeats: Repeats,
}

impl Interval {
    /// Construct `Interval` with `since`, `step` and `repeats`
    pub fn new(since: Duration, step: Duration, repeats: Repeats) -> Self {
        Self {
            since,
            step,
            repeats,
        }
    }
}

/// Enumeration of possible repetitions schemes.
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
)]
pub enum Repeats {
    /// Repeat indefinitely, until the trigger is unregistered.
    Indefinitely,
    /// Repeat a set number of times
    Exactly(u32), // If you need more, use `Indefinitely`.
}

impl From<u32> for Repeats {
    fn from(num: u32) -> Self {
        Repeats::Exactly(num)
    }
}

/// Identification of a `Trigger`.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Decode,
    Encode,
    Deserialize,
    Serialize,
    IntoSchema,
)]
pub struct Id {
    /// Name given to trigger by its creator.
    pub name: Name,
}

impl Identifiable for Trigger {
    type Id = Id;
}

impl Id {
    /// Construct [`Id`], while performing lenght checks and acceptable character validation.
    ///
    /// # Errors
    /// If name contains invalid characters.
    pub fn new(name: &str) -> Result<Self, ParseError> {
        Ok(Self {
            name: Name::new(name)?,
        })
    }

    /// Unchecked variant of [`Self::new`]. Does not panic on error.
    pub fn test(name: &str) -> Self {
        Self {
            name: Name::test(name),
        }
    }
}

pub mod prelude {
    //! Re-exports of commonly used types.
    pub use super::{EventAction, Id as TriggerId, Repeats, TimeAction, Trigger};
}
