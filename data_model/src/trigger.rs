//! Structures traits and impls related to `Trigger`s.

#[cfg(not(feature = "std"))]
use alloc::{format, string::String, vec::Vec};
use core::{cmp::Ordering, fmt, str::FromStr};

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
    pub id: <Self as Identifiable>::Id,
    /// Action to be performed when the trigger matches.
    pub action: Action,
}

impl Trigger {
    /// Construct trigger, given name action and signatories.
    pub fn new(
        id: <Self as Identifiable>::Id,
        action: Action,
    ) -> <Self as Identifiable>::RegisteredWith {
        Self { id, action }
    }
}

impl Identifiable for Trigger {
    type Id = Id;
    type RegisteredWith = Self;
}

/// Designed to differentiate between oneshot and unlimited
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
pub struct Action {
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
    /// Defines events which trigger the `Action`
    pub filter: EventFilter,
    /// Metadata used as persistent storage for trigger data.
    pub metadata: Metadata,
}

impl Action {
    /// Construct an action given `executable`, `repeats`, `technical_account` and `filter`.
    pub fn new(
        executable: impl Into<Executable>,
        repeats: impl Into<Repeats>,
        technical_account: super::account::Id,
        filter: EventFilter,
    ) -> Self {
        Self {
            executable: executable.into(),
            repeats: repeats.into(),
            // TODO: At this point the technical account is meaningless.
            technical_account,
            filter,
            metadata: Metadata::new(),
        }
    }

    /// Add [`Metadata`] to the trigger replacing previously defined
    #[must_use]
    pub fn with_metadata(mut self, metadata: Metadata) -> Self {
        self.metadata = metadata;
        self
    }
}

impl PartialOrd for Action {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Action {
    fn cmp(&self, other: &Self) -> Ordering {
        // Exclude the executable. When debugging and replacing
        // the trigger, its position in Hash and Tree maps should
        // not change depending on the content.
        match self.repeats.cmp(&other.repeats) {
            Ordering::Equal => {}
            ord => return ord,
        }
        self.technical_account.cmp(&other.technical_account)
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

impl fmt::Display for Id {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.name.fmt(f)
    }
}

impl Id {
    /// Construct [`Id`], while performing lenght checks and acceptable character validation.
    ///
    /// # Errors
    /// If name contains invalid characters.
    pub fn new(name: Name) -> Self {
        Self { name }
    }
}

impl FromStr for Id {
    type Err = ParseError;

    fn from_str(name: &str) -> Result<Self, Self::Err> {
        Ok(Self {
            name: Name::from_str(name)?,
        })
    }
}

pub mod prelude {
    //! Re-exports of commonly used types.
    pub use super::{Action, Id as TriggerId, Repeats, Trigger};
}
