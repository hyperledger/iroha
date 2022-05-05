//! Structures traits and impls related to `Trigger`s.

#[cfg(not(feature = "std"))]
use alloc::{format, string::String, vec::Vec};
use core::{
    cmp::Eq,
    fmt,
    str::FromStr,
    sync::atomic::{AtomicU32, Ordering},
};

use iroha_schema::IntoSchema;
use parity_scale_codec::{Decode, Encode, Output, WrapperTypeDecode};
use serde::{Deserialize, Serialize};

use crate::{
    events::prelude::*, metadata::Metadata, transaction::Executable, Identifiable, Name, ParseError,
};

/// Type which is used for registering a `Trigger`.
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Decode, Encode, Deserialize, Serialize, IntoSchema,
)]
pub struct Trigger<F: Filter> {
    /// [`Id`] of the [`Trigger`].
    pub id: Id,
    /// Action to be performed when the trigger matches.
    pub action: Action<F>,
}

impl<F: Filter> Trigger<F> {
    /// Construct trigger, given name action and signatories.
    pub fn new(id: Id, action: Action<F>) -> Self {
        Self { id, action }
    }
}

impl TryFrom<Trigger<FilterBox>> for Trigger<DataEventFilter> {
    type Error = &'static str;

    fn try_from(boxed: Trigger<FilterBox>) -> Result<Self, Self::Error> {
        if let FilterBox::Data(data_filter) = boxed.action.filter {
            let action = Action::new(
                boxed.action.executable,
                boxed.action.repeats,
                boxed.action.technical_account,
                data_filter,
            );
            Ok(Self {
                id: boxed.id,
                action,
            })
        } else {
            Err("Expected `FilterBox::Data`, but another variant found")
        }
    }
}

impl TryFrom<Trigger<FilterBox>> for Trigger<PipelineEventFilter> {
    type Error = &'static str;

    fn try_from(boxed: Trigger<FilterBox>) -> Result<Self, Self::Error> {
        if let FilterBox::Pipeline(pipeline_filter) = boxed.action.filter {
            let action = Action::new(
                boxed.action.executable,
                boxed.action.repeats,
                boxed.action.technical_account,
                pipeline_filter,
            );
            Ok(Self {
                id: boxed.id,
                action,
            })
        } else {
            Err("Expected `FilterBox::Pipeline`, but another variant found")
        }
    }
}

impl TryFrom<Trigger<FilterBox>> for Trigger<TimeEventFilter> {
    type Error = &'static str;

    fn try_from(boxed: Trigger<FilterBox>) -> Result<Self, Self::Error> {
        if let FilterBox::Time(time_filter) = boxed.action.filter {
            let action = Action::new(
                boxed.action.executable,
                boxed.action.repeats,
                boxed.action.technical_account,
                time_filter,
            );
            Ok(Self {
                id: boxed.id,
                action,
            })
        } else {
            Err("Expected `FilterBox::Time`, but another variant found")
        }
    }
}

impl TryFrom<Trigger<FilterBox>> for Trigger<ExecuteTriggerEventFilter> {
    type Error = &'static str;

    fn try_from(boxed: Trigger<FilterBox>) -> Result<Self, Self::Error> {
        if let FilterBox::ExecuteTrigger(execute_trigger_filter) = boxed.action.filter {
            let action = Action::new(
                boxed.action.executable,
                boxed.action.repeats,
                boxed.action.technical_account,
                execute_trigger_filter,
            );
            Ok(Self {
                id: boxed.id,
                action,
            })
        } else {
            Err("Expected `FilterBox::ExecuteTrigger`, but another variant found")
        }
    }
}

impl Identifiable for Trigger<FilterBox> {
    type Id = Id;
    type RegisteredWith = Self;
}

/// Trait for common methods for all [`Action`]'s
pub trait ActionTrait {
    /// Get action executable
    fn executable(&self) -> &Executable;

    /// Get action repeats enum
    fn repeats(&self) -> &Repeats;

    /// Set action repeats
    fn set_repeats(&mut self, repeats: Repeats);

    /// Get action technical account
    fn technical_account(&self) -> &super::account::Id;

    /// Get action metadata
    fn metadata(&self) -> &Metadata;

    /// Check if action is mintable.
    fn mintable(&self) -> bool;

    /// Convert action to a boxed representation
    fn into_boxed(self) -> Action<FilterBox>;

    /// Same as `into_boxed()` but clones `self`
    fn clone_and_box(&self) -> Action<FilterBox>;
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
pub struct Action<F: Filter> {
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
    pub filter: F,
    /// Metadata used as persistent storage for trigger data.
    pub metadata: Metadata,
}

impl<F: Filter> Action<F> {
    /// Construct an action given `executable`, `repeats`, `technical_account` and `filter`.
    pub fn new(
        executable: impl Into<Executable>,
        repeats: impl Into<Repeats>,
        technical_account: super::account::Id,
        filter: F,
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

impl<F: Filter + Into<FilterBox> + Clone> ActionTrait for Action<F> {
    fn executable(&self) -> &Executable {
        &self.executable
    }

    fn repeats(&self) -> &Repeats {
        &self.repeats
    }

    fn set_repeats(&mut self, repeats: Repeats) {
        self.repeats = repeats;
    }

    fn technical_account(&self) -> &crate::account::Id {
        &self.technical_account
    }

    fn metadata(&self) -> &Metadata {
        &self.metadata
    }

    fn mintable(&self) -> bool {
        self.filter.mintable()
    }

    fn into_boxed(self) -> Action<FilterBox> {
        Action::<FilterBox>::new(
            self.executable,
            self.repeats,
            self.technical_account,
            self.filter.into(),
        )
    }

    fn clone_and_box(&self) -> Action<FilterBox> {
        Action::<FilterBox>::new(
            self.executable.clone(),
            self.repeats.clone(),
            self.technical_account.clone(),
            self.filter.clone().into(),
        )
    }
}

impl<F: Filter + PartialEq> PartialOrd for Action<F> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        // Exclude the executable. When debugging and replacing
        // the trigger, its position in Hash and Tree maps should
        // not change depending on the content.
        match self.repeats.cmp(&other.repeats) {
            std::cmp::Ordering::Equal => {}
            ord => return Some(ord),
        }
        Some(self.technical_account.cmp(&other.technical_account))
    }
}

#[allow(clippy::expect_used)]
impl<F: Filter + Eq> Ord for Action<F> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.partial_cmp(other)
            .expect("`PartialCmp::partial_cmp()` for `Action` should never return `None`")
    }
}

/// Enumeration of possible repetitions schemes.
#[derive(Debug, Clone, Encode, Decode, Serialize, Deserialize, IntoSchema)]
pub enum Repeats {
    /// Repeat indefinitely, until the trigger is unregistered.
    Indefinitely,
    /// Repeat a set number of times
    Exactly(AtomicU32Wrapper), // If you need more, use `Indefinitely`.
}

impl PartialOrd for Repeats {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Repeats {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        match (self, other) {
            (Repeats::Indefinitely, Repeats::Indefinitely) => std::cmp::Ordering::Equal,
            (Repeats::Indefinitely, Repeats::Exactly(_)) => std::cmp::Ordering::Greater,
            (Repeats::Exactly(_), Repeats::Indefinitely) => std::cmp::Ordering::Less,
            (Repeats::Exactly(l), Repeats::Exactly(r)) => l.cmp(r),
        }
    }
}

impl PartialEq for Repeats {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Exactly(l0), Self::Exactly(r0)) => l0 == r0,
            _ => false,
        }
    }
}

impl Eq for Repeats {}

impl From<u32> for Repeats {
    fn from(num: u32) -> Self {
        Repeats::Exactly(AtomicU32Wrapper::new(num))
    }
}

/// Wrapper for [`AtomicU32`]
///
/// Provides useful implementation, using [`Ordering::Acquire`]
/// and [`Ordering::Release`] to load and store respectively
#[derive(Debug, Serialize, Deserialize)]
pub struct AtomicU32Wrapper(AtomicU32);

impl AtomicU32Wrapper {
    /// Create new [`AtomicU32Wrapper`] instance
    pub fn new(num: u32) -> AtomicU32Wrapper {
        Self(AtomicU32::new(num))
    }

    /// Get atomic value
    pub fn get(&self) -> u32 {
        self.0.load(Ordering::Acquire)
    }

    /// Set atomic value
    pub fn set(&self, num: u32) {
        self.0.store(num, Ordering::Release)
    }
}

impl Clone for AtomicU32Wrapper {
    fn clone(&self) -> Self {
        Self(AtomicU32::new(self.get()))
    }
}

impl PartialOrd for AtomicU32Wrapper {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for AtomicU32Wrapper {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.get().cmp(&other.get())
    }
}

impl PartialEq for AtomicU32Wrapper {
    fn eq(&self, other: &Self) -> bool {
        self.get() == other.get()
    }
}

impl Eq for AtomicU32Wrapper {}

impl Encode for AtomicU32Wrapper {
    fn size_hint(&self) -> usize {
        self.get().size_hint()
    }

    fn encode_to<T: Output + ?Sized>(&self, dest: &mut T) {
        self.get().encode_to(dest)
    }

    fn encode(&self) -> Vec<u8> {
        self.get().encode()
    }

    fn using_encoded<R, F: FnOnce(&[u8]) -> R>(&self, f: F) -> R {
        self.get().using_encoded(f)
    }

    fn encoded_size(&self) -> usize {
        self.get().encoded_size()
    }
}

impl WrapperTypeDecode for AtomicU32Wrapper {
    type Wrapped = u32;
}

impl IntoSchema for AtomicU32Wrapper {
    fn type_name() -> String {
        String::from("AtomicU32Wrapper")
    }

    fn schema(map: &mut iroha_schema::MetaMap) {
        let _ = map
            .entry(Self::type_name())
            .or_insert(iroha_schema::Metadata::Int(
                iroha_schema::IntMode::FixedWidth,
            ));
    }
}

impl From<u32> for AtomicU32Wrapper {
    fn from(num: u32) -> Self {
        Self::new(num)
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
    pub use super::{Action, ActionTrait, AtomicU32Wrapper, Id as TriggerId, Repeats, Trigger};
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trigger_with_filterbox_can_be_unboxed() {
        /// Should fail to compile if a new variant will be added to `FilterBox`
        #[allow(dead_code, clippy::unwrap_used)]
        fn compile_time_check(boxed: Trigger<FilterBox>) {
            match &boxed.action.filter {
                FilterBox::Data(_) => Trigger::<DataEventFilter>::try_from(boxed)
                    .map(|_| ())
                    .unwrap(),
                FilterBox::Pipeline(_) => Trigger::<PipelineEventFilter>::try_from(boxed)
                    .map(|_| ())
                    .unwrap(),
                FilterBox::Time(_) => Trigger::<TimeEventFilter>::try_from(boxed)
                    .map(|_| ())
                    .unwrap(),
                FilterBox::ExecuteTrigger(_) => {
                    Trigger::<ExecuteTriggerEventFilter>::try_from(boxed)
                        .map(|_| ())
                        .unwrap()
                }
            }
        }
    }
}
