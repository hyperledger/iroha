//! Structures traits and impls related to `Trigger`s.

#[cfg(not(feature = "std"))]
use alloc::{format, string::String, vec::Vec};
use core::{cmp, str::FromStr};

use derive_more::{Constructor, Display};
use getset::Getters;
use iroha_data_model_derive::{model, IdEqOrdHash};
use iroha_macro::FromVariant;
use iroha_schema::IntoSchema;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};
use serde_with::{DeserializeFromStr, SerializeDisplay};

pub use self::model::*;
use crate::{
    events::prelude::*,
    metadata::Metadata,
    prelude::{Domain, InstructionBox},
    transaction::Executable,
    Identifiable, Name, ParseError, Registered,
};

#[model]
pub mod model {
    use super::*;

    /// Identification of a `Trigger`.
    #[derive(
        Debug,
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Hash,
        Constructor,
        Getters,
        Decode,
        Encode,
        DeserializeFromStr,
        SerializeDisplay,
        IntoSchema,
    )]
    #[getset(get = "pub")]
    #[ffi_type]
    pub struct TriggerId {
        /// Name given to trigger by its creator.
        pub name: Name,
        /// DomainId of domain of the trigger.
        pub domain_id: Option<<Domain as Identifiable>::Id>,
    }

    /// Type which is used for registering a `Trigger`.
    #[derive(
        Debug,
        Display,
        Clone,
        IdEqOrdHash,
        Constructor,
        Getters,
        Decode,
        Encode,
        Deserialize,
        Serialize,
        IntoSchema,
    )]
    #[display(fmt = "@@{id}")]
    #[getset(get = "pub")]
    #[ffi_type]
    pub struct Trigger<F, E> {
        /// [`Id`] of the [`Trigger`].
        pub id: TriggerId,
        /// Action to be performed when the trigger matches.
        pub action: action::Action<F, E>,
    }
}

impl Registered for Trigger<FilterBox, Executable> {
    type With = Self;
}

macro_rules! impl_try_from_box {
    ($($variant:ident => $filter_type:ty),+ $(,)?) => {
        $(
            impl<E> TryFrom<Trigger<FilterBox, E>> for Trigger<$filter_type, E> {
                type Error = &'static str;

                fn try_from(boxed: Trigger<FilterBox, E>) -> Result<Self, Self::Error> {
                    if let FilterBox::$variant(concrete_filter) = boxed.action.filter {
                        let action = action::Action::new(
                            boxed.action.executable,
                            boxed.action.repeats,
                            boxed.action.technical_account,
                            concrete_filter,
                        );
                        Ok(Self {
                            id: boxed.id,
                            action,
                        })
                    } else {
                        Err(concat!("Expected `FilterBox::", stringify!($variant),"`, but another variant found"))
                    }
                }
            }
        )+
    };
}

impl_try_from_box! {
    Data => DataEventFilter,
    Pipeline => PipelineEventFilter,
    Time => TimeEventFilter,
    ExecuteTrigger => ExecuteTriggerEventFilter,
}

impl core::fmt::Display for TriggerId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if let Some(ref domain_id) = self.domain_id {
            write!(f, "{}${}", self.name, domain_id)
        } else {
            write!(f, "{}", self.name)
        }
    }
}

impl FromStr for TriggerId {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut split = s.split('$');
        match (split.next(), split.next(), split.next()) {
            (Some(""), _, _) => Err(ParseError {
                reason: "Trigger ID cannot be empty",
            }),
            (Some(name), None, _) => Ok(Self {
                name: Name::from_str(name)?,
                domain_id: None,
            }),
            (Some(name), Some(domain_id), None) if !domain_id.is_empty() => Ok(Self {
                name: Name::from_str(name)?,
                domain_id: Some(<Domain as Identifiable>::Id::from_str(domain_id)?),
            }),
            _ => Err(ParseError {
                reason: "Trigger ID should have format `name` or `name$domain_id`",
            }),
        }
    }
}

/// Same as [`Executable`] but instead of [`Wasm`](Executable::Wasm) contains
/// [`WasmInternalRepr`](OptimizedExecutable::WasmInternalRepr) with
/// serialized optimized representation from `wasmtime` library.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Hash,
    FromVariant,
    Decode,
    Encode,
    Deserialize,
    Serialize,
    IntoSchema,
)]
pub enum OptimizedExecutable {
    /// Internal representation of Wasm blob provided by preloading it with `wasmtime` crate.
    WasmInternalRepr(Vec<u8>),
    /// Vector of [`instructions`](InstructionBox).
    Instructions(Vec<InstructionBox>),
}

pub mod action {
    //! Contains trigger action and common trait for all actions

    use iroha_data_model_derive::model;
    use iroha_primitives::atomic::AtomicU32;

    pub use self::model::*;
    use super::*;
    #[cfg(feature = "transparent_api")]
    use crate::prelude::Account;

    #[model]
    pub mod model {
        use super::*;

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
        #[derive(
            Debug, Clone, PartialEq, Eq, Getters, Decode, Encode, Deserialize, Serialize, IntoSchema,
        )]
        #[getset(get = "pub")]
        pub struct Action<F, E> {
            /// The executable linked to this action
            pub executable: E,
            /// The repeating scheme of the action. It's kept as part of the
            /// action and not inside the [`Trigger`] type, so that further
            /// sanity checking can be done.
            pub repeats: Repeats,
            /// Technical account linked to this trigger. The technical
            /// account must already exist in order for `Register<Trigger>` to
            /// work.
            pub technical_account: crate::account::AccountId,
            /// Defines events which trigger the `Action`
            pub filter: F,
            /// Metadata used as persistent storage for trigger data.
            pub metadata: Metadata,
        }

        /// Enumeration of possible repetitions schemes.
        #[derive(
            Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema,
        )]
        pub enum Repeats {
            /// Repeat indefinitely, until the trigger is unregistered.
            Indefinitely,
            /// Repeat a set number of times
            Exactly(AtomicU32), // If you need more, use `Indefinitely`.
        }
    }

    #[cfg(feature = "transparent_api")]
    impl<F, E> crate::HasMetadata for Action<F, E> {
        fn metadata(&self) -> &crate::metadata::Metadata {
            &self.metadata
        }
    }

    impl<F, E> Action<F, E> {
        /// Construct an action given `executable`, `repeats`, `technical_account` and `filter`.
        pub fn new(
            executable: impl Into<E>,
            repeats: impl Into<Repeats>,
            technical_account: crate::account::AccountId,
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

    impl<F: PartialEq, E: PartialEq> PartialOrd for Action<F, E> {
        fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
            // Exclude the executable. When debugging and replacing
            // the trigger, its position in Hash and Tree maps should
            // not change depending on the content.
            match self.repeats.cmp(&other.repeats) {
                cmp::Ordering::Equal => {}
                ord => return Some(ord),
            }
            Some(self.technical_account.cmp(&other.technical_account))
        }
    }

    #[allow(clippy::expect_used)]
    impl<F: Eq, E: Eq> Ord for Action<F, E> {
        fn cmp(&self, other: &Self) -> cmp::Ordering {
            self.partial_cmp(other)
                .expect("`PartialCmp::partial_cmp()` for `Action` should never return `None`")
        }
    }

    /// Trait for common methods for all [`Action`]'s
    #[cfg(feature = "transparent_api")]
    pub trait ActionTrait {
        /// Type of action executable
        type Executable;

        /// Get action executable
        fn executable(&self) -> &Self::Executable;

        /// Get action repeats enum
        fn repeats(&self) -> &Repeats;

        /// Set action repeats
        fn set_repeats(&mut self, repeats: Repeats);

        /// Get action technical account
        fn technical_account(&self) -> &<Account as Identifiable>::Id;

        /// Get action metadata
        fn metadata(&self) -> &Metadata;

        /// Check if action is mintable.
        fn mintable(&self) -> bool;

        /// Convert action to a boxed representation
        fn into_boxed(self) -> Action<FilterBox, Self::Executable>;

        /// Same as [`into_boxed()`](ActionTrait::into_boxed) but clones `self`
        fn clone_and_box(&self) -> Action<FilterBox, Self::Executable>;
    }

    #[cfg(feature = "transparent_api")]
    impl<F: Filter + Into<FilterBox> + Clone, E: Clone> ActionTrait for Action<F, E> {
        type Executable = E;

        fn executable(&self) -> &Self::Executable {
            &self.executable
        }

        fn repeats(&self) -> &Repeats {
            &self.repeats
        }

        fn set_repeats(&mut self, repeats: Repeats) {
            self.repeats = repeats;
        }

        fn technical_account(&self) -> &<Account as Identifiable>::Id {
            &self.technical_account
        }

        fn metadata(&self) -> &Metadata {
            &self.metadata
        }

        fn mintable(&self) -> bool {
            self.filter.mintable()
        }

        fn into_boxed(self) -> Action<FilterBox, Self::Executable> {
            Action::<FilterBox, Self::Executable> {
                executable: self.executable,
                repeats: self.repeats,
                technical_account: self.technical_account,
                filter: self.filter.into(),
                metadata: self.metadata,
            }
        }

        fn clone_and_box(&self) -> Action<FilterBox, Self::Executable> {
            Action::<FilterBox, Self::Executable> {
                executable: self.executable.clone(),
                repeats: self.repeats.clone(),
                technical_account: self.technical_account.clone(),
                filter: self.filter.clone().into(),
                metadata: self.metadata.clone(),
            }
        }
    }

    impl PartialOrd for Repeats {
        fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
            Some(self.cmp(other))
        }
    }

    impl Ord for Repeats {
        fn cmp(&self, other: &Self) -> cmp::Ordering {
            match (self, other) {
                (Repeats::Indefinitely, Repeats::Indefinitely) => cmp::Ordering::Equal,
                (Repeats::Indefinitely, Repeats::Exactly(_)) => cmp::Ordering::Greater,
                (Repeats::Exactly(_), Repeats::Indefinitely) => cmp::Ordering::Less,
                (Repeats::Exactly(l), Repeats::Exactly(r)) => l.cmp(r),
            }
        }
    }

    impl From<u32> for Repeats {
        fn from(num: u32) -> Self {
            Repeats::Exactly(AtomicU32::new(num))
        }
    }

    pub mod prelude {
        //! Re-exports of commonly used types.
        pub use super::{Action, Repeats};
    }
}

pub mod prelude {
    //! Re-exports of commonly used types.

    #[cfg(feature = "transparent_api")]
    pub use super::action::ActionTrait;
    pub use super::{action::prelude::*, Trigger, TriggerId};
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trigger_with_filterbox_can_be_unboxed() {
        /// Should fail to compile if a new variant will be added to `FilterBox`
        #[allow(dead_code, clippy::unwrap_used)]
        fn compile_time_check(boxed: Trigger<FilterBox, Executable>) {
            match &boxed.action.filter {
                FilterBox::Data(_) => Trigger::<DataEventFilter, Executable>::try_from(boxed)
                    .map(|_| ())
                    .unwrap(),
                FilterBox::Pipeline(_) => {
                    Trigger::<PipelineEventFilter, Executable>::try_from(boxed)
                        .map(|_| ())
                        .unwrap()
                }
                FilterBox::Time(_) => Trigger::<TimeEventFilter, Executable>::try_from(boxed)
                    .map(|_| ())
                    .unwrap(),
                FilterBox::ExecuteTrigger(_) => {
                    Trigger::<ExecuteTriggerEventFilter, Executable>::try_from(boxed)
                        .map(|_| ())
                        .unwrap()
                }
            }
        }
    }
}
