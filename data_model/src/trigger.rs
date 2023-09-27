//! Structures traits and impls related to `Trigger`s.

#[cfg(not(feature = "std"))]
use alloc::{format, string::String, vec::Vec};
use core::{cmp, str::FromStr};

use derive_more::{Constructor, Display};
use getset::Getters;
use iroha_data_model_derive::{model, IdEqOrdHash};
use iroha_macro::{ffi_impl_opaque, FromVariant};
use iroha_schema::IntoSchema;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};
use serde_with::{DeserializeFromStr, SerializeDisplay};

pub use self::model::*;
use crate::{
    domain::DomainId, events::prelude::*, metadata::Metadata, prelude::InstructionExpr,
    transaction::Executable, Identifiable, Name, ParseError, Registered,
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
        pub domain_id: Option<DomainId>,
    }

    /// Type which is used for registering a `Trigger`.
    #[derive(
        Debug,
        Display,
        Clone,
        IdEqOrdHash,
        Constructor,
        Decode,
        Encode,
        Deserialize,
        Serialize,
        IntoSchema,
    )]
    #[display(fmt = "@@{id}")]
    #[ffi_type]
    pub struct Trigger<F, E> {
        /// [`Id`] of the [`Trigger`].
        pub id: TriggerId,
        /// Action to be performed when the trigger matches.
        pub action: action::Action<F, E>,
    }

    /// Internal representation of Wasm blob provided by preloading it with `wasmtime` crate.
    #[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
    pub struct WasmInternalRepr {
        /// Serialized with `wasmtime::Module::serialize`
        pub serialized: Vec<u8>,
        /// Hash of original WASM blob on blockchain
        pub blob_hash: iroha_crypto::HashOf<crate::transaction::WasmSmartContract>,
    }

    /// Same as [`Executable`] but instead of [`Wasm`](Executable::Wasm) contains
    /// [`WasmInternalRepr`] with serialized optimized representation
    /// from `wasmtime` library.
    #[derive(
        Debug, Clone, PartialEq, Eq, FromVariant, Decode, Encode, Deserialize, Serialize, IntoSchema,
    )]
    // TODO: Made opaque temporarily
    #[ffi_type(opaque)]
    pub enum OptimizedExecutable {
        /// WASM serialized with `wasmtime`.
        WasmInternalRepr(WasmInternalRepr),
        /// Vector of [`instructions`](InstructionExpr).
        Instructions(Vec<InstructionExpr>),
    }
}

#[ffi_impl_opaque]
impl Trigger<TriggeringFilterBox, OptimizedExecutable> {
    /// [`Id`] of the [`Trigger`].
    pub fn id(&self) -> &TriggerId {
        &self.id
    }

    /// Action to be performed when the trigger matches.
    pub fn action(&self) -> &action::Action<TriggeringFilterBox, OptimizedExecutable> {
        &self.action
    }
}

impl Registered for Trigger<TriggeringFilterBox, Executable> {
    type With = Self;
}

macro_rules! impl_try_from_box {
    ($($variant:ident => $filter_type:ty),+ $(,)?) => {
        $(
            impl<E> TryFrom<Trigger<TriggeringFilterBox, E>> for Trigger<$filter_type, E> {
                type Error = &'static str;

                fn try_from(boxed: Trigger<TriggeringFilterBox, E>) -> Result<Self, Self::Error> {
                    if let TriggeringFilterBox::$variant(concrete_filter) = boxed.action.filter {
                        let action = action::Action::new(
                            boxed.action.executable,
                            boxed.action.repeats,
                            boxed.action.authority,
                            concrete_filter,
                        );
                        Ok(Self {
                            id: boxed.id,
                            action,
                        })
                    } else {
                        Err(concat!("Expected `TriggeringFilterBox::", stringify!($variant),"`, but another variant found"))
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
                domain_id: Some(DomainId::from_str(domain_id)?),
            }),
            _ => Err(ParseError {
                reason: "Trigger ID should have format `name` or `name$domain_id`",
            }),
        }
    }
}

pub mod action {
    //! Contains trigger action and common trait for all actions

    use iroha_data_model_derive::model;

    pub use self::model::*;
    use super::*;
    use crate::account::AccountId;

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
            Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema,
        )]
        #[ffi_type]
        pub struct Action<F, E> {
            /// The executable linked to this action
            pub executable: E,
            /// The repeating scheme of the action. It's kept as part of the
            /// action and not inside the [`Trigger`] type, so that further
            /// sanity checking can be done.
            pub repeats: Repeats,
            /// Account executing this action
            pub authority: AccountId,
            /// Defines events which trigger the `Action`
            pub filter: F,
            /// Metadata used as persistent storage for trigger data.
            pub metadata: Metadata,
        }

        /// Enumeration of possible repetitions schemes.
        #[derive(
            Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema,
        )]
        #[ffi_type]
        pub enum Repeats {
            /// Repeat indefinitely, until the trigger is unregistered.
            Indefinitely,
            /// Repeat a set number of times
            Exactly(u32), // If you need more, use `Indefinitely`.
        }
    }

    #[cfg(feature = "transparent_api")]
    impl<F, E> crate::HasMetadata for Action<F, E> {
        fn metadata(&self) -> &crate::metadata::Metadata {
            &self.metadata
        }
    }

    #[ffi_impl_opaque]
    impl Action<TriggeringFilterBox, OptimizedExecutable> {
        /// The executable linked to this action
        pub fn executable(&self) -> &OptimizedExecutable {
            &self.executable
        }
        /// The repeating scheme of the action. It's kept as part of the
        /// action and not inside the [`Trigger`] type, so that further
        /// sanity checking can be done.
        pub fn repeats(&self) -> &Repeats {
            &self.repeats
        }
        /// Account executing this action
        pub fn authority(&self) -> &AccountId {
            &self.authority
        }
        /// Defines events which trigger the `Action`
        pub fn filter(&self) -> &TriggeringFilterBox {
            &self.filter
        }
    }

    impl<F, E> Action<F, E> {
        /// Construct an action given `executable`, `repeats`, `authority` and `filter`.
        pub fn new(
            executable: impl Into<E>,
            repeats: impl Into<Repeats>,
            authority: AccountId,
            filter: F,
        ) -> Self {
            Self {
                executable: executable.into(),
                repeats: repeats.into(),
                // TODO: At this point the authority is meaningless.
                authority,
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
            Some(self.authority.cmp(&other.authority))
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
        fn authority(&self) -> &AccountId;

        /// Get action metadata
        fn metadata(&self) -> &Metadata;

        /// Check if action is mintable.
        fn mintable(&self) -> bool;

        /// Convert action to a boxed representation
        fn into_boxed(self) -> Action<TriggeringFilterBox, Self::Executable>;

        /// Same as [`into_boxed()`](ActionTrait::into_boxed) but clones `self`
        fn clone_and_box(&self) -> Action<TriggeringFilterBox, Self::Executable>;
    }

    #[cfg(feature = "transparent_api")]
    impl<F: Filter + Into<TriggeringFilterBox> + Clone, E: Clone> ActionTrait for Action<F, E> {
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

        fn authority(&self) -> &AccountId {
            &self.authority
        }

        fn metadata(&self) -> &Metadata {
            &self.metadata
        }

        fn mintable(&self) -> bool {
            self.filter.mintable()
        }

        fn into_boxed(self) -> Action<TriggeringFilterBox, Self::Executable> {
            Action::<TriggeringFilterBox, Self::Executable> {
                executable: self.executable,
                repeats: self.repeats,
                authority: self.authority,
                filter: self.filter.into(),
                metadata: self.metadata,
            }
        }

        fn clone_and_box(&self) -> Action<TriggeringFilterBox, Self::Executable> {
            Action::<TriggeringFilterBox, Self::Executable> {
                executable: self.executable.clone(),
                repeats: self.repeats.clone(),
                authority: self.authority.clone(),
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
            Repeats::Exactly(num)
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
        /// Should fail to compile if a new variant will be added to `TriggeringFilterBox`
        #[allow(dead_code, clippy::unwrap_used)]
        fn compile_time_check(boxed: Trigger<TriggeringFilterBox, Executable>) {
            match &boxed.action.filter {
                TriggeringFilterBox::Data(_) => {
                    Trigger::<DataEventFilter, Executable>::try_from(boxed)
                        .map(|_| ())
                        .unwrap()
                }
                TriggeringFilterBox::Pipeline(_) => {
                    Trigger::<PipelineEventFilter, Executable>::try_from(boxed)
                        .map(|_| ())
                        .unwrap()
                }
                TriggeringFilterBox::Time(_) => {
                    Trigger::<TimeEventFilter, Executable>::try_from(boxed)
                        .map(|_| ())
                        .unwrap()
                }
                TriggeringFilterBox::ExecuteTrigger(_) => {
                    Trigger::<ExecuteTriggerEventFilter, Executable>::try_from(boxed)
                        .map(|_| ())
                        .unwrap()
                }
            }
        }
    }
}
