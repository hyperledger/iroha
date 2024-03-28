//! Contains trigger-related types that are specialized for core-specific needs.

use derive_more::Constructor;
use iroha_crypto::HashOf;
use iroha_data_model::{
    account::AccountId,
    events::{EventFilter, TriggeringEventFilterBox},
    metadata::Metadata,
    prelude::*,
};
use serde::{Deserialize, Serialize};

use crate::smartcontracts::triggers::set::{LoadedExecutable, LoadedWasm};

/// Same as [`iroha_data_model::trigger::action::Action`] but generic over the filter type
///
/// This is used to split different action types to different collections
#[derive(Serialize, Deserialize)]
pub struct SpecializedAction<F> {
    /// The executable linked to this action
    pub executable: Executable,
    /// The repeating scheme of the action. It's kept as part of the
    /// action and not inside the [`iroha_data_model::trigger::Trigger`] type, so that further
    /// sanity checking can be done.
    pub repeats: Repeats,
    /// Account executing this action
    pub authority: AccountId,
    /// Defines events which trigger the `Action`
    pub filter: F,
    /// Metadata used as persistent storage for trigger data.
    pub metadata: Metadata,
}

impl<F> SpecializedAction<F> {
    /// Construct a specialized action given `executable`, `repeats`, `authority` and `filter`.
    pub fn new(
        executable: impl Into<Executable>,
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
}

impl<F> From<SpecializedAction<F>> for Action
where
    F: Into<TriggeringEventFilterBox>,
{
    fn from(value: SpecializedAction<F>) -> Self {
        Action {
            executable: value.executable,
            repeats: value.repeats,
            authority: value.authority,
            filter: value.filter.into(),
            metadata: value.metadata,
        }
    }
}

/// Same as [`iroha_data_model::trigger::Trigger`] but generic over the filter type
#[derive(Constructor)]
pub struct SpecializedTrigger<F> {
    /// [`Id`] of the [`Trigger`].
    pub id: TriggerId,
    /// Action to be performed when the trigger matches.
    pub action: SpecializedAction<F>,
}

macro_rules! impl_try_from_box {
    ($($variant:ident => $filter_type:ty),+ $(,)?) => {
        $(
            impl TryFrom<Trigger> for SpecializedTrigger<$filter_type> {
                type Error = &'static str;

                fn try_from(boxed: Trigger) -> Result<Self, Self::Error> {
                    if let TriggeringEventFilterBox::$variant(concrete_filter) = boxed.action.filter {
                        let action = SpecializedAction::new(
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
                        Err(concat!("Expected `TriggeringEventFilterBox::", stringify!($variant),"`, but another variant found"))
                    }
                }
            }
        )+
    };
}

impl_try_from_box! {
    Data => DataEventFilter,
    Pipeline => PipelineEventFilterBox,
    Time => TimeEventFilter,
    ExecuteTrigger => ExecuteTriggerEventFilter,
}

/// Same as [`iroha_data_model::trigger::action::Action`] but with
/// executable in pre-loaded form
#[derive(Clone, Debug)]
pub struct LoadedAction<F> {
    /// The executable linked to this action in loaded form
    pub(super) executable: LoadedExecutable,
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

impl<F> LoadedAction<F> {
    pub(super) fn extract_blob_hash(&self) -> Option<HashOf<WasmSmartContract>> {
        match self.executable {
            LoadedExecutable::Wasm(LoadedWasm { blob_hash, .. }) => Some(blob_hash),
            LoadedExecutable::Instructions(_) => None,
        }
    }
}

/// Trait common for all `LoadedAction`s
pub trait LoadedActionTrait {
    /// Get action executable
    fn executable(&self) -> &LoadedExecutable;

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
    fn into_boxed(self) -> LoadedAction<TriggeringEventFilterBox>;

    /// Same as [`into_boxed()`](LoadedActionTrait::into_boxed) but clones `self`
    fn clone_and_box(&self) -> LoadedAction<TriggeringEventFilterBox>;
}

impl<F: EventFilter + Into<TriggeringEventFilterBox> + Clone> LoadedActionTrait
    for LoadedAction<F>
{
    fn executable(&self) -> &LoadedExecutable {
        &self.executable
    }

    fn repeats(&self) -> &iroha_data_model::trigger::action::Repeats {
        &self.repeats
    }

    fn set_repeats(&mut self, repeats: iroha_data_model::trigger::action::Repeats) {
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

    fn into_boxed(self) -> LoadedAction<TriggeringEventFilterBox> {
        let Self {
            executable,
            repeats,
            authority,
            filter,
            metadata,
        } = self;

        LoadedAction {
            executable,
            repeats,
            authority,
            filter: filter.into(),
            metadata,
        }
    }

    fn clone_and_box(&self) -> LoadedAction<TriggeringEventFilterBox> {
        self.clone().into_boxed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trigger_with_filterbox_can_be_unboxed() {
        /// Should fail to compile if a new variant will be added to `TriggeringEventFilterBox`
        #[allow(dead_code)]
        fn compile_time_check(boxed: Trigger) {
            match &boxed.action.filter {
                TriggeringEventFilterBox::Data(_) => {
                    SpecializedTrigger::<DataEventFilter>::try_from(boxed)
                        .map(|_| ())
                        .unwrap()
                }
                TriggeringEventFilterBox::Pipeline(_) => {
                    SpecializedTrigger::<PipelineEventFilterBox>::try_from(boxed)
                        .map(|_| ())
                        .unwrap()
                }
                TriggeringEventFilterBox::Time(_) => {
                    SpecializedTrigger::<TimeEventFilter>::try_from(boxed)
                        .map(|_| ())
                        .unwrap()
                }
                TriggeringEventFilterBox::ExecuteTrigger(_) => {
                    SpecializedTrigger::<ExecuteTriggerEventFilter>::try_from(boxed)
                        .map(|_| ())
                        .unwrap()
                }
            }
        }
    }
}
