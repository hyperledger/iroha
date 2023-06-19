//! Permission Token and related impls
#[cfg(not(feature = "std"))]
use alloc::{
    collections::{BTreeMap, BTreeSet},
    format,
    string::String,
    vec::Vec,
};
#[cfg(feature = "std")]
use std::collections::{BTreeMap, BTreeSet};

use derive_more::{Constructor, Display, FromStr};
use getset::Getters;
use iroha_data_model_derive::{model, IdEqOrdHash};
use iroha_schema::IntoSchema;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};
use serde_with::{DeserializeFromStr, SerializeDisplay};

pub use self::model::*;
use crate::{IdBox, Identifiable, Name, Registered, Value, ValueKind};

/// Collection of [`Token`]s
pub type Permissions = BTreeSet<PermissionToken>;

/// Trait to identify [`ValueKind`] of a type which can be used as a [`Token`] parameter.
///
/// On a higher level, all permission token parameters have [`Value`] type, but for now we allow
/// to define builtin permission tokens with stronger types.
/// This trait is used to retrieve the [`kind`](`ValueKind`) of a [`Value`] which can be constructed
/// from given parameter.
///
/// Will be removed as well as builtin permission tokens and validators
/// when *runtime validators* and *runtime permissions* will be properly implemented.
pub trait ValueTrait: Into<Value> {
    /// The kind of the [`Value`] which the implementing type can be converted to.
    const TYPE: ValueKind;
}

#[model]
pub mod model {
    use super::*;

    /// Unique id of [`PermissionTokenDefinition`]
    #[derive(
        derive_more::DebugCustom,
        Display,
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Hash,
        Constructor,
        FromStr,
        Getters,
        Decode,
        Encode,
        DeserializeFromStr,
        SerializeDisplay,
        IntoSchema,
    )]
    #[repr(transparent)]
    #[ffi_type(opaque)]
    #[debug(fmt = "PermissionTokenId: {name}")]
    pub struct PermissionTokenId {
        /// [`PermissionToken`] name
        #[getset(get = "pub")]
        pub name: Name,
    }

    /// Defines a type of [`PermissionToken`] with given id
    #[derive(Display, Clone, IdEqOrdHash, Decode, Encode, Deserialize, Serialize, IntoSchema)]
    #[display(fmt = "{id}")]
    #[ffi_type]
    pub struct PermissionTokenDefinition {
        /// Definition Id
        pub id: PermissionTokenId,
        /// Parameters and their types that every [`Token`] with this definition should have
        pub params: BTreeMap<Name, ValueKind>,
    }

    /// Stored proof of the account having a permission for a certain action.
    #[derive(
        Debug,
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Getters,
        Decode,
        Encode,
        Deserialize,
        Serialize,
        IntoSchema,
    )]
    #[ffi_type]
    pub struct PermissionToken {
        /// Name of the permission rule given to account.
        #[getset(get = "pub")]
        pub definition_id: PermissionTokenId,
        /// Params identifying how this rule applies.
        pub params: BTreeMap<Name, Value>,
    }
}

impl core::fmt::Debug for PermissionTokenDefinition {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mut borrow_checker_happifier = f.debug_struct("PermissionTokenDefinition");
        let intermediate = borrow_checker_happifier.field("id", &self.id.name);
        if self.params.is_empty() {
            intermediate.finish()
        } else {
            intermediate.field("params", &self.params).finish()
        }
    }
}

impl PermissionTokenDefinition {
    /// Construct new [`PermissionTokenDefinition`]
    #[inline]
    pub const fn new(id: PermissionTokenId) -> Self {
        Self {
            id,
            params: BTreeMap::new(),
        }
    }

    /// Add parameters to the [`PermissionTokenDefinition`] replacing any parameters previously defined
    #[inline]
    #[must_use]
    pub fn with_params(mut self, params: impl IntoIterator<Item = (Name, ValueKind)>) -> Self {
        self.params = params.into_iter().collect();
        self
    }

    /// Iterate over parameters of the [`PermissionTokenDefinition`]
    ///
    /// Values returned from the iterator are guaranteed to be in the alphabetical order.
    #[inline]
    pub fn params(&self) -> impl ExactSizeIterator<Item = (&Name, &ValueKind)> {
        self.params.iter()
    }
}

impl PermissionToken {
    /// Construct a permission token.
    #[inline]
    pub fn new(definition_id: PermissionTokenId) -> Self {
        Self {
            definition_id,
            params: BTreeMap::default(),
        }
    }

    /// Add parameters to the [`Token`] replacing any previously defined
    #[inline]
    #[must_use]
    pub fn with_params(mut self, params: impl IntoIterator<Item = (Name, Value)>) -> Self {
        self.params = params.into_iter().collect();
        self
    }

    /// Return a reference to the parameter corresponding to the given name
    #[inline]
    pub fn param(&self, name: &Name) -> Option<&Value> {
        self.params.get(name)
    }

    /// Get an iterator over [`Token`] parameters.
    ///
    /// Values returned from the iterator are guaranteed to be in the alphabetical order.
    #[inline]
    pub fn params(&self) -> impl ExactSizeIterator<Item = (&Name, &Value)> {
        self.params.iter()
    }
}

impl core::fmt::Display for PermissionToken {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.definition_id)?;

        if !self.params.is_empty() {
            write!(f, ": ")?;

            crate::utils::format_comma_separated(
                self.params
                    .iter()
                    .map(|(name, value)| format!("`{name}`: `{value}`")),
                ('[', ']'),
                f,
            )?;
        }

        Ok(())
    }
}

impl<I: Into<IdBox> + Into<Value>> ValueTrait for I {
    const TYPE: ValueKind = ValueKind::Id;
}

impl Registered for PermissionTokenDefinition {
    type With = Self;
}

macro_rules! impl_value_trait {
    ( $($ty:ident: $kind:expr),+ $(,)? ) => {$(
        impl ValueTrait for $ty {
            const TYPE: ValueKind = $kind;
        }
    )+}
}

impl_value_trait! {
    u32: ValueKind::Numeric,
    u128: ValueKind::Numeric
}

pub mod prelude {
    //! The prelude re-exports most commonly used traits, structs and macros from this crate.
    pub use super::{PermissionToken, PermissionTokenDefinition, PermissionTokenId};
}
