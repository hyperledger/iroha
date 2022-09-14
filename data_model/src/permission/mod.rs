//! Structures, traits and impls related to `Permission`s.

#[cfg(not(feature = "std"))]
use alloc::{
    alloc::alloc,
    boxed::Box,
    collections::{btree_map, btree_set},
    format,
    string::String,
    vec::Vec,
};
#[cfg(feature = "std")]
use std::{
    alloc::alloc,
    collections::{btree_map, btree_set},
};

use derive_more::{Constructor, Display, FromStr};
use getset::{Getters, MutGetters, Setters};
use iroha_data_model_derive::IdOrdEqHash;
use iroha_ffi::{IntoFfi, TryFromReprC};
use iroha_schema::IntoSchema;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

use crate::{ffi::ffi_item, IdBox, Identifiable, Name, Registered, Value, ValueKind};

pub mod token;
pub mod validator;

pub use token::Token;
pub use validator::Validator;

/// Collection of [`Token`]s
pub type Permissions = btree_set::BTreeSet<token::Token>;

/// The prelude re-exports most commonly used traits, structs and macros from this module.
pub mod prelude {
    pub use super::{Permissions, Token};
}
