//! Structures, traits and impls related to `Permission`s.

#[cfg(not(feature = "std"))]
use alloc::{
    collections::{btree_map, btree_set},
    format,
    string::String,
    vec::Vec,
};
#[cfg(feature = "std")]
use std::collections::{btree_map, btree_set};

use derive_more::{Constructor, Display, FromStr};
use getset::Getters;
use iroha_schema::IntoSchema;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};
use serde_with::{DeserializeFromStr, SerializeDisplay};

use crate::{IdBox, Identifiable, Name, Registered, Value, ValueKind};

pub mod token;
pub mod validator;

pub use token::Token;
pub use validator::Validator;

/// Collection of [`Token`]s
pub type Permissions = btree_set::BTreeSet<token::Token>;

/// The prelude re-exports most commonly used traits, structs and macros from this module.
pub mod prelude {
    pub use super::{
        token::{Definition as PermissionTokenDefinition, Id as PermissionTokenId},
        validator::Verdict,
        Permissions, Token as PermissionToken,
    };
}
