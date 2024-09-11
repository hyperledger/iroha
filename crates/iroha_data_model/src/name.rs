//! This module contains [`Name`](`crate::name::Name`) structure
//! and related implementations and trait implementations.
#[cfg(not(feature = "std"))]
use alloc::{format, string::String, vec::Vec};
use core::{borrow::Borrow, str::FromStr};

use iroha_data_model_derive::model;
use iroha_primitives::conststr::ConstString;
use parity_scale_codec::{Decode, Encode, Input};
use serde::{Deserialize, Serialize};

pub use self::model::*;
use crate::ParseError;

#[model]
mod model {
    use derive_more::{DebugCustom, Display};
    use iroha_schema::IntoSchema;

    use super::*;

    /// `Name` struct represents the type of Iroha Entities names, such as
    /// [`Domain`](`crate::domain::Domain`) name or
    /// [`Account`](`crate::account::Account`) name.
    #[derive(
        DebugCustom,
        Display,
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Hash,
        Encode,
        Serialize,
        IntoSchema,
    )]
    #[serde(transparent)]
    #[repr(transparent)]
    #[ffi_type(opaque)]
    pub struct Name(pub(super) ConstString);
}

impl Name {
    /// Check if `candidate` string would be valid [`Name`].
    ///
    /// # Errors
    /// Fails if not valid [`Name`].
    fn validate_str(candidate: &str) -> Result<(), ParseError> {
        const FORBIDDEN_CHARS: [char; 2] = ['@', '#'];

        if candidate.is_empty() {
            return Err(ParseError {
                reason: "Empty `Name`",
            });
        }
        if candidate.chars().any(char::is_whitespace) {
            return Err(ParseError {
                reason: "White space not allowed in `Name` constructs",
            });
        }
        if candidate.chars().any(|ch| FORBIDDEN_CHARS.contains(&ch)) {
            #[allow(clippy::non_ascii_literal)]
            return Err(ParseError {
                reason: "The `@` character is reserved for `account@domain` constructs, \
                        and `#` — for `asset#domain`.",
            });
        }
        Ok(())
    }
}

impl AsRef<str> for Name {
    fn as_ref(&self) -> &str {
        self.0.as_ref()
    }
}

impl Borrow<str> for Name {
    fn borrow(&self) -> &str {
        self.0.as_ref()
    }
}

impl FromStr for Name {
    type Err = ParseError;

    fn from_str(candidate: &str) -> Result<Self, Self::Err> {
        Self::validate_str(candidate)?;
        Ok(Self(ConstString::from(candidate)))
    }
}

impl TryFrom<String> for Name {
    type Error = ParseError;

    fn try_from(candidate: String) -> Result<Self, Self::Error> {
        Self::validate_str(&candidate)?;
        Ok(Self(ConstString::from(candidate)))
    }
}

impl<'de> Deserialize<'de> for Name {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[cfg(not(target_family = "wasm"))]
        use serde::de::Error as _;

        let candidate = ConstString::deserialize(deserializer)?;
        #[cfg(not(target_family = "wasm"))]
        Self::validate_str(&candidate).map_err(D::Error::custom)?;

        Ok(Self(candidate))
    }
}
impl Decode for Name {
    fn decode<I: Input>(input: &mut I) -> Result<Self, parity_scale_codec::Error> {
        let name = ConstString::decode(input)?;
        #[cfg(not(target_family = "wasm"))]
        Self::validate_str(&name).map_err(|error| parity_scale_codec::Error::from(error.reason))?;
        Ok(Self(name))
    }
}

/// The prelude re-exports most commonly used traits, structs and macros from this crate.
pub mod prelude {
    pub use super::Name;
}

#[cfg(test)]
mod tests {
    #[cfg(not(feature = "std"))]
    use alloc::borrow::ToOwned as _;

    use parity_scale_codec::DecodeAll;

    use super::*;

    const INVALID_NAMES: [&str; 4] = ["", " ", "@", "#"];

    #[test]
    fn deserialize_name() {
        for invalid_name in INVALID_NAMES {
            let invalid_name = Name(invalid_name.to_owned().into());
            let serialized = serde_json::to_string(&invalid_name).expect("Valid");
            let name = serde_json::from_str::<Name>(serialized.as_str());

            assert!(name.is_err());
        }
    }

    #[test]
    fn decode_name() {
        for invalid_name in INVALID_NAMES {
            let invalid_name = Name(invalid_name.to_owned().into());
            let bytes = invalid_name.encode();
            let name = Name::decode_all(&mut &bytes[..]);

            assert!(name.is_err());
        }
    }
}
