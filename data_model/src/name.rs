//! This module contains [`Name`](`crate::name::Name`) structure
//! and related implementations and trait implementations.
#[cfg(not(feature = "std"))]
use alloc::{alloc::alloc, boxed::Box, format, string::String, vec::Vec};
use core::{ops::RangeInclusive, str::FromStr};
#[cfg(feature = "std")]
use std::alloc::alloc;

use derive_more::{DebugCustom, Display};
use iroha_ffi::{IntoFfi, TryFromReprC};
use iroha_primitives::conststr::ConstString;
use iroha_schema::IntoSchema;
use parity_scale_codec::{Decode, Encode, Input};
use serde::{Deserialize, Serialize};

use crate::{ParseError, ValidationError};

/// `Name` struct represents type for Iroha Entities names, like
/// [`Domain`](`crate::domain::Domain`)'s name or
/// [`Account`](`crate::account::Account`)'s name.
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
    IntoFfi,
    TryFromReprC,
    IntoSchema,
)]
// FIXME: #[repr(transparent)] (https://github.com/hyperledger/iroha/issues/2645)
pub struct Name(ConstString);

impl Name {
    /// Check if `range` contains the number of chars in the inner `ConstString` of this [`Name`].
    ///
    /// # Errors
    /// Fails if `range` does not
    pub fn validate_len(
        &self,
        range: impl Into<RangeInclusive<usize>>,
    ) -> Result<(), ValidationError> {
        let range = range.into();
        if range.contains(&self.0.chars().count()) {
            Ok(())
        } else {
            Err(ValidationError::new(format!(
                "Name must be between {} and {} characters in length.",
                &range.start(),
                &range.end()
            )))
        }
    }

    /// Check if `candidate` string would be valid [`Name`].
    ///
    /// # Errors
    /// Fails if not valid [`Name`].
    fn validate_str(candidate: &str) -> Result<(), ParseError> {
        const FORBIDDEN_CHARS: [char; 4] = ['@', '#', '$', '%'];

        if candidate.is_empty() {
            return Err(ParseError {
                reason: "`Name` cannot be empty",
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
                        `#` — for `asset#domain`, `$` — for `trigger$domain` \
                        and `%` — for `validator%account`.",
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

#[cfg_attr(
    all(feature = "ffi_export", not(feature = "ffi_import")),
    iroha_ffi::ffi_export
)]
#[cfg_attr(feature = "ffi_import", iroha_ffi::ffi_import)]
impl FromStr for Name {
    type Err = ParseError;

    fn from_str(candidate: &str) -> Result<Self, Self::Err> {
        Self::validate_str(candidate).map(|_| Self(ConstString::from(candidate)))
    }
}

impl<'de> Deserialize<'de> for Name {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error as _;

        let name = ConstString::deserialize(deserializer)?;
        Self::validate_str(&name)
            .map(|_| Self(name))
            .map_err(D::Error::custom)
    }
}
impl Decode for Name {
    fn decode<I: Input>(input: &mut I) -> Result<Self, parity_scale_codec::Error> {
        let name = ConstString::decode(input)?;
        Self::validate_str(&name)
            .map(|_| Self(name))
            .map_err(|error| error.reason.into())
    }
}

/// The prelude re-exports most commonly used traits, structs and macros from this crate.
pub mod prelude {
    pub use super::Name;
}

#[cfg(test)]
mod tests {
    #![allow(clippy::restriction)]

    use super::*;

    const INVALID_NAMES: [&str; 6] = ["", " ", "@", "#", "$", "%"];

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
            let name = Name::decode(&mut &bytes[..]);

            assert!(name.is_err());
        }
    }
}
