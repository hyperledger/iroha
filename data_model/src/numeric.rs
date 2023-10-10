//! Tagged polymorphic numerical type.
//!
//! Special care is taken to work around limitations for wide-integer
//! types commonly used in Rust and in the code-base,
#[cfg(not(feature = "std"))]
use alloc::{
    format,
    string::{String, ToString},
    vec::Vec,
};
use core::{num::ParseIntError, str::FromStr};

use derive_more::From;
use iroha_primitives::fixed::{Fixed, FixedPointOperationError};
use serde::{de::Error, Deserializer, Serializer};

pub use self::model::*;
use super::{DebugCustom, Decode, Deserialize, Display, Encode, FromVariant, IntoSchema};

#[iroha_data_model_derive::model]
pub mod model {
    use super::*;

    /// Enum for all supported numeric values
    #[derive(
        DebugCustom,
        Display,
        Copy,
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        FromVariant,
        Decode,
        Encode,
        IntoSchema,
    )]
    #[ffi_type]
    pub enum NumericValue {
        /// `u32` value
        #[debug(fmt = "{_0}_u32")]
        U32(u32),
        /// `u64` value
        #[debug(fmt = "{_0}_u64")]
        U64(u64),
        /// `u128` value
        #[debug(fmt = "{_0}_u128")]
        U128(u128),
        /// `Fixed` value
        #[debug(fmt = "{_0}_fx")]
        Fixed(iroha_primitives::fixed::Fixed),
    }
}

impl NumericValue {
    /// Return `true` if value is zero
    pub const fn is_zero_value(self) -> bool {
        use NumericValue::*;
        match self {
            U32(value) => value == 0_u32,
            U64(value) => value == 0_u64,
            U128(value) => value == 0_u128,
            Fixed(value) => value.is_zero(),
        }
    }
}

struct NumericValueVisitor;

#[derive(Deserialize)]
#[serde(field_identifier)]
enum Discriminants {
    #[serde(alias = "Quantity")]
    U32,
    U64,
    #[serde(alias = "BigQuantity")]
    U128,
    Fixed,
}

impl FromStr for NumericValue {
    type Err = ParseNumericError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.contains('_') {
            if s.ends_with("_u32") {
                Ok(NumericValue::U32(
                    s.rsplit_once("_u32")
                        .ok_or(ParseNumericError::Format)?
                        .0
                        .parse()?,
                ))
            } else if s.ends_with("_u64") {
                Ok(NumericValue::U64(
                    s.rsplit_once("_u64")
                        .ok_or(ParseNumericError::Format)?
                        .0
                        .parse()?,
                ))
            } else if s.ends_with("_u128") {
                Ok(NumericValue::U128(
                    s.rsplit_once("_u128")
                        .ok_or(ParseNumericError::Format)?
                        .0
                        .parse()?,
                ))
            } else if s.ends_with("_fx") {
                Ok(NumericValue::Fixed(
                    s.rsplit_once("_fx")
                        .ok_or(ParseNumericError::Format)?
                        .0
                        .parse()?,
                ))
            } else {
                Err(ParseNumericError::Format)
            }
        } else if let Ok(fixed) = Fixed::from_str(s) {
            // This is the only unambiguous numerical type which we
            // can safely deserialize from a string.
            Ok(NumericValue::Fixed(fixed))
        } else {
            Err(ParseNumericError::Format)
        }
    }
}

// serialize and deserialize numbers as string literals with tagged numbers inside
// U32(42) <-> "42_u32"
// U64(42) <-> "42_u64"
// U128(42) <-> "42_u128"
// Fixed(42.0) <-> "42.0_fx"

impl serde::Serialize for NumericValue {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&format!("{self:?}"))
    }
}

impl serde::de::Visitor<'_> for NumericValueVisitor {
    type Value = NumericValue;

    #[inline]
    fn expecting(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
        formatter.write_str("A quoted string containing a tagged number")
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: Error,
    {
        let parsed = v
            .parse::<NumericValue>()
            .map_err(|e| E::custom(e.to_string()))?;

        Ok(parsed)
    }
}

impl<'de> Deserialize<'de> for NumericValue {
    fn deserialize<D>(deserializer: D) -> Result<NumericValue, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(NumericValueVisitor)
    }
}

impl TryFrom<f64> for NumericValue {
    type Error = iroha_primitives::fixed::FixedPointOperationError;

    fn try_from(source: f64) -> Result<Self, Self::Error> {
        source.try_into().map(Self::Fixed)
    }
}

/// Error emitted when a numerical value failed to be parsed from a
/// string or a JSON literal.
#[derive(Clone, Debug, Display, From)]
#[allow(missing_docs)]
pub enum ParseNumericError {
    #[display(
        fmt = "A correctly formatted numerical value was not found. Correct values are numerical followed by an underscore and a type identifier, which is one of [`u32`, `u64`, `u128`, `fx`]. Example:\"1.2_fx\"."
    )]
    Format,
    #[from]
    #[display(fmt = "Failed to parse numerical value as an integer. {_0}")]
    ParseInt(ParseIntError),
    #[from]
    #[display(fmt = "Failed to parse numerical value as a fixed-point binary rational. {_0}")]
    ParseFixed(FixedPointOperationError),
}

#[cfg(feature = "std")]
impl std::error::Error for ParseNumericError {}

// TODO: impl source correctly for conversions.

#[cfg(test)]
mod tests {
    #![allow(clippy::pedantic)]
    use super::*;

    #[test]
    fn tagged_quoted_inclusion_u128() {
        let values = [
            0_u128,
            1_u128,
            (u32::MAX - 1_u32) as u128,
            u32::MAX as u128,
            (u64::MAX - 1_u64) as u128,
            u64::MAX as u128,
            u128::MAX - 1_u128,
            u128::MAX,
        ];
        for value in values {
            let json = format!("\"{value}_u128\"",);
            let val: NumericValue = serde_json::from_str(&json).expect("Invalid JSON");
            assert_eq!(val, NumericValue::U128(value));
        }
    }

    #[test]
    fn tagged_quoted_inclusion_u64() {
        let values = [
            0_u64,
            1_u64,
            (u32::MAX - 1_u32) as u64,
            u32::MAX as u64,
            u64::MAX - 1_u64,
            u64::MAX,
        ];
        for value in values {
            let json = format!("\"{value}_u64\"",);
            let val: NumericValue = serde_json::from_str(&json).expect("Invalid JSON");
            assert_eq!(NumericValue::U64(value), val)
        }
    }

    #[test]
    fn tagged_quoted_inclusion_u32() {
        let values = [0_u32, 1_u32, (u32::MAX - 1_u32), u32::MAX];
        for value in values {
            let json = format!("\"{value}_u32\"",);
            let val: NumericValue = serde_json::from_str(&json).expect("Invalid JSON");
            assert_eq!(val, NumericValue::U32(value));
        }
    }

    #[test]
    fn serialize_is_quoted_u128() {
        let value = NumericValue::U128(u128::MAX);
        let string = serde_json::to_string(&value).unwrap();
        let expectation = format!("\"{}_u128\"", u128::MAX);
        assert_eq!(string, expectation);
    }

    #[test]
    fn serialize_fixed() {
        let value = NumericValue::Fixed(42.0.try_into().expect("trivial conversion"));
        let string = serde_json::to_string(&value).unwrap();
        let expectation = "\"42.0_fx\"";
        assert_eq!(string, expectation);
    }

    #[test]
    fn debug_and_from_str_invert_each_other() {
        let values = [
            NumericValue::U32(0_u32),
            NumericValue::U128(0_u128),
            NumericValue::Fixed(0_f64.try_into().expect("trivial conversion")),
            NumericValue::U128(u128::MAX),
            NumericValue::U128((u64::MAX - 1) as u128),
        ];
        for val in values {
            let new_value: NumericValue = format!("{val:?}").parse().expect("Failed to parse");
            assert_eq!(new_value, val);
        }
    }

    fn as_u32(v: impl Into<u32>) -> String {
        NumericValue::U32(v.into()).to_string()
    }

    #[test]
    #[should_panic]
    /// We deny ambiguous deserialisation from strings.
    fn display_from_str_integer_unsupported() {
        assert_eq!(
            NumericValue::from_str(&as_u32(0_u32)).unwrap(),
            NumericValue::U128(0_u128)
        );
    }

    #[test]
    #[should_panic]
    /// We deny ambiguous deserialisation from int literals
    fn deserialize_int_literal_unsupported() {
        serde_json::from_str::<NumericValue>("0").unwrap();
    }

    #[test]
    fn display_from_str_fixed_invert_each_other() {
        let values = [
            // This value is not preserved in not equal to the `0.2` decimal
            NumericValue::Fixed(0.2_f64.try_into().expect("trivial conversion")),
            NumericValue::Fixed((u32::MAX as f64).try_into().expect("trivial conversion")),
        ];
        for val in values {
            let new_value: NumericValue = format!("{val}").parse().expect("Failed to parse");
            assert_eq!(new_value, val);
        }
    }
}
