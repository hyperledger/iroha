//! Arbitrary precision numeric type for Iroha assets

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::{format, string::String, string::ToString, vec, vec::Vec};
use core::str::FromStr;

use derive_more::Display;
use parity_scale_codec::{Decode, Encode};
use rust_decimal::{prelude::ToPrimitive, Decimal};
use serde::{Deserialize, Serialize};
use serde_with::{DeserializeFromStr, SerializeDisplay};

/// Decimal number with arbitrary precision and scale.
///
/// The finite set of values of type [`Numeric`] are of the form $m / 10^e$,
/// where m is an integer such that $-2^96 < m < 2^96$, and e is an integer between 0 and 28 inclusive.
///
/// This type provide only bare minimum of operations required to execute ISI.
/// If more rich functionality is required (e.g. in smartcontract)
/// it's suggested to convert this type into proper decimal type (like `rust_decimal`, `bigdecimal`, `u128`, ...),
/// perform necessary operations, and then convert back into `Numeric` when sending ISI to Iroha.
#[derive(Clone, Copy, Debug, Display, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct Numeric {
    inner: Decimal,
}

/// Define maximum precision and scale for given number.
///
/// E.g.
///
/// 3.1415 has a scale of 4 and a precision of 5
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Default,
    Hash,
    SerializeDisplay,
    DeserializeFromStr,
    Encode,
    Decode,
    iroha_schema::IntoSchema,
)]
#[cfg_attr(
    all(feature = "ffi_export", not(feature = "ffi_import")),
    derive(iroha_ffi::FfiType)
)]
pub struct NumericSpec {
    /// Count of decimal digits in the fractional part.
    /// Currently only positive scale up to 28 decimal points is supported.
    scale: Option<u32>,
}

/// Error occurred during creation of [`Numeric`]
#[derive(Debug, Clone, Copy, displaydoc::Display)]
#[cfg_attr(feature = "std", derive(thiserror::Error))]
pub enum NumericError {
    /// Mantissa exceeds allowed range
    MantissaTooLarge,
    /// Scale exeeds allowed range
    ScaleTooLarge,
    /// Negative values are not allowed
    Negative,
    /// Malformed: expecting number with optional decimal point (10, 10.02)
    Malformed,
}

/// The error type returned when a numeric conversion fails.
#[derive(Debug, Clone, Copy, displaydoc::Display)]
#[cfg_attr(feature = "std", derive(thiserror::Error))]
pub struct TryFromNumericError;

/// Error occurred while checking if number satisfy given spec
#[derive(Clone, Copy, Debug, displaydoc::Display)]
#[cfg_attr(feature = "std", derive(thiserror::Error))]
pub enum NumericSpecError {
    /// Given number has scale higher than allowed by spec.
    ScaleTooHigh,
}

/// Error occurred while checking if number satisfy given spec
#[derive(Clone, Debug, displaydoc::Display)]
#[cfg_attr(feature = "std", derive(thiserror::Error))]
pub enum NumericSpecParseError {
    /// String representation should start with Numeric
    StartWithNumeric,
    /// Numeric should be followed by optional scale wrapped in braces
    WrappedInBraces,
    /// Scale should be valid integer value: {_0}
    InvalidScale(#[cfg_attr(feature = "std", source)] <u32 as FromStr>::Err),
}

impl Numeric {
    /// Zero numeric value
    pub const ZERO: Self = Self::new(0, 0);
    /// One numeric value
    pub const ONE: Self = Self::new(1, 0);
    /// Maximal numeric value
    pub const MAX: Self = Self {
        inner: Decimal::MAX,
    };

    /// Create new numeric given mantissa and scale
    ///
    /// # Panics
    /// Panics in cases where [`Self::try_new`] would return error.
    #[inline]
    pub const fn new(mantissa: u128, scale: u32) -> Self {
        match Self::try_new(mantissa, scale) {
            Ok(numeric) => numeric,
            Err(NumericError::ScaleTooLarge) => panic!("failed to create numeric: scale too large"),
            Err(NumericError::MantissaTooLarge) => {
                panic!("failed to create numeric:  mantissa too large")
            }
            // Not possible to get malformed or negative value from mantissa and scale
            Err(NumericError::Malformed | NumericError::Negative) => unreachable!(),
        }
    }

    /// Try to create numeric given mantissa and scale
    ///
    /// # Errors
    /// - if mantissa exceeds 96bits
    /// - if scale is greater than 28
    #[inline]
    pub const fn try_new(mantissa: u128, scale: u32) -> Result<Self, NumericError> {
        const MANTISSA_MASK: u128 = (u32::MAX as u128) << 96;
        if mantissa & MANTISSA_MASK != 0 {
            return Err(NumericError::MantissaTooLarge);
        }

        if scale > 28 {
            return Err(NumericError::ScaleTooLarge);
        }

        // Truncation is desired effect here
        #[allow(clippy::cast_possible_truncation)]
        let inner = {
            let lo = mantissa as u32;
            let mid = (mantissa >> 32) as u32;
            let hi = (mantissa >> 64) as u32;
            Decimal::from_parts(lo, mid, hi, false, scale)
        };

        Ok(Self { inner })
    }

    /// Return mantissa of number
    /// E.g.
    /// - 100 (scale 0) mantissa is 100
    /// - 1.01 (scale 2) mantissa is 101
    /// - 0.042 (scale 3) mantissa is 3
    #[inline]
    pub const fn mantissa(&self) -> u128 {
        // Non-negative invariant
        #[allow(clippy::cast_sign_loss)]
        {
            self.inner.mantissa() as u128
        }
    }

    /// Return scale of number
    #[inline]
    pub const fn scale(&self) -> u32 {
        self.inner.scale()
    }

    /// Checked addition
    ///
    /// # Errors
    /// In case of overflow
    pub fn checked_add(self, other: Self) -> Option<Self> {
        self.inner
            .checked_add(other.inner)
            .map(|inner| Self { inner })
    }

    /// Checked subtraction
    ///
    /// # Errors
    /// In case of overflow
    pub fn checked_sub(self, other: Self) -> Option<Self> {
        self.inner
            .checked_sub(other.inner)
            .and_then(|inner| inner.is_sign_positive().then_some(Self { inner }))
    }

    /// Convert [`Numeric`] to [`f64`] with possible loss in precision
    pub fn to_f64(self) -> f64 {
        self.inner.to_f64().expect("never fails")
    }

    /// Check if number is zero
    pub const fn is_zero(&self) -> bool {
        self.inner.is_zero()
    }
}

impl From<u32> for Numeric {
    fn from(value: u32) -> Self {
        Self::new(value.into(), 0)
    }
}

impl From<u64> for Numeric {
    fn from(value: u64) -> Self {
        Self::new(value.into(), 0)
    }
}

impl TryFrom<Numeric> for u32 {
    type Error = TryFromNumericError;

    fn try_from(value: Numeric) -> Result<Self, Self::Error> {
        value.inner.try_into().map_err(|_| TryFromNumericError)
    }
}

impl TryFrom<Numeric> for u64 {
    type Error = TryFromNumericError;

    fn try_from(value: Numeric) -> Result<Self, Self::Error> {
        value.inner.try_into().map_err(|_| TryFromNumericError)
    }
}

impl NumericSpec {
    /// Check if given numeric satisfy constrains
    ///
    /// # Errors
    /// If given number has precision or scale higher than specified by spec.
    pub fn check(self, numeric: &Numeric) -> Result<(), NumericSpecError> {
        if !self.scale.map_or(true, |scale| scale >= numeric.scale()) {
            return Err(NumericSpecError::ScaleTooHigh);
        }

        Ok(())
    }

    /// Create [`NumericSpec`] which accepts any numeric value
    #[inline]
    pub const fn unconstrained() -> Self {
        NumericSpec { scale: None }
    }

    /// Create [`NumericSpec`] which accepts only integer values
    #[inline]
    pub const fn integer() -> Self {
        Self { scale: Some(0) }
    }

    /// Create [`NumericSpec`] which accepts numeric values with scale up to given decimal places
    #[inline]
    pub const fn fractional(scale: u32) -> Self {
        Self { scale: Some(scale) }
    }

    /// Get the scale
    #[inline]
    pub const fn scale(&self) -> Option<u32> {
        self.scale
    }
}

impl core::str::FromStr for Numeric {
    type Err = NumericError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let Ok(inner) = Decimal::from_str(s) else {
            return Err(NumericError::Malformed);
        };

        if inner.is_sign_negative() {
            return Err(NumericError::Negative);
        }

        Ok(Self { inner })
    }
}

impl core::str::FromStr for NumericSpec {
    type Err = NumericSpecParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Valid formats:
        // Numeric
        // Numeric(scale)

        // Trim Numeric prefix return error if not present
        let Some(s) = s.strip_prefix("Numeric") else {
            return Err(NumericSpecParseError::StartWithNumeric);
        };

        let scale = if s.is_empty() {
            None
        } else {
            // Trim braces
            let Some(s) = s.strip_prefix('(').and_then(|s| s.strip_suffix(')')) else {
                return Err(NumericSpecParseError::WrappedInBraces);
            };

            // Parse scale
            Some(s.parse().map_err(NumericSpecParseError::InvalidScale)?)
        };

        Ok(NumericSpec { scale })
    }
}

impl core::fmt::Display for NumericSpec {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "Numeric")?;
        if let Some(scale) = self.scale {
            write!(f, "({scale})")?;
        }
        Ok(())
    }
}

mod serde_ {
    use serde::de::Error;

    use super::*;

    impl Serialize for Numeric {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: ::serde::Serializer,
        {
            rust_decimal::serde::str::serialize(&self.inner, serializer)
        }
    }

    impl<'de> Deserialize<'de> for Numeric {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: ::serde::Deserializer<'de>,
        {
            rust_decimal::serde::str::deserialize(deserializer).and_then(|inner| {
                inner
                    .is_sign_positive()
                    .then_some(Self { inner })
                    .ok_or_else(|| D::Error::custom("number must be non negative"))
            })
        }
    }
}

mod scale_ {
    use parity_scale_codec::{Decode, Encode};

    use super::*;

    #[derive(Encode, Decode)]
    // Use compact encoding for efficiency, for integer numbers scale takes only one byte
    struct NumericScaleHelper {
        #[codec(compact)]
        mantissa: u128,
        #[codec(compact)]
        scale: u32,
    }

    impl Encode for Numeric {
        fn encode(&self) -> Vec<u8> {
            NumericScaleHelper {
                mantissa: self.mantissa(),
                scale: self.scale(),
            }
            .encode()
        }
    }

    impl Decode for Numeric {
        fn decode<I: parity_scale_codec::Input>(
            input: &mut I,
        ) -> Result<Self, parity_scale_codec::Error> {
            let NumericScaleHelper { mantissa, scale } = NumericScaleHelper::decode(input)?;
            match Numeric::try_new(mantissa, scale) {
                Ok(numeric) => Ok(numeric),
                Err(NumericError::MantissaTooLarge) => {
                    Err("error decoding numeric: mantissa too large".into())
                }
                Err(NumericError::ScaleTooLarge) => {
                    Err("error decoding numeric: scale too large".into())
                }
                // Not possible to get malformed or negative value from mantissa and scale
                Err(NumericError::Malformed | NumericError::Negative) => unreachable!(),
            }
        }
    }
}

mod schema_ {
    use iroha_schema::{
        Compact, Declaration, Ident, IntoSchema, MetaMap, Metadata, NamedFieldsMeta, TypeId,
    };

    use super::*;

    impl TypeId for Numeric {
        fn id() -> Ident {
            "Numeric".to_string()
        }
    }

    impl IntoSchema for Numeric {
        fn type_name() -> Ident {
            "Numeric".to_string()
        }

        fn update_schema_map(metamap: &mut MetaMap) {
            if !metamap.contains_key::<Self>() {
                if !metamap.contains_key::<Compact<u128>>() {
                    <Compact<u128> as iroha_schema::IntoSchema>::update_schema_map(metamap);
                }
                if !metamap.contains_key::<Compact<u32>>() {
                    <Compact<u32> as iroha_schema::IntoSchema>::update_schema_map(metamap);
                }

                metamap.insert::<Self>(Metadata::Struct(NamedFieldsMeta {
                    declarations: vec![
                        Declaration {
                            name: "mantissa".to_string(),
                            ty: core::any::TypeId::of::<Compact<u128>>(),
                        },
                        Declaration {
                            name: "scale".to_string(),
                            ty: core::any::TypeId::of::<Compact<u32>>(),
                        },
                    ],
                }));
            }
        }
    }
}

#[cfg(any(feature = "ffi_export", feature = "ffi_import"))]
mod ffi {
    //! Manual implementations of FFI related functionality
    #![allow(unsafe_code)]

    use iroha_ffi::ReprC;

    use super::*;

    // SAFETY: `#[repr(transparent)]` to `#[repr(C)]` inner struct
    unsafe impl ReprC for Numeric {}

    iroha_ffi::ffi_type! {
        impl Robust for Numeric {}
    }
}

#[cfg(test)]
mod tests {
    use parity_scale_codec::{Decode, Encode};

    use super::*;

    #[test]
    fn check_add() {
        let a = Numeric::new(10, 0);
        let b = Numeric::new(9, 3);

        assert_eq!(a.checked_add(b), Some(Numeric::new(10009, 3)));

        let a = Numeric::new(1, 2);
        let b = Numeric::new(999, 2);

        assert_eq!(a.checked_add(b), Some(Numeric::new(1000, 2)));
    }

    #[test]
    fn check_serde() {
        let num1 = Numeric::new(1002, 2);

        let s = serde_json::to_string(&num1).expect("failed to serialize numeric");

        assert_eq!(s, "\"10.02\"");

        let num2 = serde_json::from_str(&s).expect("failed to deserialize numeric");

        assert_eq!(num1, num2);
    }

    #[test]
    fn check_scale() {
        let num1 = Numeric::new(1002, 2);

        let s = num1.encode();

        let num2 = Numeric::decode(&mut s.as_slice()).expect("failed to decode numeric");

        assert_eq!(num1, num2);
    }

    #[test]
    fn check_numeric_scale_from_str() {
        // Valid representations
        assert_eq!(NumericSpec { scale: None }, "Numeric".parse().unwrap());
        assert_eq!(
            NumericSpec { scale: Some(0) },
            "Numeric(0)".parse().unwrap()
        );
        assert_eq!(
            NumericSpec { scale: Some(42) },
            "Numeric(42)".parse().unwrap()
        );

        // Invalid representations
        assert!(matches!(
            "RandomString".parse::<NumericSpec>().unwrap_err(),
            NumericSpecParseError::StartWithNumeric
        ));
        assert!(matches!(
            "Numeric%123%".parse::<NumericSpec>().unwrap_err(),
            NumericSpecParseError::WrappedInBraces
        ));
        assert!(matches!(
            "Numeric(123".parse::<NumericSpec>().unwrap_err(),
            NumericSpecParseError::WrappedInBraces
        ));
        assert!(matches!(
            "Numeric123)".parse::<NumericSpec>().unwrap_err(),
            NumericSpecParseError::WrappedInBraces
        ));
        assert!(matches!(
            "Numeric(NaN)".parse::<NumericSpec>().unwrap_err(),
            NumericSpecParseError::InvalidScale(_)
        ));
        assert!(matches!(
            "Numeric(-1)".parse::<NumericSpec>().unwrap_err(),
            NumericSpecParseError::InvalidScale(_)
        ));
    }
}
