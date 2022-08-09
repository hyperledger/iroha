//! Types used for Fixed-point operations. Uses [`fixnum::FixedPoint`].
#![allow(clippy::std_instead_of_core)]

#[cfg(not(feature = "std"))]
use alloc::{format, string::String, vec::Vec};

use derive_more::Display;
use fixnum::{
    ops::{Bounded, CheckedAdd, CheckedSub, Zero},
    ArithmeticError,
};
use iroha_schema::IntoSchema;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

/// Base type for fixed implementation. May be changed in forks.  To
/// change implementation to i128 or other type you will need to
/// change it in Cargo.toml.
type Base = i64;

/// Signed fixed-point 64 bit rational fraction, having approximately
/// 9 decimal places and not Binary-coded decimal.
///
/// MAX = (2 ^ (`BITS_COUNT` - 1) - 1) / 10 ^ PRECISION =
///     = (2 ^ (64 - 1) - 1) / 1e9 =
///     = 9223372036.854775807 ~ 9.2e9
/// `ERROR_MAX` = 0.5 / (10 ^ PRECISION) =
///           = 0.5 / 1e9 =
///           = 5e-10
pub type FixNum = fixnum::FixedPoint<Base, fixnum::typenum::U9>;

/// An encapsulation of [`Fixed`] in encodable form. [`Fixed`] values
/// should never become negative.
#[derive(
    Debug,
    Clone,
    Display,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Decode,
    Encode,
    Deserialize,
    Serialize,
    IntoSchema,
)]
pub struct Fixed(FixNum);

impl Fixed {
    /// Constant, representing zero value
    pub const ZERO: Fixed = Fixed(FixNum::ZERO);

    // TODO FixNum::Bounded is private.

    /// The minimum value that can be stored in this type.
    pub const MIN: Self = Fixed(<FixNum as Bounded>::MIN);

    /// The maximum value that can be stored in this type.
    pub const MAX: Self = Fixed(<FixNum as Bounded>::MAX);

    /// Return the only possible negative [`Fixed`] value. Only used for tests.
    ///
    /// # Panics
    /// Never.
    #[inline]
    #[cfg(test)]
    pub fn negative_one() -> Self {
        #[allow(clippy::unwrap_used)]
        Self("-1".parse().unwrap())
    }

    /// Checks if this instance is zero
    #[inline]
    pub const fn is_zero(self) -> bool {
        *self.0.as_bits() == Base::ZERO
    }

    #[inline]
    fn valid(self) -> Result<Self, FixedPointOperationError> {
        if self > Self::ZERO || self.is_zero() {
            Ok(self)
        } else {
            Err(FixedPointOperationError::NegativeValue(self.0))
        }
    }

    /// Checked addition
    ///
    /// # Errors
    /// If either of the operands is negative or if addition overflows.
    #[inline]
    pub fn checked_add(self, rhs: Self) -> Result<Self, FixedPointOperationError> {
        match self.valid()?.0.cadd(rhs.valid()?.0) {
            Ok(n) => Ok(Fixed(n)),
            Err(e) => Err(e.into()),
        }
    }

    /// Checked subtraction
    ///
    /// # Errors
    /// If either of the operands is negative or if the subtraction overflows.
    #[inline]
    pub fn checked_sub(self, rhs: Self) -> Result<Self, FixedPointOperationError> {
        match self.valid()?.0.csub(rhs.valid()?.0) {
            Ok(n) => Fixed(n).valid(),
            Err(e) => Err(e.into()),
        }
    }
}

/// Custom error type for Fixed point operation errors.
#[allow(variant_size_differences)]
#[derive(Debug, Clone, Display, iroha_macro::FromVariant)]
#[cfg_attr(feature = "std", derive(thiserror::Error))]
pub enum FixedPointOperationError {
    /// All [`Fixed`] values should be positive.
    #[display(fmt = "{}: negative value not allowed", _0)]
    NegativeValue(FixNum),
    /// Conversion failed.
    #[display(fmt = "Failed to produce fixed point number")]
    Conversion(#[cfg_attr(feature = "std", source)] fixnum::ConvertError),
    /// Overflow
    #[display(fmt = "Overflow")]
    Overflow,
    /// Division by zero
    #[display(fmt = "Division by zero")]
    DivideByZero,
    /// Domain violation. E.g. computing `sqrt(-1)`
    #[display(fmt = "Domain violation")]
    DomainViolation,
    /// Arithmetic
    #[display(fmt = "Unknown Arithmetic error")]
    Arithmetic,
}

impl From<ArithmeticError> for FixedPointOperationError {
    #[inline]
    fn from(err: ArithmeticError) -> Self {
        match err {
            ArithmeticError::Overflow => Self::Overflow,
            ArithmeticError::DivisionByZero => Self::DivideByZero,
            ArithmeticError::DomainViolation => Self::DomainViolation,
            _ => Self::Arithmetic,
        }
    }
}

impl TryFrom<f64> for Fixed {
    type Error = FixedPointOperationError;

    #[inline]
    fn try_from(value: f64) -> Result<Self, Self::Error> {
        match FixNum::try_from(value) {
            Ok(n) => Fixed(n).valid(),
            Err(e) => Err(FixedPointOperationError::Conversion(e)),
        }
    }
}

impl From<Fixed> for f64 {
    #[inline]
    fn from(val: Fixed) -> Self {
        let Fixed(fix_num) = val;
        fix_num.into()
    }
}

/// Export of inner items.
pub mod prelude {
    pub use super::Fixed;
}

#[cfg(test)]
mod tests {
    #![allow(clippy::restriction, clippy::panic)]
    use super::*;

    #[test]
    fn cannot_parse_negative_value() {
        assert!(matches!(
            Fixed::try_from(-123.45_f64),
            Err(FixedPointOperationError::NegativeValue(_))
        ));
    }

    #[test]
    fn checked_add_and_subtract_should_fail_in_either_position() {
        let one = Fixed::try_from(1.0_f64).unwrap();
        match one.checked_add(Fixed::negative_one()) {
            Err(FixedPointOperationError::NegativeValue(_)) => (),
            _ => panic!("Negative values shouldn't be allowed"),
        };
        match Fixed::negative_one().checked_add(one) {
            Err(FixedPointOperationError::NegativeValue(_)) => (),
            _ => panic!("Negative values shouldn't be allowed"),
        };
        match one.checked_sub(Fixed::negative_one()) {
            Err(FixedPointOperationError::NegativeValue(_)) => (),
            _ => panic!("Negative values shouldn't be allowed"),
        };
        match Fixed::negative_one().checked_sub(one) {
            Err(FixedPointOperationError::NegativeValue(_)) => (),
            _ => panic!("Negative values shouldn't be allowed"),
        };
    }

    #[test]
    #[should_panic]
    fn deserialize_from_json_should_fail() {
        serde_json::from_str("-10.00").unwrap()
    }

    #[test]
    fn checked_work_for_positive() -> Result<(), FixedPointOperationError> {
        let one = Fixed::try_from(1_f64)?;
        let zero = Fixed::ZERO;
        let two = Fixed::try_from(2_f64)?;
        let three = Fixed::try_from(3_f64)?;
        assert_eq!(one.checked_add(zero)?, one);
        assert_eq!(two.checked_add(one)?, three);
        assert_eq!(two.checked_sub(one)?, one);
        assert_eq!(two.checked_sub(two)?, zero);
        assert_eq!(one.checked_sub(zero)?, one);
        assert_eq!(zero.checked_sub(zero)?, zero);
        Ok(())
    }

    #[test]
    fn checked_dont_work_if_result_negative() {
        let one = Fixed::try_from(1_f64).unwrap();
        let zero = Fixed::ZERO;
        let two = Fixed::try_from(2_f64).unwrap();
        match one.checked_sub(two) {
            Err(FixedPointOperationError::NegativeValue(_)) => (),
            _ => panic!("Negative values shouldn't be allowed"),
        };
        match zero.checked_sub(two) {
            Err(FixedPointOperationError::NegativeValue(_)) => (),
            _ => panic!("Negative values shouldn't be allowed"),
        };
        match one.checked_sub(two) {
            Err(FixedPointOperationError::NegativeValue(_)) => (),
            _ => panic!("Negative values shouldn't be allowed"),
        };
    }

    #[test]
    #[ignore = "takes too long, but verifies the `fixnum` guarantee"]
    fn rounding_errors() {
        let inexact = Fixed::try_from(0.6_f64).unwrap();
        let mut accumulator = Fixed::ZERO;
        for _ in 0_u64..10_u64.pow(9) {
            accumulator = accumulator.checked_add(inexact).unwrap();
        }
        assert_eq!(
            Fixed::try_from(0.6_f64 * (10_f64.powf(9_f64))).unwrap(),
            accumulator
        );
    }
}
