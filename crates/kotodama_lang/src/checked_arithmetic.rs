//! Compile-time evaluation for Kotodama's exact numeric domains.
//!
//! This module deliberately calls the same bounded primitives used by the VM
//! syscall implementation. It contains no scalar-register arithmetic and no
//! host-width fallback, so folding cannot disagree with runtime execution at a
//! width, sign, scale, normalization, or exact-division boundary.
use crate::{
    ast::{BinaryOp, UnaryOp},
    semantic::{ExprKind, Type, TypedExpr},
};
use iroha_primitives::{
    bigint::{BigInt, BigIntError},
    numeric::{MAX_MANTISSA_BYTES, Numeric, NumericOperationError, Quantity},
    numeric_int::{IntBinaryOperation, IntUnaryOperation},
};
use kotodama_surface::builtins::Builtin;
/// One fully evaluated source numeric value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ConstantNumeric {
    /// Signed adaptive-width integer.
    Int(BigInt),
    /// Canonical exact decimal.
    Decimal(Numeric),
    /// Canonical non-negative quantity.
    Quantity(Quantity),
}
/// Stable compile-time failure from the shared exact numeric implementation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ConstantNumericError {
    /// Integer-domain failure.
    Int(BigIntError),
    /// Decimal or quantity-domain failure.
    Numeric(NumericOperationError),
    /// Typed HIR violated the normative operator matrix.
    InvalidTypedOperation,
}
impl ConstantNumericError {
    /// Consensus-visible diagnostic class corresponding to the runtime fault.
    pub(crate) const fn code(self) -> &'static str {
        match self {
            Self::Int(BigIntError::Overflow) => "E_INT_OVERFLOW",
            Self::Numeric(NumericOperationError::MantissaOverflow) => "E_DECIMAL_MANTISSA_OVERFLOW",
            Self::Int(BigIntError::DivisionByZero)
            | Self::Numeric(NumericOperationError::DivisionByZero) => "E_DIVISION_BY_ZERO",
            Self::Int(BigIntError::NonCanonical)
            | Self::Numeric(NumericOperationError::NonCanonical) => "E_NON_CANONICAL_NUMERIC",
            Self::Numeric(NumericOperationError::ScaleOverflow) => "E_DECIMAL_SCALE_OVERFLOW",
            Self::Numeric(NumericOperationError::RepeatingDecimal) => "E_REPEATING_DECIMAL",
            Self::Numeric(NumericOperationError::ExactDivisionScaleOverflow) => {
                "E_EXACT_DIVISION_SCALE_OVERFLOW"
            }
            Self::Numeric(NumericOperationError::InvalidScale) => "E_INVALID_SCALE",
            Self::Numeric(NumericOperationError::InexactConversion) => "E_INEXACT_CONVERSION",
            Self::Numeric(NumericOperationError::NegativeQuantity) => "E_NEGATIVE_QUANTITY",
            Self::Numeric(NumericOperationError::QuantityUnderflow) => "E_QUANTITY_UNDERFLOW",
            Self::Numeric(NumericOperationError::NegativeSquareRoot) => "E_NEGATIVE_SQUARE_ROOT",
            Self::InvalidTypedOperation => "E_INTERNAL_NUMERIC_MATRIX",
        }
    }
}
impl core::fmt::Display for ConstantNumericError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Int(error) => write!(formatter, "{}: {error}", self.code()),
            Self::Numeric(error) => write!(formatter, "{}: {error}", self.code()),
            Self::InvalidTypedOperation => formatter.write_str(
                "E_INTERNAL_NUMERIC_MATRIX: typed numeric expression violates the V1 operator matrix",
            ),
        }
    }
}
impl From<BigIntError> for ConstantNumericError {
    fn from(error: BigIntError) -> Self {
        Self::Int(error)
    }
}
impl From<NumericOperationError> for ConstantNumericError {
    fn from(error: NumericOperationError) -> Self {
        Self::Numeric(error)
    }
}
impl ConstantNumeric {
    /// Materialize a canonical literal typed expression.
    pub(crate) fn into_typed_expr(self) -> TypedExpr {
        match self {
            Self::Int(value) => TypedExpr {
                expr: ExprKind::IntLiteral(value),
                ty: Type::Int,
            },
            Self::Decimal(value) => TypedExpr {
                expr: ExprKind::DecimalLiteral {
                    spelling: value.to_string(),
                    value,
                },
                ty: Type::Decimal,
            },
            Self::Quantity(value) => {
                let value = value.into_numeric();
                TypedExpr {
                    expr: ExprKind::DecimalLiteral {
                        spelling: value.to_string(),
                        value,
                    },
                    ty: Type::Quantity,
                }
            }
        }
    }
}
/// Evaluate a numeric typed expression exactly.
///
/// `Ok(None)` means that the expression depends on a runtime value.
pub(crate) fn evaluate(
    expression: &TypedExpr,
) -> Result<Option<ConstantNumeric>, ConstantNumericError> {
    match expression.kind() {
        ExprKind::IntLiteral(value) => {
            Ok(Some(ConstantNumeric::Int(ensure_int_v1(value.clone())?)))
        }
        ExprKind::DecimalLiteral { value, .. } => match expression.ty {
            Type::Decimal => Ok(Some(ConstantNumeric::Decimal(value.clone()))),
            Type::Quantity => Ok(Some(ConstantNumeric::Quantity(Quantity::try_from_numeric(
                value.clone(),
            )?))),
            _ => Err(ConstantNumericError::InvalidTypedOperation),
        },
        ExprKind::Call { target: name, args }
        | ExprKind::NamedCall {
            target: name, args, ..
        } => {
            let unary = match name.builtin() {
                Some(Builtin::Isqrt) => Some(IntUnaryOperation::Isqrt),
                Some(Builtin::Abs) => Some(IntUnaryOperation::Abs),
                _ => None,
            };
            let binary = match name.builtin() {
                Some(Builtin::Min) => Some(IntBinaryOperation::Min),
                Some(Builtin::Max) => Some(IntBinaryOperation::Max),
                Some(Builtin::DivCeil) => Some(IntBinaryOperation::DivCeil),
                Some(Builtin::Gcd) => Some(IntBinaryOperation::Gcd),
                Some(Builtin::Mean) => Some(IntBinaryOperation::Mean),
                _ => None,
            };
            if unary.is_none() && binary.is_none() {
                return Ok(None);
            }
            let Some(first) = args.first() else {
                return Err(ConstantNumericError::InvalidTypedOperation);
            };
            let Some(ConstantNumeric::Int(left)) = evaluate(first)? else {
                return Ok(None);
            };
            let result = if let Some(operation) = unary {
                if args.len() != 1 {
                    return Err(ConstantNumericError::InvalidTypedOperation);
                }
                operation.evaluate(&left)
            } else if let Some(operation) = binary {
                if args.len() != 2 {
                    return Err(ConstantNumericError::InvalidTypedOperation);
                }
                let Some(ConstantNumeric::Int(right)) = evaluate(&args[1])? else {
                    return Ok(None);
                };
                operation.evaluate(&left, &right)
            } else {
                return Err(ConstantNumericError::InvalidTypedOperation);
            };
            result
                .map(|value| Some(ConstantNumeric::Int(value)))
                .map_err(|error| {
                    if error == NumericOperationError::MantissaOverflow {
                        ConstantNumericError::Int(BigIntError::Overflow)
                    } else {
                        ConstantNumericError::Numeric(error)
                    }
                })
        }
        ExprKind::NumericCast { expr } => {
            let Some(value) = evaluate(expr)? else {
                return Ok(None);
            };
            let converted = match (value, &expression.ty) {
                (ConstantNumeric::Int(value), Type::Decimal) => {
                    ConstantNumeric::Decimal(Numeric::new(value, 0))
                }
                (ConstantNumeric::Int(value), Type::Quantity) => {
                    ConstantNumeric::Quantity(Quantity::try_from_numeric(Numeric::new(value, 0))?)
                }
                (ConstantNumeric::Decimal(value), Type::Int) => {
                    ConstantNumeric::Int(value.try_decimal_to_int_exact()?)
                }
                (ConstantNumeric::Decimal(value), Type::Quantity) => {
                    ConstantNumeric::Quantity(Quantity::try_from_numeric(value)?)
                }
                (ConstantNumeric::Quantity(value), Type::Decimal) => {
                    ConstantNumeric::Decimal(value.into_numeric())
                }
                (value, ty) if value_type(&value) == *ty => value,
                _ => return Err(ConstantNumericError::InvalidTypedOperation),
            };
            Ok(Some(converted))
        }
        ExprKind::NumericTryCast { .. } => Ok(None),
        ExprKind::Unary {
            op: UnaryOp::Neg,
            expr,
        } => {
            let Some(value) = evaluate(expr)? else {
                return Ok(None);
            };
            let value = match value {
                ConstantNumeric::Int(value) => {
                    ConstantNumeric::Int(ensure_int_v1(value.checked_neg()?)?)
                }
                ConstantNumeric::Decimal(value) => {
                    ConstantNumeric::Decimal(value.try_decimal_neg()?)
                }
                ConstantNumeric::Quantity(_) => {
                    return Err(ConstantNumericError::Numeric(
                        NumericOperationError::NegativeQuantity,
                    ));
                }
            };
            Ok(Some(value))
        }
        ExprKind::Binary { op, left, right }
            if matches!(
                op,
                BinaryOp::Add | BinaryOp::Sub | BinaryOp::Mul | BinaryOp::Div | BinaryOp::Mod
            ) =>
        {
            let Some(left) = evaluate(left)? else {
                return Ok(None);
            };
            let Some(right) = evaluate(right)? else {
                return Ok(None);
            };
            evaluate_binary(*op, left, right).map(Some)
        }
        _ => Ok(None),
    }
}
fn value_type(value: &ConstantNumeric) -> Type {
    match value {
        ConstantNumeric::Int(_) => Type::Int,
        ConstantNumeric::Decimal(_) => Type::Decimal,
        ConstantNumeric::Quantity(_) => Type::Quantity,
    }
}
fn ensure_int_v1(value: BigInt) -> Result<BigInt, ConstantNumericError> {
    if value.to_twos_bytes().len() > MAX_MANTISSA_BYTES {
        return Err(ConstantNumericError::Int(BigIntError::Overflow));
    }
    Ok(value)
}
fn evaluate_binary(
    operation: BinaryOp,
    left: ConstantNumeric,
    right: ConstantNumeric,
) -> Result<ConstantNumeric, ConstantNumericError> {
    match (left, operation, right) {
        (ConstantNumeric::Int(left), BinaryOp::Add, ConstantNumeric::Int(right)) => Ok(
            ConstantNumeric::Int(ensure_int_v1(left.checked_add(&right)?)?),
        ),
        (ConstantNumeric::Int(left), BinaryOp::Sub, ConstantNumeric::Int(right)) => Ok(
            ConstantNumeric::Int(ensure_int_v1(left.checked_sub(&right)?)?),
        ),
        (ConstantNumeric::Int(left), BinaryOp::Mul, ConstantNumeric::Int(right)) => Ok(
            ConstantNumeric::Int(ensure_int_v1(left.checked_mul(&right)?)?),
        ),
        (ConstantNumeric::Int(left), BinaryOp::Div, ConstantNumeric::Int(right)) => {
            let (quotient, _) = left.checked_div_rem(&right)?;
            Ok(ConstantNumeric::Int(ensure_int_v1(quotient)?))
        }
        (ConstantNumeric::Int(left), BinaryOp::Mod, ConstantNumeric::Int(right)) => {
            let (quotient, remainder) = left.checked_div_rem(&right)?;
            // Division and remainder are one paired operation. `min_int / -1`
            // therefore overflows even though its mathematical remainder is
            // zero, matching the runtime syscall contract.
            ensure_int_v1(quotient)?;
            Ok(ConstantNumeric::Int(ensure_int_v1(remainder)?))
        }
        (ConstantNumeric::Decimal(left), BinaryOp::Add, ConstantNumeric::Decimal(right)) => {
            Ok(ConstantNumeric::Decimal(left.try_decimal_add(&right)?))
        }
        (ConstantNumeric::Decimal(left), BinaryOp::Sub, ConstantNumeric::Decimal(right)) => {
            Ok(ConstantNumeric::Decimal(left.try_decimal_sub(&right)?))
        }
        (ConstantNumeric::Decimal(left), BinaryOp::Mul, ConstantNumeric::Decimal(right)) => {
            Ok(ConstantNumeric::Decimal(left.try_decimal_mul(&right)?))
        }
        (ConstantNumeric::Decimal(left), BinaryOp::Div, ConstantNumeric::Decimal(right)) => Ok(
            ConstantNumeric::Decimal(left.try_decimal_div_exact(&right)?),
        ),
        (ConstantNumeric::Quantity(left), BinaryOp::Add, ConstantNumeric::Quantity(right)) => {
            Ok(ConstantNumeric::Quantity(left.try_add(&right)?))
        }
        (ConstantNumeric::Quantity(left), BinaryOp::Sub, ConstantNumeric::Quantity(right)) => {
            Ok(ConstantNumeric::Quantity(left.try_sub(&right)?))
        }
        (ConstantNumeric::Quantity(left), BinaryOp::Mul, ConstantNumeric::Decimal(right)) => {
            Ok(ConstantNumeric::Quantity(left.try_mul_decimal(&right)?))
        }
        (ConstantNumeric::Quantity(left), BinaryOp::Div, ConstantNumeric::Decimal(right)) => Ok(
            ConstantNumeric::Quantity(left.try_div_decimal_exact(&right)?),
        ),
        (ConstantNumeric::Quantity(left), BinaryOp::Div, ConstantNumeric::Quantity(right)) => {
            Ok(ConstantNumeric::Decimal(left.try_ratio_exact(&right)?))
        }
        _ => Err(ConstantNumericError::InvalidTypedOperation),
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn int(value: BigInt) -> TypedExpr {
        ConstantNumeric::Int(value).into_typed_expr()
    }
    fn binary(operation: BinaryOp, left: TypedExpr, right: TypedExpr, ty: Type) -> TypedExpr {
        TypedExpr {
            expr: ExprKind::Binary {
                op: operation,
                left: Box::new(left),
                right: Box::new(right),
            },
            ty,
        }
    }
    #[test]
    fn checked_helper_folding_uses_shared_full_width_operations() {
        for (name, arguments, expected) in [
            (
                "isqrt",
                vec![int(BigInt::from(17_u64))],
                BigInt::from(4_u64),
            ),
            (
                "abs",
                vec![int(BigInt::from(-17_i64))],
                BigInt::from(17_u64),
            ),
            (
                "min",
                vec![int(BigInt::from(-7_i64)), int(BigInt::from(2_u64))],
                BigInt::from(-7_i64),
            ),
            (
                "max",
                vec![int(BigInt::from(-7_i64)), int(BigInt::from(2_u64))],
                BigInt::from(2_u64),
            ),
            (
                "div_ceil",
                vec![int(BigInt::from(-7_i64)), int(BigInt::from(2_u64))],
                BigInt::from(-3_i64),
            ),
            (
                "gcd",
                vec![int(BigInt::from(-12_i64)), int(BigInt::from(8_u64))],
                BigInt::from(4_u64),
            ),
            (
                "mean",
                vec![int(BigInt::from(-7_i64)), int(BigInt::from(2_u64))],
                BigInt::from(-2_i64),
            ),
        ] {
            let expression = TypedExpr {
                expr: ExprKind::Call {
                    target: crate::semantic::CallTarget::Builtin(
                        Builtin::from_name(name).expect("test builtin"),
                    ),
                    args: arguments,
                },
                ty: Type::Int,
            };
            assert_eq!(
                evaluate(&expression),
                Ok(Some(ConstantNumeric::Int(expected))),
                "{name}"
            );
        }
        let negative = TypedExpr {
            expr: ExprKind::Call {
                target: crate::semantic::CallTarget::Builtin(Builtin::Isqrt),
                args: vec![int(BigInt::from(-1_i64))],
            },
            ty: Type::Int,
        };
        assert_eq!(
            evaluate(&negative).unwrap_err().code(),
            "E_NEGATIVE_SQUARE_ROOT"
        );
    }
    #[test]
    fn integer_folding_uses_the_full_signed_domain() {
        let mut maximum_bytes = vec![0xff; MAX_MANTISSA_BYTES];
        maximum_bytes[MAX_MANTISSA_BYTES - 1] = 0x7f;
        let maximum = BigInt::from_twos_bytes(&maximum_bytes).expect("positive endpoint");
        assert!(matches!(
            evaluate(&binary(
                BinaryOp::Add,
                int(maximum),
                int(BigInt::one()),
                Type::Int,
            )),
            Err(ConstantNumericError::Int(BigIntError::Overflow))
        ));
        let mut minimum_bytes = vec![0; MAX_MANTISSA_BYTES];
        minimum_bytes[MAX_MANTISSA_BYTES - 1] = 0x80;
        let minimum = BigInt::from_twos_bytes(&minimum_bytes).expect("negative endpoint");
        assert!(matches!(
            evaluate(&binary(
                BinaryOp::Div,
                int(minimum.clone()),
                int(BigInt::from(-1_i64)),
                Type::Int,
            )),
            Err(ConstantNumericError::Int(BigIntError::Overflow))
        ));
        assert!(matches!(
            evaluate(&binary(
                BinaryOp::Mod,
                int(minimum),
                int(BigInt::from(-1_i64)),
                Type::Int,
            )),
            Err(ConstantNumericError::Int(BigIntError::Overflow))
        ));
    }
    #[test]
    fn decimal_failures_keep_runtime_classes() {
        let one = ConstantNumeric::Decimal(Numeric::one()).into_typed_expr();
        let three = ConstantNumeric::Decimal(Numeric::new(3, 0)).into_typed_expr();
        assert_eq!(
            evaluate(&binary(BinaryOp::Div, one, three, Type::Decimal)),
            Err(ConstantNumericError::Numeric(
                NumericOperationError::RepeatingDecimal
            ))
        );
        assert_eq!(
            ConstantNumericError::Numeric(NumericOperationError::MantissaOverflow).code(),
            "E_DECIMAL_MANTISSA_OVERFLOW"
        );
    }
    #[test]
    fn quantity_underflow_is_not_generic_overflow() {
        let one = ConstantNumeric::Quantity(Quantity::one()).into_typed_expr();
        let two = ConstantNumeric::Quantity(Quantity::from(2_u32)).into_typed_expr();
        assert_eq!(
            evaluate(&binary(BinaryOp::Sub, one, two, Type::Quantity)),
            Err(ConstantNumericError::Numeric(
                NumericOperationError::QuantityUnderflow
            ))
        );
    }
}
