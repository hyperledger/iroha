//! Borrowed GOST verification using the existing fixed-width point relation.
//!
//! Public bytes are checked before conversion or Montgomery reduction. The
//! selected curve fixes every scalar, point, and digest width. This owner does
//! not construct decoded-key caches or heap-backed integer intermediates.

use super::{
    AffinePoint, CurveParameters, CurveSelection, FieldElement, Uint, curve_for_algorithm,
    mul_add_impl,
};
use crate::{Algorithm, Error, ParseError};
use streebog::{Digest, Streebog256, Streebog512};
use subtle::ConstantTimeEq;

/// Fixed diagnostic data for a rejected borrowed public-key envelope.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum KeyRejection {
    /// The algorithm has no GOST parameter identity.
    Unsupported(Algorithm),
    /// The exact coordinate pair width does not match its parameter set.
    Length {
        /// Canonical diagnostic name from the parameter owner.
        name: &'static str,
        /// Exact required pair width.
        expected: usize,
        /// Caller-owned slice length.
        actual: usize,
    },
    /// Both coordinates are encoded as zero.
    AllZero(&'static str),
    /// A coordinate is noncanonical or fails the existing curve equation.
    NotOnCurve(&'static str),
}

impl KeyRejection {
    /// Materialize the existing public diagnostic at the fallible facade boundary.
    pub(crate) fn into_parse_error(self) -> ParseError {
        // TODO: fund these public diagnostic Strings, including any subsequent
        // Norito Message conversion, before materializing them.
        ParseError::Invalid(match self {
            Self::Unsupported(algorithm) => {
                format!("algorithm {algorithm:?} is not a supported GOST parameter set")
            }
            Self::Length {
                name,
                expected,
                actual,
            } => {
                format!("public key for {name} must be {expected} bytes, got {actual}")
            }
            Self::AllZero(name) => format!("public key for {name} must not be all zero"),
            Self::NotOnCurve(name) => format!("public key is not on the curve for {name}"),
        })
    }
}

fn parse_point<const LIMBS: usize>(
    curve: &CurveParameters<LIMBS>,
    payload: &[u8],
) -> Result<AffinePoint<LIMBS>, KeyRejection> {
    let expected = Uint::<LIMBS>::BYTES * 2;
    if payload.len() != expected {
        return Err(KeyRejection::Length {
            name: curve.name,
            expected,
            actual: payload.len(),
        });
    }
    if payload.iter().all(|&byte| byte == 0) {
        return Err(KeyRejection::AllZero(curve.name));
    }
    let (x_bytes, y_bytes) = payload.split_at(Uint::<LIMBS>::BYTES);
    let x = Uint::<LIMBS>::from_le_slice(x_bytes);
    let y = Uint::<LIMBS>::from_le_slice(y_bytes);
    let modulus = curve.field_params.modulus().as_ref();
    if x >= *modulus || y >= *modulus {
        return Err(KeyRejection::NotOnCurve(curve.name));
    }
    let point = AffinePoint {
        x: FieldElement::from_uint(x, curve.field_params),
        y: FieldElement::from_uint(y, curve.field_params),
    };
    let lhs = point.y.square();
    let rhs = point
        .x
        .square()
        .mul(&point.x)
        .add(&curve.a.mul(&point.x))
        .add(&curve.b);
    if !bool::from(lhs.ct_eq(&rhs)) {
        return Err(KeyRejection::NotOnCurve(curve.name));
    }
    Ok(point)
}

pub(in crate::signature::gost) fn validate_public_key(
    algorithm: Algorithm,
    payload: &[u8],
) -> Result<(), KeyRejection> {
    match curve_for_algorithm(algorithm).ok_or(KeyRejection::Unsupported(algorithm))? {
        CurveSelection::Bits256(curve) => parse_point(curve, payload).map(drop),
        CurveSelection::Bits512(curve) => parse_point(curve, payload).map(drop),
    }
}

fn reduce_digest<const LIMBS: usize>(
    curve: &CurveParameters<LIMBS>,
    digest: &Uint<LIMBS>,
) -> FieldElement<LIMBS> {
    let reduced = FieldElement::from_uint(*digest, curve.scalar_params);
    FieldElement::conditional_select(
        &reduced,
        &FieldElement::one(curve.scalar_params),
        reduced.is_zero(),
    )
}

fn message_scalar<const LIMBS: usize>(
    curve: &CurveParameters<LIMBS>,
    message: &[u8],
) -> FieldElement<LIMBS> {
    // The canonical existing relation reverses the digest before little-endian
    // decoding, which is exactly big-endian decoding of the original digest.
    let digest = if Uint::<LIMBS>::BYTES == 32 {
        Uint::from_be_slice(Streebog256::digest(message).as_slice())
    } else {
        Uint::from_be_slice(Streebog512::digest(message).as_slice())
    };
    reduce_digest(curve, &digest)
}

fn verify<const LIMBS: usize>(
    curve: &CurveParameters<LIMBS>,
    message: &[u8],
    signature: &[u8],
    public: &[u8],
) -> Result<(), Error> {
    if signature.len() != Uint::<LIMBS>::BYTES * 2 {
        return Err(Error::BadSignature);
    }
    let (r_bytes, s_bytes) = signature.split_at(Uint::<LIMBS>::BYTES);
    let r = Uint::<LIMBS>::from_le_slice(r_bytes);
    let s = Uint::<LIMBS>::from_le_slice(s_bytes);
    if r == Uint::ZERO || r >= curve.scalar_modulus || s == Uint::ZERO || s >= curve.scalar_modulus
    {
        return Err(Error::BadSignature);
    }
    let point = parse_point(curve, public).map_err(|_| Error::BadSignature)?;
    let inverse = message_scalar(curve, message)
        .invert()
        .ok_or(Error::BadSignature)?;
    let z1 = FieldElement::from_uint(s, curve.scalar_params)
        .mul(&inverse)
        .as_uint();
    let z2 = FieldElement::from_uint(r, curve.scalar_params)
        .negate()
        .mul(&inverse)
        .as_uint();
    let sum = mul_add_impl(curve, &z1, &z2, &point).ok_or(Error::BadSignature)?;
    let x = FieldElement::from_uint(sum.x.as_uint(), curve.scalar_params).as_uint();
    if bool::from(x.ct_eq(&r)) {
        Ok(())
    } else {
        Err(Error::BadSignature)
    }
}

pub(in crate::signature::gost) fn verify_bytes(
    algorithm: Algorithm,
    message: &[u8],
    signature: &[u8],
    public: &[u8],
) -> Result<(), Error> {
    match curve_for_algorithm(algorithm).ok_or_else(|| {
        Error::KeyGen(
            KeyRejection::Unsupported(algorithm)
                .into_parse_error()
                .to_string(),
        )
    })? {
        CurveSelection::Bits256(curve) => verify(curve, message, signature, public),
        CurveSelection::Bits512(curve) => verify(curve, message, signature, public),
    }
}

#[cfg(test)]
#[path = "verification/tests.rs"]
mod tests;
