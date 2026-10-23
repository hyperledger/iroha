//! One canonical Ed25519 public-key relation with fixed rejection custody.

use super::PublicKey;
use crate::ParseError;
use curve25519_dalek::edwards::CompressedEdwardsY;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum KeyRejection {
    Length(usize),
    AllZero,
    Encoding,
    NonCanonical,
    SmallOrder,
    Torsion,
}
impl KeyRejection {
    pub(crate) fn into_parse_error(self) -> ParseError {
        let message = match self {
            Self::Length(length) => {
                return ParseError::Invalid(format!(
                    "the payload size is incorrect: expected 32, but got {length}"
                ));
            }
            Self::AllZero => "ed25519 public key material must not be all zero",
            Self::Encoding => "invalid ed25519 public key encoding",
            Self::NonCanonical => "non-canonical ed25519 public key encoding",
            Self::SmallOrder => "ed25519 public key is small-order (weak); rejected",
            Self::Torsion => "ed25519 public key is outside the prime-order subgroup; rejected",
        };
        ParseError::Invalid(message.to_owned())
    }
}

pub(super) fn array(payload: &[u8]) -> Result<[u8; 32], KeyRejection> {
    payload
        .try_into()
        .map_err(|_| KeyRejection::Length(payload.len()))
}

pub(super) fn parse(payload: &[u8]) -> Result<PublicKey, KeyRejection> {
    parse_array(&array(payload)?)
}

pub(super) fn parse_array(bytes: &[u8; 32]) -> Result<PublicKey, KeyRejection> {
    if bytes.iter().all(|byte| *byte == 0) {
        return Err(KeyRejection::AllZero);
    }
    let point = CompressedEdwardsY(*bytes)
        .decompress()
        .ok_or(KeyRejection::Encoding)?;
    // ZIP-215 accepts encodings excluded by Iroha's canonical key relation.
    if point.compress().as_bytes() != bytes {
        return Err(KeyRejection::NonCanonical);
    }
    if point.is_small_order() {
        return Err(KeyRejection::SmallOrder);
    }
    if !point.is_torsion_free() {
        return Err(KeyRejection::Torsion);
    }
    Ok(PublicKey::from(point))
}
