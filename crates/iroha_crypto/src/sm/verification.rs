//! Fixed-storage SM2 public-key parsing, identity hashing and verification.
//!
//! Owned and compact-key verification share this relation. The distinguishing
//! identifier is always read from the original caller; no default is substituted.

use sm2::{
    AffinePoint, ProjectivePoint, PublicKey, Scalar,
    dsa::Signature,
    elliptic_curve::{
        Group,
        ops::{LinearCombination, Reduce},
        point::AffineCoordinates,
        sec1::{Coordinates, ToEncodedPoint},
    },
};
use sm3::{Digest, Sm3};

use super::{
    SM2_EQUATION_A_BYTES, SM2_EQUATION_B_BYTES, SM2_GENERATOR_X_BYTES, SM2_GENERATOR_Y_BYTES,
    SM2_PUBLIC_KEY_UNCOMPRESSED_LEN,
};
use crate::{Error, ParseError};

/// Fixed rejection before the ordinary public diagnostic adapter allocates.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyRejection {
    MissingPrefix,
    TruncatedIdentity,
    IdentityUtf8,
    IdentityOverflow,
    IdentityTooLong,
    PublicKeyLength,
    ZeroKey,
    ZeroCoordinates,
    InvalidPoint,
    NonCanonical,
}

impl KeyRejection {
    pub(crate) fn into_parse_error(self) -> ParseError {
        let message = match self {
            Self::MissingPrefix => "SM2 payload missing distid length prefix",
            Self::TruncatedIdentity => "SM2 payload truncated distid",
            Self::IdentityUtf8 => "SM2 distid must be valid UTF-8",
            Self::IdentityOverflow => "SM2 distinguishing identifier length overflowed",
            Self::IdentityTooLong => "SM2 distinguishing identifier exceeds 65535 bits",
            Self::PublicKeyLength => "SM2 public key payload must be 65 bytes",
            Self::ZeroKey => "invalid SM2 public key: all-zero SEC1 payload",
            Self::ZeroCoordinates => "invalid SM2 public key: all-zero SEC1 coordinate payload",
            Self::InvalidPoint => "invalid SM2 public key",
            Self::NonCanonical => "non-canonical SM2 public key encoding",
        };
        ParseError::Invalid(message.into())
    }
}

pub fn identity_bits(distid: &str) -> Result<u16, KeyRejection> {
    let bits = distid
        .len()
        .checked_mul(8)
        .ok_or(KeyRejection::IdentityOverflow)?;
    u16::try_from(bits).map_err(|_| KeyRejection::IdentityTooLong)
}

pub fn split_payload(payload: &[u8]) -> Result<(&str, &[u8]), KeyRejection> {
    let prefix = payload.get(..2).ok_or(KeyRejection::MissingPrefix)?;
    let length = usize::from(u16::from_be_bytes([prefix[0], prefix[1]]));
    // A u16 byte length plus this fixed prefix fits every supported std target.
    let end = 2 + length;
    let id = payload.get(2..end).ok_or(KeyRejection::TruncatedIdentity)?;
    let distid = std::str::from_utf8(id).map_err(|_| KeyRejection::IdentityUtf8)?;
    identity_bits(distid)?;
    Ok((distid, &payload[end..]))
}

pub fn parse_point(distid: &str, bytes: &[u8]) -> Result<PublicKey, KeyRejection> {
    identity_bits(distid)?;
    if !bytes.is_empty() && bytes.iter().all(|byte| *byte == 0) {
        return Err(KeyRejection::ZeroKey);
    }
    if bytes.len() == SM2_PUBLIC_KEY_UNCOMPRESSED_LEN
        && bytes.first() == Some(&4)
        && bytes[1..].iter().all(|byte| *byte == 0)
    {
        return Err(KeyRejection::ZeroCoordinates);
    }
    PublicKey::from_sec1_bytes(bytes).map_err(|_| KeyRejection::InvalidPoint)
}

pub fn identity_hash(distid: &str, point: &AffinePoint) -> Result<[u8; 32], KeyRejection> {
    let bits = identity_bits(distid)?;
    let encoded = point.to_encoded_point(false);
    let Coordinates::Uncompressed { x, y } = encoded.coordinates() else {
        return Err(KeyRejection::InvalidPoint);
    };
    let mut hash = Sm3::new();
    hash.update(bits.to_be_bytes());
    hash.update(distid.as_bytes());
    hash.update(SM2_EQUATION_A_BYTES);
    hash.update(SM2_EQUATION_B_BYTES);
    hash.update(SM2_GENERATOR_X_BYTES);
    hash.update(SM2_GENERATOR_Y_BYTES);
    hash.update(x);
    hash.update(y);
    Ok(hash.finalize().into())
}

/// Parsed fixed point plus original borrowed canonical payload and identity.
#[derive(Clone, Copy)]
pub struct BorrowedKey<'a> {
    payload: &'a [u8],
    point: PublicKey,
    identity_hash: [u8; 32],
}

impl<'a> BorrowedKey<'a> {
    pub(crate) fn parse(payload: &'a [u8]) -> Result<Self, KeyRejection> {
        let (distid, bytes) = split_payload(payload)?;
        if bytes.len() != SM2_PUBLIC_KEY_UNCOMPRESSED_LEN {
            return Err(KeyRejection::PublicKeyLength);
        }
        let point = parse_point(distid, bytes)?;
        if point.to_encoded_point(false).as_bytes() != bytes {
            return Err(KeyRejection::NonCanonical);
        }
        let identity_hash = identity_hash(distid, point.as_affine())?;
        Ok(Self {
            payload,
            point,
            identity_hash,
        })
    }

    pub(crate) fn payload(&self) -> &'a [u8] {
        self.payload
    }

    pub(crate) fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), Error> {
        verify(
            self.point.as_affine(),
            &self.identity_hash,
            message,
            signature,
        )
    }
}

/// SM2 relation over the existing fixed scalar and point implementation.
/// The same checked r/s parser and lincomb/reduction primitives are used by the
/// pinned dependency. Infinity is rejected before affine-coordinate extraction.
/// There is no ECDSA, backend-specific or cache-based verdict.
pub fn verify(
    point: &AffinePoint,
    identity_hash: &[u8; 32],
    message: &[u8],
    signature: &[u8],
) -> Result<(), Error> {
    let signature = Signature::from_slice(signature).map_err(|_| Error::BadSignature)?;
    let (r, s) = signature.split_scalars();
    let t = *r + *s;
    if bool::from(t.is_zero()) {
        return Err(Error::BadSignature);
    }
    let digest: [u8; 32] = Sm3::new_with_prefix(identity_hash)
        .chain_update(message)
        .finalize()
        .into();
    // SM3 and the pinned curve use different fixed-array container versions.
    // Bridge their identical 32 bytes on the stack before scalar reduction.
    let digest_scalar = Scalar::reduce_bytes(&digest.into());
    let combined = ProjectivePoint::lincomb(
        &ProjectivePoint::generator(),
        &s,
        &ProjectivePoint::from(*point),
        &t,
    );
    // B6 requires a finite affine point. The arithmetic library's identity
    // sentinel has x=0, which is not an affine coordinate for infinity.
    if bool::from(combined.is_identity()) {
        return Err(Error::BadSignature);
    }
    let x_coordinate = combined.to_affine().x();
    if *r == digest_scalar + Scalar::reduce_bytes(&x_coordinate) {
        Ok(())
    } else {
        Err(Error::BadSignature)
    }
}

#[cfg(test)]
mod tests;
