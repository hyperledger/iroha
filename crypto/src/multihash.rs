//! Module with multihash implementation

#[cfg(not(feature = "std"))]
use alloc::{
    string::{String, ToString as _},
    vec,
    vec::Vec,
};

use derive_more::Display;
use iroha_primitives::const_vec::ConstVec;

use crate::{varint, Algorithm, NoSuchAlgorithm, ParseError, PublicKey, PublicKeyInner};

/// ed25519 public string
pub const ED_25519_PUB_STR: &str = "ed25519-pub";
/// secp256k1 public string
pub const SECP_256_K1_PUB_STR: &str = "secp256k1-pub";
/// bls12 381 g1 public string
pub const BLS12_381_G1_PUB: &str = "bls12_381-g1-pub";
/// bls12 381 g2 public string
pub const BLS12_381_G2_PUB: &str = "bls12_381-g2-pub";

/// Type of digest function.
/// The corresponding byte codes are taken from [official multihash table](https://github.com/multiformats/multicodec/blob/master/table.csv)
#[allow(clippy::enum_variant_names)]
#[repr(u64)]
#[derive(Debug, Display, Clone, Copy, PartialEq, Eq, Default)]
pub enum DigestFunction {
    /// `Ed25519`
    #[display(fmt = "{ED_25519_PUB_STR}")]
    #[default]
    Ed25519Pub = 0xed,
    /// `Secp256k1`
    #[display(fmt = "{SECP_256_K1_PUB_STR}")]
    Secp256k1Pub = 0xe7,
    /// `Bls12381G1`
    #[display(fmt = "{BLS12_381_G1_PUB}")]
    Bls12381G1Pub = 0xea,
    /// `Bls12381G2`
    #[display(fmt = "{BLS12_381_G2_PUB}")]
    Bls12381G2Pub = 0xeb,
}

impl From<DigestFunction> for Algorithm {
    fn from(f: DigestFunction) -> Self {
        match f {
            DigestFunction::Ed25519Pub => Self::Ed25519,
            DigestFunction::Secp256k1Pub => Self::Secp256k1,
            DigestFunction::Bls12381G1Pub => Self::BlsNormal,
            DigestFunction::Bls12381G2Pub => Self::BlsSmall,
        }
    }
}

impl From<Algorithm> for DigestFunction {
    fn from(a: Algorithm) -> Self {
        match a {
            Algorithm::Ed25519 => Self::Ed25519Pub,
            Algorithm::Secp256k1 => Self::Secp256k1Pub,
            Algorithm::BlsNormal => Self::Bls12381G1Pub,
            Algorithm::BlsSmall => Self::Bls12381G2Pub,
        }
    }
}

impl core::str::FromStr for DigestFunction {
    type Err = NoSuchAlgorithm;

    fn from_str(source: &str) -> Result<Self, Self::Err> {
        match source {
            ED_25519_PUB_STR => Ok(DigestFunction::Ed25519Pub),
            SECP_256_K1_PUB_STR => Ok(DigestFunction::Secp256k1Pub),
            BLS12_381_G1_PUB => Ok(DigestFunction::Bls12381G1Pub),
            BLS12_381_G2_PUB => Ok(DigestFunction::Bls12381G2Pub),
            _ => Err(Self::Err {}),
        }
    }
}

impl TryFrom<u64> for DigestFunction {
    type Error = NoSuchAlgorithm;

    fn try_from(variant: u64) -> Result<Self, Self::Error> {
        match variant {
            variant if variant == DigestFunction::Ed25519Pub as u64 => {
                Ok(DigestFunction::Ed25519Pub)
            }
            variant if variant == DigestFunction::Secp256k1Pub as u64 => {
                Ok(DigestFunction::Secp256k1Pub)
            }
            variant if variant == DigestFunction::Bls12381G1Pub as u64 => {
                Ok(DigestFunction::Bls12381G1Pub)
            }
            variant if variant == DigestFunction::Bls12381G2Pub as u64 => {
                Ok(DigestFunction::Bls12381G2Pub)
            }
            _ => Err(Self::Error {}),
        }
    }
}

impl From<DigestFunction> for u64 {
    fn from(digest_function: DigestFunction) -> Self {
        digest_function as u64
    }
}

/// Multihash.
///
/// Offers a middleware representation of [`PublicKey`] which can be converted
/// to/from bytes or string.
#[derive(Debug, PartialEq, Eq)]
pub struct Multihash(PublicKeyInner);

impl TryFrom<Vec<u8>> for Multihash {
    type Error = ParseError;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        let idx = bytes
            .iter()
            .enumerate()
            .find(|&(_, &byte)| (byte & 0b1000_0000) == 0)
            .ok_or_else(|| {
                ParseError(String::from(
                    "Failed to find last byte(byte smaller than 128)",
                ))
            })?
            .0;

        let (digest_function, bytes) = bytes.split_at(idx + 1);
        let mut bytes = bytes.iter().copied();

        let digest_function: u64 = varint::VarUint::new(digest_function)
            .map_err(|err| ParseError(err.to_string()))?
            .try_into()
            .map_err(|err: varint::ConvertError| ParseError(err.to_string()))?;
        let digest_function =
            DigestFunction::try_from(digest_function).map_err(|err| ParseError(err.to_string()))?;
        let algorithm = Algorithm::from(digest_function);

        let digest_size = bytes
            .next()
            .ok_or_else(|| ParseError(String::from("Digest size not found")))?;

        let payload: Vec<u8> = bytes.collect();
        if payload.len() != digest_size as usize {
            return Err(ParseError(String::from(
                "Digest size not equal to actual length",
            )));
        }
        let payload = ConstVec::new(payload);

        Ok(Self::from(*PublicKey::from_bytes(algorithm, &payload)?.0))
    }
}

impl TryFrom<&Multihash> for Vec<u8> {
    type Error = MultihashConvertError;

    fn try_from(multihash: &Multihash) -> Result<Self, Self::Error> {
        let mut bytes = vec![];

        let (algorithm, payload) = multihash.0.to_raw();
        let digest_function: DigestFunction = algorithm.into();
        let digest_function: u64 = digest_function.into();
        let digest_function: varint::VarUint = digest_function.into();
        let mut digest_function = digest_function.into();
        bytes.append(&mut digest_function);
        bytes.push(payload.len().try_into().map_err(|_e| {
            MultihashConvertError::new(String::from("Digest size can't fit into u8"))
        })?);
        bytes.extend_from_slice(payload.as_ref());

        Ok(bytes)
    }
}

impl From<Multihash> for PublicKeyInner {
    #[inline]
    fn from(multihash: Multihash) -> Self {
        multihash.0
    }
}

impl From<PublicKeyInner> for Multihash {
    #[inline]
    fn from(public_key: PublicKeyInner) -> Self {
        Self(public_key)
    }
}

/// Error which occurs when converting to/from `Multihash`
#[derive(Debug, Clone, Display)]
pub struct MultihashConvertError {
    reason: String,
}

impl MultihashConvertError {
    pub(crate) const fn new(reason: String) -> Self {
        Self { reason }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for MultihashConvertError {}

impl From<NoSuchAlgorithm> for MultihashConvertError {
    fn from(source: NoSuchAlgorithm) -> Self {
        Self {
            reason: source.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hex_decode;

    #[test]
    fn multihash_to_bytes() {
        let multihash = Multihash(
            *PublicKey::from_bytes(
                Algorithm::Ed25519,
                &hex_decode("1509A611AD6D97B01D871E58ED00C8FD7C3917B6CA61A8C2833A19E000AAC2E4")
                    .unwrap(),
            )
            .unwrap()
            .0,
        );
        let bytes = Vec::try_from(&multihash).expect("Failed to serialize multihash");
        assert_eq!(
            hex_decode("ed01201509A611AD6D97B01D871E58ED00C8FD7C3917B6CA61A8C2833A19E000AAC2E4")
                .unwrap(),
            bytes
        );
    }

    #[test]
    fn multihash_from_bytes() {
        let multihash = Multihash(
            *PublicKey::from_bytes(
                Algorithm::Ed25519,
                &hex_decode("1509A611AD6D97B01D871E58ED00C8FD7C3917B6CA61A8C2833A19E000AAC2E4")
                    .unwrap(),
            )
            .unwrap()
            .0,
        );
        let bytes =
            hex_decode("ed01201509A611AD6D97B01D871E58ED00C8FD7C3917B6CA61A8C2833A19E000AAC2E4")
                .unwrap();
        let multihash_decoded: Multihash = bytes.try_into().unwrap();
        assert_eq!(multihash, multihash_decoded);
    }

    #[test]
    fn digest_function_display() {
        assert_eq!(DigestFunction::Ed25519Pub.to_string(), ED_25519_PUB_STR);
    }
}
