//! Module with multihash implementation

#[cfg(not(feature = "std"))]
use alloc::{
    string::{String, ToString as _},
    vec,
    vec::Vec,
};

use derive_more::Display;

use crate::{varint, NoSuchAlgorithm};

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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Display)]
pub enum DigestFunction {
    /// Ed25519
    #[display(fmt = "{}", "ED_25519_PUB_STR")]
    Ed25519Pub = 0xed,
    /// Secp256k1
    #[display(fmt = "{}", "SECP_256_K1_PUB_STR")]
    Secp256k1Pub = 0xe7,
    /// Bls12381G1
    #[display(fmt = "{}", "BLS12_381_G1_PUB")]
    Bls12381G1Pub = 0xea,
    /// Bls12381G2
    #[display(fmt = "{}", "BLS12_381_G2_PUB")]
    Bls12381G2Pub = 0xeb,
}

impl Default for DigestFunction {
    fn default() -> Self {
        Self::Ed25519Pub
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

/// Error which occurs when converting to/from `Multihash`
#[derive(Debug, Clone, Display)]
pub struct ConvertError {
    reason: String,
}

impl ConvertError {
    const fn new(reason: String) -> Self {
        Self { reason }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ConvertError {}

impl From<NoSuchAlgorithm> for ConvertError {
    fn from(_: NoSuchAlgorithm) -> Self {
        Self {
            reason: String::from("Digest function not supported"),
        }
    }
}

/// Multihash
#[derive(Debug, PartialEq, Eq)]
pub struct Multihash {
    /// digest
    pub digest_function: DigestFunction,
    /// hash payload
    pub payload: Vec<u8>,
}

impl TryFrom<Vec<u8>> for Multihash {
    type Error = ConvertError;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        let idx = bytes
            .iter()
            .enumerate()
            .find(|&(_, &byte)| (byte & 0b1000_0000) == 0)
            .ok_or_else(|| {
                Self::Error::new(String::from(
                    "Failed to find last byte(byte smaller than 128)",
                ))
            })?
            .0;

        let (digest_function, bytes) = bytes.split_at(idx + 1);
        let mut bytes = bytes.iter().copied();

        let digest_function: u64 = varint::VarUint::new(digest_function)
            .map_err(|err| Self::Error::new(err.to_string()))?
            .try_into()
            .map_err(|err: varint::ConvertError| Self::Error::new(err.to_string()))?;
        let digest_function = digest_function.try_into()?;

        let digest_size = bytes
            .next()
            .ok_or_else(|| Self::Error::new(String::from("Digest size not found")))?;

        let payload: Vec<u8> = bytes.collect();
        if payload.len() != digest_size as usize {
            return Err(Self::Error::new(String::from(
                "Digest size not equal to actual length",
            )));
        }

        Ok(Self {
            digest_function,
            payload,
        })
    }
}

impl TryFrom<&Multihash> for Vec<u8> {
    type Error = ConvertError;

    fn try_from(multihash: &Multihash) -> Result<Self, Self::Error> {
        let mut bytes = vec![];

        let digest_function: u64 = multihash.digest_function.into();
        let digest_function: varint::VarUint = digest_function.into();
        let mut digest_function = digest_function.into();
        bytes.append(&mut digest_function);
        bytes.push(
            multihash
                .payload
                .len()
                .try_into()
                .map_err(|_e| ConvertError::new(String::from("Digest size can't fit into u8")))?,
        );
        bytes.extend_from_slice(&multihash.payload);

        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::restriction)]

    use super::*;

    #[test]
    fn multihash_to_bytes() {
        let multihash = &Multihash {
            digest_function: DigestFunction::Ed25519Pub,
            payload: hex::decode(
                "1509a611ad6d97b01d871e58ed00c8fd7c3917b6ca61a8c2833a19e000aac2e4",
            )
            .expect("Failed to decode hex."),
        };
        let bytes: Vec<u8> = multihash.try_into().expect("Failed to serialize multihash");
        assert_eq!(
            hex::decode("ed01201509a611ad6d97b01d871e58ed00c8fd7c3917b6ca61a8c2833a19e000aac2e4")
                .expect("Failed to decode"),
            bytes
        )
    }

    #[test]
    fn multihash_from_bytes() {
        let multihash = Multihash {
            digest_function: DigestFunction::Ed25519Pub,
            payload: hex::decode(
                "1509a611ad6d97b01d871e58ed00c8fd7c3917b6ca61a8c2833a19e000aac2e4",
            )
            .expect("Failed to decode hex."),
        };
        let bytes =
            hex::decode("ed01201509a611ad6d97b01d871e58ed00c8fd7c3917b6ca61a8c2833a19e000aac2e4")
                .expect("Failed to decode");
        let multihash_decoded: Multihash = bytes.try_into().expect("Failed to decode.");
        assert_eq!(multihash, multihash_decoded)
    }

    #[test]
    fn digest_function_display() {
        assert_eq!(DigestFunction::Ed25519Pub.to_string(), ED_25519_PUB_STR);
    }
}
