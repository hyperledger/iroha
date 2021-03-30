use std::{
    convert::{TryFrom, TryInto},
    fmt::Display,
    str::FromStr,
};

use iroha_error::{error, Error, Result};

use super::varint::VarUint;

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
#[repr(u64)]
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum DigestFunction {
    /// Ed25519
    Ed25519Pub = 0xed,
    /// Secp256k1
    Secp256k1Pub = 0xe7,
    /// Bls12381G1
    Bls12381G1Pub = 0xea,
    /// Bls12381G2
    Bls12381G2Pub = 0xeb,
}

impl Default for DigestFunction {
    fn default() -> Self {
        Self::Ed25519Pub
    }
}

impl Display for DigestFunction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DigestFunction::Ed25519Pub => write!(f, "{}", ED_25519_PUB_STR),
            DigestFunction::Secp256k1Pub => write!(f, "{}", SECP_256_K1_PUB_STR),
            DigestFunction::Bls12381G1Pub => write!(f, "{}", BLS12_381_G1_PUB),
            DigestFunction::Bls12381G2Pub => write!(f, "{}", BLS12_381_G2_PUB),
        }
    }
}

impl FromStr for DigestFunction {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            ED_25519_PUB_STR => Ok(DigestFunction::Ed25519Pub),
            SECP_256_K1_PUB_STR => Ok(DigestFunction::Secp256k1Pub),
            BLS12_381_G1_PUB => Ok(DigestFunction::Bls12381G1Pub),
            BLS12_381_G2_PUB => Ok(DigestFunction::Bls12381G2Pub),
            _ => Err(error!("The specified digest function is not supported.",)),
        }
    }
}

impl From<&DigestFunction> for u64 {
    fn from(digest_function: &DigestFunction) -> Self {
        *digest_function as u64
    }
}

impl TryFrom<u64> for DigestFunction {
    type Error = Error;

    fn try_from(variant: u64) -> Result<Self> {
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
            _ => Err(error!("The specified digest function is not supported.",)),
        }
    }
}

/// Multihash
#[derive(Eq, PartialEq, Debug)]
pub struct Multihash {
    /// digest
    pub digest_function: DigestFunction,
    /// hash payload
    pub payload: Vec<u8>,
}

impl Default for Multihash {
    fn default() -> Self {
        Self {
            digest_function: DigestFunction::default(),
            payload: Vec::new(),
        }
    }
}

impl TryFrom<Vec<u8>> for Multihash {
    type Error = Error;
    fn try_from(bytes: Vec<u8>) -> Result<Self> {
        let idx = bytes
            .iter()
            .enumerate()
            .find(|&(_, &byte)| (byte & 0b1000_0000) == 0)
            .ok_or_else(|| error!("Last byte should be less than 128"))?
            .0;
        let (digest_function, bytes) = bytes.split_at(idx + 1);
        let mut bytes = bytes.iter().copied();

        let digest_function: u64 = VarUint::new(digest_function)?.try_into()?;
        let digest_function = digest_function.try_into()?;

        let digest_size = bytes
            .next()
            .ok_or_else(|| error!("Failed to parse digest size."))?;
        let payload: Vec<u8> = bytes.collect();
        if payload.len() == digest_size as usize {
            Ok(Multihash {
                digest_function,
                payload,
            })
        } else {
            Err(error!("The digest size is not equal to the actual length.",))
        }
    }
}

impl TryFrom<&Multihash> for Vec<u8> {
    type Error = Error;

    fn try_from(multihash: &Multihash) -> Result<Self> {
        let mut bytes = Vec::new();
        let digest_function: u64 = (&multihash.digest_function).into();
        let digest_function: VarUint = digest_function.into();
        let mut digest_function: Vec<_> = digest_function.into();
        bytes.append(&mut digest_function);
        bytes.push(multihash.payload.len().try_into()?);
        bytes.extend_from_slice(&multihash.payload);
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
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
}
