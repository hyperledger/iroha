use std::{
    convert::{TryFrom, TryInto},
    fmt::Display,
    num::TryFromIntError,
    str::FromStr,
};

pub const ED_25519_PUB_STR: &str = "ed25519-pub";
pub const SECP_256_K1_PUB_STR: &str = "secp256k1-pub";
pub const BLS12_381_G1_PUB: &str = "bls12_381-g1-pub";
pub const BLS12_381_G2_PUB: &str = "bls12_381-g2-pub";

/// Type of digest function.
/// The corresponding byte codes are taken from [official multihash table](https://github.com/multiformats/multicodec/blob/master/table.csv)
#[repr(u8)]
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum DigestFunction {
    Ed25519Pub = 0xed,
    Secp256k1Pub = 0xe7,
    Bls12381G1Pub = 0xea,
    Bls12381G2Pub = 0xeb,
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
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            ED_25519_PUB_STR => Ok(DigestFunction::Ed25519Pub),
            SECP_256_K1_PUB_STR => Ok(DigestFunction::Secp256k1Pub),
            BLS12_381_G1_PUB => Ok(DigestFunction::Bls12381G1Pub),
            BLS12_381_G2_PUB => Ok(DigestFunction::Bls12381G2Pub),
            _ => Err("The specified digest function is not supported.".to_string()),
        }
    }
}

impl From<&DigestFunction> for u8 {
    fn from(digest_function: &DigestFunction) -> Self {
        *digest_function as u8
    }
}

impl TryFrom<u8> for DigestFunction {
    type Error = String;

    fn try_from(byte: u8) -> Result<Self, Self::Error> {
        match byte {
            byte if byte == DigestFunction::Ed25519Pub as u8 => Ok(DigestFunction::Ed25519Pub),
            byte if byte == DigestFunction::Secp256k1Pub as u8 => Ok(DigestFunction::Secp256k1Pub),
            byte if byte == DigestFunction::Bls12381G1Pub as u8 => {
                Ok(DigestFunction::Bls12381G1Pub)
            }
            byte if byte == DigestFunction::Bls12381G2Pub as u8 => {
                Ok(DigestFunction::Bls12381G2Pub)
            }
            _ => Err("The specified digest function is not supported.".to_string()),
        }
    }
}

#[derive(Eq, PartialEq, Debug)]
pub struct Multihash {
    pub digest_function: DigestFunction,
    pub payload: Vec<u8>,
}

impl TryFrom<Vec<u8>> for Multihash {
    type Error = String;
    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        let mut bytes = bytes.into_iter();
        let digest_function: DigestFunction = bytes
            .next()
            .ok_or_else(|| "Failed to parse digest function.".to_string())?
            .try_into()?;
        let digest_size = bytes
            .next()
            .ok_or_else(|| "Failed to parse digest size.".to_string())?;
        let payload: Vec<u8> = bytes.collect();
        if payload.len() == digest_size as usize {
            Ok(Multihash {
                digest_function,
                payload,
            })
        } else {
            Err("The digest size is not equal to the actual length.".to_string())
        }
    }
}

impl TryFrom<&Multihash> for Vec<u8> {
    type Error = String;

    fn try_from(multihash: &Multihash) -> Result<Self, Self::Error> {
        let mut bytes = Vec::new();
        bytes.push((&multihash.digest_function).into());
        bytes.push(
            multihash
                .payload
                .len()
                .try_into()
                .map_err(|err: TryFromIntError| err.to_string())?,
        );
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
            hex::decode("ed201509a611ad6d97b01d871e58ed00c8fd7c3917b6ca61a8c2833a19e000aac2e4")
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
            hex::decode("ed201509a611ad6d97b01d871e58ed00c8fd7c3917b6ca61a8c2833a19e000aac2e4")
                .expect("Failed to decode");
        let multihash_decoded: Multihash = bytes.try_into().expect("Failed to decode.");
        assert_eq!(multihash, multihash_decoded)
    }
}
