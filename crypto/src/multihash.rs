//! Module with multihash implementation

#[cfg(not(feature = "std"))]
use alloc::{
    format,
    string::{String, ToString as _},
    vec,
    vec::Vec,
};

use derive_more::Display;

use crate::{varint, Algorithm, ParseError};

pub fn decode_public_key(bytes: &[u8]) -> Result<(Algorithm, Vec<u8>), ParseError> {
    let (digest_function, payload) = decode_multihash(bytes)?;
    let algorithm = digest_function_public::decode(digest_function)?;
    Ok((algorithm, payload))
}

pub fn encode_public_key(
    algorithm: Algorithm,
    payload: &[u8],
) -> Result<Vec<u8>, MultihashConvertError> {
    let digest_function = digest_function_public::encode(algorithm);
    encode_multihash(digest_function, payload)
}

pub fn decode_private_key(bytes: &[u8]) -> Result<(Algorithm, Vec<u8>), ParseError> {
    let (digest_function, payload) = decode_multihash(bytes)?;
    let algorithm = digest_function_private::decode(digest_function)?;
    Ok((algorithm, payload))
}

pub fn encode_private_key(
    algorithm: Algorithm,
    payload: &[u8],
) -> Result<Vec<u8>, MultihashConvertError> {
    let digest_function = digest_function_private::encode(algorithm);
    encode_multihash(digest_function, payload)
}

pub fn multihash_to_hex_string(bytes: &[u8]) -> String {
    let mut bytes_iter = bytes.iter().copied();
    let fn_code = hex::encode(bytes_iter.by_ref().take(2).collect::<Vec<_>>());
    let dig_size = hex::encode(bytes_iter.by_ref().take(1).collect::<Vec<_>>());
    let key = hex::encode_upper(bytes_iter.by_ref().collect::<Vec<_>>());

    format!("{fn_code}{dig_size}{key}")
}

/// Value of byte code corresponding to algorithm.
/// See [official multihash table](https://github.com/multiformats/multicodec/blob/master/table.csv)
type DigestFunction = u64;

mod digest_function_public {
    #[cfg(not(feature = "std"))]
    use alloc::string::String;

    use crate::{error::ParseError, multihash::DigestFunction, Algorithm};

    const ED_25519: DigestFunction = 0xed;
    const SECP_256_K1: DigestFunction = 0xe7;
    const BLS12_381_G1: DigestFunction = 0xea;
    const BLS12_381_G2: DigestFunction = 0xeb;

    pub fn decode(digest_function: DigestFunction) -> Result<Algorithm, ParseError> {
        let algorithm = match digest_function {
            ED_25519 => Algorithm::Ed25519,
            SECP_256_K1 => Algorithm::Secp256k1,
            BLS12_381_G1 => Algorithm::BlsNormal,
            BLS12_381_G2 => Algorithm::BlsSmall,
            _ => return Err(ParseError(String::from("No such algorithm"))),
        };
        Ok(algorithm)
    }

    pub fn encode(algorithm: Algorithm) -> u64 {
        match algorithm {
            Algorithm::Ed25519 => ED_25519,
            Algorithm::Secp256k1 => SECP_256_K1,
            Algorithm::BlsNormal => BLS12_381_G1,
            Algorithm::BlsSmall => BLS12_381_G2,
        }
    }
}

mod digest_function_private {
    #[cfg(not(feature = "std"))]
    use alloc::string::String;

    use crate::{error::ParseError, multihash::DigestFunction, Algorithm};

    const ED_25519: DigestFunction = 0x1300;
    const SECP_256_K1: DigestFunction = 0x1301;
    const BLS12_381_G1: DigestFunction = 0x1309;
    const BLS12_381_G2: DigestFunction = 0x130a;

    pub fn decode(digest_function: DigestFunction) -> Result<Algorithm, ParseError> {
        let algorithm = match digest_function {
            ED_25519 => Algorithm::Ed25519,
            SECP_256_K1 => Algorithm::Secp256k1,
            BLS12_381_G1 => Algorithm::BlsNormal,
            BLS12_381_G2 => Algorithm::BlsSmall,
            _ => return Err(ParseError(String::from("No such algorithm"))),
        };
        Ok(algorithm)
    }

    pub fn encode(algorithm: Algorithm) -> u64 {
        match algorithm {
            Algorithm::Ed25519 => ED_25519,
            Algorithm::Secp256k1 => SECP_256_K1,
            Algorithm::BlsNormal => BLS12_381_G1,
            Algorithm::BlsSmall => BLS12_381_G2,
        }
    }
}

fn decode_multihash(bytes: &[u8]) -> Result<(DigestFunction, Vec<u8>), ParseError> {
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

    let digest_size = bytes
        .next()
        .ok_or_else(|| ParseError(String::from("Digest size not found")))?;

    let payload: Vec<u8> = bytes.collect();
    if payload.len() != digest_size as usize {
        return Err(ParseError(String::from(
            "Digest size not equal to actual length",
        )));
    }
    Ok((digest_function, payload))
}

fn encode_multihash(
    digest_function: DigestFunction,
    payload: &[u8],
) -> Result<Vec<u8>, MultihashConvertError> {
    let mut bytes = vec![];

    let digest_function: varint::VarUint = digest_function.into();
    let mut digest_function = digest_function.into();
    bytes.append(&mut digest_function);
    bytes.push(
        payload.len().try_into().map_err(|_e| {
            MultihashConvertError::new(String::from("Digest size can't fit into u8"))
        })?,
    );
    bytes.extend_from_slice(payload.as_ref());
    Ok(bytes)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hex_decode;

    #[test]
    fn test_encode_public_key() {
        let algorithm = Algorithm::Ed25519;
        let payload =
            hex_decode("1509A611AD6D97B01D871E58ED00C8FD7C3917B6CA61A8C2833A19E000AAC2E4").unwrap();
        let multihash =
            hex_decode("ed01201509A611AD6D97B01D871E58ED00C8FD7C3917B6CA61A8C2833A19E000AAC2E4")
                .unwrap();
        assert_eq!(encode_public_key(algorithm, &payload).unwrap(), multihash);
    }

    #[test]
    fn test_decode_public_key() {
        let algorithm = Algorithm::Ed25519;
        let payload =
            hex_decode("1509A611AD6D97B01D871E58ED00C8FD7C3917B6CA61A8C2833A19E000AAC2E4").unwrap();
        let multihash =
            hex_decode("ed01201509A611AD6D97B01D871E58ED00C8FD7C3917B6CA61A8C2833A19E000AAC2E4")
                .unwrap();
        assert_eq!(decode_public_key(&multihash).unwrap(), (algorithm, payload));
    }

    #[test]
    fn test_encode_private_key() {
        let algorithm = Algorithm::Ed25519;
        let payload =
            hex_decode("8F4C15E5D664DA3F13778801D23D4E89B76E94C1B94B389544168B6CB894F84F8BA62848CF767D72E7F7F4B9D2D7BA07FEE33760F79ABE5597A51520E292A0CB").unwrap();
        let multihash =
            hex_decode("8026408F4C15E5D664DA3F13778801D23D4E89B76E94C1B94B389544168B6CB894F84F8BA62848CF767D72E7F7F4B9D2D7BA07FEE33760F79ABE5597A51520E292A0CB")
                .unwrap();
        assert_eq!(encode_private_key(algorithm, &payload).unwrap(), multihash);
    }

    #[test]
    fn test_decode_private_key() {
        let algorithm = Algorithm::Ed25519;
        let payload =
            hex_decode("8F4C15E5D664DA3F13778801D23D4E89B76E94C1B94B389544168B6CB894F84F8BA62848CF767D72E7F7F4B9D2D7BA07FEE33760F79ABE5597A51520E292A0CB").unwrap();
        let multihash =
            hex_decode("8026408F4C15E5D664DA3F13778801D23D4E89B76E94C1B94B389544168B6CB894F84F8BA62848CF767D72E7F7F4B9D2D7BA07FEE33760F79ABE5597A51520E292A0CB")
                .unwrap();
        assert_eq!(
            decode_private_key(&multihash).unwrap(),
            (algorithm, payload)
        );
    }
}
