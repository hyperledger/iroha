//! Shared fixed-storage SEC1 parsing; only the public adapter formats errors.

use super::PublicKey;
use crate::ParseError;
use k256::elliptic_curve::{Error, sec1::ToEncodedPoint as _};

#[derive(Clone, Copy, Debug)]
pub(crate) enum KeyRejection {
    AllZero,
    Encoding(Error),
    NonCanonical,
}
impl KeyRejection {
    pub(crate) fn into_parse_error(self) -> ParseError {
        match self {
            Self::AllZero => {
                ParseError::Invalid("secp256k1 public key material must not be all zero".to_owned())
            }
            Self::Encoding(error) => ParseError::Invalid(error.to_string()),
            Self::NonCanonical => {
                ParseError::Invalid("non-canonical secp256k1 public key encoding".to_owned())
            }
        }
    }
}

pub(crate) fn parse(payload: &[u8]) -> Result<PublicKey, KeyRejection> {
    if !payload.is_empty() && payload.iter().all(|&byte| byte == 0) {
        return Err(KeyRejection::AllZero);
    }
    let key = PublicKey::from_sec1_bytes(payload).map_err(KeyRejection::Encoding)?;
    // EncodedPoint keeps canonical compressed SEC1 bytes inline.
    if key.to_encoded_point(true).as_bytes() != payload {
        return Err(KeyRejection::NonCanonical);
    }
    Ok(key)
}
