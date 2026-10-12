//! Canonical section decoding with original local resource refusal preserved.

use crate::error::VMError;
use norito::core::DecodeLimits;

pub(super) fn decode<T>(bytes: &[u8], limits: DecodeLimits) -> Result<T, VMError>
where
    T: norito::NoritoSerialize,
    for<'de> T: norito::NoritoDeserialize<'de>,
{
    norito::decode_canonical_for_admission(bytes, limits).map_err(|error| {
        match error.into_local_refusal() {
            Ok(original) => VMError::DecodeDeferred(original),
            Err(_) => VMError::InvalidMetadata,
        }
    })
}

#[cfg(test)]
mod tests;
