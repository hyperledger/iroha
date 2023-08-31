//! An implementation of compact container for constant bytes.
#[cfg(not(feature = "std"))]
use alloc::{boxed::Box, format, string::String, vec::Vec};
use core::ops::Deref;
#[cfg(feature = "std")]
use std::{boxed::Box, vec::Vec};

use iroha_schema::IntoSchema;
use parity_scale_codec::{WrapperTypeDecode, WrapperTypeEncode};
use serde::{Deserialize, Serialize};

/// Stores bytes that are not supposed to change during the runtime of the program in a compact way
///
/// This is a more efficient than `Vec<u8>` because it does not have to store the capacity field
///
/// It does not do reference-counting, so cloning is not cheap
#[derive(
    Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Default, Serialize, Deserialize, IntoSchema,
)]
#[schema(transparent = "Vec<u8>")]
pub struct ConstBytes(Box<[u8]>);

impl ConstBytes {
    /// Create a new `ConstBytes` from something convertible into a `Box<[u8]>`.
    ///
    /// Using `Vec<u8>` here would take ownership of the data without needing to copy it (if length is the same as capacity).
    pub fn new(bytes: impl Into<Box<[u8]>>) -> Self {
        Self(bytes.into())
    }

    /// Construct a new `ConstBytes` by parsing the given hex string.
    ///
    /// # Errors
    ///
    /// This function returns an error if the passed string is not a valid hex-encoded byte sequence.
    /// (that is, it contains invalid characters or has an odd length).
    pub fn from_hex<T: AsRef<[u8]> + ?Sized>(payload: &T) -> Result<Self, hex::FromHexError> {
        Ok(Self::new(hex::decode(payload)?))
    }

    /// Converts the `ImmutableBytes` into a `Vec<u8>`, reusing the heap allocation.
    pub fn into_vec(self) -> Vec<u8> {
        self.0.into_vec()
    }
}

impl AsRef<[u8]> for ConstBytes {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl Deref for ConstBytes {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<Vec<u8>> for ConstBytes {
    fn from(value: Vec<u8>) -> Self {
        Self::new(value)
    }
}

impl WrapperTypeEncode for ConstBytes {}
impl WrapperTypeDecode for ConstBytes {
    type Wrapped = Vec<u8>;
}

#[cfg(test)]
mod tests {
    use parity_scale_codec::{Decode, Encode};

    use super::ConstBytes;

    #[test]
    fn encoded_repr_is_same_as_vec() {
        let bytes = vec![1u8, 2, 3, 4, 5];
        let encoded = ConstBytes::new(bytes.clone());
        assert_eq!(bytes.encode(), encoded.encode());
    }

    #[test]
    fn encode_decode_round_trip() {
        let bytes = vec![1u8, 2, 3, 4, 5];
        let encoded = ConstBytes::new(bytes.clone());
        let decoded = ConstBytes::decode(&mut encoded.encode().as_slice()).unwrap();
        assert_eq!(bytes, decoded.into_vec());
    }
}
