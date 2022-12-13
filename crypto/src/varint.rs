#[cfg(not(feature = "std"))]
use alloc::{format, string::String, vec::Vec};

use derive_more::Display;

/// Variable length unsigned int. [ref](https://github.com/multiformats/unsigned-varint)
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct VarUint {
    /// Contains validated varuint number
    payload: Vec<u8>,
}

/// Error which occurs when converting to/from `VarUint`
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

macro_rules! try_from_var_uint(
    { $( $ty:ty ),* } => {
        $(
            #[allow(trivial_numeric_casts)]
            impl TryFrom<VarUint> for $ty {
                type Error = ConvertError;

                fn try_from(source: VarUint) -> Result<Self, Self::Error> {
                    let VarUint { payload } = source;
                    if core::mem::size_of::<Self>() * 8 < payload.len() * 7 {
                        return Err(Self::Error::new(String::from(
                            concat!("Number too large for ", stringify!($ty))
                        )));
                    }
                    let offsets = (0..payload.len()).map(|i| i * 7);
                    let bytes = payload.into_iter().map(|byte| byte & 0b0111_1111);
                    let number = bytes
                        .zip(offsets)
                        .map(|(byte, offset)| (byte as Self) << offset)
                        .fold(0, |number, part| number + part);
                    Ok(number)
                }
            }
        )*
    }
);

try_from_var_uint!(u8, u16, u32, u64, u128);

impl From<VarUint> for Vec<u8> {
    fn from(int: VarUint) -> Self {
        int.payload
    }
}

impl AsRef<[u8]> for VarUint {
    fn as_ref(&self) -> &[u8] {
        self.payload.as_ref()
    }
}

macro_rules! from_uint(
    { $( $ty:ty ),* } => {
        $(
            #[allow(trivial_numeric_casts)]
            impl From<$ty> for VarUint {
                fn from(n: $ty) -> Self {
                    let zeros = n.leading_zeros();
                    let end = core::mem::size_of::<$ty>() * 8 - zeros as usize;

                    let mut payload = (0..end)
                        .step_by(7)
                        .map(|offset| (((n >> offset) as u8) | 0b1000_0000))
                        .collect::<Vec<_>>();
                    *payload.last_mut().unwrap() &= 0b0111_1111;

                    Self { payload }
                }
            }
        )*
    }
);

from_uint!(u8, u16, u32, u64, u128);

impl VarUint {
    /// Construct `VarUint`.
    pub fn new(bytes: impl AsRef<[u8]>) -> Result<Self, ConvertError> {
        let idx = bytes
            .as_ref()
            .iter()
            .enumerate()
            .find(|&(_, &byte)| (byte & 0b1000_0000) == 0)
            .ok_or_else(|| {
                ConvertError::new(String::from(
                    "Failed to find last byte(byte smaller than 128)",
                ))
            })?
            .0;
        let (payload, empty) = bytes.as_ref().split_at(idx + 1);
        let payload = payload.to_vec();

        if empty.is_empty() {
            return Ok(Self { payload });
        }

        Err(ConvertError::new(format!(
            "{:?}: found these bytes following last byte",
            empty
        )))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::restriction)]

    #[cfg(not(feature = "std"))]
    use alloc::vec;

    use super::*;

    #[test]
    fn test_basic_into() {
        let n = 0x4000_u64;
        let varuint: VarUint = n.into();
        let vec: Vec<_> = varuint.into();
        let should_be = vec![0b1000_0000, 0b1000_0000, 0b0000_0001];
        assert_eq!(vec, should_be);
    }

    #[test]
    fn test_basic_from() {
        let n_should: u64 = VarUint::new([0b1000_0000, 0b1000_0000, 0b0000_0001])
            .unwrap()
            .try_into()
            .unwrap();
        assert_eq!(0x4000_u64, n_should);
    }

    #[test]
    fn test_basic_into_from() {
        let n = 0x4000_u64;
        let varuint: VarUint = n.into();
        let n_new: u64 = varuint.try_into().unwrap();
        assert_eq!(n, n_new);
    }

    #[test]
    fn test_multihash() {
        let n = 0xed;
        let varuint: VarUint = n.into();
        let vec: Vec<_> = varuint.clone().into();
        let n_new: u64 = varuint.try_into().unwrap();
        assert_eq!(n, n_new);
        assert_eq!(vec, vec![0xed, 0x01]);
    }
}
