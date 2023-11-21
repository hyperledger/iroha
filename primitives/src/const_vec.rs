//! An implementation of compact container for constant bytes.
#[cfg(not(feature = "std"))]
use alloc::{boxed::Box, format, string::String, vec::Vec};
use core::ops::Deref;
#[cfg(feature = "std")]
use std::{boxed::Box, vec::Vec};

use iroha_schema::{IntoSchema, MetaMap, Metadata, TypeId, VecMeta};
use parity_scale_codec::{WrapperTypeDecode, WrapperTypeEncode};
use serde::{Deserialize, Serialize};

use crate::ffi;

ffi::ffi_item! {
    /// Stores bytes that are not supposed to change during the runtime of the program in a compact way
    ///
    /// This is a more efficient than `Vec<u8>` because it does not have to store the capacity field
    ///
    /// It does not do reference-counting, so cloning is not cheap
    #[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Default, Serialize, Deserialize)]
    #[repr(transparent)]
    pub struct ConstVec<T>(Box<[T]>);

    // SAFETY: `ConstVec` has no trap representation in ConstVec
    ffi_type(unsafe {robust})
}

impl<T> ConstVec<T> {
    /// Create a new `ConstVec` from something convertible into a `Box<[T]>`.
    ///
    /// Using `Vec<T>` here would take ownership of the data without needing to copy it (if length is the same as capacity).
    #[inline]
    pub fn new(content: impl Into<Box<[T]>>) -> Self {
        Self(content.into())
    }

    /// Creates an empty `ConstVec`. This operation does not allocate any memory.
    #[inline]
    pub fn new_empty() -> Self {
        Self(Vec::new().into())
    }

    /// Converts the `ConstVec` into a `Vec<T>`, reusing the heap allocation.
    #[inline]
    pub fn into_vec(self) -> Vec<T> {
        self.0.into_vec()
    }
}

impl<T> AsRef<[T]> for ConstVec<T> {
    fn as_ref(&self) -> &[T] {
        self.0.as_ref()
    }
}

impl<T> Deref for ConstVec<T> {
    type Target = [T];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> From<Vec<T>> for ConstVec<T> {
    fn from(value: Vec<T>) -> Self {
        Self::new(value)
    }
}

impl<T> WrapperTypeEncode for ConstVec<T> {}
impl<T> WrapperTypeDecode for ConstVec<T> {
    type Wrapped = Vec<T>;
}

impl<T: TypeId> TypeId for ConstVec<T> {
    fn id() -> String {
        format!("ConstVec<{}>", T::id())
    }
}
impl<T: IntoSchema> IntoSchema for ConstVec<T> {
    fn type_name() -> String {
        format!("Vec<{}>", T::type_name())
    }
    fn update_schema_map(map: &mut MetaMap) {
        if !map.contains_key::<Self>() {
            map.insert::<Self>(Metadata::Vec(VecMeta {
                ty: core::any::TypeId::of::<T>(),
            }));

            T::update_schema_map(map);
        }
    }
}

#[cfg(test)]
mod tests {
    use parity_scale_codec::{Decode, Encode};

    use super::ConstVec;

    #[test]
    fn encoded_repr_is_same_as_vec() {
        let bytes = vec![1u8, 2, 3, 4, 5];
        let encoded = ConstVec::<u8>::new(bytes.clone());
        assert_eq!(bytes.encode(), encoded.encode());
    }

    #[test]
    fn encode_decode_round_trip() {
        let bytes = vec![1u8, 2, 3, 4, 5];
        let encoded = ConstVec::<u8>::new(bytes.clone());
        let decoded = ConstVec::<u8>::decode(&mut encoded.encode().as_slice()).unwrap();
        assert_eq!(bytes, decoded.into_vec());
    }
}
