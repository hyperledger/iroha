#[cfg(not(feature = "std"))]
use alloc::{borrow::ToOwned as _, format, string::String, vec, vec::Vec};
use core::{hash, marker::PhantomData, num::NonZeroU8, str::FromStr};

#[cfg(not(feature = "ffi_import"))]
use blake2::{
    digest::{Update, VariableOutput},
    Blake2bVar,
};
use derive_more::{DebugCustom, Deref, DerefMut, Display};
use iroha_schema::{IntoSchema, TypeId};
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};
use serde_with::DeserializeFromStr;

use crate::{hex_decode, ParseError};

/// Hash of Iroha entities. Currently supports only blake2b-32.
/// The least significant bit of hash is set to 1.
#[derive(
    DebugCustom,
    Display,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    DeserializeFromStr,
    TypeId,
)]
#[display(fmt = "{}", "hex::encode(self.as_ref())")]
#[debug(fmt = "{}", "hex::encode(self.as_ref())")]
// NOTE: Invariants are maintained in `FromStr`
#[allow(clippy::unsafe_derive_deserialize)]
#[repr(C)]
pub struct Hash {
    more_significant_bits: [u8; Self::LENGTH - 1],
    least_significant_byte: NonZeroU8,
}

impl Hash {
    /// Length of hash
    pub const LENGTH: usize = 32;

    /// Wrap the given bytes; they must be prehashed with `Blake2bVar`
    pub fn prehashed(mut hash: [u8; Self::LENGTH]) -> Self {
        hash[Self::LENGTH - 1] |= 1;
        // SAFETY:
        // - any `u8` value after bitwise or with 1 will be at least 1
        // - `Hash` and `[u8; Hash::LENGTH]` have the same memory layout
        #[allow(unsafe_code)]
        unsafe {
            core::mem::transmute(hash)
        }
    }

    /// Check if least significant bit of `[u8; Hash::LENGTH]` is 1
    fn is_lsb_1(hash: &[u8; Self::LENGTH]) -> bool {
        hash[Self::LENGTH - 1] & 1 == 1
    }
}

impl Hash {
    /// Hash the given bytes.
    #[must_use]
    pub fn new(bytes: impl AsRef<[u8]>) -> Self {
        let vec_hash = Blake2bVar::new(Self::LENGTH)
            .expect("Failed to initialize variable size hash")
            .chain(bytes)
            .finalize_boxed();

        let mut hash = [0; Self::LENGTH];
        hash.copy_from_slice(&vec_hash);

        Hash::prehashed(hash)
    }
}

impl From<Hash> for [u8; Hash::LENGTH] {
    #[inline]
    fn from(hash: Hash) -> Self {
        #[allow(unsafe_code)]
        // SAFETY: `Hash` and `[u8; Hash::LENGTH]` have the same memory layout
        unsafe {
            core::mem::transmute(hash)
        }
    }
}

impl AsRef<[u8; Hash::LENGTH]> for Hash {
    #[inline]
    fn as_ref(&self) -> &[u8; Hash::LENGTH] {
        #[allow(unsafe_code, trivial_casts)]
        // SAFETY: `Hash` and `[u8; Hash::LENGTH]` have the same memory layout
        unsafe {
            &*(core::ptr::from_ref(self).cast::<[u8; Self::LENGTH]>())
        }
    }
}

impl Serialize for Hash {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let hash: &[u8; Self::LENGTH] = self.as_ref();
        hex::encode_upper(hash).serialize(serializer)
    }
}

impl Encode for Hash {
    #[inline]
    fn size_hint(&self) -> usize {
        self.as_ref().size_hint()
    }

    #[inline]
    fn encode_to<T: parity_scale_codec::Output + ?Sized>(&self, dest: &mut T) {
        self.as_ref().encode_to(dest);
    }

    #[inline]
    fn encode(&self) -> Vec<u8> {
        self.as_ref().encode()
    }

    #[inline]
    fn using_encoded<R, F: FnOnce(&[u8]) -> R>(&self, f: F) -> R {
        f(self.as_ref())
    }

    #[inline]
    fn encoded_size(&self) -> usize {
        self.as_ref().encoded_size()
    }
}

impl FromStr for Hash {
    type Err = ParseError;

    fn from_str(key: &str) -> Result<Self, Self::Err> {
        let hash: [u8; Self::LENGTH] = hex_decode(key)?.try_into().map_err(|hash_vec| {
            ParseError(format!(
                "Unable to parse {hash_vec:?} as [u8; {}]",
                Self::LENGTH
            ))
        })?;

        Hash::is_lsb_1(&hash)
            .then_some(hash)
            .ok_or_else(|| ParseError("expect least significant bit of hash to be 1".to_owned()))
            .map(Self::prehashed)
    }
}

impl Decode for Hash {
    fn decode<I: parity_scale_codec::Input>(
        input: &mut I,
    ) -> Result<Self, parity_scale_codec::Error> {
        <[u8; Self::LENGTH]>::decode(input)
            .and_then(|hash| {
                Hash::is_lsb_1(&hash)
                    .then_some(hash)
                    .ok_or_else(|| "expect least significant bit of hash to be 1".into())
            })
            .map(Self::prehashed)
    }
}

impl IntoSchema for Hash {
    fn type_name() -> String {
        "Hash".to_owned()
    }
    fn update_schema_map(map: &mut iroha_schema::MetaMap) {
        if !map.contains_key::<Self>() {
            <[u8; Self::LENGTH]>::update_schema_map(map);

            map.insert::<Self>(iroha_schema::Metadata::Tuple(
                iroha_schema::UnnamedFieldsMeta {
                    types: vec![core::any::TypeId::of::<[u8; Self::LENGTH]>()],
                },
            ));
        }
    }
}

impl<T> From<HashOf<T>> for Hash {
    fn from(HashOf(hash, _): HashOf<T>) -> Self {
        hash
    }
}

crate::ffi::ffi_item! {
    /// Represents hash of Iroha entities like `Block` or `Transaction`. Currently supports only blake2b-32.
    #[derive(DebugCustom, Display, Deref, DerefMut, Decode, Encode, Deserialize, Serialize, TypeId)]
    #[debug(fmt = "{{ {} {_0} }}", "core::any::type_name::<Self>()")]
    #[display(fmt = "{_0}")]
    #[serde(transparent)]
    #[repr(transparent)]
    pub struct HashOf<T>(
        #[deref]
        #[deref_mut]
        Hash,
        #[codec(skip)] PhantomData<T>,
    );

    // SAFETY: `HashOf` has no trap representation in `Hash`
    ffi_type(unsafe {robust})
}

impl<T> Clone for HashOf<T> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<T> Copy for HashOf<T> {}

#[allow(clippy::unconditional_recursion)] // False-positive
impl<T> PartialEq for HashOf<T> {
    fn eq(&self, other: &Self) -> bool {
        self.0.eq(&other.0)
    }
}
impl<T> Eq for HashOf<T> {}

impl<T> PartialOrd for HashOf<T> {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl<T> Ord for HashOf<T> {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.0.cmp(&other.0)
    }
}

impl<T> hash::Hash for HashOf<T> {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

impl<T> AsRef<[u8; Hash::LENGTH]> for HashOf<T> {
    fn as_ref(&self) -> &[u8; Hash::LENGTH] {
        self.0.as_ref()
    }
}

impl<T> HashOf<T> {
    /// Transmutes hash to some specific type.
    /// Don't use this method if not required.
    #[inline]
    #[must_use]
    pub(crate) const fn transmute<F>(self) -> HashOf<F> {
        HashOf(self.0, PhantomData)
    }

    /// Adds type information to the hash. Be careful about using this function
    /// since it is not possible to validate the correctness of the conversion.
    /// Prefer creating new hashes with [`HashOf::new`] whenever possible
    #[must_use]
    pub const fn from_untyped_unchecked(hash: Hash) -> Self {
        HashOf(hash, PhantomData)
    }
}

impl<T: Encode> HashOf<T> {
    /// Construct typed hash
    #[must_use]
    pub fn new(value: &T) -> Self {
        Self(Hash::new(value.encode()), PhantomData)
    }
}

impl<T> FromStr for HashOf<T> {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.parse::<Hash>().map(Self::from_untyped_unchecked)
    }
}

impl<T: IntoSchema> IntoSchema for HashOf<T> {
    fn type_name() -> String {
        format!("HashOf<{}>", T::type_name())
    }
    fn update_schema_map(map: &mut iroha_schema::MetaMap) {
        if !map.contains_key::<Self>() {
            Hash::update_schema_map(map);

            map.insert::<Self>(iroha_schema::Metadata::Tuple(
                iroha_schema::UnnamedFieldsMeta {
                    types: vec![core::any::TypeId::of::<Hash>()],
                },
            ));
        }
    }
}

#[cfg(any(feature = "ffi_export", feature = "ffi_import"))]
mod ffi {
    //! Manual implementations of FFI related functionality

    use super::*;

    // NOTE: Hash is FFI serialized as an array (a pointer in a function call, by value when part of a struct)
    iroha_ffi::ffi_type! {
        unsafe impl Transparent for Hash {
            type Target = [u8; Hash::LENGTH];

            validation_fn=unsafe {Hash::is_lsb_1},
            niche_value = [0; Hash::LENGTH]
        }
    }

    impl iroha_ffi::WrapperTypeOf<Hash> for [u8; Hash::LENGTH] {
        type Type = Hash;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blake2_32b() {
        let mut hasher = Blake2bVar::new(32).unwrap();
        hasher.update(&hex_literal::hex!("6920616d2064617461"));
        assert_eq!(
            hasher.finalize_boxed().as_ref(),
            &hex_literal::hex!("BA67336EFD6A3DF3A70EEB757860763036785C182FF4CF587541A0068D09F5B2")
                [..]
        );
    }
}
