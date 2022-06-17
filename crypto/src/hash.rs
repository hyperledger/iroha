#[cfg(not(feature = "std"))]
use alloc::{format, string::String, vec, vec::Vec};
use core::{hash, marker::PhantomData};

use derive_more::{DebugCustom, Deref, DerefMut, Display};
use iroha_schema::prelude::*;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};
#[cfg(feature = "std")]
use ursa::blake2::{
    digest::{Update, VariableOutput},
    VarBlake2b,
};

/// Hash of Iroha entities. Currently supports only blake2b-32.
#[derive(
    Clone,
    Copy,
    Display,
    DebugCustom,
    Hash,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Decode,
    Encode,
    Deserialize,
    Serialize,
    IntoSchema,
)]
#[display(fmt = "{}", "hex::encode(_0)")]
#[debug(fmt = "{{ Hash({}) }}", "hex::encode(_0)")]
pub struct Hash<const LENGTH: usize>(#[serde(with = "serde_arrays")] [u8; LENGTH]);

impl<const LENGTH: usize> Hash<LENGTH> {
    /// Length of hash
    // pub const LENGTH: usize = 32;

    /// Wrap the given bytes; they must be prehashed with `VarBlake2b`
    pub const fn prehashed(bytes: [u8; LENGTH]) -> Self {
        Self(bytes)
    }

    /// Construct zeroed hash
    #[must_use]
    // TODO: It would be best if all uses of zeroed hash could be replaced with Option<Hash>
    pub const fn zeroed() -> Self {
        Hash::prehashed([0; LENGTH])
    }

    /// Hash the given bytes.
    #[cfg(feature = "std")]
    #[allow(clippy::expect_used)]
    #[must_use]
    pub fn new(bytes: impl AsRef<[u8]>) -> Self {
        let vec_hash = VarBlake2b::new(LENGTH)
            .expect("Failed to initialize variable size hash")
            .chain(bytes)
            .finalize_boxed();
        let mut hash = [0; LENGTH];
        hash.copy_from_slice(&vec_hash);
        Hash::prehashed(hash)
    }

    /// Adds type information to the hash. Be careful about using this function
    /// since it is not possible to validate the correctness of the conversion.
    /// Prefer creating new hashes with [`HashOf::new`] whenever possible
    #[must_use]
    pub const fn typed<T>(self) -> HashOf<T, LENGTH> {
        HashOf(self, PhantomData)
    }
}

impl<const LENGTH: usize> From<Hash<LENGTH>> for [u8; LENGTH] {
    #[inline]
    fn from(Hash(bytes): Hash<LENGTH>) -> Self {
        bytes
    }
}

impl<const LENGTH: usize> AsRef<[u8; LENGTH]> for Hash<LENGTH> {
    #[inline]
    fn as_ref(&self) -> &[u8; LENGTH] {
        &self.0
    }
}

impl<T, const LENGTH: usize> From<HashOf<T, LENGTH>> for Hash<LENGTH> {
    fn from(HashOf(hash, _): HashOf<T, LENGTH>) -> Self {
        hash
    }
}

/// Represents hash of Iroha entities like `Block` or `Transaction`. Currently supports only
/// blake2b-32.
// Lint triggers when expanding #[codec(skip)]
#[allow(clippy::default_trait_access)]
#[derive(DebugCustom, Deref, DerefMut, Display, Decode, Encode, Deserialize, Serialize)]
#[display(fmt = "{}", _0)]
#[debug(fmt = "{{ {} {_0} }}", "core::any::type_name::<Self>()")]
#[serde(transparent)]
pub struct HashOf<T, const LENGTH: usize>(
    #[deref]
    #[deref_mut]
    Hash<LENGTH>,
    #[codec(skip)] PhantomData<T>,
);

impl<T, const LENGTH: usize> Clone for HashOf<T, LENGTH> {
    fn clone(&self) -> Self {
        Self(self.0, PhantomData)
    }
}
impl<T, const LENGTH: usize> Copy for HashOf<T, LENGTH> {}

impl<T, const LENGTH: usize> PartialEq for HashOf<T, LENGTH> {
    fn eq(&self, other: &Self) -> bool {
        self.0.eq(&other.0)
    }
}
impl<T, const LENGTH: usize> Eq for HashOf<T, LENGTH> {}

impl<T, const LENGTH: usize> PartialOrd for HashOf<T, LENGTH> {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        self.0.partial_cmp(&other.0)
    }
}
impl<T, const LENGTH: usize> Ord for HashOf<T, LENGTH> {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.0.cmp(&other.0)
    }
}

impl<T, const LENGTH: usize> hash::Hash for HashOf<T, LENGTH> {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.0.hash(state)
    }
}

impl<T, const LENGTH: usize> AsRef<[u8; LENGTH]> for HashOf<T, LENGTH> {
    fn as_ref(&self) -> &[u8; LENGTH] {
        self.0.as_ref()
    }
}

impl<T, const LENGTH: usize> HashOf<T, LENGTH> {
    /// Transmutes hash to some specific type.
    /// Don't use this method if not required.
    #[inline]
    #[must_use]
    pub const fn transmute<F>(self) -> HashOf<F, LENGTH> {
        HashOf(self.0, PhantomData)
    }
}

impl<T: Encode, const LENGTH: usize> HashOf<T, LENGTH> {
    /// Construct typed hash
    #[cfg(feature = "std")]
    #[must_use]
    pub fn new(value: &T) -> Self {
        Self(Hash::new(value.encode()), PhantomData)
    }
}

impl<T: IntoSchema, const LENGTH: usize> IntoSchema for HashOf<T, LENGTH> {
    fn type_name() -> String {
        format!("{}::HashOf<{}>", module_path!(), T::type_name())
    }
    fn schema(map: &mut MetaMap) {
        Hash::<LENGTH>::schema(map);

        map.entry(Self::type_name()).or_insert_with(|| {
            Metadata::Tuple(UnnamedFieldsMeta {
                types: vec![Hash::<LENGTH>::type_name()],
            })
        });
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::restriction)]

    #[cfg(feature = "std")]
    use hex_literal::hex;

    #[cfg(feature = "std")]
    use super::*;

    #[test]
    #[cfg(feature = "std")]
    fn blake2_32b() {
        let mut hasher = VarBlake2b::new(32).unwrap();
        hasher.update(hex!("6920616d2064617461"));
        hasher.finalize_variable(|res| {
            assert_eq!(
                res[..],
                hex!("ba67336efd6a3df3a70eeb757860763036785c182ff4cf587541a0068d09f5b2")[..]
            );
        })
    }
}
