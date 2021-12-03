use std::{
    fmt::{self, Debug, Display, Formatter},
    hash,
    marker::PhantomData,
};

use derive_more::{Deref, DerefMut, Display};
use iroha_schema::IntoSchema;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};
use ursa::blake2::{
    digest::{Update, VariableOutput},
    VarBlake2b,
};

/// Hash of Iroha entities. Currently supports only blake2b-32.
#[derive(
    Eq,
    PartialEq,
    Clone,
    Encode,
    Decode,
    Serialize,
    Deserialize,
    Ord,
    PartialOrd,
    Copy,
    Hash,
    IntoSchema,
)]
pub struct Hash(pub [u8; Self::LENGTH]);

impl Hash {
    /// Length of hash
    pub const LENGTH: usize = 32;

    /// new hash from bytes
    #[allow(clippy::expect_used)]
    pub fn new(bytes: &[u8]) -> Self {
        let vec_hash = VarBlake2b::new(Self::LENGTH)
            .expect("Failed to initialize variable size hash")
            .chain(bytes)
            .finalize_boxed();
        let mut hash = [0; Self::LENGTH];
        hash.copy_from_slice(&vec_hash);
        Hash(hash)
    }
}

impl Display for Hash {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let Hash(bytes) = self;
        write!(f, "{}", hex::encode(bytes))
    }
}

impl Debug for Hash {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let Hash(bytes) = self;
        write!(f, "{}", hex::encode(bytes))
    }
}

impl AsRef<[u8]> for Hash {
    fn as_ref(&self) -> &[u8] {
        let Hash(bytes) = self;
        bytes
    }
}

/// Represents hash of Iroha entities like `Block` or `Transaction`. Currently supports only blake2b-32.
#[derive(Debug, Encode, Decode, Serialize, Deserialize, Deref, DerefMut, Display)]
#[display(fmt = "{}", _0)]
pub struct HashOf<T>(
    #[deref]
    #[deref_mut]
    Hash,
    PhantomData<T>,
);

impl<T> AsRef<[u8]> for HashOf<T> {
    fn as_ref(&self) -> &[u8] {
        Hash::as_ref(&self.0)
    }
}

impl<T> From<HashOf<T>> for Hash {
    fn from(HashOf(hash, _): HashOf<T>) -> Self {
        hash
    }
}

impl<T> Clone for HashOf<T> {
    fn clone(&self) -> Self {
        Self(self.0, PhantomData)
    }
}
impl<T> Copy for HashOf<T> {}

impl<T> PartialEq for HashOf<T> {
    fn eq(&self, other: &Self) -> bool {
        self.0.eq(other)
    }
}
impl<T> Eq for HashOf<T> {}

impl<T> PartialOrd for HashOf<T> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.0.partial_cmp(&other.0)
    }
}
impl<T> Ord for HashOf<T> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.cmp(&other.0)
    }
}

impl<T> hash::Hash for HashOf<T> {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.0.hash(state)
    }
}

impl<T> HashOf<T> {
    /// Unsafe constructor for typed hash
    pub const fn from_hash(hash: Hash) -> Self {
        Self(hash, PhantomData)
    }

    /// Transmutes hash to some specific type
    /// SAFETY:
    /// Do at your own risk
    pub const fn transmute<F>(self) -> HashOf<F> {
        HashOf(self.0, PhantomData)
    }
}

impl<T: Encode> HashOf<T> {
    /// Constructor for typed hash
    pub fn new(value: &T) -> Self {
        Self(Hash::new(&value.encode()), PhantomData)
    }
}

impl<T> IntoSchema for HashOf<T> {
    fn schema(metamap: &mut iroha_schema::MetaMap) {
        Hash::schema(metamap)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::restriction)]

    use hex_literal::hex;
    use ursa::blake2::{
        digest::{Update, VariableOutput},
        VarBlake2b,
    };

    #[test]
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
