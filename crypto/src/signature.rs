#![allow(clippy::std_instead_of_core)]
#[cfg(not(feature = "std"))]
use alloc::{boxed::Box, collections::btree_set, format, string::String, vec, vec::Vec};
use core::marker::PhantomData;
#[cfg(feature = "std")]
#[cfg(not(feature = "ffi_import"))]
use std::collections::btree_set;

use derive_more::{Deref, DerefMut};
use iroha_macro::ffi_impl_opaque;
use iroha_primitives::const_vec::ConstVec;
use iroha_schema::{IntoSchema, TypeId};
use parity_scale_codec::{Decode, Encode};
#[cfg(not(feature = "ffi_import"))]
use serde::{Deserialize, Serialize};
#[cfg(feature = "std")]
#[cfg(not(feature = "ffi_import"))]
use ursa::{
    keys::{PrivateKey as UrsaPrivateKey, PublicKey as UrsaPublicKey},
    signatures::{
        bls::{normal::Bls as BlsNormal, small::Bls as BlsSmall},
        ed25519::Ed25519Sha512,
        secp256k1::EcdsaSecp256k1Sha256,
        SignatureScheme,
    },
};

use crate::{ffi, Error, PublicKey};
#[cfg(feature = "std")]
use crate::{HashOf, KeyPair};

ffi::ffi_item! {
    /// Represents signature of the data (`Block` or `Transaction` for example).
    #[derive(Clone, PartialEq, Eq, PartialOrd, Ord, getset::Getters)]
    #[cfg_attr(not(feature="ffi_import"), derive(derive_more::DebugCustom, Hash, Decode, Encode, Deserialize, Serialize, IntoSchema))]
    #[cfg_attr(not(feature="ffi_import"), debug(
        fmt = "{{ pub_key: {public_key}, payload: {} }}",
        "hex::encode_upper(payload)"
    ))]
    pub struct Signature {
        /// Public key that is used for verification. Payload is verified by algorithm
        /// that corresponds with the public key's digest function.
        #[getset(get = "pub")]
        public_key: PublicKey,
        /// Signature payload
        payload: ConstVec<u8>,
    }
}

#[ffi_impl_opaque]
impl Signature {
    /// Key payload
    pub fn payload(&self) -> &[u8] {
        self.payload.as_ref()
    }

    /// Creates new [`Signature`] by signing payload via [`KeyPair::private_key`].
    ///
    /// # Errors
    /// Fails if signing fails
    #[cfg(any(feature = "std", feature = "import_ffi"))]
    pub fn new(key_pair: KeyPair, payload: &[u8]) -> Result<Self, Error> {
        let (public_key, private_key) = key_pair.into();

        let algorithm: crate::Algorithm = private_key.digest_function();
        let private_key = UrsaPrivateKey(private_key.payload.into_vec());

        let signature = match algorithm {
            crate::Algorithm::Ed25519 => Ed25519Sha512::new().sign(payload, &private_key),
            crate::Algorithm::Secp256k1 => EcdsaSecp256k1Sha256::new().sign(payload, &private_key),
            crate::Algorithm::BlsSmall => BlsSmall::new().sign(payload, &private_key),
            crate::Algorithm::BlsNormal => BlsNormal::new().sign(payload, &private_key),
        }?;
        Ok(Self {
            public_key,
            payload: ConstVec::new(signature),
        })
    }

    /// Verify `message` using signed data and [`KeyPair::public_key`].
    ///
    /// # Errors
    /// Fails if message didn't pass verification
    #[cfg(any(feature = "std", feature = "import_ffi"))]
    pub fn verify(&self, payload: &[u8]) -> Result<(), Error> {
        let algorithm: crate::Algorithm = self.public_key.digest_function();
        let public_key = UrsaPublicKey(self.public_key.payload().to_owned());

        match algorithm {
            crate::Algorithm::Ed25519 => {
                Ed25519Sha512::new().verify(payload, self.payload(), &public_key)
            }
            crate::Algorithm::Secp256k1 => {
                EcdsaSecp256k1Sha256::new().verify(payload, self.payload(), &public_key)
            }
            crate::Algorithm::BlsSmall => {
                BlsSmall::new().verify(payload, self.payload(), &public_key)
            }
            crate::Algorithm::BlsNormal => {
                BlsNormal::new().verify(payload, self.payload(), &public_key)
            }
        }?;

        Ok(())
    }
}

// TODO: Enable in ffi_import
#[cfg(not(feature = "ffi_import"))]
impl From<Signature> for (PublicKey, Vec<u8>) {
    fn from(
        Signature {
            public_key,
            payload: signature,
        }: Signature,
    ) -> Self {
        (public_key, signature.into_vec())
    }
}

// TODO: Enable in ffi_import
#[cfg(not(feature = "ffi_import"))]
impl<T> From<SignatureOf<T>> for Signature {
    fn from(SignatureOf(signature, ..): SignatureOf<T>) -> Self {
        signature
    }
}

ffi::ffi_item! {
    /// Represents signature of the data (`Block` or `Transaction` for example).
    // Lint triggers when expanding #[codec(skip)]
    #[allow(clippy::default_trait_access, clippy::unsafe_derive_deserialize)]
    #[derive(Deref, DerefMut, TypeId)]
    #[cfg_attr(not(feature="ffi_import"), derive(Decode, Encode, Serialize, Deserialize))]
    #[cfg_attr(not(feature="ffi_import"), serde(transparent))]
    // Transmute guard
    #[repr(transparent)]
    pub struct SignatureOf<T>(
        #[deref]
        #[deref_mut]
        Signature,
        #[cfg_attr(not(feature = "ffi_import"), codec(skip))] PhantomData<T>,
    );

    // SAFETY: `SignatureOf` has no trap representation in `Signature`
    ffi_type(unsafe {robust})
}

#[cfg(not(feature = "ffi_import"))]
impl<T> core::fmt::Debug for SignatureOf<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple(core::any::type_name::<Self>())
            .field(&self.0)
            .finish()
    }
}

impl<T> Clone for SignatureOf<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone(), PhantomData)
    }
}

impl<T> PartialEq for SignatureOf<T> {
    fn eq(&self, other: &Self) -> bool {
        self.0.eq(&other.0)
    }
}
impl<T> Eq for SignatureOf<T> {}

impl<T> PartialOrd for SignatureOf<T> {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl<T> Ord for SignatureOf<T> {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.0.cmp(&other.0)
    }
}

#[cfg(not(feature = "ffi_import"))]
impl<T> core::hash::Hash for SignatureOf<T> {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.0.hash(state)
    }
}

#[cfg(not(feature = "ffi_import"))]
impl<T: IntoSchema> IntoSchema for SignatureOf<T> {
    fn type_name() -> String {
        format!("SignatureOf<{}>", T::type_name())
    }
    fn update_schema_map(map: &mut iroha_schema::MetaMap) {
        if !map.contains_key::<Self>() {
            map.insert::<Self>(iroha_schema::Metadata::Tuple(
                iroha_schema::UnnamedFieldsMeta {
                    types: vec![core::any::TypeId::of::<Signature>()],
                },
            ));

            Signature::update_schema_map(map);
        }
    }
}

impl<T> SignatureOf<T> {
    /// Create [`SignatureOf`] from the given hash with [`KeyPair::private_key`].
    ///
    /// # Errors
    /// Fails if signing fails
    #[cfg(any(feature = "std", feature = "import_ffi"))]
    fn from_hash(key_pair: KeyPair, hash: HashOf<T>) -> Result<Self, Error> {
        Signature::new(key_pair, hash.as_ref()).map(|signature| Self(signature, PhantomData))
    }

    /// Verify signature for this hash
    ///
    /// # Errors
    ///
    /// Fails if the given hash didn't pass verification
    #[cfg(any(feature = "std", feature = "import_ffi"))]
    fn verify_hash(&self, hash: HashOf<T>) -> Result<(), Error> {
        self.0.verify(hash.as_ref())
    }
}

#[cfg(any(feature = "std", feature = "import_ffi"))]
impl<T: parity_scale_codec::Encode> SignatureOf<T> {
    /// Create [`SignatureOf`] by signing the given value with [`KeyPair::private_key`].
    /// The value provided will be hashed before being signed. If you already have the
    /// hash of the value you can sign it with [`SignatureOf::from_hash`] instead.
    ///
    /// # Errors
    /// Fails if signing fails
    pub fn new(key_pair: KeyPair, value: &T) -> Result<Self, Error> {
        Self::from_hash(key_pair, HashOf::new(value))
    }

    /// Verifies signature for this item
    ///
    /// # Errors
    /// Fails if verification fails
    pub fn verify(&self, value: &T) -> Result<(), Error> {
        self.verify_hash(HashOf::new(value))
    }
}

/// Wrapper around [`SignatureOf`] used to reimplement [`Eq`], [`Ord`], [`Hash`]
/// to compare signatures only by their [`PublicKey`].
#[derive(Deref, DerefMut, Decode, Encode, Deserialize, Serialize, IntoSchema)]
#[serde(transparent, bound(deserialize = ""))]
#[schema(transparent)]
#[repr(transparent)]
#[cfg(not(feature = "ffi_import"))]
pub struct SignatureWrapperOf<T>(
    #[deref]
    #[deref_mut]
    SignatureOf<T>,
);

#[cfg(not(feature = "ffi_import"))]
impl<T> SignatureWrapperOf<T> {
    #[inline]
    fn inner(self) -> SignatureOf<T> {
        self.0
    }
}

#[cfg(not(feature = "ffi_import"))]
impl<T> core::fmt::Debug for SignatureWrapperOf<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.0.fmt(f)
    }
}

#[cfg(not(feature = "ffi_import"))]
impl<T> Clone for SignatureWrapperOf<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

#[cfg(not(feature = "ffi_import"))]
impl<T> PartialEq for SignatureWrapperOf<T> {
    fn eq(&self, other: &Self) -> bool {
        self.0.public_key().eq(other.0.public_key())
    }
}
#[cfg(not(feature = "ffi_import"))]
impl<T> Eq for SignatureWrapperOf<T> {}

#[cfg(not(feature = "ffi_import"))]
impl<T> PartialOrd for SignatureWrapperOf<T> {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
#[cfg(not(feature = "ffi_import"))]
impl<T> Ord for SignatureWrapperOf<T> {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.0.public_key().cmp(other.0.public_key())
    }
}

#[cfg(not(feature = "ffi_import"))]
impl<T> core::hash::Hash for SignatureWrapperOf<T> {
    // Implement `Hash` manually to be consistent with `Ord`
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.0.public_key().hash(state);
    }
}

/// Container for multiple signatures, each corresponding to a different public key.
///
/// If the public key of the added signature is already in the set,
/// the associated signature will be replaced with the new one.
///
/// GUARANTEE 1: Each signature corresponds to a different public key
#[allow(clippy::derived_hash_with_manual_eq)]
#[derive(Hash, Decode, Encode, Deserialize, Serialize, IntoSchema)]
#[serde(transparent)]
// Transmute guard
#[repr(transparent)]
#[cfg(not(feature = "ffi_import"))]
pub struct SignaturesOf<T> {
    signatures: btree_set::BTreeSet<SignatureWrapperOf<T>>,
}

#[cfg(not(feature = "ffi_import"))]
impl<T> core::fmt::Debug for SignaturesOf<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct(core::any::type_name::<Self>())
            .field("signatures", &self.signatures)
            .finish()
    }
}

#[cfg(not(feature = "ffi_import"))]
impl<T> Clone for SignaturesOf<T> {
    fn clone(&self) -> Self {
        let signatures = self.signatures.clone();
        Self { signatures }
    }
}

#[cfg(not(feature = "ffi_import"))]
impl<T> PartialEq for SignaturesOf<T> {
    fn eq(&self, other: &Self) -> bool {
        self.signatures.eq(&other.signatures)
    }
}

#[cfg(not(feature = "ffi_import"))]
impl<T> Eq for SignaturesOf<T> {}

#[cfg(not(feature = "ffi_import"))]
impl<T> PartialOrd for SignaturesOf<T> {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

#[cfg(not(feature = "ffi_import"))]
impl<T> Ord for SignaturesOf<T> {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.signatures.cmp(&other.signatures)
    }
}

#[cfg(not(feature = "ffi_import"))]
impl<T> IntoIterator for SignaturesOf<T> {
    type Item = SignatureOf<T>;
    type IntoIter = core::iter::Map<
        btree_set::IntoIter<SignatureWrapperOf<T>>,
        fn(SignatureWrapperOf<T>) -> SignatureOf<T>,
    >;
    fn into_iter(self) -> Self::IntoIter {
        self.signatures.into_iter().map(SignatureWrapperOf::inner)
    }
}

#[cfg(not(feature = "ffi_import"))]
impl<'itm, T> IntoIterator for &'itm SignaturesOf<T> {
    type Item = &'itm SignatureOf<T>;
    type IntoIter = core::iter::Map<
        btree_set::Iter<'itm, SignatureWrapperOf<T>>,
        fn(&'itm SignatureWrapperOf<T>) -> &'itm SignatureOf<T>,
    >;
    fn into_iter(self) -> Self::IntoIter {
        self.signatures.iter().map(core::ops::Deref::deref)
    }
}

#[cfg(not(feature = "ffi_import"))]
impl<A> Extend<SignatureOf<A>> for SignaturesOf<A> {
    fn extend<T>(&mut self, iter: T)
    where
        T: IntoIterator<Item = SignatureOf<A>>,
    {
        for signature in iter {
            self.insert(signature);
        }
    }
}

#[cfg(not(feature = "ffi_import"))]
impl<T> From<SignaturesOf<T>> for btree_set::BTreeSet<SignatureOf<T>> {
    fn from(source: SignaturesOf<T>) -> Self {
        source.into_iter().collect()
    }
}

#[cfg(not(feature = "ffi_import"))]
impl<T> From<btree_set::BTreeSet<SignatureOf<T>>> for SignaturesOf<T> {
    fn from(source: btree_set::BTreeSet<SignatureOf<T>>) -> Self {
        source.into_iter().collect()
    }
}

#[cfg(not(feature = "ffi_import"))]
impl<A> From<SignatureOf<A>> for SignaturesOf<A> {
    fn from(signature: SignatureOf<A>) -> Self {
        Self {
            signatures: [SignatureWrapperOf(signature)].into(),
        }
    }
}

#[cfg(not(feature = "ffi_import"))]
impl<A> FromIterator<SignatureOf<A>> for SignaturesOf<A> {
    fn from_iter<T: IntoIterator<Item = SignatureOf<A>>>(signatures: T) -> Self {
        Self {
            signatures: signatures.into_iter().map(SignatureWrapperOf).collect(),
        }
    }
}

#[cfg(not(feature = "ffi_import"))]
impl<T> SignaturesOf<T> {
    /// Adds a signature. If the signature with this key was present, replaces it.
    pub fn insert(&mut self, signature: SignatureOf<T>) {
        self.signatures.insert(SignatureWrapperOf(signature));
    }

    /// Return all signatures.
    #[inline]
    pub fn iter(&self) -> impl ExactSizeIterator<Item = &SignatureOf<T>> {
        self.into_iter()
    }

    /// Number of signatures.
    #[inline]
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        self.signatures.len()
    }

    /// Verify signatures for this hash
    ///
    /// # Errors
    /// Fails if verificatoin of any signature fails
    #[cfg(feature = "std")]
    pub fn verify_hash(&self, hash: HashOf<T>) -> Result<(), SignatureVerificationFail<T>> {
        self.iter().try_for_each(|signature| {
            signature
                .verify_hash(hash)
                .map_err(|error| SignatureVerificationFail {
                    signature: Box::new(signature.clone()),
                    reason: error.to_string(),
                })
        })
    }

    /// Returns true if the set is a subset of another, i.e., other contains at least all the elements in self.
    pub fn is_subset(&self, other: &Self) -> bool {
        self.signatures.is_subset(&other.signatures)
    }
}

#[cfg(feature = "std")]
#[cfg(not(feature = "ffi_import"))]
impl<T: Encode> SignaturesOf<T> {
    /// Create new signatures container
    ///
    /// # Errors
    /// Forwards [`SignatureOf::new`] errors
    pub fn new(key_pair: KeyPair, value: &T) -> Result<Self, Error> {
        SignatureOf::new(key_pair, value).map(Self::from)
    }

    /// Verifies all signatures
    ///
    /// # Errors
    /// Fails if validation of any signature fails
    pub fn verify(&self, item: &T) -> Result<(), SignatureVerificationFail<T>> {
        self.verify_hash(HashOf::new(item))
    }
}

/// Verification failed of some signature due to following reason
#[derive(Clone, PartialEq, Eq)]
pub struct SignatureVerificationFail<T> {
    /// Signature which verification has failed
    pub signature: Box<SignatureOf<T>>,
    /// Error which happened during verification
    pub reason: String,
}

#[cfg(not(feature = "ffi_import"))]
impl<T> core::fmt::Debug for SignatureVerificationFail<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SignatureVerificationFail")
            .field("signature", &self.signature.0)
            .field("reason", &self.reason)
            .finish()
    }
}

#[cfg(not(feature = "ffi_import"))]
impl<T> core::fmt::Display for SignatureVerificationFail<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "Failed to verify signatures because of signature {}: {}",
            self.signature.public_key(),
            self.reason,
        )
    }
}

#[cfg(feature = "std")]
#[cfg(not(feature = "ffi_import"))]
impl<T> std::error::Error for SignatureVerificationFail<T> {}

#[cfg(test)]
mod tests {
    #![allow(clippy::restriction)]

    #[cfg(feature = "std")]
    use super::*;
    #[cfg(any(feature = "std", feature = "ffi_import"))]
    use crate::KeyGenConfiguration;

    #[test]
    #[cfg(any(feature = "std", feature = "ffi_import"))]
    fn create_signature_ed25519() {
        let key_pair = KeyPair::generate_with_configuration(
            KeyGenConfiguration::default().with_algorithm(crate::Algorithm::Ed25519),
        )
        .expect("Failed to generate key pair.");
        let message = b"Test message to sign.";
        let signature =
            Signature::new(key_pair.clone(), message).expect("Failed to create signature.");
        assert!(*signature.public_key() == *key_pair.public_key());
        assert!(signature.verify(message).is_ok())
    }

    #[test]
    #[cfg(any(feature = "std", feature = "ffi_import"))]
    fn create_signature_secp256k1() {
        let key_pair = KeyPair::generate_with_configuration(
            KeyGenConfiguration::default().with_algorithm(crate::Algorithm::Secp256k1),
        )
        .expect("Failed to generate key pair.");
        let message = b"Test message to sign.";
        let signature =
            Signature::new(key_pair.clone(), message).expect("Failed to create signature.");
        assert!(*signature.public_key() == *key_pair.public_key());
        assert!(signature.verify(message).is_ok())
    }

    #[test]
    #[cfg(any(feature = "std", feature = "ffi_import"))]
    fn create_signature_bls_normal() {
        let key_pair = KeyPair::generate_with_configuration(
            KeyGenConfiguration::default().with_algorithm(crate::Algorithm::BlsNormal),
        )
        .expect("Failed to generate key pair.");
        let message = b"Test message to sign.";
        let signature =
            Signature::new(key_pair.clone(), message).expect("Failed to create signature.");
        assert!(*signature.public_key() == *key_pair.public_key());
        assert!(signature.verify(message).is_ok())
    }

    #[test]
    #[cfg(any(feature = "std", feature = "ffi_import"))]
    fn create_signature_bls_small() {
        let key_pair = KeyPair::generate_with_configuration(
            KeyGenConfiguration::default().with_algorithm(crate::Algorithm::BlsSmall),
        )
        .expect("Failed to generate key pair.");
        let message = b"Test message to sign.";
        let signature =
            Signature::new(key_pair.clone(), message).expect("Failed to create signature.");
        assert!(*signature.public_key() == *key_pair.public_key());
        assert!(signature.verify(message).is_ok())
    }

    #[test]
    #[cfg(feature = "std")]
    #[cfg(not(feature = "ffi_import"))]
    fn signatures_of_deduplication_by_public_key() {
        let key_pair = KeyPair::generate().expect("Failed to generate keys");
        let signatures = [
            SignatureOf::new(key_pair.clone(), &1).expect("Failed to sign"),
            SignatureOf::new(key_pair.clone(), &2).expect("Failed to sign"),
            SignatureOf::new(key_pair, &3).expect("Failed to sign"),
        ]
        .into_iter()
        .collect::<SignaturesOf<u8>>();
        // Signatures with the same public key was deduplicated
        assert_eq!(signatures.len(), 1);
    }

    #[test]
    #[cfg(feature = "std")]
    #[cfg(not(feature = "ffi_import"))]
    fn signature_wrapper_btree_and_hash_sets_consistent_results() {
        use std::collections::{BTreeSet, HashSet};

        let keys = 5;
        let signatures_per_key = 10;
        let signatures =
            core::iter::repeat_with(|| KeyPair::generate().expect("Failed to generate keys"))
                .take(keys)
                .flat_map(|key| {
                    core::iter::repeat_with(move || key.clone())
                        .zip(0..)
                        .map(|(key, i)| SignatureOf::new(key, &i).expect("Failed to sign"))
                        .take(signatures_per_key)
                })
                .map(SignatureWrapperOf)
                .collect::<Vec<_>>();
        let hash_set: HashSet<_> = signatures.clone().into_iter().collect();
        let btree_set: BTreeSet<_> = signatures.into_iter().collect();

        // Check that `hash_set` is subset of `btree_set`
        for signature in &hash_set {
            assert!(btree_set.contains(signature));
        }
        // Check that `btree_set` is subset `hash_set`
        for signature in &btree_set {
            assert!(hash_set.contains(signature));
        }
        // From the above we can conclude that `SignatureWrapperOf` have consistent behavior for `HashSet` and `BTreeSet`
    }
}
