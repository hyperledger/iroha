#![allow(clippy::std_instead_of_core)]
#[cfg(not(feature = "std"))]
use alloc::{boxed::Box, collections::btree_set, format, string::String, vec, vec::Vec};
use core::{fmt, marker::PhantomData};
#[cfg(feature = "std")]
use std::collections::btree_set;

use derive_more::{DebugCustom, Deref, DerefMut};
use getset::Getters;
use iroha_schema::{IntoSchema, TypeId};
use parity_scale_codec::{Decode, Encode, Input};
use serde::{Deserialize, Serialize};
#[cfg(feature = "std")]
use ursa::{
    keys::{PrivateKey as UrsaPrivateKey, PublicKey as UrsaPublicKey},
    signatures::{
        bls::{normal::Bls as BlsNormal, small::Bls as BlsSmall},
        ed25519::Ed25519Sha512,
        secp256k1::EcdsaSecp256k1Sha256,
        SignatureScheme,
    },
};

#[cfg(feature = "std")]
use crate::{Algorithm, HashOf, KeyPair};
use crate::{Error, PublicKey};
/// Signature payload(i.e THE signature)
pub type Payload = Vec<u8>;

/// Represents signature of the data (`Block` or `Transaction` for example).
#[derive(
    DebugCustom,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Getters,
    Decode,
    Encode,
    Deserialize,
    Serialize,
    Hash,
    IntoSchema,
)]
#[getset(get = "pub")]
#[debug(
    fmt = "{{ pub_key: {public_key}, payload: {} }}",
    "hex::encode_upper(payload.as_slice())"
)]
pub struct Signature {
    /// Public key that is used for verification. Payload is verified by algorithm
    /// that corresponds with the public key's digest function.
    public_key: PublicKey,
    /// Actual signature payload is placed here.
    payload: Payload,
}

impl Signature {
    /// Creates new [`Signature`] by signing payload via [`KeyPair::private_key`].
    ///
    /// # Errors
    /// Fails if signing fails
    #[cfg(feature = "std")]
    pub fn new(key_pair: KeyPair, payload: &[u8]) -> Result<Self, Error> {
        let (public_key, private_key) = key_pair.into();

        let algorithm: Algorithm = private_key.digest_function();
        let private_key = UrsaPrivateKey(private_key.payload);

        let signature = match algorithm {
            Algorithm::Ed25519 => Ed25519Sha512::new().sign(payload, &private_key),
            Algorithm::Secp256k1 => EcdsaSecp256k1Sha256::new().sign(payload, &private_key),
            Algorithm::BlsSmall => BlsSmall::new().sign(payload, &private_key),
            Algorithm::BlsNormal => BlsNormal::new().sign(payload, &private_key),
        }?;

        Ok(Self {
            public_key,
            payload: signature,
        })
    }

    /// Adds type information to the signature. Be careful about using this function
    /// since it is not possible to validate the correctness of the conversion.
    /// Prefer creating new signatures with [`SignatureOf::new`] whenever possible
    #[inline]
    #[cfg_attr(not(feature = "std"), allow(dead_code))]
    const fn typed<T>(self) -> SignatureOf<T> {
        SignatureOf(self, PhantomData)
    }

    /// Verify `message` using signed data and [`KeyPair::public_key`].
    ///
    /// # Errors
    /// Fails if message didn't pass verification
    #[cfg(feature = "std")]
    pub fn verify(&self, payload: &[u8]) -> Result<(), Error> {
        let algorithm: Algorithm = self.public_key.digest_function();
        let public_key = UrsaPublicKey(self.public_key.payload().to_owned());

        match algorithm {
            Algorithm::Ed25519 => Ed25519Sha512::new().verify(payload, self.payload(), &public_key),
            Algorithm::Secp256k1 => {
                EcdsaSecp256k1Sha256::new().verify(payload, self.payload(), &public_key)
            }
            Algorithm::BlsSmall => BlsSmall::new().verify(payload, self.payload(), &public_key),
            Algorithm::BlsNormal => BlsNormal::new().verify(payload, self.payload(), &public_key),
        }?;

        Ok(())
    }
}

impl From<Signature> for (PublicKey, Payload) {
    fn from(
        Signature {
            public_key,
            payload: signature,
        }: Signature,
    ) -> Self {
        (public_key, signature)
    }
}

impl<T> From<SignatureOf<T>> for Signature {
    fn from(SignatureOf(signature, ..): SignatureOf<T>) -> Self {
        signature
    }
}

/// Represents signature of the data (`Block` or `Transaction` for example).
// Lint triggers when expanding #[codec(skip)]
#[allow(
    clippy::default_trait_access,
    clippy::unsafe_derive_deserialize,
    clippy::derive_hash_xor_eq
)]
#[derive(Deref, DerefMut, Hash, Decode, Encode, Deserialize, Serialize, TypeId)]
#[serde(transparent)]
// Transmute guard
#[repr(transparent)]
pub struct SignatureOf<T>(
    #[deref]
    #[deref_mut]
    Signature,
    #[codec(skip)] PhantomData<T>,
);

impl<T> fmt::Debug for SignatureOf<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
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
        self.0.partial_cmp(&other.0)
    }
}
impl<T> Ord for SignatureOf<T> {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.0.cmp(&other.0)
    }
}

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
    #[cfg(feature = "std")]
    pub fn from_hash(key_pair: KeyPair, hash: &HashOf<T>) -> Result<Self, Error> {
        Ok(Signature::new(key_pair, hash.as_ref())?.typed())
    }

    /// Transmutes signature to some specific type
    pub fn transmute<F>(self) -> SignatureOf<F> {
        SignatureOf(self.0, PhantomData)
    }

    /// Transmutes signature to some specific type
    ///
    /// # Warning:
    ///
    /// This method uses [`core::mem::transmute`] internally
    pub const fn transmute_ref<F>(&self) -> &SignatureOf<F> {
        #[allow(unsafe_code, trivial_casts)]
        // SAFETY: transmuting is safe, because we're casting a
        // pointer of type `SignatureOf<T>` into a pointer of type
        // `SignatureOf<F>`, where `<F>` and `<T>` type parameters are
        // normally related types that have the exact same alignment.
        unsafe {
            &*((self as *const Self).cast::<SignatureOf<F>>())
        }
    }

    /// Verify signature for this hash
    ///
    /// # Errors
    ///
    /// Fails if the given hash didn't pass verification
    #[cfg(feature = "std")]
    pub fn verify_hash(&self, hash: &HashOf<T>) -> Result<(), Error> {
        self.0.verify(hash.as_ref())
    }
}

#[cfg(feature = "std")]
impl<T: Encode> SignatureOf<T> {
    /// Create [`SignatureOf`] by signing the given value with [`KeyPair::private_key`].
    /// The value provided will be hashed before being signed. If you already have the
    /// hash of the value you can sign it with [`SignatureOf::from_hash`] instead.
    ///
    /// # Errors
    /// Fails if signing fails
    pub fn new(key_pair: KeyPair, value: &T) -> Result<Self, Error> {
        Self::from_hash(key_pair, &HashOf::new(value))
    }

    /// Verifies signature for this item
    ///
    /// # Errors
    /// Fails if verification fails
    pub fn verify(&self, value: &T) -> Result<(), Error> {
        self.verify_hash(&HashOf::new(value))
    }
}

/// Wrapper around [`SignatureOf`] used to reimplement [`Eq`], [`Ord`], [`Hash`]
/// to compare signatures only by their [`PublicKey`].
#[derive(Deref, DerefMut, Decode, Encode, Deserialize, Serialize, IntoSchema)]
#[serde(transparent, bound(deserialize = ""))]
#[schema(transparent = "SignatureOf<T>")]
#[repr(transparent)]
pub struct SignatureWrapperOf<T>(
    #[deref]
    #[deref_mut]
    SignatureOf<T>,
);

impl<T> SignatureWrapperOf<T> {
    #[inline]
    fn inner(self) -> SignatureOf<T> {
        self.0
    }
}

impl<T> PartialEq for SignatureWrapperOf<T> {
    fn eq(&self, other: &Self) -> bool {
        self.0.public_key.eq(&other.0.public_key)
    }
}
impl<T> Eq for SignatureWrapperOf<T> {}

impl<T> PartialOrd for SignatureWrapperOf<T> {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        self.0.public_key.partial_cmp(&other.0.public_key)
    }
}
impl<T> Ord for SignatureWrapperOf<T> {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.0.public_key.cmp(&other.0.public_key)
    }
}

impl<T> fmt::Debug for SignatureWrapperOf<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl<T> Clone for SignatureWrapperOf<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

// Implement `Hash` manually to be consistent with `Ord`
impl<T> core::hash::Hash for SignatureWrapperOf<T> {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.0.public_key.hash(state);
    }
}

/// Container for multiple signatures, each corresponding to a different public key.
///
/// If the public key of the added signature is already in the set,
/// the associated signature will be replaced with the new one.
///
/// GUARANTEE 1: Each signature corresponds to a different public key
#[allow(clippy::derive_hash_xor_eq)]
#[derive(Hash, Encode, Serialize, IntoSchema)]
#[serde(transparent)]
// Transmute guard
#[repr(transparent)]
pub struct SignaturesOf<T> {
    signatures: btree_set::BTreeSet<SignatureWrapperOf<T>>,
}

impl<T> fmt::Debug for SignaturesOf<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct(core::any::type_name::<Self>())
            .field("signatures", &self.signatures)
            .finish()
    }
}

impl<T> Clone for SignaturesOf<T> {
    fn clone(&self) -> Self {
        let signatures = self.signatures.clone();
        Self { signatures }
    }
}
impl<T> PartialEq for SignaturesOf<T> {
    fn eq(&self, other: &Self) -> bool {
        self.signatures.eq(&other.signatures)
    }
}
impl<T> Eq for SignaturesOf<T> {}

impl<'de, T> Deserialize<'de> for SignaturesOf<T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error as _;

        let signatures = <btree_set::BTreeSet<SignatureWrapperOf<T>>>::deserialize(deserializer)?;

        if signatures.is_empty() {
            return Err(D::Error::custom(
                "Could not deserialize SignaturesOf<T>. Input contains 0 signatures",
            ));
        }

        Ok(Self { signatures })
    }
}
impl<T> Decode for SignaturesOf<T> {
    fn decode<I: Input>(input: &mut I) -> Result<Self, parity_scale_codec::Error> {
        let signatures = <btree_set::BTreeSet<SignatureWrapperOf<T>>>::decode(input)?;

        if signatures.is_empty() {
            return Err("Could not decode SignaturesOf<T>. Input contains 0 signatures".into());
        }

        Ok(Self { signatures })
    }
}

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

impl<T> From<SignaturesOf<T>> for btree_set::BTreeSet<SignatureOf<T>> {
    fn from(source: SignaturesOf<T>) -> Self {
        source.into_iter().collect()
    }
}

impl<T> TryFrom<btree_set::BTreeSet<SignatureOf<T>>> for SignaturesOf<T> {
    type Error = Error;

    fn try_from(signatures: btree_set::BTreeSet<SignatureOf<T>>) -> Result<Self, Self::Error> {
        signatures.into_iter().collect()
    }
}

impl<A> From<SignatureOf<A>> for SignaturesOf<A> {
    fn from(signature: SignatureOf<A>) -> Self {
        Self {
            signatures: [SignatureWrapperOf(signature)].into(),
        }
    }
}

impl<A> FromIterator<SignatureOf<A>> for Result<SignaturesOf<A>, Error> {
    fn from_iter<T: IntoIterator<Item = SignatureOf<A>>>(iter: T) -> Self {
        let mut iter = iter.into_iter();
        iter.next()
            .ok_or(Error::EmptySignatureIter)
            .map(move |first_signature| core::iter::once(first_signature).chain(iter))
            .map(|signatures| signatures.map(SignatureWrapperOf).collect())
            .map(|signatures| SignaturesOf { signatures })
    }
}

impl<T> SignaturesOf<T> {
    /// Transmutes signature generic type
    ///
    /// # Warning:
    ///
    /// This method uses [`core::mem::transmute`] internally
    #[allow(unsafe_code, clippy::transmute_undefined_repr)]
    pub fn transmute<F>(self) -> SignaturesOf<F> {
        // SAFETY: Safe because we are transmuting to a pointer of
        // type `<F>` which is related to type `<T>`.
        let signatures = unsafe { core::mem::transmute(self.signatures) };
        SignaturesOf { signatures }
    }

    /// Adds a signature. If the signature with this key was present, replaces it.
    pub fn insert(&mut self, signature: SignatureOf<T>) {
        self.signatures.insert(SignatureWrapperOf(signature));
    }

    /// Return signatures that have passed verification, remove all others.
    #[cfg(feature = "std")]
    pub fn retain_verified_by_hash(
        &mut self,
        hash: HashOf<T>,
    ) -> impl Iterator<Item = &SignatureOf<T>> {
        self.signatures
            .retain(|sign| sign.verify_hash(&hash).is_ok());
        self.iter()
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

    /// Clear signatures.
    pub fn clear(&mut self) {
        self.signatures.clear()
    }

    /// Verify signatures for this hash
    ///
    /// # Errors
    /// Fails if verificatoin of any signature fails
    #[cfg(feature = "std")]
    pub fn verify_hash(&self, hash: &HashOf<T>) -> Result<(), SignatureVerificationFail<T>> {
        self.iter().try_for_each(|signature| {
            signature
                .verify_hash(hash)
                .map_err(|error| SignatureVerificationFail::new(signature.clone(), error))
        })
    }
}

#[cfg(feature = "std")]
impl<T: Encode> SignaturesOf<T> {
    /// Create new signatures container
    ///
    /// # Errors
    /// Forwards [`SignatureOf::new`] errors
    pub fn new(key_pair: KeyPair, value: &T) -> Result<Self, Error> {
        SignatureOf::new(key_pair, value).map(SignaturesOf::from)
    }

    /// Verifies all signatures
    ///
    /// # Errors
    /// Fails if validation of any signature fails
    pub fn verify(&self, item: &T) -> Result<(), SignatureVerificationFail<T>> {
        self.verify_hash(&HashOf::new(item))
    }

    /// Return signatures that have passed verification, remove all others.
    pub fn retain_verified(&mut self, value: &T) -> impl Iterator<Item = &SignatureOf<T>> {
        self.retain_verified_by_hash(HashOf::new(value))
    }
}

/// Verification failed of some signature due to following reason
#[derive(Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
pub struct SignatureVerificationFail<T> {
    /// Signature which verification has failed
    pub signature: Box<SignatureOf<T>>,
    /// Error which happened during verification
    pub reason: String,
}

impl<T> SignatureVerificationFail<T> {
    // `Self` should consume given `Error`
    #[cfg(feature = "std")]
    #[allow(clippy::needless_pass_by_value)]
    fn new(signature: SignatureOf<T>, error: Error) -> Self {
        Self {
            signature: Box::new(signature),
            reason: error.to_string(),
        }
    }
}

impl<T> fmt::Debug for SignatureVerificationFail<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SignatureVerificationFail")
            .field("signature", &self.signature.0)
            .field("reason", &self.reason)
            .finish()
    }
}

impl<T> fmt::Display for SignatureVerificationFail<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Failed to verify signatures because of signature {}: {}",
            self.signature.public_key(),
            self.reason,
        )
    }
}

#[cfg(feature = "std")]
impl<T> std::error::Error for SignatureVerificationFail<T> {}

#[cfg(test)]
mod tests {
    #![allow(clippy::restriction)]

    use parity_scale_codec::DecodeAll;

    #[cfg(feature = "std")]
    use super::*;
    #[cfg(feature = "std")]
    use crate::KeyGenConfiguration;

    #[test]
    #[cfg(feature = "std")]
    fn create_signature_ed25519() {
        let key_pair = KeyPair::generate_with_configuration(
            KeyGenConfiguration::default().with_algorithm(Algorithm::Ed25519),
        )
        .expect("Failed to generate key pair.");
        let message = b"Test message to sign.";
        let signature =
            Signature::new(key_pair.clone(), message).expect("Failed to create signature.");
        assert_eq!(signature.public_key(), key_pair.public_key());
        assert!(signature.verify(message).is_ok())
    }

    #[test]
    #[cfg(feature = "std")]
    fn create_signature_secp256k1() {
        let key_pair = KeyPair::generate_with_configuration(
            KeyGenConfiguration::default().with_algorithm(Algorithm::Secp256k1),
        )
        .expect("Failed to generate key pair.");
        let message = b"Test message to sign.";
        let signature =
            Signature::new(key_pair.clone(), message).expect("Failed to create signature.");
        assert_eq!(signature.public_key(), key_pair.public_key());
        assert!(signature.verify(message).is_ok())
    }

    #[test]
    #[cfg(feature = "std")]
    fn create_signature_bls_normal() {
        let key_pair = KeyPair::generate_with_configuration(
            KeyGenConfiguration::default().with_algorithm(Algorithm::BlsNormal),
        )
        .expect("Failed to generate key pair.");
        let message = b"Test message to sign.";
        let signature =
            Signature::new(key_pair.clone(), message).expect("Failed to create signature.");
        assert_eq!(signature.public_key(), key_pair.public_key());
        assert!(signature.verify(message).is_ok())
    }

    #[test]
    #[cfg(feature = "std")]
    fn create_signature_bls_small() {
        let key_pair = KeyPair::generate_with_configuration(
            KeyGenConfiguration::default().with_algorithm(Algorithm::BlsSmall),
        )
        .expect("Failed to generate key pair.");
        let message = b"Test message to sign.";
        let signature =
            Signature::new(key_pair.clone(), message).expect("Failed to create signature.");
        assert_eq!(signature.public_key(), key_pair.public_key());
        assert!(signature.verify(message).is_ok())
    }

    #[test]
    #[cfg(feature = "std")]
    fn decode_signatures_of() {
        let no_signatures: SignaturesOf<i32> = SignaturesOf {
            signatures: btree_set::BTreeSet::new(),
        };
        let bytes = no_signatures.encode();

        let signatures = SignaturesOf::<i32>::decode_all(&mut &bytes[..]);
        assert!(signatures.is_err());
    }

    #[test]
    #[cfg(feature = "std")]
    fn deserialize_signatures_of() -> Result<(), serde_json::Error> {
        let no_signatures: SignaturesOf<i32> = SignaturesOf {
            signatures: btree_set::BTreeSet::new(),
        };
        let serialized = serde_json::to_string(&no_signatures)?;

        let signatures = serde_json::from_str::<SignaturesOf<i32>>(serialized.as_str());
        assert!(signatures.is_err());

        Ok(())
    }

    #[test]
    #[cfg(feature = "std")]
    fn signatures_of_deduplication_by_public_key() {
        let key_pair = KeyPair::generate().expect("Failed to generate keys");
        let signatures = [
            SignatureOf::new(key_pair.clone(), &1).expect("Failed to sign"),
            SignatureOf::new(key_pair.clone(), &2).expect("Failed to sign"),
            SignatureOf::new(key_pair, &3).expect("Failed to sign"),
        ];
        let signatures = signatures
            .into_iter()
            .collect::<Result<SignaturesOf<u8>, Error>>()
            .expect("One signature must stay");
        // Signatures with the same public key was deduplicated
        assert_eq!(signatures.len(), 1);
    }

    #[test]
    #[cfg(feature = "std")]
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
