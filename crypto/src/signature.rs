use std::{
    collections::BTreeMap,
    error::Error as StdError,
    fmt::{self, Debug, Display, Formatter},
    marker::PhantomData,
};

use derive_more::{Deref, DerefMut};
use eyre::{eyre, Context, Result};
use iroha_schema::IntoSchema;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};
use ursa::{
    keys::{PrivateKey as UrsaPrivateKey, PublicKey as UrsaPublicKey},
    signatures::{
        bls::{normal::Bls as BlsNormal, small::Bls as BlsSmall},
        ed25519::Ed25519Sha512,
        secp256k1::EcdsaSecp256k1Sha256,
        SignatureScheme,
    },
};

use super::{Algorithm, KeyPair, PublicKey};
use crate::HashOf;

/// Represents signature of the data (`Block` or `Transaction` for example).
#[derive(Clone, Encode, Decode, Serialize, Deserialize, PartialOrd, Ord, IntoSchema)]
pub struct Signature {
    /// Public key that is used for verification. Payload is verified by algorithm
    /// that corresponds with the public key's digest function.
    pub public_key: PublicKey,
    /// Actual signature payload is placed here.
    signature: Vec<u8>,
}

impl Signature {
    /// Creates new [`Signature`] by signing payload via [`KeyPair::private_key`].
    ///
    /// # Errors
    /// Fails if decoding digest of key pair fails
    pub fn new(
        KeyPair {
            public_key,
            private_key,
        }: KeyPair,
        payload: &[u8],
    ) -> Result<Signature> {
        let private_key = UrsaPrivateKey(private_key.payload);
        let algorithm: Algorithm = public_key.digest_function.parse()?;
        let signature = match algorithm {
            Algorithm::Ed25519 => Ed25519Sha512::new().sign(payload, &private_key),
            Algorithm::Secp256k1 => EcdsaSecp256k1Sha256::new().sign(payload, &private_key),
            Algorithm::BlsSmall => BlsSmall::new().sign(payload, &private_key),
            Algorithm::BlsNormal => BlsNormal::new().sign(payload, &private_key),
        }
        .map_err(|e| {
            eyre!(
                "Failed to sign payload with public_key {}: {}",
                public_key,
                e
            )
        })?;
        Ok(Signature {
            public_key,
            signature,
        })
    }

    /// Verify `message` using signed data and [`KeyPair::public_key`].
    ///
    /// # Errors
    /// Fails if decoding digest of key pair fails or if message didn't pass verification
    pub fn verify(&self, payload: &[u8]) -> Result<()> {
        let public_key = UrsaPublicKey(self.public_key.payload.clone());
        let algorithm: Algorithm = self.public_key.digest_function.parse()?;
        let result = match algorithm {
            Algorithm::Ed25519 => {
                Ed25519Sha512::new().verify(payload, &self.signature, &public_key)
            }
            Algorithm::Secp256k1 => {
                EcdsaSecp256k1Sha256::new().verify(payload, &self.signature, &public_key)
            }
            Algorithm::BlsSmall => BlsSmall::new().verify(payload, &self.signature, &public_key),
            Algorithm::BlsNormal => BlsNormal::new().verify(payload, &self.signature, &public_key),
        };
        match result {
            Ok(true) => Ok(()),
            _ => Err(eyre!("Signature did not pass verification: {:?}", payload)),
        }
    }
}

impl PartialEq for Signature {
    fn eq(&self, other: &Self) -> bool {
        self.public_key == other.public_key && self.signature.clone() == other.signature.clone()
    }
}

impl Eq for Signature {}

impl Debug for Signature {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("Signature")
            .field("public_key", &self.public_key)
            .field("signature", &hex::encode_upper(self.signature.as_slice()))
            .finish()
    }
}

/// Represents signature of the data (`Block` or `Transaction` for example).
#[allow(clippy::unsafe_derive_deserialize)]
#[derive(Debug, Serialize, Deserialize, Deref, DerefMut)]
#[serde(transparent)]
pub struct SignatureOf<T>(
    #[deref]
    #[deref_mut]
    Signature,
    #[serde(skip)] PhantomData<T>,
);

impl<T> PartialEq for SignatureOf<T> {
    fn eq(&self, other: &Self) -> bool {
        self.signature.eq(&other.signature)
    }
}

impl<T> Eq for SignatureOf<T> {}
impl<T> PartialOrd for SignatureOf<T> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.signature.partial_cmp(&other.signature)
    }
}
impl<T> Ord for SignatureOf<T> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.signature.cmp(&other.signature)
    }
}

impl<T> Encode for SignatureOf<T> {
    fn size_hint(&self) -> usize {
        Signature::size_hint(&self.0)
    }
    fn encode_to<U: parity_scale_codec::Output + ?Sized>(&self, dest: &mut U) {
        self.0.encode_to(dest)
    }
    fn encode(&self) -> Vec<u8> {
        self.0.encode()
    }
    fn using_encoded<R, F: FnOnce(&[u8]) -> R>(&self, f: F) -> R {
        self.0.using_encoded(f)
    }
    fn encoded_size(&self) -> usize {
        self.0.encoded_size()
    }
}

impl<T> Decode for SignatureOf<T> {
    fn decode<I: parity_scale_codec::Input>(
        input: &mut I,
    ) -> Result<Self, parity_scale_codec::Error> {
        Ok(Self(Signature::decode(input)?, PhantomData))
    }
    fn skip<I: parity_scale_codec::Input>(input: &mut I) -> Result<(), parity_scale_codec::Error> {
        Signature::skip(input)
    }
    fn encoded_fixed_size() -> Option<usize> {
        Signature::encoded_fixed_size()
    }
}

impl<T> SignatureOf<T> {
    /// Verifies signature for this hash
    /// # Errors
    /// Fails if verification fails
    pub fn verify_hash(&self, hash: &HashOf<T>) -> Result<(), SignatureVerificationFail<T>> {
        self.0
            .verify(hash.as_ref())
            .map_err(|err| SignatureVerificationFail {
                signature: Box::new(self.clone()),
                reason: err.to_string(),
            })
    }

    /// Transmutes signature to some specific type
    /// SAFETY:
    /// Do at your own risk
    pub fn transmute<F>(self) -> SignatureOf<F> {
        SignatureOf(self.0, PhantomData)
    }

    /// Transmutes signature to some specific type
    /// SAFETY:
    /// Do at your own risk
    pub fn transmute_ref<F>(&self) -> &SignatureOf<F> {
        #[allow(unsafe_code, trivial_casts)]
        unsafe {
            &*((self as *const Self).cast::<SignatureOf<F>>())
        }
    }

    /// Creates new [`SignatureOf`] by signing value via [`KeyPair::private_key`].
    /// # Errors
    /// Fails if decoding digest of key pair fails
    pub fn from_hash(key_pair: KeyPair, hash: &HashOf<T>) -> Result<Self> {
        Ok(Self(Signature::new(key_pair, hash.as_ref())?, PhantomData))
    }
}

impl<T: Encode> SignatureOf<T> {
    /// Creates new [`SignatureOf`] by signing value via [`KeyPair::private_key`].
    /// # Errors
    /// Fails if decoding digest of key pair fails
    pub fn new(key_pair: KeyPair, value: &T) -> Result<Self> {
        Self::from_hash(key_pair, &HashOf::new(value))
    }

    /// Verifies signature for this item
    /// # Errors
    /// Fails if verification fails
    pub fn verify(&self, value: &T) -> Result<(), SignatureVerificationFail<T>> {
        self.verify_hash(&HashOf::new(value))
    }
}

impl<T> Clone for SignatureOf<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone(), PhantomData)
    }
}

impl<T> IntoSchema for SignatureOf<T> {
    fn type_name() -> String {
        Signature::type_name()
    }

    fn schema(metamap: &mut iroha_schema::MetaMap) {
        Signature::schema(metamap)
    }
}

/// Container for multiple signatures.
#[allow(clippy::unsafe_derive_deserialize)]
#[derive(Debug, Encode, PartialEq, Eq, Serialize, Deserialize, IntoSchema)]
#[serde(transparent)]
pub struct SignaturesOf<T> {
    signatures: BTreeMap<PublicKey, SignatureOf<T>>,
}

impl<T> Clone for SignaturesOf<T> {
    fn clone(&self) -> Self {
        let signatures = self.signatures.clone();
        Self { signatures }
    }
}

impl<T> IntoIterator for SignaturesOf<T> {
    type Item = SignatureOf<T>;
    type IntoIter = std::collections::btree_map::IntoValues<PublicKey, Self::Item>;
    fn into_iter(self) -> Self::IntoIter {
        self.signatures.into_values()
    }
}

impl<'a, T> IntoIterator for &'a SignaturesOf<T> {
    type Item = &'a SignatureOf<T>;
    type IntoIter = std::collections::btree_map::Values<'a, PublicKey, SignatureOf<T>>;
    fn into_iter(self) -> Self::IntoIter {
        self.signatures.values()
    }
}

// SAFETY: As this container should always have at least 1 signature
#[allow(clippy::len_without_is_empty)]
impl<T> SignaturesOf<T> {
    /// Transmutes signature generic type
    /// SAFETY: Check complience of hashes of this types
    pub fn transmute<F>(self) -> SignaturesOf<F> {
        #[allow(unsafe_code)]
        let signatures = unsafe { std::mem::transmute(self.signatures) };
        SignaturesOf { signatures }
    }

    /// Builds container using single signature
    pub fn from_signature(sign: SignatureOf<T>) -> Self {
        let mut me = Self {
            signatures: BTreeMap::new(),
        };
        me.add(sign);
        me
    }

    /// Constructs from iterator.
    ///
    /// SAFETY: Doesn't check number of signatures (should be >= 1) and signatures themselves
    pub fn from_iter_unchecked(iter: impl IntoIterator<Item = SignatureOf<T>>) -> Self
    where
        T: Send + Sync + 'static,
    {
        let signatures = iter
            .into_iter()
            .map(|sign| (sign.public_key.clone(), sign))
            .collect::<BTreeMap<_, _>>();
        Self { signatures }
    }

    /// Merges 2 signature collections
    pub fn merge(&mut self, mut other: Self) {
        self.signatures.append(&mut other.signatures)
    }

    /// Adds multiple signatures and replaces the duplicates.
    pub fn append(&mut self, signatures: &[SignatureOf<T>]) {
        for signature in signatures.iter().cloned() {
            self.add(signature.clone());
        }
    }

    /// Adds a signature. If the signature with this key was present, replaces it.
    pub fn add(&mut self, signature: SignatureOf<T>) {
        self.signatures
            .insert(signature.public_key.clone(), signature);
    }

    /// Whether signatures contain a signature with the specified `public_key`
    pub fn contains(&self, public_key: &PublicKey) -> bool {
        self.signatures.contains_key(public_key)
    }

    /// Returns signatures that have passed verification.
    pub fn verified_by_hash(
        &'_ self,
        hash: HashOf<T>,
    ) -> impl Iterator<Item = &'_ SignatureOf<T>> + '_ {
        self.signatures
            .values()
            .filter(move |sign| sign.verify_hash(&hash).is_ok())
    }

    /// Returns all signatures.
    pub fn values(&self) -> Vec<SignatureOf<T>> {
        self.signatures.values().cloned().collect()
    }

    /// Number of signatures.
    pub fn len(&self) -> usize {
        self.signatures.len()
    }
}

impl<T: Encode> SignaturesOf<T> {
    /// Creates new signatures container.
    /// # Errors
    /// Might fail in signature creation
    pub fn new(key_pair: KeyPair, value: &T) -> Result<Self> {
        SignatureOf::new(key_pair, value).map(Self::from_signature)
    }

    /// Constructs from iterator and also validates signatures
    /// # Errors
    /// Might fail in validation of signatures
    pub fn from_iter(value: &T, iter: impl IntoIterator<Item = SignatureOf<T>>) -> Result<Self>
    where
        T: Send + Sync + 'static,
    {
        let signatures = iter
            .into_iter()
            .map(|sign| (sign.public_key.clone(), sign))
            .collect::<BTreeMap<_, _>>();
        if signatures.is_empty() {
            return Err(eyre!("Please supply at least one signature"));
        }

        let hash = HashOf::new(value);
        signatures
            .values()
            .try_for_each(|sign| sign.verify_hash(&hash))
            .wrap_err("Failed to verify signatures")?;
        Ok(Self { signatures })
    }

    /// Verifies all signatures
    /// # Errors
    /// Fails if validation of any signature fails
    pub fn verify(&self, item: &T) -> Result<(), SignatureVerificationFail<T>> {
        let hash = HashOf::new(item);
        self.signatures
            .values()
            .try_for_each(|sign| sign.verify_hash(&hash))
    }

    /// Returns signatures that have passed verification.
    pub fn verified(&'_ self, value: &T) -> impl Iterator<Item = &'_ SignatureOf<T>> + '_ {
        let payload = HashOf::new(value);
        self.verified_by_hash(payload)
    }
}

impl<T: Encode> Decode for SignaturesOf<T> {
    fn decode<I: parity_scale_codec::Input>(
        input: &mut I,
    ) -> Result<Self, parity_scale_codec::Error> {
        Ok(Self {
            signatures: BTreeMap::decode(input)?,
        })
    }
    fn skip<I: parity_scale_codec::Input>(input: &mut I) -> Result<(), parity_scale_codec::Error> {
        BTreeMap::<PublicKey, SignatureOf<T>>::skip(input)
    }
    fn encoded_fixed_size() -> Option<usize> {
        BTreeMap::<PublicKey, SignatureOf<T>>::encoded_fixed_size()
    }
}

/// Verification failed of some signature due to following reason
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize, Decode, Encode, IntoSchema)]
pub struct SignatureVerificationFail<T> {
    /// Signature which verification has failed
    pub signature: Box<SignatureOf<T>>,
    /// Error which happened during verification
    pub reason: String,
}

impl<T> Debug for SignatureVerificationFail<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("SignatureVerificationFail")
            .field("signature", &self.signature.0)
            .field("reason", &self.reason)
            .finish()
    }
}

impl<T> Display for SignatureVerificationFail<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Failed to verify signatures because of signature {}: {}",
            self.signature.public_key, self.reason,
        )
    }
}

impl<T> StdError for SignatureVerificationFail<T> {}

#[cfg(test)]
mod tests {
    #![allow(clippy::restriction)]

    use super::*;
    use crate::KeyGenConfiguration;

    #[test]
    fn create_signature_ed25519() {
        let key_pair = KeyPair::generate_with_configuration(
            KeyGenConfiguration::default().with_algorithm(Algorithm::Ed25519),
        )
        .expect("Failed to generate key pair.");
        let message = b"Test message to sign.";
        let signature =
            Signature::new(key_pair.clone(), message).expect("Failed to create signature.");
        assert_eq!(signature.public_key, key_pair.public_key);
        assert!(signature.verify(message).is_ok())
    }

    #[test]
    fn create_signature_secp256k1() {
        let key_pair = KeyPair::generate_with_configuration(
            KeyGenConfiguration::default().with_algorithm(Algorithm::Secp256k1),
        )
        .expect("Failed to generate key pair.");
        let message = b"Test message to sign.";
        let signature =
            Signature::new(key_pair.clone(), message).expect("Failed to create signature.");
        assert_eq!(signature.public_key, key_pair.public_key);
        assert!(signature.verify(message).is_ok())
    }

    #[test]
    fn create_signature_bls_normal() {
        let key_pair = KeyPair::generate_with_configuration(
            KeyGenConfiguration::default().with_algorithm(Algorithm::BlsNormal),
        )
        .expect("Failed to generate key pair.");
        let message = b"Test message to sign.";
        let signature =
            Signature::new(key_pair.clone(), message).expect("Failed to create signature.");
        assert_eq!(signature.public_key, key_pair.public_key);
        assert!(signature.verify(message).is_ok())
    }

    #[test]
    fn create_signature_bls_small() {
        let key_pair = KeyPair::generate_with_configuration(
            KeyGenConfiguration::default().with_algorithm(Algorithm::BlsSmall),
        )
        .expect("Failed to generate key pair.");
        let message = b"Test message to sign.";
        let signature =
            Signature::new(key_pair.clone(), message).expect("Failed to create signature.");
        assert_eq!(signature.public_key, key_pair.public_key);
        assert!(signature.verify(message).is_ok())
    }
}
