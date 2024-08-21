// pub(crate) for inner modules it is not redundant, the contents of `signature` module get re-exported at root
#![allow(clippy::redundant_pub_crate)]

#[cfg(not(feature = "ffi_import"))]
pub(crate) mod bls;

#[cfg(not(feature = "ffi_import"))]
pub(crate) mod ed25519;

#[cfg(not(feature = "ffi_import"))]
pub(crate) mod secp256k1;

#[cfg(not(feature = "std"))]
use alloc::{format, string::String, vec, vec::Vec};
use core::{borrow::Borrow as _, marker::PhantomData};

use arrayref::array_ref;
use derive_more::{Deref, DerefMut};
use iroha_primitives::const_vec::ConstVec;
use iroha_schema::{IntoSchema, TypeId};
use parity_scale_codec::{Decode, Encode};
use rand_core::{CryptoRngCore, SeedableRng as _};
#[cfg(not(feature = "ffi_import"))]
use serde::{Deserialize, Serialize};
use sha2::Digest as _;
use zeroize::Zeroize as _;

use crate::{error::ParseError, ffi, hex_decode, Error, HashOf, PrivateKey, PublicKey};

/// Construct cryptographic RNG from seed.
fn rng_from_seed(mut seed: Vec<u8>) -> impl CryptoRngCore {
    let hash = sha2::Sha256::digest(&seed);
    seed.zeroize();
    rand_chacha::ChaChaRng::from_seed(*array_ref!(hash.as_slice(), 0, 32))
}

ffi::ffi_item! {
    /// Represents a signature of the data (`Block` or `Transaction` for example).
    #[serde_with::serde_as]
    #[derive(Clone, PartialEq, Eq, PartialOrd, Ord, getset::Getters)]
    #[cfg_attr(not(feature="ffi_import"), derive(derive_more::DebugCustom, Hash, Decode, Encode, Deserialize, Serialize, IntoSchema))]
    #[cfg_attr(not(feature="ffi_import"), debug(fmt = "{{ {} }}", "hex::encode_upper(payload)"))]
    #[serde(transparent)]
    pub struct Signature {
        #[serde_as(as = "serde_with::hex::Hex<serde_with::formats::Uppercase>")]
        payload: ConstVec<u8>
    }
}

impl Signature {
    /// Creates new signature by signing payload via [`KeyPair::private_key`].
    pub fn new(private_key: &PrivateKey, payload: &[u8]) -> Self {
        use crate::secrecy::ExposeSecret;

        let signature = match private_key.0.expose_secret() {
            crate::PrivateKeyInner::Ed25519(sk) => ed25519::Ed25519Sha512::sign(payload, sk),
            crate::PrivateKeyInner::Secp256k1(sk) => {
                secp256k1::EcdsaSecp256k1Sha256::sign(payload, sk)
            }
            crate::PrivateKeyInner::BlsSmall(sk) => bls::BlsSmall::sign(payload, sk),
            crate::PrivateKeyInner::BlsNormal(sk) => bls::BlsNormal::sign(payload, sk),
        };

        Self {
            payload: ConstVec::new(signature),
        }
    }

    /// Creates new signature from its raw payload and public key.
    ///
    /// **This method does not sign the payload.** Use [`Signature::new`] for this purpose.
    ///
    /// This method exists to allow reproducing the signature in a more efficient way than through
    /// deserialization.
    pub fn from_bytes(payload: &[u8]) -> Self {
        Self {
            payload: ConstVec::new(payload),
        }
    }

    /// A shorthand for [`Self::from_bytes`] accepting payload as hex.
    ///
    /// # Errors
    /// If passed string is not a valid hex.
    pub fn from_hex(payload: impl AsRef<str>) -> Result<Self, ParseError> {
        let payload: Vec<u8> = hex_decode(payload.as_ref())?;
        Ok(Self::from_bytes(&payload))
    }

    /// Verify `payload` using signed data and [`KeyPair::public_key`].
    ///
    /// # Errors
    /// Fails if the message doesn't pass verification
    pub fn verify(&self, public_key: &PublicKey, payload: &[u8]) -> Result<(), Error> {
        match public_key.0.borrow() {
            crate::PublicKeyInner::Ed25519(pk) => {
                ed25519::Ed25519Sha512::verify(payload, &self.payload, pk)
            }
            crate::PublicKeyInner::Secp256k1(pk) => {
                secp256k1::EcdsaSecp256k1Sha256::verify(payload, &self.payload, pk)
            }
            crate::PublicKeyInner::BlsSmall(pk) => {
                bls::BlsSmall::verify(payload, &self.payload, pk)
            }
            crate::PublicKeyInner::BlsNormal(pk) => {
                bls::BlsNormal::verify(payload, &self.payload, pk)
            }
        }?;

        Ok(())
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

#[allow(clippy::unconditional_recursion)] // False-positive
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
        self.0.hash(state);
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
    #[inline]
    fn from_hash(private_key: &PrivateKey, hash: HashOf<T>) -> Self {
        Self(Signature::new(private_key, hash.as_ref()), PhantomData)
    }

    /// Verify signature for this hash
    ///
    /// # Errors
    ///
    /// Fails if the given hash didn't pass verification
    pub fn verify_hash(&self, public_key: &PublicKey, hash: HashOf<T>) -> Result<(), Error> {
        self.0.verify(public_key, hash.as_ref())
    }
}

impl<T: parity_scale_codec::Encode> SignatureOf<T> {
    /// Create [`SignatureOf`] by signing the given value with [`KeyPair::private_key`].
    /// The value provided will be hashed before being signed. If you already have the
    /// hash of the value you can sign it with [`SignatureOf::from_hash`] instead.
    ///
    /// # Errors
    /// Fails if signing fails
    #[inline]
    pub fn new(private_key: &PrivateKey, value: &T) -> Self {
        Self::from_hash(private_key, HashOf::new(value))
    }

    /// Verifies signature for this item
    ///
    /// # Errors
    /// Fails if verification fails
    pub fn verify(&self, public_key: &PublicKey, value: &T) -> Result<(), Error> {
        self.verify_hash(public_key, HashOf::new(value))
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::{Algorithm, KeyPair};

    #[test]
    #[cfg(feature = "rand")]
    fn create_signature_ed25519() {
        let key_pair = KeyPair::random_with_algorithm(crate::Algorithm::Ed25519);
        let message = b"Test message to sign.";
        let signature = Signature::new(key_pair.private_key(), message);
        signature.verify(key_pair.public_key(), message).unwrap();
    }

    #[test]
    #[cfg(feature = "rand")]
    fn create_signature_secp256k1() {
        let key_pair = KeyPair::random_with_algorithm(Algorithm::Secp256k1);
        let message = b"Test message to sign.";
        let signature = Signature::new(key_pair.private_key(), message);
        signature.verify(key_pair.public_key(), message).unwrap();
    }

    #[test]
    #[cfg(feature = "rand")]
    fn create_signature_bls_normal() {
        let key_pair = KeyPair::random_with_algorithm(Algorithm::BlsNormal);
        let message = b"Test message to sign.";
        let signature = Signature::new(key_pair.private_key(), message);
        signature.verify(key_pair.public_key(), message).unwrap();
    }

    #[test]
    #[cfg(all(feature = "rand", any(feature = "std", feature = "ffi_import")))]
    fn create_signature_bls_small() {
        let key_pair = KeyPair::random_with_algorithm(Algorithm::BlsSmall);
        let message = b"Test message to sign.";
        let signature = Signature::new(key_pair.private_key(), message);
        signature.verify(key_pair.public_key(), message).unwrap();
    }

    #[test]
    fn signature_serialized_representation() {
        let input = json!("3A7991AF1ABB77F3FD27CC148404A6AE4439D095A63591B77C788D53F708A02A1509A611AD6D97B01D871E58ED00C8FD7C3917B6CA61A8C2833A19E000AAC2E4");

        let signature: Signature = serde_json::from_value(input.clone()).unwrap();

        assert_eq!(serde_json::to_value(signature).unwrap(), input);
    }

    #[test]
    fn signature_from_hex_simply_reproduces_the_data() {
        let payload = "3a7991af1abb77f3fd27cc148404a6ae4439d095a63591b77c788d53f708a02a1509a611ad6d97b01d871e58ed00c8fd7c3917b6ca61a8c2833a19e000aac2e4";

        let value = Signature::from_hex(payload).unwrap();
        assert_eq!(value.payload.as_ref(), &hex::decode(payload).unwrap());
    }
}
