//! This module contains structures and implementations related to the cryptographic parts of the Iroha.
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "ffi_import"))]
pub mod encryption;
mod hash;
#[cfg(not(feature = "ffi_import"))]
pub mod kex;
mod merkle;
#[cfg(not(feature = "ffi_import"))]
mod multihash;
mod secrecy;
mod signature;
#[cfg(not(feature = "ffi_import"))]
mod varint;

#[cfg(not(feature = "std"))]
use alloc::{
    borrow::ToOwned as _,
    boxed::Box,
    format,
    string::{String, ToString as _},
    vec,
    vec::Vec,
};
use core::{fmt, str::FromStr};

#[cfg(not(feature = "ffi_import"))]
pub use blake2;
use derive_more::Display;
pub use error::Error;
use error::{NoSuchAlgorithm, ParseError};
use getset::Getters;
pub use hash::*;
use iroha_macro::ffi_impl_opaque;
use iroha_primitives::const_vec::ConstVec;
use iroha_schema::{Declaration, IntoSchema, MetaMap, Metadata, NamedFieldsMeta, TypeId};
#[cfg(target_family = "wasm")]
use lazy::PublicKeyLazy;
pub use merkle::MerkleTree;
#[cfg(not(feature = "ffi_import"))]
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize, Serializer};
use serde_with::{DeserializeFromStr, SerializeDisplay};
use w3f_bls::SerializableToBytes;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub use self::signature::*;
use crate::secrecy::Secret;

// Hiding constants is a bad idea. For one, you're forcing the user to
// create temporaries, but also you're not actually hiding any
// information that can be used in malicious ways. If you want to hide
// these, I'd prefer inlining them instead.

/// String algorithm representation
pub const ED_25519: &str = "ed25519";
/// String algorithm representation
pub const SECP_256_K1: &str = "secp256k1";
/// String algorithm representation
pub const BLS_NORMAL: &str = "bls_normal";
/// String algorithm representation
pub const BLS_SMALL: &str = "bls_small";

ffi::ffi_item! {
    /// Algorithm for hashing & signing
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, DeserializeFromStr, SerializeDisplay, Decode, Encode, IntoSchema)]
    #[repr(u8)]
    pub enum Algorithm {
        #[default]
        #[allow(missing_docs)]
        Ed25519,
        #[allow(missing_docs)]
        Secp256k1,
        #[allow(missing_docs)]
        BlsNormal,
        #[allow(missing_docs)]
        BlsSmall,
    }
}

impl Algorithm {
    /// Maps the algorithm to its static string representation
    pub const fn as_static_str(self) -> &'static str {
        match self {
            Self::Ed25519 => ED_25519,
            Self::Secp256k1 => SECP_256_K1,
            Self::BlsNormal => BLS_NORMAL,
            Self::BlsSmall => BLS_SMALL,
        }
    }
}

impl fmt::Display for Algorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_static_str())
    }
}

impl FromStr for Algorithm {
    type Err = NoSuchAlgorithm;

    fn from_str(algorithm: &str) -> Result<Self, Self::Err> {
        match algorithm {
            ED_25519 => Ok(Algorithm::Ed25519),
            SECP_256_K1 => Ok(Algorithm::Secp256k1),
            BLS_NORMAL => Ok(Algorithm::BlsNormal),
            BLS_SMALL => Ok(Algorithm::BlsSmall),
            _ => Err(NoSuchAlgorithm),
        }
    }
}

/// Key pair generation option. Passed to a specific algorithm.
#[derive(Debug)]
pub enum KeyGenOption<K> {
    /// Use random number generator
    #[cfg(feature = "rand")]
    Random,
    /// Use seed
    UseSeed(Vec<u8>),
    /// Derive from a private key
    FromPrivateKey(K),
}

ffi::ffi_item! {
    /// Pair of Public and Private keys.
    #[derive(Clone, PartialEq, Eq, Getters)]
    #[cfg_attr(not(feature="ffi_import"), derive(Debug, Serialize))]
    #[getset(get = "pub")]
    pub struct KeyPair {
        /// Public key.
        public_key: PublicKey,
        /// Private key.
        private_key: PrivateKey,
    }
}

#[cfg(feature = "rand")]
impl KeyPair {
    /// Generate a random key pair using a default [`Algorithm`].
    pub fn random() -> Self {
        Self::random_with_algorithm(Algorithm::default())
    }

    /// Generate a random key pair
    pub fn random_with_algorithm(algorithm: Algorithm) -> Self {
        macro_rules! with_algorithm_variations {
            ($(($alg:ident, $alg_mod:path)),+) => {
                match algorithm {
                    $(Algorithm::$alg => <$alg_mod>::keypair(KeyGenOption::Random).into()),*
                }
            }
        }

        with_algorithm_variations!(
            (Ed25519, ed25519::Ed25519Sha512),
            (Secp256k1, secp256k1::EcdsaSecp256k1Sha256),
            (BlsNormal, bls::BlsNormal),
            (BlsSmall, bls::BlsSmall)
        )
    }
}

#[ffi_impl_opaque]
impl KeyPair {
    /// Derive a key pair from a seed using pRNG
    pub fn from_seed(seed: Vec<u8>, algorithm: Algorithm) -> Self {
        macro_rules! with_algorithm_variations {
            ($(($alg:ident, $alg_mod:path)),+) => {
                match algorithm {
                    $(Algorithm::$alg => <$alg_mod>::keypair(KeyGenOption::UseSeed(seed)).into()),*
                }
            }
        }

        with_algorithm_variations!(
            (Ed25519, ed25519::Ed25519Sha512),
            (Secp256k1, secp256k1::EcdsaSecp256k1Sha256),
            (BlsNormal, bls::BlsNormal),
            (BlsSmall, bls::BlsSmall)
        )
    }

    /// Algorithm
    pub fn algorithm(&self) -> Algorithm {
        self.private_key.algorithm()
    }

    /// Construct a [`KeyPair`].
    ///
    /// See [`Self::into_parts`] for an opposite conversion.
    ///
    /// # Errors
    /// If public and private keys don't match, i.e. if they don't make a pair
    pub fn new(public_key: PublicKey, private_key: PrivateKey) -> Result<Self, Error> {
        let algorithm = private_key.algorithm();

        if algorithm != public_key.algorithm() {
            return Err(Error::KeyGen("Mismatch of key algorithms".to_owned()));
        }

        if PublicKey::from(private_key.clone()) != public_key {
            return Err(Error::KeyGen(String::from("Key pair mismatch")));
        }

        Ok(Self {
            public_key,
            private_key,
        })
    }

    /// Get [`PublicKey`] and [`PrivateKey`] contained in the [`KeyPair`].
    ///
    /// See [`Self::from_raw_parts`] for an opposite conversion.
    pub fn into_parts(self) -> (PublicKey, PrivateKey) {
        (self.public_key, self.private_key)
    }
}

/// Derives full [`KeyPair`] from its [`PrivateKey`] only
// TODO: consider whether to use or not a method `KeyPair::from_private_key` instead/in addition.
impl From<PrivateKey> for KeyPair {
    fn from(value: PrivateKey) -> Self {
        use crate::secrecy::ExposeSecret;
        macro_rules! with_algorithm_variations {
            ($(($alg:ident, $alg_mod:path)),+) => {
                match value.0.expose_secret() {
                    $(
                        PrivateKeyInner::$alg(secret) => {
                            <$alg_mod>::keypair(KeyGenOption::FromPrivateKey(secret.clone())).into()
                        }
                    )*
                }
            }
        }

        with_algorithm_variations!(
            (Ed25519, ed25519::Ed25519Sha512),
            (Secp256k1, secp256k1::EcdsaSecp256k1Sha256),
            (BlsNormal, bls::BlsNormal),
            (BlsSmall, bls::BlsSmall)
        )
    }
}

impl From<(ed25519::PublicKey, ed25519::PrivateKey)> for KeyPair {
    fn from((public_key, private_key): (ed25519::PublicKey, ed25519::PrivateKey)) -> Self {
        Self {
            public_key: PublicKey::new(PublicKeyInner::Ed25519(public_key)),
            private_key: PrivateKey(Box::new(Secret::new(PrivateKeyInner::Ed25519(private_key)))),
        }
    }
}

impl From<(secp256k1::PublicKey, secp256k1::PrivateKey)> for KeyPair {
    fn from((public_key, private_key): (secp256k1::PublicKey, secp256k1::PrivateKey)) -> Self {
        Self {
            public_key: PublicKey::new(PublicKeyInner::Secp256k1(public_key)),
            private_key: PrivateKey(Box::new(Secret::new(PrivateKeyInner::Secp256k1(
                private_key,
            )))),
        }
    }
}

impl From<(bls::BlsNormalPublicKey, bls::BlsNormalPrivateKey)> for KeyPair {
    fn from(
        (public_key, private_key): (bls::BlsNormalPublicKey, bls::BlsNormalPrivateKey),
    ) -> Self {
        Self {
            public_key: PublicKey::new(PublicKeyInner::BlsNormal(public_key)),
            private_key: PrivateKey(Box::new(Secret::new(PrivateKeyInner::BlsNormal(
                private_key,
            )))),
        }
    }
}

impl From<(bls::BlsSmallPublicKey, bls::BlsSmallPrivateKey)> for KeyPair {
    fn from((public_key, private_key): (bls::BlsSmallPublicKey, bls::BlsSmallPrivateKey)) -> Self {
        Self {
            public_key: PublicKey::new(PublicKeyInner::BlsSmall(public_key)),
            private_key: PrivateKey(Box::new(Secret::new(PrivateKeyInner::BlsSmall(
                private_key,
            )))),
        }
    }
}

#[cfg(not(feature = "ffi_import"))]
impl<'de> Deserialize<'de> for KeyPair {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error as _;

        #[derive(Deserialize)]
        struct KeyPairCandidate {
            public_key: PublicKey,
            private_key: PrivateKey,
        }

        // NOTE: Verify that key pair is valid
        let key_pair = KeyPairCandidate::deserialize(deserializer)?;
        Self::new(key_pair.public_key, key_pair.private_key).map_err(D::Error::custom)
    }
}

#[derive(Clone, PartialEq, Eq)]
#[allow(missing_docs, variant_size_differences)]
enum PublicKeyInner {
    Ed25519(ed25519::PublicKey),
    Secp256k1(secp256k1::PublicKey),
    BlsNormal(bls::BlsNormalPublicKey),
    BlsSmall(bls::BlsSmallPublicKey),
}

impl PublicKeyInner {
    fn from_bytes(algorithm: Algorithm, payload: &[u8]) -> Result<Self, ParseError> {
        match algorithm {
            Algorithm::Ed25519 => {
                ed25519::Ed25519Sha512::parse_public_key(payload).map(PublicKeyInner::Ed25519)
            }
            Algorithm::Secp256k1 => secp256k1::EcdsaSecp256k1Sha256::parse_public_key(payload)
                .map(PublicKeyInner::Secp256k1),
            Algorithm::BlsNormal => {
                bls::BlsNormal::parse_public_key(payload).map(PublicKeyInner::BlsNormal)
            }
            Algorithm::BlsSmall => {
                bls::BlsSmall::parse_public_key(payload).map(PublicKeyInner::BlsSmall)
            }
        }
    }

    #[cfg(not(target_family = "wasm"))]
    fn to_raw(&self) -> (Algorithm, Vec<u8>) {
        (self.algorithm(), self.payload())
    }

    /// Key payload
    fn payload(&self) -> Vec<u8> {
        use w3f_bls::SerializableToBytes as _;

        match self {
            Self::Ed25519(key) => key.as_bytes().to_vec(),
            Self::Secp256k1(key) => key.to_sec1_bytes().to_vec(),
            Self::BlsNormal(key) => key.to_bytes(),
            Self::BlsSmall(key) => key.to_bytes(),
        }
    }

    fn algorithm(&self) -> Algorithm {
        match self {
            Self::Ed25519(_) => Algorithm::Ed25519,
            Self::Secp256k1(_) => Algorithm::Secp256k1,
            Self::BlsNormal(_) => Algorithm::BlsNormal,
            Self::BlsSmall(_) => Algorithm::BlsSmall,
        }
    }
}

/// `PublicKey` will be lazily deserialized inside WASM.
/// This is needed for performance reasons, since `PublicKeyInner::from_bytes` is quite slow.
/// However inside WASM in most cases `PublicKey` is used only for comparisons (==).
/// See https://github.com/hyperledger/iroha/issues/5038 for details.
#[cfg(target_family = "wasm")]
mod lazy {
    use alloc::{boxed::Box, vec::Vec};
    use core::{borrow::Borrow, cell::OnceCell};

    use crate::{Algorithm, PublicKeyInner};

    #[derive(Clone, Eq)]
    pub struct PublicKeyLazy {
        algorithm: Algorithm,
        payload: Vec<u8>,
        inner: OnceCell<Box<PublicKeyInner>>,
    }

    impl PublicKeyLazy {
        pub fn new(inner: PublicKeyInner) -> Self {
            Self {
                algorithm: inner.algorithm(),
                payload: inner.payload(),
                inner: OnceCell::from(Box::new(inner)),
            }
        }

        pub fn new_lazy(algorithm: Algorithm, payload: Vec<u8>) -> Self {
            Self {
                algorithm,
                payload,
                inner: OnceCell::new(),
            }
        }

        fn get_inner(&self) -> &PublicKeyInner {
            self.inner.get_or_init(|| {
                let inner = PublicKeyInner::from_bytes(self.algorithm, &self.payload)
                    .expect("Public key deserialization at WASM side must not fail because data received from host side");
                Box::new(inner)
            })
        }

        pub fn algorithm(&self) -> Algorithm {
            self.algorithm
        }

        pub fn to_raw(&self) -> (Algorithm, Vec<u8>) {
            (self.algorithm, self.payload.clone())
        }
    }

    impl Borrow<PublicKeyInner> for PublicKeyLazy {
        fn borrow(&self) -> &PublicKeyInner {
            self.get_inner()
        }
    }

    impl PartialEq for PublicKeyLazy {
        fn eq(&self, other: &Self) -> bool {
            self.algorithm == other.algorithm && self.payload == other.payload
        }
    }
}

#[cfg(not(target_family = "wasm"))]
type PublicKeyInnerType = Box<PublicKeyInner>;
#[cfg(target_family = "wasm")]
type PublicKeyInnerType = PublicKeyLazy;

ffi::ffi_item! {
    /// Public key used in signatures.
    ///
    /// Its serialized form ([`Serialize`], [`Deserialize`], [`Display`], [`FromStr`]) is
    /// represented as a [multihash](https://www.multiformats.io/multihash/) string.
    /// For example:
    ///
    /// ```
    /// use iroha_crypto::{PublicKey, Algorithm};
    ///
    /// let key = PublicKey::from_hex(
    ///     Algorithm::Ed25519,
    ///     "1509A611AD6D97B01D871E58ED00C8FD7C3917B6CA61A8C2833A19E000AAC2E4",
    /// )
    /// .unwrap();
    ///
    /// assert_eq!(
    ///     format!("{key}"),
    ///     "ed01201509A611AD6D97B01D871E58ED00C8FD7C3917B6CA61A8C2833A19E000AAC2E4"
    /// );
    /// ```
    #[derive(Clone, PartialEq, Eq, TypeId)]
    #[cfg_attr(not(feature="ffi_import"), derive(DeserializeFromStr, SerializeDisplay))]
    #[cfg_attr(all(feature = "ffi_export", not(feature = "ffi_import")), ffi_type(opaque))]
    #[allow(missing_docs)]
    pub struct PublicKey(PublicKeyInnerType);
}

#[ffi_impl_opaque]
impl PublicKey {
    #[cfg(not(target_family = "wasm"))]
    fn new(inner: PublicKeyInner) -> Self {
        Self(Box::new(inner))
    }
    #[cfg(target_family = "wasm")]
    fn new(inner: PublicKeyInner) -> Self {
        Self(PublicKeyLazy::new(inner))
    }

    /// Creates a new public key from raw bytes received from elsewhere
    ///
    /// # Errors
    ///
    /// Fails if public key parsing fails
    pub fn from_bytes(algorithm: Algorithm, payload: &[u8]) -> Result<Self, ParseError> {
        #[cfg(not(target_family = "wasm"))]
        let inner = Box::new(PublicKeyInner::from_bytes(algorithm, payload)?);
        #[cfg(target_family = "wasm")]
        let inner = PublicKeyLazy::new_lazy(algorithm, payload.to_vec());

        Ok(Self(inner))
    }

    /// Extracts raw bytes from the public key, copying the payload.
    ///
    /// `into_bytes()` without copying is not provided because underlying crypto
    /// libraries do not provide move functionality.
    pub fn to_bytes(&self) -> (Algorithm, Vec<u8>) {
        self.0.to_raw()
    }

    /// Construct from hex encoded string. A shorthand over [`Self::from_bytes`].
    ///
    /// # Errors
    ///
    /// - If the given payload is not hex encoded
    /// - If the given payload is not a valid private key
    pub fn from_hex(algorithm: Algorithm, payload: impl AsRef<str>) -> Result<Self, ParseError> {
        let payload = hex_decode(payload.as_ref())?;

        Self::from_bytes(algorithm, &payload)
    }

    /// Get the digital signature algorithm of the public key
    pub fn algorithm(&self) -> Algorithm {
        self.0.algorithm()
    }
}

#[cfg(not(feature = "ffi_import"))]
impl PublicKey {
    fn normalize(&self) -> String {
        let (algorithm, payload) = self.to_bytes();
        let bytes = multihash::encode_public_key(algorithm, &payload)
            .expect("Failed to convert multihash to bytes.");

        multihash::multihash_to_hex_string(&bytes)
    }
}

#[cfg(not(feature = "ffi_import"))]
impl core::hash::Hash for PublicKey {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        (self.to_bytes()).hash(state)
    }
}

impl PartialOrd for PublicKey {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PublicKey {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.to_bytes().cmp(&other.to_bytes())
    }
}

#[cfg(not(feature = "ffi_import"))]
impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // This could be simplified using `f.field_with` when `debug_closure_helpers` feature become stable
        struct Helper {
            algorithm: Algorithm,
            normalized: String,
        }
        impl fmt::Debug for Helper {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_tuple(self.algorithm.as_static_str())
                    .field(&self.normalized)
                    .finish()
            }
        }

        let helper = Helper {
            algorithm: self.algorithm(),
            normalized: self.normalize(),
        };
        f.debug_tuple("PublicKey").field(&helper).finish()
    }
}

#[cfg(not(feature = "ffi_import"))]
impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.normalize())
    }
}

#[cfg(not(feature = "ffi_import"))]
impl FromStr for PublicKey {
    type Err = ParseError;

    fn from_str(key: &str) -> Result<Self, Self::Err> {
        let bytes = hex_decode(key)?;
        let (algorithm, payload) = multihash::decode_public_key(&bytes)?;
        Self::from_bytes(algorithm, &payload)
    }
}

#[cfg(not(feature = "ffi_import"))]
impl Encode for PublicKey {
    fn size_hint(&self) -> usize {
        self.to_bytes().size_hint()
    }

    fn encode_to<W: parity_scale_codec::Output + ?Sized>(&self, dest: &mut W) {
        self.to_bytes().encode_to(dest);
    }
}

#[cfg(not(feature = "ffi_import"))]
impl Decode for PublicKey {
    fn decode<I: parity_scale_codec::Input>(
        input: &mut I,
    ) -> Result<Self, parity_scale_codec::Error> {
        let algorithm = Algorithm::decode(input)?;
        let payload = Vec::decode(input)?;
        Self::from_bytes(algorithm, &payload).map_err(|_| {
            parity_scale_codec::Error::from(
                "Failed to construct public key from digest function and payload",
            )
        })
    }
}

#[cfg(not(feature = "ffi_import"))]
impl IntoSchema for PublicKey {
    fn type_name() -> String {
        Self::id()
    }

    fn update_schema_map(metamap: &mut MetaMap) {
        if !metamap.contains_key::<Self>() {
            if !metamap.contains_key::<Algorithm>() {
                <Algorithm as iroha_schema::IntoSchema>::update_schema_map(metamap);
            }
            if !metamap.contains_key::<ConstVec<u8>>() {
                <ConstVec<u8> as iroha_schema::IntoSchema>::update_schema_map(metamap);
            }

            metamap.insert::<Self>(Metadata::Struct(NamedFieldsMeta {
                declarations: vec![
                    Declaration {
                        name: String::from("algorithm"),
                        ty: core::any::TypeId::of::<Algorithm>(),
                    },
                    Declaration {
                        name: String::from("payload"),
                        ty: core::any::TypeId::of::<ConstVec<u8>>(),
                    },
                ],
            }));
        }
    }
}

// TODO: Enable in ffi_import
#[cfg(not(feature = "ffi_import"))]
impl From<PrivateKey> for PublicKey {
    fn from(private_key: PrivateKey) -> Self {
        macro_rules! with_algorithm_variations {
            ($private_inner:expr, $(($alg:ident, $alg_mod:path)),+) => {
                match $private_inner {
                    $(
                        PrivateKeyInner::$alg(secret) => {
                            PublicKeyInner::$alg(<$alg_mod>::keypair(KeyGenOption::FromPrivateKey(secret.clone())).0)
                        }
                    )*
                }
            }
        }

        use crate::secrecy::ExposeSecret;
        let inner = with_algorithm_variations!(
            private_key.0.expose_secret(),
            (Ed25519, ed25519::Ed25519Sha512),
            (Secp256k1, secp256k1::EcdsaSecp256k1Sha256),
            (BlsNormal, bls::BlsNormal),
            (BlsSmall, bls::BlsSmall)
        );

        Self::new(inner)
    }
}

#[derive(Clone)]
#[allow(missing_docs, variant_size_differences)]
enum PrivateKeyInner {
    Ed25519(ed25519::PrivateKey),
    Secp256k1(secp256k1::PrivateKey),
    BlsNormal(bls::BlsNormalPrivateKey),
    BlsSmall(bls::BlsSmallPrivateKey),
}

ffi::ffi_item! {
    /// Private Key used in signatures.
    #[derive(Clone, DeserializeFromStr)]
    #[cfg_attr(all(feature = "ffi_export", not(feature = "ffi_import")), ffi_type(opaque))]
    #[allow(missing_docs, variant_size_differences)]
    pub struct PrivateKey(Box<Secret<PrivateKeyInner>>);
}

impl PartialEq for PrivateKey {
    fn eq(&self, other: &Self) -> bool {
        use crate::secrecy::ExposeSecret;
        match (self.0.expose_secret(), other.0.expose_secret()) {
            (PrivateKeyInner::Ed25519(l), PrivateKeyInner::Ed25519(r)) => l == r,
            (PrivateKeyInner::Secp256k1(l), PrivateKeyInner::Secp256k1(r)) => l == r,
            (PrivateKeyInner::BlsNormal(l), PrivateKeyInner::BlsNormal(r)) => {
                l.to_bytes() == r.to_bytes()
            }
            (PrivateKeyInner::BlsSmall(l), PrivateKeyInner::BlsSmall(r)) => {
                l.to_bytes() == r.to_bytes()
            }
            _ => false,
        }
    }
}

impl Eq for PrivateKey {}

impl PrivateKey {
    /// Creates a new public key from raw bytes received from elsewhere
    ///
    /// # Errors
    ///
    /// - If the given payload is not a valid private key for the given digest function
    pub fn from_bytes(algorithm: Algorithm, payload: &[u8]) -> Result<Self, ParseError> {
        match algorithm {
            Algorithm::Ed25519 => {
                ed25519::Ed25519Sha512::parse_private_key(payload).map(PrivateKeyInner::Ed25519)
            }
            Algorithm::Secp256k1 => secp256k1::EcdsaSecp256k1Sha256::parse_private_key(payload)
                .map(PrivateKeyInner::Secp256k1),
            Algorithm::BlsNormal => {
                bls::BlsNormal::parse_private_key(payload).map(PrivateKeyInner::BlsNormal)
            }
            Algorithm::BlsSmall => {
                bls::BlsSmall::parse_private_key(payload).map(PrivateKeyInner::BlsSmall)
            }
        }
        .map(Secret::new)
        .map(Box::new)
        .map(PrivateKey)
    }

    /// Construct [`PrivateKey`] from hex encoded string.
    /// A shorthand over [`PrivateKey::from_bytes`]
    ///
    /// # Errors
    ///
    /// - If the given payload is not hex encoded
    /// - If the given payload is not a valid private key
    pub fn from_hex(algorithm: Algorithm, payload: impl AsRef<str>) -> Result<Self, ParseError> {
        let payload = hex_decode(payload.as_ref())?;

        Self::from_bytes(algorithm, &payload)
    }

    /// Get the digital signature algorithm of the private key
    pub fn algorithm(&self) -> Algorithm {
        use crate::secrecy::ExposeSecret;
        match self.0.expose_secret() {
            PrivateKeyInner::Ed25519(_) => Algorithm::Ed25519,
            PrivateKeyInner::Secp256k1(_) => Algorithm::Secp256k1,
            PrivateKeyInner::BlsNormal(_) => Algorithm::BlsNormal,
            PrivateKeyInner::BlsSmall(_) => Algorithm::BlsSmall,
        }
    }

    /// Key payload
    fn payload(&self) -> Vec<u8> {
        use crate::secrecy::ExposeSecret;
        match self.0.expose_secret() {
            PrivateKeyInner::Ed25519(key) => key.to_bytes().to_vec(),
            PrivateKeyInner::Secp256k1(key) => key.to_bytes().to_vec(),
            PrivateKeyInner::BlsNormal(key) => key.to_bytes(),
            PrivateKeyInner::BlsSmall(key) => key.to_bytes(),
        }
    }

    /// Extracts the raw bytes from the private key, copying the payload.
    ///
    /// `into_bytes()` without copying is not provided because underlying crypto
    /// libraries do not provide move functionality.
    pub fn to_bytes(&self) -> (Algorithm, Vec<u8>) {
        (self.algorithm(), self.payload())
    }

    /// Wrap itself into [`ExposedPrivateKey`].
    pub fn expose(self) -> ExposedPrivateKey {
        ExposedPrivateKey(self)
    }
}

impl FromStr for PrivateKey {
    type Err = ParseError;

    fn from_str(key: &str) -> Result<Self, Self::Err> {
        let bytes = hex_decode(key)?;
        let (algorithm, payload) = multihash::decode_private_key(&bytes)?;
        PrivateKey::from_bytes(algorithm, &payload)
    }
}

impl ZeroizeOnDrop for PrivateKeyInner {}

impl Drop for PrivateKeyInner {
    fn drop(&mut self) {
        fn assert_will_zeroize_on_drop(_value: &mut impl ZeroizeOnDrop) {
            // checks that `zeroize` feature of `ed25519-dalek` crate is enabled
            // actual zeroize will be in `impl Drop` for nested key
        }
        match self {
            PrivateKeyInner::Ed25519(key) => {
                assert_will_zeroize_on_drop(key);
            }
            PrivateKeyInner::Secp256k1(key) => {
                assert_will_zeroize_on_drop(key);
            }
            PrivateKeyInner::BlsNormal(key) => {
                key.0 .0 .0.zeroize();
            }
            PrivateKeyInner::BlsSmall(key) => {
                key.0 .0 .0.zeroize();
            }
        }
    }
}

const PRIVATE_KEY_REDACTED: &str = "[REDACTED PrivateKey]";

#[cfg(not(feature = "ffi_import"))]
impl core::fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        PRIVATE_KEY_REDACTED.fmt(f)
    }
}

#[cfg(not(feature = "ffi_import"))]
impl core::fmt::Display for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        PRIVATE_KEY_REDACTED.fmt(f)
    }
}

impl Serialize for PrivateKey {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        PRIVATE_KEY_REDACTED.serialize(serializer)
    }
}

/// Use when you need to format/serialize private key (e.g in kagami)
#[derive(Eq, PartialEq)]
#[cfg_attr(
    not(feature = "ffi_import"),
    derive(DeserializeFromStr, SerializeDisplay)
)]
pub struct ExposedPrivateKey(pub PrivateKey);

impl FromStr for ExposedPrivateKey {
    type Err = ParseError;

    fn from_str(key: &str) -> Result<Self, Self::Err> {
        let private_key = key.parse()?;
        Ok(ExposedPrivateKey(private_key))
    }
}

impl ExposedPrivateKey {
    fn normalize(&self) -> String {
        let (algorithm, payload) = self.0.to_bytes();
        let bytes = multihash::encode_private_key(algorithm, &payload)
            .expect("Failed to convert multihash to bytes.");

        multihash::multihash_to_hex_string(&bytes)
    }
}

#[cfg(not(feature = "ffi_import"))]
impl fmt::Debug for ExposedPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple(self.0.algorithm().as_static_str())
            .field(&self.normalize())
            .finish()
    }
}

#[cfg(not(feature = "ffi_import"))]
impl fmt::Display for ExposedPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.normalize())
    }
}

/// A session key derived from a key exchange. Will usually be used for a symmetric encryption afterwards
pub struct SessionKey(ConstVec<u8>);

impl SessionKey {
    /// Expose the raw bytes of the session key
    pub fn payload(&self) -> &[u8] {
        self.0.as_ref()
    }
}

/// Shim for decoding hexadecimal strings
pub(crate) fn hex_decode<T: AsRef<[u8]> + ?Sized>(payload: &T) -> Result<Vec<u8>, ParseError> {
    hex::decode(payload).map_err(|err| ParseError(err.to_string()))
}

pub mod error {
    //! Module containing errors
    use super::*;

    /// Error indicating algorithm could not be found
    #[derive(Debug, Display, Clone, Copy)]
    #[display(fmt = "Algorithm not supported")]
    pub struct NoSuchAlgorithm;

    #[cfg(feature = "std")]
    impl std::error::Error for NoSuchAlgorithm {}

    /// Error parsing a key
    #[derive(Debug, Display, Clone, serde::Deserialize, PartialEq, Eq)]
    #[display(fmt = "{_0}")]
    pub struct ParseError(pub(crate) String);

    #[cfg(feature = "std")]
    impl std::error::Error for ParseError {}

    /// Error when dealing with cryptographic functions
    #[derive(Debug, Display, serde::Deserialize, PartialEq, Eq)]
    pub enum Error {
        /// Returned when trying to create an algorithm which does not exist
        #[display(fmt = "Algorithm doesn't exist")] // TODO: which algorithm
        NoSuchAlgorithm(String),
        /// Occurs during deserialization of a private or public key
        #[display(fmt = "Key could not be parsed. {_0}")]
        Parse(ParseError),
        /// Returned when an error occurs during the signing process
        #[display(fmt = "Signing failed. {_0}")]
        Signing(String),
        /// Returned when an error occurs during the signature verification process
        #[display(fmt = "Signature verification failed")]
        BadSignature,
        /// Returned when an error occurs during key generation
        #[display(fmt = "Key generation failed. {_0}")]
        KeyGen(String),
        /// A General purpose error message that doesn't fit in any category
        #[display(fmt = "General error. {_0}")] // This is going to cause a headache
        Other(String),
    }

    impl From<NoSuchAlgorithm> for Error {
        fn from(source: NoSuchAlgorithm) -> Self {
            Self::NoSuchAlgorithm(source.to_string())
        }
    }

    impl From<ParseError> for Error {
        fn from(source: ParseError) -> Self {
            Self::Parse(source)
        }
    }

    #[cfg(feature = "std")]
    impl std::error::Error for Error {}
}

mod ffi {
    //! Definitions and implementations of FFI related functionalities

    #[cfg(any(feature = "ffi_export", feature = "ffi_import"))]
    use super::*;

    macro_rules! ffi_item {
        ($it: item $($attr: meta)?) => {
            #[cfg(all(not(feature = "ffi_export"), not(feature = "ffi_import")))]
            $it

            #[cfg(all(feature = "ffi_export", not(feature = "ffi_import")))]
            #[derive(iroha_ffi::FfiType)]
            #[iroha_ffi::ffi_export]
            $(#[$attr])?
            $it

            #[cfg(feature = "ffi_import")]
            iroha_ffi::ffi! {
                #[iroha_ffi::ffi_import]
                $(#[$attr])?
                $it
            }
        };
    }

    #[cfg(any(feature = "ffi_export", feature = "ffi_import"))]
    iroha_ffi::handles! {
        PublicKey,
        PrivateKey,
        KeyPair,
        Signature,
    }

    #[cfg(feature = "ffi_import")]
    iroha_ffi::decl_ffi_fns! { link_prefix="iroha_crypto" Drop, Clone, Eq, Ord, Default }
    #[cfg(all(feature = "ffi_export", not(feature = "ffi_import")))]
    iroha_ffi::def_ffi_fns! { link_prefix="iroha_crypto"
        Drop: { PublicKey, PrivateKey, KeyPair, Signature },
        Clone: { PublicKey, PrivateKey, KeyPair, Signature },
        Eq: { PublicKey, PrivateKey, KeyPair, Signature },
        Ord: { PublicKey, Signature },
    }

    // NOTE: Makes sure that only one `dealloc` is exported per generated dynamic library
    #[cfg(any(crate_type = "dylib", crate_type = "cdylib"))]
    #[cfg(all(feature = "ffi_export", not(feature = "ffi_import")))]
    mod dylib {
        #[cfg(not(feature = "std"))]
        use alloc::alloc;
        #[cfg(feature = "std")]
        use std::alloc;

        iroha_ffi::def_ffi_fns! {dealloc}
    }

    pub(crate) use ffi_item;
}

#[cfg(test)]
mod tests {
    use parity_scale_codec::{Decode, Encode};
    #[cfg(not(feature = "ffi_import"))]
    use serde::Deserialize;
    use serde_json::json;

    use super::*;

    #[test]
    fn algorithm_serialize_deserialize_consistent() {
        for algorithm in [
            Algorithm::Ed25519,
            Algorithm::Secp256k1,
            Algorithm::BlsNormal,
            Algorithm::BlsSmall,
        ] {
            assert_eq!(
                algorithm,
                serde_json::to_string(&algorithm)
                    .and_then(|algorithm| serde_json::from_str(&algorithm))
                    .unwrap_or_else(|_| panic!("Failed to de/serialize key {:?}", &algorithm))
            );
        }
    }

    #[test]
    #[cfg(feature = "rand")]
    fn key_pair_serialize_deserialize_consistent() {
        #[derive(Serialize)]
        struct ExposedKeyPair {
            public_key: PublicKey,
            private_key: ExposedPrivateKey,
        }

        for algorithm in [
            Algorithm::Ed25519,
            Algorithm::Secp256k1,
            Algorithm::BlsNormal,
            Algorithm::BlsSmall,
        ] {
            let key_pair = KeyPair::random_with_algorithm(algorithm);
            let exposed_key_pair = ExposedKeyPair {
                public_key: key_pair.public_key.clone(),
                private_key: ExposedPrivateKey(key_pair.private_key.clone()),
            };

            assert_eq!(
                key_pair,
                serde_json::to_string(&exposed_key_pair)
                    .and_then(|key_pair| serde_json::from_str(&key_pair))
                    .unwrap_or_else(|_| panic!("Failed to de/serialize key {:?}", &key_pair))
            );
        }
    }

    #[test]
    fn private_key_format_or_serialize_redacted() {
        let key_pair = KeyPair::random();
        let (_, private_key) = key_pair.into_parts();

        assert_eq!(
            serde_json::to_string(&private_key).expect("Couldn't serialize key"),
            format!("\"{PRIVATE_KEY_REDACTED}\"")
        );
        assert_eq!(format!("{}", &private_key), PRIVATE_KEY_REDACTED);
    }

    #[test]
    fn encode_decode_algorithm_consistent() {
        for algorithm in [
            Algorithm::Ed25519,
            Algorithm::Secp256k1,
            Algorithm::BlsNormal,
            Algorithm::BlsSmall,
        ] {
            let encoded_algorithm = algorithm.encode();

            let decoded_algorithm =
                Algorithm::decode(&mut encoded_algorithm.as_slice()).expect("Failed to decode");
            assert_eq!(
                algorithm, decoded_algorithm,
                "Failed to decode encoded {:?}",
                &algorithm
            );
        }
    }

    #[test]
    fn key_pair_match() {
        KeyPair::new(
            "ed012059C8A4DA1EBB5380F74ABA51F502714652FDCCE9611FAFB9904E4A3C4D382774"
                .parse()
                .expect("Public key not in mulithash format"),
            "80262093CA389FC2979F3F7D2A7F8B76C70DE6D5EAF5FA58D4F93CB8B0FB298D398ACC"
                .parse()
                .expect("Private key not in mulithash format"),
        )
        .unwrap();

        KeyPair::new("ea01309060D021340617E9554CCBC2CF3CC3DB922A9BA323ABDF7C271FCC6EF69BE7A8DEBCA7D9E96C0F0089ABA22CDAADE4A2"
            .parse()
            .expect("Public key not in multihash format"),
            "8926201ca347641228c3b79aa43839dedc85fa51c0e8b9b6a00f6b0d6b0423e902973f"
            .parse()
            .expect("Private key not in multihash format")
        ).unwrap();
    }

    #[test]
    #[cfg(feature = "rand")]
    fn encode_decode_public_key_consistent() {
        for algorithm in [
            Algorithm::Ed25519,
            Algorithm::Secp256k1,
            Algorithm::BlsNormal,
            Algorithm::BlsSmall,
        ] {
            let key_pair = KeyPair::random_with_algorithm(algorithm);
            let (public_key, _) = key_pair.into_parts();

            let encoded_public_key = public_key.encode();

            let decoded_public_key =
                PublicKey::decode(&mut encoded_public_key.as_slice()).expect("Failed to decode");
            assert_eq!(
                public_key, decoded_public_key,
                "Failed to decode encoded Public Key{:?}",
                &public_key
            );
        }
    }

    #[test]
    fn invalid_private_key() {
        assert!(PrivateKey::from_hex(
            Algorithm::Ed25519,
            "0000000000000000000000000000000049BF70187154C57B97AF913163E8E875733B4EAF1F3F0689B31CE392129493E9"
        ).is_err());

        assert!(
            PrivateKey::from_hex(
                Algorithm::BlsNormal,
                "93CA389FC2979F3F7D2A7F8B76C70DE6D5EAF5FA58D4F93CB8B0FB298D398ACC59C8A4DA1EBB5380F74ABA51F502714652FDCCE9611FAFB9904E4A3C4D382774"
            ).is_err());
    }

    #[test]
    fn key_pair_mismatch() {
        KeyPair::new(
            "ed012059C8A4DA1EBB5380F74ABA51F502714652FDCCE9611FAFB9904E4A3C4D382774"
                .parse()
                .expect("Public key not in mulithash format"),
            "8026203A7991AF1ABB77F3FD27CC148404A6AE4439D095A63591B77C788D53F708A02A"
                .parse()
                .expect("Public key not in mulithash format"),
        )
        .unwrap_err();

        KeyPair::new("ea01309060D021340617E9554CCBC2CF3CC3DB922A9BA323ABDF7C271FCC6EF69BE7A8DEBCA7D9E96C0F0089ABA22CDAADE4A2"
            .parse()
            .expect("Public key not in mulithash format"),
            "892620CC176E44C41AA144FD1BEE4E0BCD2EF43F06D0C7BC2988E89A799951D240E503"
            .parse()
            .expect("Private key not in mulithash format"),
            ).unwrap_err();
    }

    #[test]
    #[cfg(not(feature = "ffi_import"))]
    fn display_public_key() {
        assert_eq!(
            format!(
                "{}",
                PublicKey::from_hex(
                    Algorithm::Ed25519,
                    "1509A611AD6D97B01D871E58ED00C8FD7C3917B6CA61A8C2833A19E000AAC2E4"
                )
                .unwrap()
            ),
            "ed01201509A611AD6D97B01D871E58ED00C8FD7C3917B6CA61A8C2833A19E000AAC2E4"
        );
        assert_eq!(
            format!(
                "{}",
                PublicKey::from_hex(
                    Algorithm::Secp256k1,
                    "0312273E8810581E58948D3FB8F9E8AD53AAA21492EBB8703915BBB565A21B7FCC"
                )
                .unwrap()
            ),
            "e701210312273E8810581E58948D3FB8F9E8AD53AAA21492EBB8703915BBB565A21B7FCC"
        );
        assert_eq!(
            format!(
                "{}",
                PublicKey::from_hex(
                    Algorithm::BlsNormal,
                    "9060D021340617E9554CCBC2CF3CC3DB922A9BA323ABDF7C271FCC6EF69BE7A8DEBCA7D9E96C0F0089ABA22CDAADE4A2",
                ).unwrap()
            ),
            "ea01309060D021340617E9554CCBC2CF3CC3DB922A9BA323ABDF7C271FCC6EF69BE7A8DEBCA7D9E96C0F0089ABA22CDAADE4A2",
        );
        assert_eq!(
            format!(
                "{}",
                PublicKey::from_hex(
                    Algorithm::BlsSmall,
                    "9051D4A9C69402423413EBBA4C00BC82A0102AA2B783057BD7BCEE4DD17B37DE5D719EE84BE43783F2AE47A673A74B8315DD3E595ED1FBDFAC17DA1D7A36F642B423ED18275FAFD671B1D331439D22F12FB6EB436A47E8656F182A78DF29D310",
                ).unwrap()
            ),
            "eb01609051D4A9C69402423413EBBA4C00BC82A0102AA2B783057BD7BCEE4DD17B37DE5D719EE84BE43783F2AE47A673A74B8315DD3E595ED1FBDFAC17DA1D7A36F642B423ED18275FAFD671B1D331439D22F12FB6EB436A47E8656F182A78DF29D310",
        );
    }
    #[cfg(not(feature = "ffi_import"))]
    #[derive(Debug, PartialEq, Deserialize, Serialize)]
    struct TestJson {
        public_key: PublicKey,
        private_key: ExposedPrivateKey,
    }

    macro_rules! assert_test_json_serde {
        ($json:expr, $actual:expr) => {
            assert_eq!(
                serde_json::from_value::<TestJson>($json.clone()).expect("failed to deserialize"),
                $actual
            );
            assert_eq!(
                serde_json::to_value($actual).expect("failed to serialize"),
                $json
            );
        };
    }

    #[test]
    #[cfg(not(feature = "ffi_import"))]
    fn serde_keys_ed25519() {
        assert_test_json_serde!(
            json!({
                "public_key": "ed01201509A611AD6D97B01D871E58ED00C8FD7C3917B6CA61A8C2833A19E000AAC2E4",
                "private_key": "8026203A7991AF1ABB77F3FD27CC148404A6AE4439D095A63591B77C788D53F708A02A"
            }),
            TestJson {
                public_key: PublicKey::from_hex(
                    Algorithm::Ed25519,
                    "1509A611AD6D97B01D871E58ED00C8FD7C3917B6CA61A8C2833A19E000AAC2E4"
                )
                .unwrap(),
                private_key: ExposedPrivateKey(
                    PrivateKey::from_hex(
                        Algorithm::Ed25519,
                        "3a7991af1abb77f3fd27cc148404a6ae4439d095a63591b77c788d53f708a02a",
                    )
                    .unwrap()
                )
            }
        );
    }

    #[test]
    #[cfg(not(feature = "ffi_import"))]
    fn serde_keys_secp256k1() {
        assert_test_json_serde!(
            json!({
                "public_key": "e701210312273E8810581E58948D3FB8F9E8AD53AAA21492EBB8703915BBB565A21B7FCC",
                "private_key": "8126204DF4FCA10762D4B529FE40A2188A60CA4469D2C50A825B5F33ADC2CB78C69445"
            }),
            TestJson {
                public_key: PublicKey::from_hex(
                    Algorithm::Secp256k1,
                    "0312273E8810581E58948D3FB8F9E8AD53AAA21492EBB8703915BBB565A21B7FCC"
                )
                .unwrap(),
                private_key: ExposedPrivateKey(
                    PrivateKey::from_hex(
                        Algorithm::Secp256k1,
                        "4DF4FCA10762D4B529FE40A2188A60CA4469D2C50A825B5F33ADC2CB78C69445",
                    )
                    .unwrap()
                )
            }
        );
    }

    #[test]
    #[cfg(not(feature = "ffi_import"))]
    fn serde_keys_bls() {
        assert_test_json_serde!(
            json!({
                "public_key": "ea01309060D021340617E9554CCBC2CF3CC3DB922A9BA323ABDF7C271FCC6EF69BE7A8DEBCA7D9E96C0F0089ABA22CDAADE4A2",
                "private_key": "8926201CA347641228C3B79AA43839DEDC85FA51C0E8B9B6A00F6B0D6B0423E902973F"
            }),
            TestJson {
                public_key: PublicKey::from_hex(
                    Algorithm::BlsNormal,
                    "9060D021340617E9554CCBC2CF3CC3DB922A9BA323ABDF7C271FCC6EF69BE7A8DEBCA7D9E96C0F0089ABA22CDAADE4A2",
                ).unwrap(),
                private_key: ExposedPrivateKey(PrivateKey::from_hex(
                    Algorithm::BlsNormal,
                    "1ca347641228c3b79aa43839dedc85fa51c0e8b9b6a00f6b0d6b0423e902973f",
                ).unwrap())
            }
        );
        assert_test_json_serde!(
            json!({
                "public_key": "eb01609051D4A9C69402423413EBBA4C00BC82A0102AA2B783057BD7BCEE4DD17B37DE5D719EE84BE43783F2AE47A673A74B8315DD3E595ED1FBDFAC17DA1D7A36F642B423ED18275FAFD671B1D331439D22F12FB6EB436A47E8656F182A78DF29D310",
                "private_key": "8a26208CB95072914CDD8E4CF682FDBE1189CDF4FC54D445E760B3446F896DBDBF5B2B"
            }),
            TestJson {
                public_key: PublicKey::from_hex(
                    Algorithm::BlsSmall,
                    "9051D4A9C69402423413EBBA4C00BC82A0102AA2B783057BD7BCEE4DD17B37DE5D719EE84BE43783F2AE47A673A74B8315DD3E595ED1FBDFAC17DA1D7A36F642B423ED18275FAFD671B1D331439D22F12FB6EB436A47E8656F182A78DF29D310",
                ).unwrap(),
                private_key: ExposedPrivateKey(PrivateKey::from_hex(
                    Algorithm::BlsSmall,
                    "8cb95072914cdd8e4cf682fdbe1189cdf4fc54d445e760b3446f896dbdbf5b2b",
                ).unwrap())
            }
        );
    }
}
