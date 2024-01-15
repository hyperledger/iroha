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

#[cfg(feature = "base64")]
pub use base64;
#[cfg(not(feature = "ffi_import"))]
pub use blake2;
use derive_more::Display;
use error::{Error, NoSuchAlgorithm, ParseError};
use getset::Getters;
pub use hash::*;
use iroha_macro::ffi_impl_opaque;
use iroha_primitives::const_vec::ConstVec;
use iroha_schema::{Declaration, IntoSchema, MetaMap, Metadata, NamedFieldsMeta, TypeId};
pub use merkle::MerkleTree;
#[cfg(not(feature = "ffi_import"))]
use parity_scale_codec::{Decode, Encode};
use serde::{ser::SerializeStruct, Deserialize, Serialize};
use serde_with::{DeserializeFromStr, SerializeDisplay};

pub use self::signature::*;

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

/// Options for key generation
#[cfg(not(feature = "ffi_import"))]
#[derive(Debug, Clone)]
pub enum KeyGenOption {
    /// Use seed
    UseSeed(Vec<u8>),
    /// Derive from private key
    FromPrivateKey(PrivateKey),
}

ffi::ffi_item! {
    /// Configuration of key generation
    #[derive(Clone, Default)]
    #[cfg_attr(not(feature="ffi_import"), derive(Debug))]
    pub struct KeyGenConfiguration {
        /// Options
        key_gen_option: Option<KeyGenOption>,
        /// Algorithm
        algorithm: Algorithm,
    }
}

#[ffi_impl_opaque]
impl KeyGenConfiguration {
    /// Use seed
    #[must_use]
    pub fn use_seed(mut self, seed: Vec<u8>) -> Self {
        self.key_gen_option = Some(KeyGenOption::UseSeed(seed));
        self
    }

    /// Use private key
    #[must_use]
    pub fn use_private_key(mut self, private_key: PrivateKey) -> Self {
        self.key_gen_option = Some(KeyGenOption::FromPrivateKey(private_key));
        self
    }

    /// With algorithm
    #[must_use]
    pub fn with_algorithm(mut self, algorithm: Algorithm) -> Self {
        self.algorithm = algorithm;
        self
    }
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

impl KeyPair {
    /// Generates a pair of Public and Private key with [`Algorithm::default()`] selected as generation algorithm.
    ///
    /// # Errors
    /// Fails if decoding fails
    pub fn generate() -> Result<Self, Error> {
        Self::generate_with_configuration(KeyGenConfiguration::default())
    }
}

#[ffi_impl_opaque]
impl KeyPair {
    /// Digest function
    pub fn digest_function(&self) -> Algorithm {
        self.private_key.algorithm()
    }

    /// Construct a [`KeyPair`]
    /// # Errors
    /// If public and private key don't match, i.e. if they don't make a pair
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

    /// Generates a pair of Public and Private key with the corresponding [`KeyGenConfiguration`].
    ///
    /// # Errors
    /// Fails if decoding fails
    pub fn generate_with_configuration(configuration: KeyGenConfiguration) -> Result<Self, Error> {
        let key_gen_option = match (configuration.algorithm, configuration.key_gen_option) {
            (Algorithm::Secp256k1, Some(KeyGenOption::UseSeed(seed))) if seed.len() < 32 => {
                return Err(Error::KeyGen(
                    "secp256k1 seed for must be at least 32 bytes long".to_owned(),
                ))
            }
            (_, key_gen_option) => key_gen_option,
        };

        Ok(match configuration.algorithm {
            Algorithm::Ed25519 => signature::ed25519::Ed25519Sha512::keypair(key_gen_option).into(),
            Algorithm::Secp256k1 => {
                signature::secp256k1::EcdsaSecp256k1Sha256::keypair(key_gen_option).into()
            }
            Algorithm::BlsNormal => signature::bls::BlsNormal::keypair(key_gen_option).into(),
            Algorithm::BlsSmall => signature::bls::BlsSmall::keypair(key_gen_option).into(),
        })
    }
}

impl From<(ed25519::PublicKey, ed25519::PrivateKey)> for KeyPair {
    fn from((public_key, private_key): (ed25519::PublicKey, ed25519::PrivateKey)) -> Self {
        Self {
            public_key: PublicKey::Ed25519(public_key),
            private_key: PrivateKey::Ed25519(Box::new(private_key)),
        }
    }
}

impl From<(secp256k1::PublicKey, secp256k1::PrivateKey)> for KeyPair {
    fn from((public_key, private_key): (secp256k1::PublicKey, secp256k1::PrivateKey)) -> Self {
        Self {
            public_key: PublicKey::Secp256k1(public_key),
            private_key: PrivateKey::Secp256k1(private_key),
        }
    }
}

impl From<(bls::BlsNormalPublicKey, bls::PrivateKey)> for KeyPair {
    fn from((public_key, private_key): (bls::BlsNormalPublicKey, bls::PrivateKey)) -> Self {
        Self {
            public_key: PublicKey::BlsNormal(public_key),
            private_key: PrivateKey::BlsNormal(private_key),
        }
    }
}

impl From<(bls::BlsSmallPublicKey, bls::PrivateKey)> for KeyPair {
    fn from((public_key, private_key): (bls::BlsSmallPublicKey, bls::PrivateKey)) -> Self {
        Self {
            public_key: PublicKey::BlsSmall(Box::new(public_key)),
            private_key: PrivateKey::BlsSmall(private_key),
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

// TODO: enable in ffi_import?
#[cfg(not(feature = "ffi_import"))]
impl From<KeyPair> for (PublicKey, PrivateKey) {
    fn from(key_pair: KeyPair) -> Self {
        (key_pair.public_key, key_pair.private_key)
    }
}

ffi::ffi_item! {
    /// Public Key used in signatures.
    #[derive(Clone, PartialEq, Eq)]
    #[cfg_attr(not(feature="ffi_import"), derive(DeserializeFromStr, SerializeDisplay))]
    #[cfg_attr(all(feature = "ffi_export", not(feature = "ffi_import")), ffi_type(opaque))]
    #[allow(missing_docs)]
    pub enum PublicKey {
        Ed25519(ed25519::PublicKey),
        Secp256k1(secp256k1::PublicKey),
        BlsNormal(bls::BlsNormalPublicKey),
        BlsSmall(Box<bls::BlsSmallPublicKey>),
    }
}

#[ffi_impl_opaque]
impl PublicKey {
    /// Creates a new public key from raw bytes received from elsewhere
    pub fn from_raw(algorithm: Algorithm, payload: &[u8]) -> Result<Self, ParseError> {
        match algorithm {
            Algorithm::Ed25519 => {
                ed25519::Ed25519Sha512::parse_public_key(payload).map(Self::Ed25519)
            }
            Algorithm::Secp256k1 => {
                secp256k1::EcdsaSecp256k1Sha256::parse_public_key(payload).map(Self::Secp256k1)
            }
            Algorithm::BlsNormal => bls::BlsNormal::parse_public_key(payload).map(Self::BlsNormal),
            Algorithm::BlsSmall => bls::BlsSmall::parse_public_key(payload)
                .map(Box::new)
                .map(Self::BlsSmall),
        }
    }

    /// Extracts the raw bytes from public key, copying the payload.
    ///
    /// `into_raw()` without copying is not provided because underlying crypto
    /// libraries do not provide move functionality.
    pub fn to_raw(&self) -> (Algorithm, Vec<u8>) {
        (self.algorithm(), self.payload())
    }

    /// Key payload
    fn payload(&self) -> Vec<u8> {
        match self {
            PublicKey::Ed25519(key) => key.as_bytes().to_vec(),
            PublicKey::Secp256k1(key) => key.to_sec1_bytes().to_vec(),
            PublicKey::BlsNormal(key) => key.to_bytes(),
            PublicKey::BlsSmall(key) => key.to_bytes(),
        }
    }

    /// Construct [`PublicKey`] from hex encoded string
    /// # Errors
    ///
    /// - If the given payload is not hex encoded
    /// - If the given payload is not a valid private key
    pub fn from_hex(digest_function: Algorithm, payload: &str) -> Result<Self, ParseError> {
        let payload = hex_decode(payload)?;

        Self::from_raw(digest_function, &payload)
    }

    /// Get the digital signature algorithm of the public key
    pub fn algorithm(&self) -> Algorithm {
        match self {
            Self::Ed25519(_) => Algorithm::Ed25519,
            Self::Secp256k1(_) => Algorithm::Secp256k1,
            Self::BlsNormal(_) => Algorithm::BlsNormal,
            Self::BlsSmall(_) => Algorithm::BlsSmall,
        }
    }
}

#[cfg(not(feature = "ffi_import"))]
impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple(self.algorithm().as_static_str())
            .field(&self.normalize())
            .finish()
    }
}

#[cfg(not(feature = "ffi_import"))]
impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.normalize())
    }
}

#[cfg(not(feature = "ffi_import"))]
impl core::hash::Hash for PublicKey {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        (self.algorithm(), self.payload()).hash(state)
    }
}

impl PartialOrd for PublicKey {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PublicKey {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        (self.algorithm(), self.payload()).cmp(&(other.algorithm(), other.payload()))
    }
}

#[cfg(not(feature = "ffi_import"))]
impl Encode for PublicKey {
    fn size_hint(&self) -> usize {
        self.algorithm().size_hint() + self.payload().size_hint()
    }

    fn encode_to<W: parity_scale_codec::Output + ?Sized>(&self, dest: &mut W) {
        self.algorithm().encode_to(dest);
        self.payload().encode_to(dest);
    }
}

#[cfg(not(feature = "ffi_import"))]
impl Decode for PublicKey {
    fn decode<I: parity_scale_codec::Input>(
        input: &mut I,
    ) -> Result<Self, parity_scale_codec::Error> {
        let digest_function = Algorithm::decode(input)?;
        let payload = <ConstVec<u8>>::decode(input)?;
        Self::from_raw(digest_function, &payload).map_err(|_| {
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

#[cfg(not(feature = "ffi_import"))]
impl TypeId for PublicKey {
    fn id() -> String {
        "PublicKey".to_owned()
    }
}

impl FromStr for PublicKey {
    type Err = ParseError;

    // TODO: Can we check the key is valid?
    fn from_str(key: &str) -> Result<Self, Self::Err> {
        let bytes = hex_decode(key)?;

        multihash::Multihash::try_from(bytes).map(Into::into)
    }
}

#[cfg(not(feature = "ffi_import"))]
impl PublicKey {
    fn normalize(&self) -> String {
        let multihash: &multihash::Multihash = &self.clone().into();
        let bytes = Vec::try_from(multihash).expect("Failed to convert multihash to bytes.");

        let mut bytes_iter = bytes.into_iter();
        let fn_code = hex::encode(bytes_iter.by_ref().take(2).collect::<Vec<_>>());
        let dig_size = hex::encode(bytes_iter.by_ref().take(1).collect::<Vec<_>>());
        let key = hex::encode_upper(bytes_iter.by_ref().collect::<Vec<_>>());

        format!("{fn_code}{dig_size}{key}")
    }
}

// TODO: Enable in ffi_import
#[cfg(not(feature = "ffi_import"))]
impl From<PrivateKey> for PublicKey {
    fn from(private_key: PrivateKey) -> Self {
        let digest_function = private_key.algorithm();
        let key_gen_option = Some(KeyGenOption::FromPrivateKey(private_key));

        match digest_function {
            Algorithm::Ed25519 => {
                PublicKey::Ed25519(ed25519::Ed25519Sha512::keypair(key_gen_option).0)
            }
            Algorithm::Secp256k1 => {
                PublicKey::Secp256k1(secp256k1::EcdsaSecp256k1Sha256::keypair(key_gen_option).0)
            }
            Algorithm::BlsNormal => PublicKey::BlsNormal(bls::BlsNormal::keypair(key_gen_option).0),
            Algorithm::BlsSmall => {
                PublicKey::BlsSmall(Box::new(bls::BlsSmall::keypair(key_gen_option).0))
            }
        }
    }
}

ffi::ffi_item! {
    /// Private Key used in signatures.
    #[derive(Clone, PartialEq, Eq)]
    #[cfg_attr(all(feature = "ffi_export", not(feature = "ffi_import")), ffi_type(opaque))]
    #[allow(missing_docs)]
    pub enum PrivateKey {
        Ed25519(Box<ed25519::PrivateKey>),
        Secp256k1(secp256k1::PrivateKey),
        BlsNormal(bls::PrivateKey),
        BlsSmall(bls::PrivateKey),
    }
}

impl PrivateKey {
    /// Creates a new public key from raw bytes received from elsewhere
    ///
    /// # Errors
    ///
    /// - If the given payload is not a valid private key for the given digest function
    pub fn from_raw(algorithm: Algorithm, payload: &[u8]) -> Result<Self, ParseError> {
        match algorithm {
            Algorithm::Ed25519 => ed25519::Ed25519Sha512::parse_private_key(payload)
                .map(Box::new)
                .map(Self::Ed25519),
            Algorithm::Secp256k1 => {
                secp256k1::EcdsaSecp256k1Sha256::parse_private_key(payload).map(Self::Secp256k1)
            }
            Algorithm::BlsNormal => bls::BlsNormal::parse_private_key(payload).map(Self::BlsNormal),
            Algorithm::BlsSmall => bls::BlsSmall::parse_private_key(payload).map(Self::BlsSmall),
        }
    }

    /// Construct [`PrivateKey`] from hex encoded string
    ///
    /// # Errors
    ///
    /// - If the given payload is not hex encoded
    /// - If the given payload is not a valid private key
    pub fn from_hex(algorithm: Algorithm, payload: &str) -> Result<Self, ParseError> {
        let payload = hex_decode(payload)?;
        let payload = ConstVec::new(payload);

        Self::from_raw(algorithm, &payload)
    }

    /// Get the digital signature algorithm of the private key
    pub fn algorithm(&self) -> Algorithm {
        match self {
            Self::Ed25519(_) => Algorithm::Ed25519,
            Self::Secp256k1(_) => Algorithm::Secp256k1,
            Self::BlsNormal(_) => Algorithm::BlsNormal,
            Self::BlsSmall(_) => Algorithm::BlsSmall,
        }
    }

    /// Key payload
    fn payload(&self) -> Vec<u8> {
        match self {
            Self::Ed25519(key) => key.to_keypair_bytes().to_vec(),
            Self::Secp256k1(key) => key.to_bytes().to_vec(),
            Self::BlsNormal(key) | Self::BlsSmall(key) => key.to_bytes(),
        }
    }
}

#[cfg(not(feature = "ffi_import"))]
impl core::fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple(self.algorithm().as_static_str())
            .field(&hex::encode_upper(self.payload()))
            .finish()
    }
}

#[cfg(not(feature = "ffi_import"))]
impl core::fmt::Display for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode_upper(self.payload()))
    }
}

#[cfg(not(feature = "ffi_import"))]
impl Serialize for PrivateKey {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("PublicKey", 2)?;
        state.serialize_field("digest_function", &self.algorithm())?;
        state.serialize_field("payload", &hex::encode(self.payload()))?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for PrivateKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error as _;

        #[derive(Deserialize)]
        struct PrivateKeyCandidate {
            digest_function: Algorithm,
            payload: String,
        }

        // NOTE: Verify that private key is valid
        let private_key = PrivateKeyCandidate::deserialize(deserializer)?;
        Self::from_hex(private_key.digest_function, private_key.payload.as_ref())
            .map_err(D::Error::custom)
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
        /// Returned when an error occurs during digest generation
        #[display(fmt = "Digest generation failed. {_0}")]
        DigestGen(String),
        /// Returned when an error occurs during creation of [`SignaturesOf`]
        #[display(fmt = "`SignaturesOf` must contain at least one signature")]
        EmptySignatureIter,
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
        KeyGenConfiguration,
        PublicKey,
        PrivateKey,
        KeyPair,
        Signature,
    }

    #[cfg(feature = "ffi_import")]
    iroha_ffi::decl_ffi_fns! { link_prefix="iroha_crypto" Drop, Clone, Eq, Ord, Default }
    #[cfg(all(feature = "ffi_export", not(feature = "ffi_import")))]
    iroha_ffi::def_ffi_fns! { link_prefix="iroha_crypto"
        Drop: { KeyGenConfiguration, PublicKey, PrivateKey, KeyPair, Signature },
        Clone: { KeyGenConfiguration, PublicKey, PrivateKey, KeyPair, Signature },
        Eq: { PublicKey, PrivateKey, KeyPair, Signature },
        Ord: { PublicKey, Signature },
        Default: { KeyGenConfiguration },
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

/// The prelude re-exports most commonly used traits, structs and macros from this crate.
pub mod prelude {
    pub use super::{Algorithm, Hash, KeyPair, PrivateKey, PublicKey, Signature};
}

#[cfg(test)]
mod tests {
    use parity_scale_codec::{Decode, Encode};
    #[cfg(not(feature = "ffi_import"))]
    use serde::Deserialize;

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
    fn key_pair_serialize_deserialize_consistent() {
        for algorithm in [
            Algorithm::Ed25519,
            Algorithm::Secp256k1,
            Algorithm::BlsNormal,
            Algorithm::BlsSmall,
        ] {
            let key_pair = KeyPair::generate_with_configuration(
                KeyGenConfiguration::default().with_algorithm(algorithm),
            )
            .expect("Failed to generate key pair");

            assert_eq!(
                key_pair,
                serde_json::to_string(&key_pair)
                    .and_then(|key_pair| serde_json::from_str(&key_pair))
                    .unwrap_or_else(|_| panic!("Failed to de/serialize key {:?}", &key_pair))
            );
        }
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
        assert!(KeyPair::new("ed012059C8A4DA1EBB5380F74ABA51F502714652FDCCE9611FAFB9904E4A3C4D382774"
            .parse()
            .expect("Public key not in mulithash format"),
        PrivateKey::from_hex(
            Algorithm::Ed25519,
            "93CA389FC2979F3F7D2A7F8B76C70DE6D5EAF5FA58D4F93CB8B0FB298D398ACC59C8A4DA1EBB5380F74ABA51F502714652FDCCE9611FAFB9904E4A3C4D382774"
        ).expect("Private key not hex encoded")).is_ok());

        assert!(KeyPair::new("ea0161040FCFADE2FC5D9104A9ACF9665EA545339DDF10AE50343249E01AF3B8F885CD5D52956542CCE8105DB3A2EC4006E637A7177FAAEA228C311F907DAAFC254F22667F1A1812BB710C6F4116A1415275D27BB9FB884F37E8EF525CC31F3945E945FA"
            .parse()
            .expect("Public key not in mulithash format"),
        PrivateKey::from_hex(
            Algorithm::BlsNormal,
            "0000000000000000000000000000000049BF70187154C57B97AF913163E8E875733B4EAF1F3F0689B31CE392129493E9"
        ).expect("Private key not hex encoded")).is_ok());
    }

    #[test]
    fn encode_decode_public_key_consistent() {
        for algorithm in [
            Algorithm::Ed25519,
            Algorithm::Secp256k1,
            Algorithm::BlsNormal,
            Algorithm::BlsSmall,
        ] {
            let key_pair = KeyPair::generate_with_configuration(
                KeyGenConfiguration::default().with_algorithm(algorithm),
            )
            .expect("Failed to generate key pair");
            let (public_key, _) = key_pair.into();

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
        assert!(KeyPair::new("ed012059C8A4DA1EBB5380F74ABA51F502714652FDCCE9611FAFB9904E4A3C4D382774"
            .parse()
            .expect("Public key not in mulithash format"),
        PrivateKey::from_hex(
            Algorithm::Ed25519,
            "3A7991AF1ABB77F3FD27CC148404A6AE4439D095A63591B77C788D53F708A02A1509A611AD6D97B01D871E58ED00C8FD7C3917B6CA61A8C2833A19E000AAC2E4"
        ).expect("Private key not valid")).is_err());

        assert!(KeyPair::new("ea0161040FCFADE2FC5D9104A9ACF9665EA545339DDF10AE50343249E01AF3B8F885CD5D52956542CCE8105DB3A2EC4006E637A7177FAAEA228C311F907DAAFC254F22667F1A1812BB710C6F4116A1415275D27BB9FB884F37E8EF525CC31F3945E945FA"
            .parse()
            .expect("Public key not in mulithash format"),
        PrivateKey::from_hex(
            Algorithm::BlsNormal,
            "000000000000000000000000000000002F57460183837EFBAC6AA6AB3B8DBB7CFFCFC59E9448B7860A206D37D470CBA3"
        ).expect("Private key not valid")).is_err());
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

                        "04175B1E79B15E8A2D5893BF7F8933CA7D0863105D8BAC3D6F976CB043378A0E4B885C57ED14EB85FC2FABC639ADC7DE7F0020C70C57ACC38DEE374AF2C04A6F61C11DE8DF9034B12D849C7EB90099B0881267D0E1507D4365D838D7DCC31511E7"
                ).unwrap()
            ),
            "ea016104175B1E79B15E8A2D5893BF7F8933CA7D0863105D8BAC3D6F976CB043378A0E4B885C57ED14EB85FC2FABC639ADC7DE7F0020C70C57ACC38DEE374AF2C04A6F61C11DE8DF9034B12D849C7EB90099B0881267D0E1507D4365D838D7DCC31511E7"
        );
        assert_eq!(
            format!(
                "{}",
                PublicKey::from_hex(
                    Algorithm::BlsSmall,

                        "040CB3231F601E7245A6EC9A647B450936F707CA7DC347ED258586C1924941D8BC38576473A8BA3BB2C37E3E121130AB67103498A96D0D27003E3AD960493DA79209CF024E2AA2AE961300976AEEE599A31A5E1B683EAA1BCFFC47B09757D20F21123C594CF0EE0BAF5E1BDD272346B7DC98A8F12C481A6B28174076A352DA8EAE881B90911013369D7FA960716A5ABC5314307463FA2285A5BF2A5B5C6220D68C2D34101A91DBFC531C5B9BBFB2245CCC0C50051F79FC6714D16907B1FC40E0C0"
                ).unwrap()
            ),
            "eb01c1040CB3231F601E7245A6EC9A647B450936F707CA7DC347ED258586C1924941D8BC38576473A8BA3BB2C37E3E121130AB67103498A96D0D27003E3AD960493DA79209CF024E2AA2AE961300976AEEE599A31A5E1B683EAA1BCFFC47B09757D20F21123C594CF0EE0BAF5E1BDD272346B7DC98A8F12C481A6B28174076A352DA8EAE881B90911013369D7FA960716A5ABC5314307463FA2285A5BF2A5B5C6220D68C2D34101A91DBFC531C5B9BBFB2245CCC0C50051F79FC6714D16907B1FC40E0C0"
        );
    }
    #[cfg(not(feature = "ffi_import"))]
    #[derive(Debug, PartialEq, Deserialize, Serialize)]
    struct TestJson {
        public_key: PublicKey,
        private_key: PrivateKey,
    }

    #[test]
    #[cfg(not(feature = "ffi_import"))]
    fn deserialize_keys_ed25519() {
        assert_eq!(
            serde_json::from_str::<'_, TestJson>("{
                \"public_key\": \"ed01201509A611AD6D97B01D871E58ED00C8FD7C3917B6CA61A8C2833A19E000AAC2E4\",
                \"private_key\": {
                    \"digest_function\": \"ed25519\",
                    \"payload\": \"3A7991AF1ABB77F3FD27CC148404A6AE4439D095A63591B77C788D53F708A02A1509A611AD6D97B01D871E58ED00C8FD7C3917B6CA61A8C2833A19E000AAC2E4\"
                }
            }").expect("Failed to deserialize."),
            TestJson {
                public_key: PublicKey::from_hex(
                    Algorithm::Ed25519,

                        "1509A611AD6D97B01D871E58ED00C8FD7C3917B6CA61A8C2833A19E000AAC2E4"
                ).unwrap(),
                private_key: PrivateKey::from_hex(
                    Algorithm::Ed25519,
                    "3A7991AF1ABB77F3FD27CC148404A6AE4439D095A63591B77C788D53F708A02A1509A611AD6D97B01D871E58ED00C8FD7C3917B6CA61A8C2833A19E000AAC2E4",
                ).unwrap()
            }
        );
    }

    #[test]
    #[cfg(not(feature = "ffi_import"))]
    fn deserialize_keys_secp256k1() {
        assert_eq!(
            serde_json::from_str::<'_, TestJson>("{
                \"public_key\": \"e701210312273E8810581E58948D3FB8F9E8AD53AAA21492EBB8703915BBB565A21B7FCC\",
                \"private_key\": {
                    \"digest_function\": \"secp256k1\",
                    \"payload\": \"4DF4FCA10762D4B529FE40A2188A60CA4469D2C50A825B5F33ADC2CB78C69445\"
                }
            }").expect("Failed to deserialize."),
            TestJson {
                public_key: PublicKey::from_hex(
                    Algorithm::Secp256k1,

                        "0312273E8810581E58948D3FB8F9E8AD53AAA21492EBB8703915BBB565A21B7FCC"
                ).unwrap(),
                private_key: PrivateKey::from_hex(
                    Algorithm::Secp256k1,
                    "4DF4FCA10762D4B529FE40A2188A60CA4469D2C50A825B5F33ADC2CB78C69445",
                ).unwrap()
            }
        );
    }

    #[test]
    #[cfg(not(feature = "ffi_import"))]
    fn deserialize_keys_bls() {
        assert_eq!(
            serde_json::from_str::<'_, TestJson>("{
                \"public_key\": \"ea016104175B1E79B15E8A2D5893BF7F8933CA7D0863105D8BAC3D6F976CB043378A0E4B885C57ED14EB85FC2FABC639ADC7DE7F0020C70C57ACC38DEE374AF2C04A6F61C11DE8DF9034B12D849C7EB90099B0881267D0E1507D4365D838D7DCC31511E7\",
                \"private_key\": {
                    \"digest_function\": \"bls_normal\",
                    \"payload\": \"000000000000000000000000000000002F57460183837EFBAC6AA6AB3B8DBB7CFFCFC59E9448B7860A206D37D470CBA3\"
                }
            }").expect("Failed to deserialize."),
            TestJson {
                public_key: PublicKey::from_hex(
                    Algorithm::BlsNormal,

                        "04175B1E79B15E8A2D5893BF7F8933CA7D0863105D8BAC3D6F976CB043378A0E4B885C57ED14EB85FC2FABC639ADC7DE7F0020C70C57ACC38DEE374AF2C04A6F61C11DE8DF9034B12D849C7EB90099B0881267D0E1507D4365D838D7DCC31511E7"
                ).unwrap(),
                private_key: PrivateKey::from_hex(
                    Algorithm::BlsNormal,
                    "000000000000000000000000000000002F57460183837EFBAC6AA6AB3B8DBB7CFFCFC59E9448B7860A206D37D470CBA3",
                ).unwrap()
            }
        );
        assert_eq!(
            serde_json::from_str::<'_, TestJson>("{
                \"public_key\": \"eb01C1040CB3231F601E7245A6EC9A647B450936F707CA7DC347ED258586C1924941D8BC38576473A8BA3BB2C37E3E121130AB67103498A96D0D27003E3AD960493DA79209CF024E2AA2AE961300976AEEE599A31A5E1B683EAA1BCFFC47B09757D20F21123C594CF0EE0BAF5E1BDD272346B7DC98A8F12C481A6B28174076A352DA8EAE881B90911013369D7FA960716A5ABC5314307463FA2285A5BF2A5B5C6220D68C2D34101A91DBFC531C5B9BBFB2245CCC0C50051F79FC6714D16907B1FC40E0C0\",
                \"private_key\": {
                    \"digest_function\": \"bls_small\",
                    \"payload\": \"0000000000000000000000000000000060F3C1AC9ADDBBED8DB83BC1B2EF22139FB049EECB723A557A41CA1A4B1FED63\"
                }
            }").expect("Failed to deserialize."),
            TestJson {
                public_key: PublicKey::from_hex(
                    Algorithm::BlsSmall,

                            "040CB3231F601E7245A6EC9A647B450936F707CA7DC347ED258586C1924941D8BC38576473A8BA3BB2C37E3E121130AB67103498A96D0D27003E3AD960493DA79209CF024E2AA2AE961300976AEEE599A31A5E1B683EAA1BCFFC47B09757D20F21123C594CF0EE0BAF5E1BDD272346B7DC98A8F12C481A6B28174076A352DA8EAE881B90911013369D7FA960716A5ABC5314307463FA2285A5BF2A5B5C6220D68C2D34101A91DBFC531C5B9BBFB2245CCC0C50051F79FC6714D16907B1FC40E0C0"
                ).unwrap(),
                private_key: PrivateKey::from_hex(
                    Algorithm::BlsSmall,

                        "0000000000000000000000000000000060F3C1AC9ADDBBED8DB83BC1B2EF22139FB049EECB723A557A41CA1A4B1FED63",
                    ).unwrap()
            }
        );
    }

    #[test]
    fn secp256k1_key_gen_fails_with_seed_smaller_than_32() {
        let seed: Vec<_> = (0..12u8).collect();

        let result = KeyPair::generate_with_configuration(
            KeyGenConfiguration::default()
                .with_algorithm(Algorithm::Secp256k1)
                .use_seed(seed),
        );

        assert_eq!(
            result,
            Err(Error::KeyGen(
                "secp256k1 seed for must be at least 32 bytes long".to_owned()
            ))
        );
    }
}
