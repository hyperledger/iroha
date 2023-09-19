//! This module contains structures and implementations related to the cryptographic parts of the Iroha.
#![cfg_attr(not(feature = "std"), no_std)]
#![allow(clippy::arithmetic_side_effects)]

#[cfg(not(feature = "std"))]
extern crate alloc;

mod hash;
mod merkle;
#[cfg(not(feature = "ffi_import"))]
mod multihash;
mod signature;
#[cfg(not(feature = "ffi_import"))]
mod varint;

#[cfg(not(feature = "std"))]
use alloc::{
    format,
    string::{String, ToString as _},
    vec::Vec,
};
use core::{fmt, str::FromStr};

#[cfg(feature = "base64")]
pub use base64;
use derive_more::{DebugCustom, Display};
use error::{Error, NoSuchAlgorithm};
use getset::{CopyGetters, Getters};
pub use hash::*;
use iroha_macro::ffi_impl_opaque;
use iroha_primitives::const_vec::ConstVec;
use iroha_schema::IntoSchema;
pub use merkle::MerkleTree;
#[cfg(not(feature = "ffi_import"))]
use parity_scale_codec::{Decode, Encode};
#[cfg(feature = "std")]
use serde::Deserialize;
use serde::Serialize;
use serde_with::{DeserializeFromStr, SerializeDisplay};
pub use signature::*;
#[cfg(feature = "std")]
#[cfg(not(feature = "ffi_import"))]
pub use ursa;
#[cfg(feature = "std")]
#[cfg(not(feature = "ffi_import"))]
use ursa::{
    keys::{KeyGenOption as UrsaKeyGenOption, PrivateKey as UrsaPrivateKey},
    signatures::{
        bls::{normal::Bls as BlsNormal, small::Bls as BlsSmall},
        ed25519::Ed25519Sha512,
        secp256k1::EcdsaSecp256k1Sha256,
        SignatureScheme,
    },
};

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
    /// Algorithm for hashing
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
enum KeyGenOption {
    /// Use seed
    UseSeed(Vec<u8>),
    /// Derive from private key
    FromPrivateKey(PrivateKey),
}

#[cfg(feature = "std")]
#[cfg(not(feature = "ffi_import"))]
impl TryFrom<KeyGenOption> for UrsaKeyGenOption {
    type Error = NoSuchAlgorithm;

    fn try_from(key_gen_option: KeyGenOption) -> Result<Self, Self::Error> {
        match key_gen_option {
            KeyGenOption::UseSeed(seed) => Ok(Self::UseSeed(seed)),
            KeyGenOption::FromPrivateKey(key) => {
                let algorithm = key.digest_function();

                match algorithm {
                    Algorithm::Ed25519 | Algorithm::Secp256k1 => {
                        Ok(Self::FromSecretKey(UrsaPrivateKey(key.payload.into_vec())))
                    }
                    _ => Err(Self::Error {}),
                }
            }
        }
    }
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
    #[cfg(any(feature = "std", feature = "ffi_import"))]
    pub fn generate() -> Result<Self, Error> {
        Self::generate_with_configuration(KeyGenConfiguration::default())
    }
}

#[ffi_impl_opaque]
impl KeyPair {
    /// Digest function
    pub fn digest_function(&self) -> Algorithm {
        self.private_key.digest_function()
    }

    /// Construct `KeyPair`
    ///
    /// # Errors
    /// If public and private key don't match, i.e. if they don't make a pair
    #[cfg(any(feature = "std", feature = "ffi_import"))]
    pub fn new(public_key: PublicKey, private_key: PrivateKey) -> Result<Self, Error> {
        let algorithm = private_key.digest_function();

        if algorithm != public_key.digest_function() {
            #[cfg(not(feature = "std"))]
            use alloc::borrow::ToOwned as _;
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
    #[cfg(any(feature = "std", feature = "ffi_import"))]
    pub fn generate_with_configuration(configuration: KeyGenConfiguration) -> Result<Self, Error> {
        let key_gen_option: Option<UrsaKeyGenOption> =
            match (configuration.algorithm, configuration.key_gen_option) {
                (Algorithm::Secp256k1, Some(KeyGenOption::UseSeed(seed))) if seed.len() < 32 => {
                    return Err(Error::KeyGen(
                        "secp256k1 seed for must be at least 32 bytes long".to_owned(),
                    ))
                }
                (_, key_gen_option) => key_gen_option,
            }
            .map(TryInto::try_into)
            .transpose()?;
        let (mut public_key, mut private_key) = match configuration.algorithm {
            Algorithm::Ed25519 => Ed25519Sha512.keypair(key_gen_option),
            Algorithm::Secp256k1 => EcdsaSecp256k1Sha256::new().keypair(key_gen_option),
            Algorithm::BlsNormal => BlsNormal::new().keypair(key_gen_option),
            Algorithm::BlsSmall => BlsSmall::new().keypair(key_gen_option),
        }?;

        Ok(Self {
            public_key: PublicKey {
                digest_function: configuration.algorithm,
                payload: ConstVec::new(core::mem::take(&mut public_key.0)),
            },
            private_key: PrivateKey {
                digest_function: configuration.algorithm,
                payload: ConstVec::new(core::mem::take(&mut private_key.0)),
            },
        })
    }
}

#[cfg(feature = "std")]
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
    #[derive(Clone, PartialEq, Eq, PartialOrd, Ord, CopyGetters)]
    #[cfg_attr(not(feature="ffi_import"), derive(DebugCustom, Display, Hash, DeserializeFromStr, SerializeDisplay, Decode, Encode, IntoSchema))]
    #[cfg_attr(not(feature="ffi_import"), debug(fmt = "{{digest: {digest_function}, payload: {}}}", "self.normalize()"))]
    #[cfg_attr(not(feature="ffi_import"), display(fmt = "{}", "self.normalize()"))]
    pub struct PublicKey {
        /// Digest function
        #[getset(get_copy = "pub")]
        digest_function: Algorithm,
        /// Key payload
        payload: ConstVec<u8>,
    }
}

#[ffi_impl_opaque]
impl PublicKey {
    /// Key payload
    // TODO: Derive with getset once FFI impl is fixed
    pub fn payload(&self) -> &[u8] {
        self.payload.as_ref()
    }

    #[cfg(feature = "std")]
    fn try_from_private(private_key: PrivateKey) -> Result<PublicKey, Error> {
        let digest_function = private_key.digest_function();
        let key_gen_option = Some(UrsaKeyGenOption::FromSecretKey(UrsaPrivateKey(
            private_key.payload.into_vec(),
        )));

        let (mut public_key, _) = match digest_function {
            Algorithm::Ed25519 => Ed25519Sha512.keypair(key_gen_option),
            Algorithm::Secp256k1 => EcdsaSecp256k1Sha256::new().keypair(key_gen_option),
            Algorithm::BlsNormal => BlsNormal::new().keypair(key_gen_option),
            Algorithm::BlsSmall => BlsSmall::new().keypair(key_gen_option),
        }?;

        Ok(PublicKey {
            digest_function: private_key.digest_function,
            payload: ConstVec::new(core::mem::take(&mut public_key.0)),
        })
    }
}

impl FromStr for PublicKey {
    type Err = Error;

    // TODO: Can we check the key is valid?
    fn from_str(key: &str) -> Result<Self, Self::Err> {
        let bytes = hex_decode(key).map_err(|err| Error::Parse(err.to_string()))?;

        multihash::Multihash::try_from(bytes)
            .map_err(|err| Error::Parse(err.to_string()))
            .map(Into::into)
    }
}

#[cfg(not(feature = "ffi_import"))]
impl PublicKey {
    fn normalize(&self) -> String {
        let multihash: &multihash::Multihash = &self
            .clone()
            .try_into()
            .expect("Failed to get multihash representation.");
        let bytes = Vec::try_from(multihash).expect("Failed to convert multihash to bytes.");

        let mut bytes_iter = bytes.into_iter();
        let fn_code = hex::encode(bytes_iter.by_ref().take(2).collect::<Vec<_>>());
        let dig_size = hex::encode(bytes_iter.by_ref().take(1).collect::<Vec<_>>());
        let key = hex::encode_upper(bytes_iter.by_ref().collect::<Vec<_>>());

        format!("{fn_code}{dig_size}{key}")
    }
}

// TODO: Enable in ffi_import
#[cfg(feature = "std")]
#[cfg(not(feature = "ffi_import"))]
impl From<PrivateKey> for PublicKey {
    fn from(private_key: PrivateKey) -> Self {
        Self::try_from_private(private_key).expect("can't fail for valid `PrivateKey`")
    }
}

ffi::ffi_item! {
    /// Private Key used in signatures.
    #[derive(Clone, PartialEq, Eq, CopyGetters)]
    #[cfg_attr(not(feature="ffi_import"), derive(DebugCustom, Display, Serialize))]
    #[cfg_attr(not(feature="ffi_import"), debug(fmt = "{{digest: {digest_function}, payload: {}}}", "hex::encode_upper(payload)"))]
    #[cfg_attr(not(feature="ffi_import"), display(fmt = "{}", "hex::encode_upper(payload)"))]
    pub struct PrivateKey {
        /// Digest function
        #[getset(get_copy = "pub")]
        digest_function: Algorithm,
        /// Key payload
        #[serde(with = "hex::serde")]
        payload: ConstVec<u8>,
    }
}

#[ffi_impl_opaque]
impl PrivateKey {
    /// Key payload
    // TODO: Derive with getset once FFI impl is fixed
    pub fn payload(&self) -> &[u8] {
        self.payload.as_ref()
    }
}

impl PrivateKey {
    /// Construct `PrivateKey` from hex encoded string without validating the key
    ///
    /// # Errors
    ///
    /// If the given payload is not hex encoded
    pub fn from_hex_unchecked(
        digest_function: Algorithm,
        payload: &(impl AsRef<[u8]> + ?Sized),
    ) -> Result<Self, Error> {
        Ok(Self {
            digest_function,
            payload: crate::hex_decode(payload).map(ConstVec::new)?,
        })
    }

    /// Construct `PrivateKey` from hex encoded string
    ///
    /// # Errors
    ///
    /// - If the given payload is not hex encoded
    /// - If the given payload is not a valid private key
    #[cfg(feature = "std")]
    pub fn from_hex(digest_function: Algorithm, payload: &[u8]) -> Result<Self, Error> {
        let payload = hex_decode(payload)?;
        let payload = ConstVec::new(payload);

        let private_key_candidate = Self {
            digest_function,
            payload: payload.clone(),
        };

        PublicKey::try_from_private(private_key_candidate).map(|_| Self {
            digest_function,
            payload,
        })
    }
}

#[cfg(feature = "std")]
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

/// Shim for decoding hexadecimal strings
pub(crate) fn hex_decode<T: AsRef<[u8]> + ?Sized>(payload: &T) -> Result<Vec<u8>, Error> {
    hex::decode(payload).map_err(|err| Error::Parse(err.to_string()))
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

    /// Error when dealing with cryptographic functions
    #[derive(Debug, Display, serde::Deserialize, PartialEq, Eq)]
    pub enum Error {
        /// Returned when trying to create an algorithm which does not exist
        #[display(fmt = "Algorithm doesn't exist")] // TODO: which algorithm
        NoSuchAlgorithm(String),
        /// Occurs during deserialization of a private or public key
        #[display(fmt = "Key could not be parsed. {_0}")]
        Parse(String),
        /// Returned when an error occurs during the signing process
        #[display(fmt = "Signing failed. {_0}")]
        Signing(String),
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

    #[cfg(feature = "std")]
    #[cfg(not(feature = "ffi_import"))]
    impl From<ursa::CryptoError> for Error {
        fn from(source: ursa::CryptoError) -> Self {
            match source {
                ursa::CryptoError::NoSuchAlgorithm(source) => Self::NoSuchAlgorithm(source),
                ursa::CryptoError::ParseError(source) => Self::Parse(source),
                ursa::CryptoError::SigningError(source) => Self::Signing(source),
                ursa::CryptoError::KeyGenError(source) => Self::KeyGen(source),
                ursa::CryptoError::DigestGenError(source) => Self::DigestGen(source),
                ursa::CryptoError::GeneralError(source) => Self::Other(source),
            }
        }
    }

    #[cfg(feature = "std")]
    impl From<NoSuchAlgorithm> for Error {
        fn from(source: NoSuchAlgorithm) -> Self {
            Self::NoSuchAlgorithm(source.to_string())
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
    #![allow(clippy::restriction)]

    use parity_scale_codec::{Decode, Encode};
    #[cfg(all(feature = "std", not(feature = "ffi_import")))]
    use serde::Deserialize;

    use super::*;

    fn parse_const_bytes(hex: &str) -> ConstVec<u8> {
        ConstVec::new(hex_decode(hex).expect("Failed to decode hex bytes"))
    }

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
            )
        }
    }
    #[test]
    #[cfg(any(feature = "std", feature = "ffi_import"))]
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
            )
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
            )
        }
    }

    #[test]
    #[cfg(any(feature = "std", feature = "ffi_import"))]
    fn key_pair_match() {
        assert!(KeyPair::new("ed012059C8A4DA1EBB5380F74ABA51F502714652FDCCE9611FAFB9904E4A3C4D382774"
            .parse()
            .expect("Public key not in mulithash format"),
        PrivateKey::from_hex(
            Algorithm::Ed25519,
            "93CA389FC2979F3F7D2A7F8B76C70DE6D5EAF5FA58D4F93CB8B0FB298D398ACC59C8A4DA1EBB5380F74ABA51F502714652FDCCE9611FAFB9904E4A3C4D382774".as_ref()
        ).expect("Private key not hex encoded")).is_ok());

        assert!(KeyPair::new("ea0161040FCFADE2FC5D9104A9ACF9665EA545339DDF10AE50343249E01AF3B8F885CD5D52956542CCE8105DB3A2EC4006E637A7177FAAEA228C311F907DAAFC254F22667F1A1812BB710C6F4116A1415275D27BB9FB884F37E8EF525CC31F3945E945FA"
            .parse()
            .expect("Public key not in mulithash format"),
        PrivateKey::from_hex(
            Algorithm::BlsNormal,
            "0000000000000000000000000000000049BF70187154C57B97AF913163E8E875733B4EAF1F3F0689B31CE392129493E9".as_ref()
        ).expect("Private key not hex encoded")).is_ok());
    }

    #[test]
    #[cfg(any(feature = "std", feature = "ffi_import"))]
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
            )
        }
    }

    #[test]
    #[cfg(feature = "std")]
    fn invalid_private_key() {
        assert!(PrivateKey::from_hex(
            Algorithm::Ed25519,
            "0000000000000000000000000000000049BF70187154C57B97AF913163E8E875733B4EAF1F3F0689B31CE392129493E9".as_ref()
        ).is_err());

        assert!(
            PrivateKey::from_hex(
                Algorithm::BlsNormal,
                "93CA389FC2979F3F7D2A7F8B76C70DE6D5EAF5FA58D4F93CB8B0FB298D398ACC59C8A4DA1EBB5380F74ABA51F502714652FDCCE9611FAFB9904E4A3C4D382774".as_ref()
            ).is_err());
    }

    #[test]
    #[cfg(any(feature = "std", feature = "ffi_import"))]
    fn key_pair_mismatch() {
        assert!(KeyPair::new("ed012059C8A4DA1EBB5380F74ABA51F502714652FDCCE9611FAFB9904E4A3C4D382774"
            .parse()
            .expect("Public key not in mulithash format"),
        PrivateKey::from_hex(
            Algorithm::Ed25519,
            "3A7991AF1ABB77F3FD27CC148404A6AE4439D095A63591B77C788D53F708A02A1509A611AD6D97B01D871E58ED00C8FD7C3917B6CA61A8C2833A19E000AAC2E4".as_ref()
        ).expect("Private key not valid")).is_err());

        assert!(KeyPair::new("ea0161040FCFADE2FC5D9104A9ACF9665EA545339DDF10AE50343249E01AF3B8F885CD5D52956542CCE8105DB3A2EC4006E637A7177FAAEA228C311F907DAAFC254F22667F1A1812BB710C6F4116A1415275D27BB9FB884F37E8EF525CC31F3945E945FA"
            .parse()
            .expect("Public key not in mulithash format"),
        PrivateKey::from_hex(
            Algorithm::BlsNormal,
            "000000000000000000000000000000002F57460183837EFBAC6AA6AB3B8DBB7CFFCFC59E9448B7860A206D37D470CBA3".as_ref()
        ).expect("Private key not valid")).is_err());
    }

    #[test]
    #[cfg(not(feature = "ffi_import"))]
    fn display_public_key() {
        assert_eq!(
            format!(
                "{}",
                PublicKey {
                    digest_function: Algorithm::Ed25519,
                    payload: parse_const_bytes(
                        "1509A611AD6D97B01D871E58ED00C8FD7C3917B6CA61A8C2833A19E000AAC2E4"
                    )
                }
            ),
            "ed01201509A611AD6D97B01D871E58ED00C8FD7C3917B6CA61A8C2833A19E000AAC2E4"
        );
        assert_eq!(
            format!(
                "{}",
                PublicKey {
                    digest_function: Algorithm::Secp256k1,
                    payload: parse_const_bytes(
                        "0312273E8810581E58948D3FB8F9E8AD53AAA21492EBB8703915BBB565A21B7FCC"
                    )
                }
            ),
            "e701210312273E8810581E58948D3FB8F9E8AD53AAA21492EBB8703915BBB565A21B7FCC"
        );
        assert_eq!(
            format!(
                "{}",
                PublicKey {
                    digest_function: Algorithm::BlsNormal,
                    payload: parse_const_bytes(
                        "04175B1E79B15E8A2D5893BF7F8933CA7D0863105D8BAC3D6F976CB043378A0E4B885C57ED14EB85FC2FABC639ADC7DE7F0020C70C57ACC38DEE374AF2C04A6F61C11DE8DF9034B12D849C7EB90099B0881267D0E1507D4365D838D7DCC31511E7"
                    )
                }
            ),
            "ea016104175B1E79B15E8A2D5893BF7F8933CA7D0863105D8BAC3D6F976CB043378A0E4B885C57ED14EB85FC2FABC639ADC7DE7F0020C70C57ACC38DEE374AF2C04A6F61C11DE8DF9034B12D849C7EB90099B0881267D0E1507D4365D838D7DCC31511E7"
        );
        assert_eq!(
            format!(
                "{}",
                PublicKey {
                    digest_function: Algorithm::BlsSmall,
                    payload: parse_const_bytes(
                        "040CB3231F601E7245A6EC9A647B450936F707CA7DC347ED258586C1924941D8BC38576473A8BA3BB2C37E3E121130AB67103498A96D0D27003E3AD960493DA79209CF024E2AA2AE961300976AEEE599A31A5E1B683EAA1BCFFC47B09757D20F21123C594CF0EE0BAF5E1BDD272346B7DC98A8F12C481A6B28174076A352DA8EAE881B90911013369D7FA960716A5ABC5314307463FA2285A5BF2A5B5C6220D68C2D34101A91DBFC531C5B9BBFB2245CCC0C50051F79FC6714D16907B1FC40E0C0"
                    )
                }
            ),
            "eb01c1040CB3231F601E7245A6EC9A647B450936F707CA7DC347ED258586C1924941D8BC38576473A8BA3BB2C37E3E121130AB67103498A96D0D27003E3AD960493DA79209CF024E2AA2AE961300976AEEE599A31A5E1B683EAA1BCFFC47B09757D20F21123C594CF0EE0BAF5E1BDD272346B7DC98A8F12C481A6B28174076A352DA8EAE881B90911013369D7FA960716A5ABC5314307463FA2285A5BF2A5B5C6220D68C2D34101A91DBFC531C5B9BBFB2245CCC0C50051F79FC6714D16907B1FC40E0C0"
        )
    }
    #[cfg(all(feature = "std", not(feature = "ffi_import")))]
    #[derive(Debug, PartialEq, Deserialize, Serialize)]
    struct TestJson {
        public_key: PublicKey,
        private_key: PrivateKey,
    }

    #[test]
    #[cfg(all(feature = "std", not(feature = "ffi_import")))]
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
                public_key: PublicKey {
                    digest_function: Algorithm::Ed25519,
                    payload: parse_const_bytes(
                        "1509A611AD6D97B01D871E58ED00C8FD7C3917B6CA61A8C2833A19E000AAC2E4"
                    )
                },
                private_key: PrivateKey {
                    digest_function: Algorithm::Ed25519,
                    payload: parse_const_bytes("3A7991AF1ABB77F3FD27CC148404A6AE4439D095A63591B77C788D53F708A02A1509A611AD6D97B01D871E58ED00C8FD7C3917B6CA61A8C2833A19E000AAC2E4"),
                }
            }
        );
    }

    #[test]
    #[cfg(all(feature = "std", not(feature = "ffi_import")))]
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
                public_key: PublicKey {
                    digest_function: Algorithm::Secp256k1,
                    payload: parse_const_bytes(
                        "0312273E8810581E58948D3FB8F9E8AD53AAA21492EBB8703915BBB565A21B7FCC"
                    )
                },
                private_key: PrivateKey {
                    digest_function: Algorithm::Secp256k1,
                    payload: parse_const_bytes("4DF4FCA10762D4B529FE40A2188A60CA4469D2C50A825B5F33ADC2CB78C69445"),
                }
            }
        );
    }

    #[test]
    #[cfg(all(feature = "std", not(feature = "ffi_import")))]
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
                public_key: PublicKey {
                    digest_function: Algorithm::BlsNormal,
                    payload: parse_const_bytes(
                        "04175B1E79B15E8A2D5893BF7F8933CA7D0863105D8BAC3D6F976CB043378A0E4B885C57ED14EB85FC2FABC639ADC7DE7F0020C70C57ACC38DEE374AF2C04A6F61C11DE8DF9034B12D849C7EB90099B0881267D0E1507D4365D838D7DCC31511E7"
                    )
                },
                private_key: PrivateKey {
                    digest_function: Algorithm::BlsNormal,
                    payload: parse_const_bytes("000000000000000000000000000000002F57460183837EFBAC6AA6AB3B8DBB7CFFCFC59E9448B7860A206D37D470CBA3"),
                }
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
                public_key: PublicKey {
                    digest_function: Algorithm::BlsSmall,
                    payload: parse_const_bytes(
                            "040CB3231F601E7245A6EC9A647B450936F707CA7DC347ED258586C1924941D8BC38576473A8BA3BB2C37E3E121130AB67103498A96D0D27003E3AD960493DA79209CF024E2AA2AE961300976AEEE599A31A5E1B683EAA1BCFFC47B09757D20F21123C594CF0EE0BAF5E1BDD272346B7DC98A8F12C481A6B28174076A352DA8EAE881B90911013369D7FA960716A5ABC5314307463FA2285A5BF2A5B5C6220D68C2D34101A91DBFC531C5B9BBFB2245CCC0C50051F79FC6714D16907B1FC40E0C0"
                        )
                },
                private_key: PrivateKey {
                    digest_function: Algorithm::BlsSmall,
                    payload: parse_const_bytes(
                        "0000000000000000000000000000000060F3C1AC9ADDBBED8DB83BC1B2EF22139FB049EECB723A557A41CA1A4B1FED63"),
                }
            }
        )
    }

    #[test]
    #[cfg(any(feature = "std", feature = "ffi_import"))]
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
        )
    }
}
