//! This module contains structures and implementations related to the cryptographic parts of the Iroha.

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
extern crate alloc;

mod hash;
mod merkle;
mod multihash;
mod signature;
mod varint;

#[cfg(not(feature = "std"))]
use alloc::{format, string::String, vec::Vec};
use core::{fmt, str::FromStr};

#[cfg(feature = "base64")]
pub use base64;
use derive_more::Display;
use getset::Getters;
pub use hash::*;
use iroha_schema::IntoSchema;
pub use merkle::MerkleTree;
use multihash::{DigestFunction as MultihashDigestFunction, Multihash};
use parity_scale_codec::{Decode, Encode, Error as ScaleError};
use serde::{Deserialize, Serialize};
pub use signature::*;
#[cfg(feature = "std")]
pub use ursa;
#[cfg(feature = "std")]
use ursa::{
    keys::{KeyGenOption as UrsaKeyGenOption, PrivateKey as UrsaPrivateKey},
    signatures::{
        bls::{normal::Bls as BlsNormal, small::Bls as BlsSmall},
        ed25519::Ed25519Sha512,
        secp256k1::EcdsaSecp256k1Sha256,
        SignatureScheme,
    },
};

/// ed25519
const ED_25519: &str = "ed25519";
/// secp256k1
const SECP_256_K1: &str = "secp256k1";
/// bls normal
const BLS_NORMAL: &str = "bls_normal";
/// bls small
const BLS_SMALL: &str = "bls_small";

/// Error indicating algorithm could not be found
#[derive(Debug, Clone, Copy, Display, IntoSchema)]
#[display(fmt = "Algorithm not supported")]
pub struct NoSuchAlgorithm;

#[cfg(feature = "std")]
impl std::error::Error for NoSuchAlgorithm {}

/// Algorithm for hashing
#[derive(Debug, Clone, Copy, PartialEq, Eq, Display)]
pub enum Algorithm {
    /// Ed25519
    #[display(fmt = "{}", "ED_25519")]
    Ed25519,
    /// Secp256k1
    #[display(fmt = "{}", "SECP_256_K1")]
    Secp256k1,
    /// BlsNormal
    #[display(fmt = "{}", "BLS_NORMAL")]
    BlsNormal,
    /// BlsSmall
    #[display(fmt = "{}", "BLS_SMALL")]
    BlsSmall,
}

impl Default for Algorithm {
    fn default() -> Self {
        Algorithm::Ed25519
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
            _ => Err(Self::Err {}),
        }
    }
}

/// Options for key generation
#[derive(Debug, Clone)]
pub enum KeyGenOption {
    /// Use seed
    UseSeed(Vec<u8>),
    /// Derive from private key
    FromPrivateKey(PrivateKey),
}

#[cfg(feature = "std")]
impl TryFrom<KeyGenOption> for UrsaKeyGenOption {
    type Error = NoSuchAlgorithm;

    fn try_from(key_gen_option: KeyGenOption) -> Result<Self, Self::Error> {
        match key_gen_option {
            KeyGenOption::UseSeed(seed) => Ok(UrsaKeyGenOption::UseSeed(seed)),
            KeyGenOption::FromPrivateKey(key) => {
                let algorithm = key.digest_function();

                match algorithm {
                    Algorithm::Ed25519 | Algorithm::Secp256k1 => {
                        Ok(Self::FromSecretKey(UrsaPrivateKey(key.payload)))
                    }
                    _ => Err(Self::Error {}),
                }
            }
        }
    }
}

/// Configuration of key generation
#[derive(Debug, Clone, Default)]
pub struct KeyGenConfiguration {
    /// Options
    pub key_gen_option: Option<KeyGenOption>,
    /// Algorithm
    pub algorithm: Algorithm,
}

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
    pub const fn with_algorithm(mut self, algorithm: Algorithm) -> Self {
        self.algorithm = algorithm;
        self
    }
}

/// Pair of Public and Private keys.
#[derive(Debug, Clone, PartialEq, Eq, Getters, Serialize)]
#[getset(get = "pub")]
pub struct KeyPair {
    /// Public Key.
    public_key: PublicKey,
    /// Private Key.
    private_key: PrivateKey,
}

/// Error when dealing with cryptographic functions
#[derive(Debug, Display)]
pub enum Error {
    /// Returned when trying to create an algorithm which does not exist
    NoSuchAlgorithm,
    /// Occurs during deserialization of a private or public key
    Parse(String),
    /// Returned when an error occurs during the signing process
    Signing(String),
    /// Returned when an error occurs during key generation
    KeyGen(String),
    /// Returned when an error occurs during digest generation
    DigestGen(String),
    /// A General purpose error message that doesn't fit in any category
    Other(String),
}

#[cfg(feature = "std")]
impl From<ursa::CryptoError> for Error {
    fn from(source: ursa::CryptoError) -> Self {
        match source {
            ursa::CryptoError::NoSuchAlgorithm(_) => Self::NoSuchAlgorithm,
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
    fn from(_: NoSuchAlgorithm) -> Self {
        Self::NoSuchAlgorithm
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

impl KeyPair {
    /// Digest function
    pub fn digest_function(&self) -> Algorithm {
        self.private_key.digest_function()
    }

    /// Construct `KeyPair` from a matching pair of public and private key.
    /// It is up to the user to ensure that the given keys indeed make a pair.
    #[cfg(not(feature = "std"))]
    pub fn new_unchecked(public_key: PublicKey, private_key: PrivateKey) -> Self {
        Self {
            public_key,
            private_key,
        }
    }

    /// Construct `KeyPair`
    ///
    /// # Errors
    /// If public and private key don't match, i.e. if they don't make a pair
    #[cfg(feature = "std")]
    pub fn new(public_key: PublicKey, private_key: PrivateKey) -> Result<Self, Error> {
        let algorithm = private_key.digest_function();

        if algorithm != public_key.digest_function() {
            return Err(Error::KeyGen(String::from("Mismatch of key algorithms")));
        }

        match algorithm {
            Algorithm::Ed25519 | Algorithm::Secp256k1 => {
                let key_pair = Self::generate_with_configuration(KeyGenConfiguration {
                    key_gen_option: Some(KeyGenOption::FromPrivateKey(private_key)),
                    algorithm,
                })?;

                if *key_pair.public_key() != public_key {
                    return Err(Error::KeyGen(String::from("Key pair mismatch")));
                }

                Ok(key_pair)
            }
            Algorithm::BlsNormal | Algorithm::BlsSmall => {
                let dummy_payload = 1_u8;

                let key_pair = Self {
                    public_key,
                    private_key,
                };

                SignatureOf::new(key_pair.clone(), &dummy_payload)?
                    .verify(&dummy_payload)
                    .map_err(|_err| Error::KeyGen(String::from("Key pair mismatch")))?;

                Ok(key_pair)
            }
        }
    }

    /// Generates a pair of Public and Private key with [`Algorithm::default()`] selected as generation algorithm.
    ///
    /// # Errors
    /// Fails if decoding fails
    #[cfg(feature = "std")]
    pub fn generate() -> Result<Self, Error> {
        Self::generate_with_configuration(KeyGenConfiguration::default())
    }

    /// Generates a pair of Public and Private key with the corresponding [`KeyGenConfiguration`].
    ///
    /// # Errors
    /// Fails if decoding fails
    #[cfg(feature = "std")]
    pub fn generate_with_configuration(configuration: KeyGenConfiguration) -> Result<Self, Error> {
        let digest_function = configuration.algorithm.to_string();

        let key_gen_option: Option<UrsaKeyGenOption> = configuration
            .key_gen_option
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
                digest_function: digest_function.clone(),
                payload: core::mem::take(&mut public_key.0),
            },
            private_key: PrivateKey {
                digest_function,
                payload: core::mem::take(&mut private_key.0),
            },
        })
    }
}

#[cfg(feature = "std")]
impl<'de> Deserialize<'de> for KeyPair {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error as _;

        #[derive(Deserialize)]
        struct KeyPair {
            public_key: PublicKey,
            private_key: PrivateKey,
        }

        let key_pair = KeyPair::deserialize(deserializer)?;
        Self::new(key_pair.public_key, key_pair.private_key).map_err(D::Error::custom)
    }
}

impl From<KeyPair> for (PublicKey, PrivateKey) {
    fn from(key_pair: KeyPair) -> Self {
        (key_pair.public_key, key_pair.private_key)
    }
}

/// Error which occurs when parsing [`PublicKey`]
#[derive(Debug, Clone, Display)]
pub enum KeyParseError {
    /// Decoding hex failed
    Decode(hex::FromHexError),
    /// Converting bytes to multihash failed
    Multihash(multihash::ConvertError),
}

impl From<hex::FromHexError> for KeyParseError {
    fn from(source: hex::FromHexError) -> Self {
        Self::Decode(source)
    }
}

impl From<multihash::ConvertError> for KeyParseError {
    fn from(source: multihash::ConvertError) -> Self {
        Self::Multihash(source)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for KeyParseError {}

/// Public Key used in signatures.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Getters, Encode, IntoSchema)]
#[getset(get = "pub")]
pub struct PublicKey {
    /// Digest function
    #[getset(skip)]
    digest_function: String,
    /// payload of key
    payload: Vec<u8>,
}

impl PublicKey {
    /// Digest function
    #[allow(clippy::expect_used)]
    pub fn digest_function(&self) -> Algorithm {
        self.digest_function.parse().expect("Valid")
    }
}

impl FromStr for PublicKey {
    type Err = KeyParseError;

    fn from_str(key: &str) -> Result<Self, Self::Err> {
        let bytes = hex::decode(key)?;
        let multihash = Multihash::try_from(bytes)?;

        Ok(multihash.into())
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PublicKey")
            .field("digest_function", &self.digest_function())
            .field("payload", &hex::encode_upper(self.payload().as_slice()))
            .finish()
    }
}

impl fmt::Display for PublicKey {
    #[allow(clippy::expect_used, clippy::unwrap_in_result)]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let multihash: &Multihash = &self
            .clone()
            .try_into()
            .expect("Failed to get multihash representation.");
        let bytes: Vec<u8> = multihash
            .try_into()
            .expect("Failed to convert multihash to bytes.");
        write!(f, "{}", hex::encode(bytes))
    }
}

impl From<Multihash> for PublicKey {
    fn from(multihash: Multihash) -> Self {
        #[cfg(not(feature = "std"))]
        use alloc::string::ToString as _;

        let digest_function = match multihash.digest_function {
            MultihashDigestFunction::Ed25519Pub => Algorithm::Ed25519,
            MultihashDigestFunction::Secp256k1Pub => Algorithm::Secp256k1,
            MultihashDigestFunction::Bls12381G1Pub => Algorithm::BlsNormal,
            MultihashDigestFunction::Bls12381G2Pub => Algorithm::BlsSmall,
        };

        Self {
            digest_function: digest_function.to_string(),
            payload: multihash.payload,
        }
    }
}

impl From<PublicKey> for Multihash {
    fn from(public_key: PublicKey) -> Self {
        let digest_function = match public_key.digest_function() {
            Algorithm::Ed25519 => MultihashDigestFunction::Ed25519Pub,
            Algorithm::Secp256k1 => MultihashDigestFunction::Secp256k1Pub,
            Algorithm::BlsNormal => MultihashDigestFunction::Bls12381G1Pub,
            Algorithm::BlsSmall => MultihashDigestFunction::Bls12381G2Pub,
        };

        Self {
            digest_function,
            payload: public_key.payload,
        }
    }
}

impl Serialize for PublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&format!("{}", self))
    }
}

impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[cfg(not(feature = "std"))]
        use alloc::borrow::Cow;
        #[cfg(feature = "std")]
        use std::borrow::Cow;

        use serde::de::Error as _;

        let public_key_str = <Cow<str>>::deserialize(deserializer)?;
        PublicKey::from_str(&public_key_str).map_err(D::Error::custom)
    }
}

impl Decode for PublicKey {
    fn decode<I: parity_scale_codec::Input>(input: &mut I) -> Result<Self, ScaleError> {
        let digest_function = String::decode(input)?;

        if Algorithm::from_str(&digest_function).is_err() {
            return Err(ScaleError::from("Algorithm not supported"));
        }

        Ok(Self {
            digest_function,
            payload: Decode::decode(input)?,
        })
    }
}

/// Private Key used in signatures.
#[derive(Clone, PartialEq, Eq, Getters, Serialize)]
#[getset(get = "pub")]
pub struct PrivateKey {
    /// Digest function
    #[getset(skip)]
    digest_function: String,
    /// key payload. WARNING! Do not use `"string".as_bytes()` to obtain the key.
    #[serde(with = "hex::serde")]
    payload: Vec<u8>,
}

impl PrivateKey {
    /// Construct `PrivateKey` from hex encoded string
    ///
    /// # Errors
    ///
    /// If given payload is not hex encoded
    pub fn from_hex(
        digest_function: Algorithm,
        payload: &(impl AsRef<[u8]> + ?Sized),
    ) -> Result<Self, hex::FromHexError> {
        #[cfg(not(feature = "std"))]
        use alloc::string::ToString as _;

        let payload: Vec<u8> = payload
            .as_ref()
            .iter()
            .filter(|&e| *e as char != ' ')
            .copied()
            .collect();

        Ok(Self {
            digest_function: digest_function.to_string(),
            payload: hex::decode(payload)?,
        })
    }

    /// Digest function
    #[allow(clippy::expect_used)]
    pub fn digest_function(&self) -> Algorithm {
        self.digest_function.parse().expect("Valid")
    }
}

impl<'de> Deserialize<'de> for PrivateKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error as _;

        #[derive(Deserialize)]
        struct PrivateKey {
            digest_function: String,
            #[serde(with = "hex::serde")]
            payload: Vec<u8>,
        }

        let private_key = PrivateKey::deserialize(deserializer)?;
        match Algorithm::from_str(&private_key.digest_function) {
            Ok(_) => Ok(Self {
                digest_function: private_key.digest_function,
                payload: private_key.payload,
            }),
            Err(err) => Err(D::Error::custom(err)),
        }
    }
}

impl fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateKey")
            .field("digest_function", &self.digest_function())
            .field("payload", &format!("{:X?}", self.payload()))
            .finish()
    }
}

impl fmt::Display for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.payload()))
    }
}

/// The prelude re-exports most commonly used traits, structs and macros from this crate.
pub mod prelude {
    pub use super::{Algorithm, Hash, KeyPair, PrivateKey, PublicKey, Signature};
}

#[cfg(test)]
mod tests {
    #![allow(clippy::restriction)]

    #[cfg(not(feature = "std"))]
    use alloc::borrow::ToString as _;

    use super::*;

    #[test]
    fn key_pair_match() {
        assert!(KeyPair::new("ed012059c8a4da1ebb5380f74aba51f502714652fdcce9611fafb9904e4a3c4d382774"
            .parse()
            .expect("Public key not in mulithash format"),
        PrivateKey::from_hex(
            Algorithm::Ed25519,
            "93ca389fc2979f3f7d2a7f8b76c70de6d5eaf5fa58d4f93cb8b0fb298d398acc59c8a4da1ebb5380f74aba51f502714652fdcce9611fafb9904e4a3c4d382774"
        ).expect("Private key not hex encoded")).is_ok());

        assert!(KeyPair::new("ea0161040fcfade2fc5d9104a9acf9665ea545339ddf10ae50343249e01af3b8f885cd5d52956542cce8105db3a2ec4006e637a7177faaea228c311f907daafc254f22667f1a1812bb710c6f4116a1415275d27bb9fb884f37e8ef525cc31f3945e945fa"
            .parse()
            .expect("Public key not in mulithash format"),
        PrivateKey::from_hex(
            Algorithm::BlsNormal,
            "0000000000000000000000000000000049bf70187154c57b97af913163e8e875733b4eaf1f3f0689b31ce392129493e9"
        ).expect("Private key not hex encoded")).is_ok());
    }

    #[test]
    fn key_pair_mismatch() {
        assert!(KeyPair::new("ed012059c8a4da1ebb5380f74aba51f502714652fdcce9611fafb9904e4a3c4d382774"
            .parse()
            .expect("Public key not in mulithash format"),
        PrivateKey::from_hex(
            Algorithm::Ed25519,
            "0000000000000000000000000000000049bf70187154c57b97af913163e8e875733b4eaf1f3f0689b31ce392129493e9"
        ).expect("Private key not hex encoded")).is_err());

        assert!(KeyPair::new("ea0161040fcfade2fc5d9104a9acf9665ea545339ddf10ae50343249e01af3b8f885cd5d52956542cce8105db3a2ec4006e637a7177faaea228c311f907daafc254f22667f1a1812bb710c6f4116a1415275d27bb9fb884f37e8ef525cc31f3945e945fa"
            .parse()
            .expect("Public key not in mulithash format"),
        PrivateKey::from_hex(
            Algorithm::BlsNormal,
            "93ca389fc2979f3f7d2a7f8b76c70de6d5eaf5fa58d4f93cb8b0fb298d398acc59c8a4da1ebb5380f74aba51f502714652fdcce9611fafb9904e4a3c4d382774"
        ).expect("Private key not hex encoded")).is_err());
    }

    #[test]
    fn display_public_key() {
        assert_eq!(
            format!(
                "{}",
                PublicKey {
                    digest_function: Algorithm::Ed25519.to_string(),
                    payload: hex::decode(
                        "1509a611ad6d97b01d871e58ed00c8fd7c3917b6ca61a8c2833a19e000aac2e4"
                    )
                    .expect("Failed to decode public key.")
                }
            ),
            "ed01201509a611ad6d97b01d871e58ed00c8fd7c3917b6ca61a8c2833a19e000aac2e4"
        );
        assert_eq!(
            format!(
                "{}",
                PublicKey {
                    digest_function: Algorithm::Secp256k1.to_string(),
                    payload: hex::decode(
                        "0312273e8810581e58948d3fb8f9e8ad53aaa21492ebb8703915bbb565a21b7fcc"
                    )
                    .expect("Failed to decode public key.")
                }
            ),
            "e701210312273e8810581e58948d3fb8f9e8ad53aaa21492ebb8703915bbb565a21b7fcc"
        );
        assert_eq!(
            format!(
                "{}",
                PublicKey {
                    digest_function: Algorithm::BlsNormal.to_string(),
                    payload: hex::decode(
                        "04175b1e79b15e8a2d5893bf7f8933ca7d0863105d8bac3d6f976cb043378a0e4b885c57ed14eb85fc2fabc639adc7de7f0020c70c57acc38dee374af2c04a6f61c11de8df9034b12d849c7eb90099b0881267d0e1507d4365d838d7dcc31511e7"
                    )
                    .expect("Failed to decode public key.")
                }
            ),
            "ea016104175b1e79b15e8a2d5893bf7f8933ca7d0863105d8bac3d6f976cb043378a0e4b885c57ed14eb85fc2fabc639adc7de7f0020c70c57acc38dee374af2c04a6f61c11de8df9034b12d849c7eb90099b0881267d0e1507d4365d838d7dcc31511e7"
        );
        assert_eq!(
            format!(
                "{}",
                PublicKey {
                    digest_function: Algorithm::BlsSmall.to_string(),
                    payload: hex::decode(
                        "040cb3231f601e7245a6ec9a647b450936f707ca7dc347ed258586c1924941d8bc38576473a8ba3bb2c37e3e121130ab67103498a96d0d27003e3ad960493da79209cf024e2aa2ae961300976aeee599a31a5e1b683eaa1bcffc47b09757d20f21123c594cf0ee0baf5e1bdd272346b7dc98a8f12c481a6b28174076a352da8eae881b90911013369d7fa960716a5abc5314307463fa2285a5bf2a5b5c6220d68c2d34101a91dbfc531c5b9bbfb2245ccc0c50051f79fc6714d16907b1fc40e0c0"
                    )
                    .expect("Failed to decode public key.")
                }
            ),
            "eb01c1040cb3231f601e7245a6ec9a647b450936f707ca7dc347ed258586c1924941d8bc38576473a8ba3bb2c37e3e121130ab67103498a96d0d27003e3ad960493da79209cf024e2aa2ae961300976aeee599a31a5e1b683eaa1bcffc47b09757d20f21123c594cf0ee0baf5e1bdd272346b7dc98a8f12c481a6b28174076a352da8eae881b90911013369d7fa960716a5abc5314307463fa2285a5bf2a5b5c6220d68c2d34101a91dbfc531c5b9bbfb2245ccc0c50051f79fc6714d16907b1fc40e0c0"
        )
    }

    #[derive(Debug, PartialEq, Deserialize)]
    struct TestJson {
        public_key: PublicKey,
        private_key: PrivateKey,
    }

    #[test]
    fn deserialize_keys() {
        assert_eq!(
            serde_json::from_str::<'_, TestJson>("{
                \"public_key\": \"ed01201509a611ad6d97b01d871e58ed00c8fd7c3917b6ca61a8c2833a19e000aac2e4\",
                \"private_key\": {
                    \"digest_function\": \"ed25519\",
                    \"payload\": \"3a7991af1abb77f3fd27cc148404a6ae4439d095a63591b77c788d53f708a02a1509a611ad6d97b01d871e58ed00c8fd7c3917b6ca61a8c2833a19e000aac2e4\"
                }
            }").expect("Failed to deserialize."),
            TestJson {
                public_key: PublicKey {
                    digest_function: Algorithm::Ed25519.to_string(),
                    payload: hex::decode(
                        "1509a611ad6d97b01d871e58ed00c8fd7c3917b6ca61a8c2833a19e000aac2e4"
                    )
                    .expect("Failed to decode public key.")
                },
                private_key: PrivateKey {
                    digest_function: Algorithm::Ed25519.to_string(),
                    payload: hex::decode("3a7991af1abb77f3fd27cc148404a6ae4439d095a63591b77c788d53f708a02a1509a611ad6d97b01d871e58ed00c8fd7c3917b6ca61a8c2833a19e000aac2e4")
                    .expect("Failed to decode private key"),
                }
            }
        );
        assert_eq!(
            serde_json::from_str::<'_, TestJson>("{
                \"public_key\": \"e701210312273e8810581e58948d3fb8f9e8ad53aaa21492ebb8703915bbb565a21b7fcc\",
                \"private_key\": {
                    \"digest_function\": \"secp256k1\",
                    \"payload\": \"4df4fca10762d4b529fe40a2188a60ca4469d2c50a825b5f33adc2cb78c69445\"
                }
            }").expect("Failed to deserialize."),
            TestJson {
                public_key: PublicKey {
                    digest_function: Algorithm::Secp256k1.to_string(),
                    payload: hex::decode(
                        "0312273e8810581e58948d3fb8f9e8ad53aaa21492ebb8703915bbb565a21b7fcc"
                    )
                    .expect("Failed to decode public key.")
                },
                private_key: PrivateKey {
                    digest_function: Algorithm::Secp256k1.to_string(),
                    payload: hex::decode("4df4fca10762d4b529fe40a2188a60ca4469d2c50a825b5f33adc2cb78c69445")
                    .expect("Failed to decode private key"),
                }
            }
        );
        assert_eq!(
            serde_json::from_str::<'_, TestJson>("{
                \"public_key\": \"ea016104175b1e79b15e8a2d5893bf7f8933ca7d0863105d8bac3d6f976cb043378a0e4b885c57ed14eb85fc2fabc639adc7de7f0020c70c57acc38dee374af2c04a6f61c11de8df9034b12d849c7eb90099b0881267d0e1507d4365d838d7dcc31511e7\",
                \"private_key\": {
                    \"digest_function\": \"bls_normal\",
                    \"payload\": \"000000000000000000000000000000002f57460183837efbac6aa6ab3b8dbb7cffcfc59e9448b7860a206d37d470cba3\"
                }
            }").expect("Failed to deserialize."),
            TestJson {
                public_key: PublicKey {
                    digest_function: Algorithm::BlsNormal.to_string(),
                    payload: hex::decode(
                        "04175b1e79b15e8a2d5893bf7f8933ca7d0863105d8bac3d6f976cb043378a0e4b885c57ed14eb85fc2fabc639adc7de7f0020c70c57acc38dee374af2c04a6f61c11de8df9034b12d849c7eb90099b0881267d0e1507d4365d838d7dcc31511e7"
                    )
                    .expect("Failed to decode public key.")
                },
                private_key: PrivateKey {
                    digest_function: Algorithm::BlsNormal.to_string(),
                    payload: hex::decode("000000000000000000000000000000002f57460183837efbac6aa6ab3b8dbb7cffcfc59e9448b7860a206d37d470cba3")
                    .expect("Failed to decode private key"),
                }
            }
        );
        assert_eq!(
            serde_json::from_str::<'_, TestJson>("{
                \"public_key\": \"eb01c1040cb3231f601e7245a6ec9a647b450936f707ca7dc347ed258586c1924941d8bc38576473a8ba3bb2c37e3e121130ab67103498a96d0d27003e3ad960493da79209cf024e2aa2ae961300976aeee599a31a5e1b683eaa1bcffc47b09757d20f21123c594cf0ee0baf5e1bdd272346b7dc98a8f12c481a6b28174076a352da8eae881b90911013369d7fa960716a5abc5314307463fa2285a5bf2a5b5c6220d68c2d34101a91dbfc531c5b9bbfb2245ccc0c50051f79fc6714d16907b1fc40e0c0\",
                \"private_key\": {
                    \"digest_function\": \"bls_small\",
                    \"payload\": \"0000000000000000000000000000000060f3c1ac9addbbed8db83bc1b2ef22139fb049eecb723a557a41ca1a4b1fed63\"
                }
            }").expect("Failed to deserialize."),
            TestJson {
                public_key: PublicKey {
                    digest_function: Algorithm::BlsSmall.to_string(),
                    payload: hex::decode(
                        "040cb3231f601e7245a6ec9a647b450936f707ca7dc347ed258586c1924941d8bc38576473a8ba3bb2c37e3e121130ab67103498a96d0d27003e3ad960493da79209cf024e2aa2ae961300976aeee599a31a5e1b683eaa1bcffc47b09757d20f21123c594cf0ee0baf5e1bdd272346b7dc98a8f12c481a6b28174076a352da8eae881b90911013369d7fa960716a5abc5314307463fa2285a5bf2a5b5c6220d68c2d34101a91dbfc531c5b9bbfb2245ccc0c50051f79fc6714d16907b1fc40e0c0"
                    )
                    .expect("Failed to decode public key.")
                },
                private_key: PrivateKey {
                    digest_function: Algorithm::BlsSmall.to_string(),
                    payload: hex::decode("0000000000000000000000000000000060f3c1ac9addbbed8db83bc1b2ef22139fb049eecb723a557a41ca1a4b1fed63")
                    .expect("Failed to decode private key"),
                }
            }
        )
    }
}
