//! This module contains structures and implementations related to the cryptographic parts of the Iroha.

pub use ursa;

mod hash;
pub mod multihash;
mod signature;
mod varint;

use std::{
    fmt::{self, Debug, Display, Formatter},
    str::FromStr,
};

use eyre::{eyre, Error, Result, WrapErr};
pub use hash::*;
use iroha_schema::IntoSchema;
use multihash::{DigestFunction as MultihashDigestFunction, Multihash};
use parity_scale_codec::{Decode, Encode};
use serde::{de::Error as SerdeError, Deserialize, Serialize};
pub use signature::*;
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
pub const ED_25519: &str = "ed25519";
/// secp256k1
pub const SECP_256_K1: &str = "secp256k1";
/// bls normal
pub const BLS_NORMAL: &str = "bls_normal";
/// bls small
pub const BLS_SMALL: &str = "bls_small";

/// Algorithm for hashing
#[derive(Clone, Copy, Debug)]
pub enum Algorithm {
    /// Ed25519
    Ed25519,
    /// Secp256k1
    Secp256k1,
    /// BlsSmall
    BlsSmall,
    /// BlsNormal
    BlsNormal,
}

impl Default for Algorithm {
    fn default() -> Self {
        Algorithm::Ed25519
    }
}

impl FromStr for Algorithm {
    type Err = Error;
    fn from_str(algorithm: &str) -> Result<Self> {
        match algorithm {
            ED_25519 => Ok(Algorithm::Ed25519),
            SECP_256_K1 => Ok(Algorithm::Secp256k1),
            BLS_NORMAL => Ok(Algorithm::BlsNormal),
            BLS_SMALL => Ok(Algorithm::BlsSmall),
            _ => Err(eyre!("The {} algorithm is not supported.", algorithm)),
        }
    }
}

impl Display for Algorithm {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Algorithm::Ed25519 => write!(f, "{}", ED_25519),
            Algorithm::Secp256k1 => write!(f, "{}", SECP_256_K1),
            Algorithm::BlsSmall => write!(f, "{}", BLS_SMALL),
            Algorithm::BlsNormal => write!(f, "{}", BLS_NORMAL),
        }
    }
}

/// Options for key generation
#[derive(Clone, Debug)]
pub enum KeyGenOption {
    /// Use seed
    UseSeed(Vec<u8>),
    /// Derive from private key
    FromPrivateKey(PrivateKey),
}

impl TryFrom<KeyGenOption> for UrsaKeyGenOption {
    type Error = Error;

    fn try_from(key_gen_option: KeyGenOption) -> Result<Self> {
        match key_gen_option {
            KeyGenOption::UseSeed(seed) => Ok(UrsaKeyGenOption::UseSeed(seed)),
            KeyGenOption::FromPrivateKey(key) => {
                if key.digest_function == ED_25519 || key.digest_function == SECP_256_K1 {
                    Ok(UrsaKeyGenOption::FromSecretKey(UrsaPrivateKey(key.payload)))
                } else {
                    Err(eyre!(
                        "Ursa does not support {} digest function.",
                        key.digest_function
                    ))
                }
            }
        }
    }
}

/// Configuration of key generation
#[derive(Default, Clone, Debug)]
pub struct KeyGenConfiguration {
    /// Options
    pub key_gen_option: Option<KeyGenOption>,
    /// Algorithm
    pub algorithm: Algorithm,
}

impl KeyGenConfiguration {
    /// Use seed
    pub fn use_seed(mut self, seed: Vec<u8>) -> Self {
        self.key_gen_option = Some(KeyGenOption::UseSeed(seed));
        self
    }

    /// Use private key
    pub fn use_private_key(mut self, private_key: PrivateKey) -> Self {
        self.key_gen_option = Some(KeyGenOption::FromPrivateKey(private_key));
        self
    }

    /// with algorithm
    pub fn with_algorithm(mut self, algorithm: Algorithm) -> Self {
        self.algorithm = algorithm;
        self
    }
}

/// Pair of Public and Private keys.
#[derive(Clone, Debug, Deserialize, Default, Serialize, PartialEq, Eq)]
pub struct KeyPair {
    /// Public Key.
    pub public_key: PublicKey,
    /// Private Key.
    pub private_key: PrivateKey,
}

impl KeyPair {
    /// Generates a pair of Public and Private key with [`Algorithm::default()`] selected as generation algorithm.
    ///
    /// # Errors
    /// Fails if decoding fails
    pub fn generate() -> Result<Self> {
        Self::generate_with_configuration(KeyGenConfiguration::default())
    }

    /// Generates a pair of Public and Private key with the corresponding [`KeyGenConfiguration`].
    ///
    /// # Errors
    /// Fails if decoding fails
    pub fn generate_with_configuration(configuration: KeyGenConfiguration) -> Result<Self> {
        let key_gen_option: Option<UrsaKeyGenOption> = configuration
            .key_gen_option
            .map(TryInto::try_into)
            .transpose()?;
        let (public_key, private_key) = match configuration.algorithm {
            Algorithm::Ed25519 => Ed25519Sha512.keypair(key_gen_option),
            Algorithm::Secp256k1 => EcdsaSecp256k1Sha256::new().keypair(key_gen_option),
            Algorithm::BlsNormal => BlsNormal::new().keypair(key_gen_option),
            Algorithm::BlsSmall => BlsSmall::new().keypair(key_gen_option),
        }
        // TODO: Create an issue for ursa to impl Error for ursa::CryptoError
        //.wrap_err("Failed to generate key pair")?;
        .map_err(|e| eyre!("{}", e.to_string()))?;
        Ok(KeyPair {
            public_key: PublicKey {
                digest_function: configuration.algorithm.to_string(),
                payload: public_key.as_ref().to_vec(),
            },
            private_key: PrivateKey {
                digest_function: configuration.algorithm.to_string(),
                payload: private_key.as_ref().to_vec(),
            },
        })
    }
}

impl From<KeyPair> for (PublicKey, PrivateKey) {
    fn from(key_pair: KeyPair) -> Self {
        (key_pair.public_key, key_pair.private_key)
    }
}

/// Public Key used in signatures.
#[derive(Encode, Decode, Ord, PartialEq, Eq, PartialOrd, Clone, Hash, IntoSchema)]
pub struct PublicKey {
    /// Digest function
    pub digest_function: String,
    /// payload of key
    pub payload: Vec<u8>,
}

impl FromStr for PublicKey {
    type Err = Error;
    fn from_str(key: &str) -> Result<Self> {
        serde_json::from_value(serde_json::json!(key))
            .wrap_err("Failed to deserialize supplied public key argument.")
    }
}

impl Default for PublicKey {
    #[allow(clippy::unwrap_used)]
    fn default() -> Self {
        (&Multihash::default()).try_into().unwrap()
    }
}

impl Debug for PublicKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PublicKey")
            .field("digest_function", &self.digest_function)
            .field("payload", &hex::encode_upper(self.payload.as_slice()))
            .finish()
    }
}

impl Display for PublicKey {
    #[allow(clippy::expect_used, clippy::unwrap_in_result)]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let multihash: &Multihash = &self
            .try_into()
            .expect("Failed to get multihash representation.");
        let bytes: Vec<u8> = multihash
            .try_into()
            .expect("Failed to convert multihash to bytes.");
        write!(f, "{}", hex::encode(bytes))
    }
}

impl TryFrom<&Multihash> for PublicKey {
    type Error = Error;

    fn try_from(multihash: &Multihash) -> Result<Self> {
        match multihash.digest_function {
            MultihashDigestFunction::Ed25519Pub => Ok(ED_25519.to_owned()),
            MultihashDigestFunction::Secp256k1Pub => Ok(SECP_256_K1.to_owned()),
            MultihashDigestFunction::Bls12381G1Pub => Ok(BLS_NORMAL.to_owned()),
            MultihashDigestFunction::Bls12381G2Pub => Ok(BLS_SMALL.to_owned()),
        }
        .map(|digest_function| PublicKey {
            digest_function,
            payload: multihash.payload.clone(),
        })
    }
}

impl TryFrom<&PublicKey> for Multihash {
    type Error = Error;

    fn try_from(public_key: &PublicKey) -> Result<Self> {
        match public_key.digest_function.as_ref() {
            ED_25519 => Ok(MultihashDigestFunction::Ed25519Pub),
            SECP_256_K1 => Ok(MultihashDigestFunction::Secp256k1Pub),
            BLS_NORMAL => Ok(MultihashDigestFunction::Bls12381G1Pub),
            BLS_SMALL => Ok(MultihashDigestFunction::Bls12381G2Pub),
            _ => Err(eyre!("Digest function not implemented.")),
        }
        .map(|digest_function| Multihash {
            digest_function,
            payload: public_key.payload.clone(),
        })
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
        let bytes = hex::decode(String::deserialize(deserializer)?).map_err(SerdeError::custom)?;
        let multihash = &Multihash::try_from(bytes)
            .map_err(|e| e.to_string())
            .map_err(SerdeError::custom)?;
        multihash.try_into().map_err(SerdeError::custom)
    }
}

/// Private Key used in signatures.
#[derive(Clone, Deserialize, PartialEq, Eq, Default, Serialize)]
pub struct PrivateKey {
    /// Digest function
    pub digest_function: String,
    /// key payload. WARNING! Do not use `"string".as_bytes()` to obtain the key.
    #[serde(deserialize_with = "from_hex", serialize_with = "to_hex")]
    pub payload: Vec<u8>,
}

fn from_hex<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    hex::decode(String::deserialize(deserializer)?).map_err(SerdeError::custom)
}

fn to_hex<S>(payload: &[u8], serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(&hex::encode(payload))
}

impl Debug for PrivateKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateKey")
            .field("digest_function", &self.digest_function)
            .field("payload", &format!("{:X?}", self.payload))
            .finish()
    }
}

impl Display for PrivateKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(&self.payload))
    }
}

/// The prelude re-exports most commonly used traits, structs and macros from this crate.
pub mod prelude {
    pub use super::{Hash, KeyPair, PrivateKey, PublicKey, Signature};
}

#[cfg(test)]
mod tests {
    #![allow(clippy::restriction)]

    use serde::Deserialize;

    use super::*;

    #[test]
    fn display_public_key() {
        assert_eq!(
            format!(
                "{}",
                PublicKey {
                    digest_function: ED_25519.to_owned(),
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
                    digest_function: SECP_256_K1.to_owned(),
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
                    digest_function: BLS_NORMAL.to_owned(),
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
                    digest_function: BLS_SMALL.to_owned(),
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
                    digest_function: ED_25519.to_owned(),
                    payload: hex::decode(
                        "1509a611ad6d97b01d871e58ed00c8fd7c3917b6ca61a8c2833a19e000aac2e4"
                    )
                    .expect("Failed to decode public key.")
                },
                private_key: PrivateKey {
                    digest_function: ED_25519.to_owned(),
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
                    digest_function: SECP_256_K1.to_owned(),
                    payload: hex::decode(
                        "0312273e8810581e58948d3fb8f9e8ad53aaa21492ebb8703915bbb565a21b7fcc"
                    )
                    .expect("Failed to decode public key.")
                },
                private_key: PrivateKey {
                    digest_function: SECP_256_K1.to_owned(),
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
                    digest_function: BLS_NORMAL.to_owned(),
                    payload: hex::decode(
                        "04175b1e79b15e8a2d5893bf7f8933ca7d0863105d8bac3d6f976cb043378a0e4b885c57ed14eb85fc2fabc639adc7de7f0020c70c57acc38dee374af2c04a6f61c11de8df9034b12d849c7eb90099b0881267d0e1507d4365d838d7dcc31511e7"
                    )
                    .expect("Failed to decode public key.")
                },
                private_key: PrivateKey {
                    digest_function: BLS_NORMAL.to_owned(),
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
                    digest_function: BLS_SMALL.to_owned(),
                    payload: hex::decode(
                        "040cb3231f601e7245a6ec9a647b450936f707ca7dc347ed258586c1924941d8bc38576473a8ba3bb2c37e3e121130ab67103498a96d0d27003e3ad960493da79209cf024e2aa2ae961300976aeee599a31a5e1b683eaa1bcffc47b09757d20f21123c594cf0ee0baf5e1bdd272346b7dc98a8f12c481a6b28174076a352da8eae881b90911013369d7fa960716a5abc5314307463fa2285a5bf2a5b5c6220d68c2d34101a91dbfc531c5b9bbfb2245ccc0c50051f79fc6714d16907b1fc40e0c0"
                    )
                    .expect("Failed to decode public key.")
                },
                private_key: PrivateKey {
                    digest_function: BLS_SMALL.to_owned(),
                    payload: hex::decode("0000000000000000000000000000000060f3c1ac9addbbed8db83bc1b2ef22139fb049eecb723a557a41ca1a4b1fed63")
                    .expect("Failed to decode private key"),
                }
            }
        )
    }
}
