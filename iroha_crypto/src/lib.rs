//! This module contains structures and implementations related to the c{ digest_function: (), payload: ()}digest_function: (), payload: ()}ptographic parts of the
//! Iroha.

pub mod multihash;

use multihash::Multihash;
use parity_scale_codec::{Decode, Encode};
use serde::{de::Error as SerdeError, Deserialize};
use std::{
    collections::BTreeMap,
    convert::{TryFrom, TryInto},
    fmt::{self, Debug, Display, Formatter},
};
use ursa::{
    blake2::{
        digest::{Input, VariableOutput},
        VarBlake2b,
    },
    keys::{
        KeyGenOption as UrsaKeyGenOption, PrivateKey as UrsaPrivateKey, PublicKey as UrsaPublicKey,
    },
    signatures::{ed25519::Ed25519Sha512, SignatureScheme, Signer},
};

pub const SIGNATURE_LENGTH: usize = 64;
pub const HASH_LENGTH: usize = 32;
pub const ED_25519: &str = "ed25519";

/// Represents hash of Iroha entities like `Block` or `Transaction.
pub type Hash = [u8; HASH_LENGTH];

pub enum KeyGenOption {
    UseSeed(Vec<u8>),
    FromPrivateKey(PrivateKey),
}

impl TryFrom<KeyGenOption> for UrsaKeyGenOption {
    type Error = String;

    fn try_from(key_gen_option: KeyGenOption) -> Result<Self, Self::Error> {
        match key_gen_option {
            KeyGenOption::UseSeed(seed) => Ok(UrsaKeyGenOption::UseSeed(seed)),
            KeyGenOption::FromPrivateKey(key) => {
                if key.digest_function == ED_25519 {
                    Ok(UrsaKeyGenOption::FromSecretKey(UrsaPrivateKey(key.payload)))
                } else {
                    Err(format!(
                        "Ursa does not support {} digest function.",
                        key.digest_function
                    ))
                }
            }
        }
    }
}

/// Pair of Public and Private keys.
#[derive(Clone, Debug, Deserialize, Default)]
pub struct KeyPair {
    /// Public Key.
    pub public_key: PublicKey,
    /// Private Key.
    pub private_key: PrivateKey,
}

impl KeyPair {
    /// Generates a pair of Public and Private key with the corresponding `KeyGenOption`.
    /// Returns `Err(String)` with error message if failed.
    pub fn generate_with_option(key_gen_option: KeyGenOption) -> Result<Self, String> {
        let (public_key, ursa_private_key) = Ed25519Sha512
            .keypair(Some(key_gen_option.try_into()?))
            .map_err(|e| format!("Failed to generate Ed25519Sha512 key pair: {}", e))?;
        let public_key: [u8; 32] = public_key[..]
            .try_into()
            .map_err(|e| format!("Public key should be [u8;32]: {}", e))?;
        let mut private_key = [0; 64];
        private_key.copy_from_slice(ursa_private_key.as_ref());
        Ok(KeyPair {
            public_key: PublicKey {
                digest_function: ED_25519.to_string(),
                payload: public_key.to_vec(),
            },
            private_key: PrivateKey {
                digest_function: ED_25519.to_string(),
                payload: private_key.to_vec(),
            },
        })
    }

    /// Generates a pair of Public and Private key.
    /// Returns `Err(String)` with error message if failed.
    pub fn generate() -> Result<Self, String> {
        let (public_key, ursa_private_key) = Ed25519Sha512
            .keypair(None)
            .map_err(|e| format!("Failed to generate Ed25519Sha512 key pair: {}", e))?;
        let public_key: [u8; 32] = public_key[..]
            .try_into()
            .map_err(|e| format!("Public key should be [u8;32]: {}", e))?;
        let mut private_key = [0; 64];
        private_key.copy_from_slice(ursa_private_key.as_ref());
        Ok(KeyPair {
            public_key: PublicKey {
                digest_function: ED_25519.to_string(),
                payload: public_key.to_vec(),
            },
            private_key: PrivateKey {
                digest_function: ED_25519.to_string(),
                payload: private_key.to_vec(),
            },
        })
    }
}

/// Public Key used in signatures.
#[derive(Encode, Decode, Ord, PartialEq, Eq, PartialOrd, Clone, Hash, Default)]
pub struct PublicKey {
    pub digest_function: String,
    pub payload: Vec<u8>,
}

impl Debug for PublicKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PublicKey")
            .field("digest_function", &self.digest_function)
            .field("payload", &format!("{:X?}", self.payload))
            .finish()
    }
}

impl Display for PublicKey {
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
    type Error = String;

    fn try_from(multihash: &Multihash) -> Result<Self, Self::Error> {
        match multihash.digest_function.to_string().as_ref() {
            multihash::ED_25519_PUB_STR => Ok(ED_25519.to_string()),
            _ => Err("Digest function not implemented.".to_string()),
        }
        .map(|digest_function| PublicKey {
            digest_function,
            payload: multihash.payload.clone(),
        })
    }
}

impl TryFrom<&PublicKey> for Multihash {
    type Error = String;

    fn try_from(public_key: &PublicKey) -> Result<Self, Self::Error> {
        match public_key.digest_function.as_ref() {
            ED_25519 => Ok(multihash::ED_25519_PUB_STR),
            _ => Err("Digest function not implemented.".to_string()),
        }
        .and_then(|digest_function| {
            Ok(Multihash {
                digest_function: digest_function.parse()?,
                payload: public_key.payload.clone(),
            })
        })
    }
}

impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes = hex::decode(String::deserialize(deserializer)?).map_err(SerdeError::custom)?;
        let multihash: &Multihash = &bytes.try_into().map_err(SerdeError::custom)?;
        multihash.try_into().map_err(SerdeError::custom)
    }
}

/// Private Key used in signatures.
#[derive(Clone, Deserialize, PartialEq, Default)]
pub struct PrivateKey {
    pub digest_function: String,
    #[serde(deserialize_with = "from_hex")]
    pub payload: Vec<u8>,
}

fn from_hex<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    hex::decode(String::deserialize(deserializer)?).map_err(SerdeError::custom)
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

type Ed25519Signature = [u8; SIGNATURE_LENGTH];

/// Calculates hash of the given bytes.
pub fn hash(bytes: Vec<u8>) -> Hash {
    let vec_hash = VarBlake2b::new(32)
        .expect("Failed to initialize variable size hash")
        .chain(bytes)
        .vec_result();
    let mut hash = [0; HASH_LENGTH];
    hash.copy_from_slice(&vec_hash);
    hash
}

/// Represents signature of the data (`Block` or `Transaction` for example).
#[derive(Clone, Encode, Decode)]
pub struct Signature {
    /// Ed25519 (Edwards-curve Digital Signature Algorithm scheme using SHA-512 and Curve25519)
    /// public-key of an approved authority.
    pub public_key: PublicKey,
    /// Ed25519 signature is placed here.
    signature: Ed25519Signature,
}

impl Signature {
    /// Creates new `Signature` by signing payload via `private_key`.
    pub fn new(key_pair: KeyPair, payload: &[u8]) -> Result<Signature, String> {
        if key_pair.public_key.digest_function == ED_25519 {
            let private_key = UrsaPrivateKey(key_pair.private_key.payload.to_vec());
            let transaction_signature = Signer::new(&Ed25519Sha512, &private_key)
                .sign(payload)
                .map_err(|e| format!("Failed to sign payload: {}", e))?;
            let mut signature = [0; SIGNATURE_LENGTH];
            signature.copy_from_slice(&transaction_signature);
            Ok(Signature {
                public_key: key_pair.public_key,
                signature,
            })
        } else {
            Err("Unsupported digest function.".to_string())
        }
    }

    /// Verify `message` using signed data and `public_key`.
    pub fn verify(&self, message: &[u8]) -> Result<(), String> {
        Ed25519Sha512::new()
            .verify(
                message,
                &self.signature,
                &UrsaPublicKey(self.public_key.payload.to_vec()),
            )
            .map_err(|e| e.to_string())
            .map(|_| ())
    }
}

impl PartialEq for Signature {
    fn eq(&self, other: &Self) -> bool {
        self.public_key == other.public_key && self.signature.to_vec() == other.signature.to_vec()
    }
}

impl Eq for Signature {}

impl Debug for Signature {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("Signature")
            .field("public_key", &self.public_key)
            .field("signature", &format!("{:X?}", self.signature.to_vec()))
            .finish()
    }
}

/// Container for multiple signatures.
#[derive(Debug, Clone, Encode, Decode, Default)]
pub struct Signatures {
    signatures: BTreeMap<PublicKey, Signature>,
}

impl Signatures {
    /// Adds multiple signatures and replaces the duplicates.
    pub fn append(&mut self, signatures: &[Signature]) {
        for signature in signatures.iter().cloned() {
            self.add(signature.clone())
        }
    }

    /// Adds a signature. If the signature with this key was present, replaces it.
    pub fn add(&mut self, signature: Signature) {
        let _option = self
            .signatures
            .insert(signature.public_key.clone(), signature);
    }

    /// Whether signatures contain a signature with the specified `public_key`
    pub fn contains(&self, public_key: &PublicKey) -> bool {
        self.signatures.contains_key(public_key)
    }

    /// Removes all signatures
    pub fn clear(&mut self) {
        self.signatures.clear()
    }

    /// Returns signatures that have passed verification.
    pub fn verified(&self, payload: &[u8]) -> Vec<Signature> {
        self.signatures
            .iter()
            .filter(|&(_, signature)| signature.verify(payload).is_ok())
            .map(|(_, signature)| signature)
            .cloned()
            .collect()
    }

    /// Returns all signatures.
    pub fn values(&self) -> Vec<Signature> {
        self.signatures
            .iter()
            .map(|(_, signature)| signature)
            .cloned()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;
    use serde::Deserialize;
    use ursa::blake2::{
        digest::{Input, VariableOutput},
        VarBlake2b,
    };

    #[test]
    fn create_signature() {
        let key_pair = KeyPair::generate().expect("Failed to generate key pair.");
        let result = Signature::new(key_pair.clone(), b"Test message to sign.")
            .expect("Failed to create signature.");
        assert_eq!(result.public_key, key_pair.public_key);
    }

    #[test]
    fn blake2_32b() {
        let mut hasher = VarBlake2b::new(32).unwrap();
        hasher.input(hex!("6920616d2064617461"));
        hasher.variable_result(|res| {
            assert_eq!(
                res[..],
                hex!("ba67336efd6a3df3a70eeb757860763036785c182ff4cf587541a0068d09f5b2")[..]
            );
        })
    }

    #[test]
    fn display_public_key() {
        assert_eq!(
            format!(
                "{}",
                PublicKey {
                    digest_function: ED_25519.to_string(),
                    payload: hex::decode(
                        "1509a611ad6d97b01d871e58ed00c8fd7c3917b6ca61a8c2833a19e000aac2e4"
                    )
                    .expect("Failed to decode public key.")
                }
            ),
            "ed201509a611ad6d97b01d871e58ed00c8fd7c3917b6ca61a8c2833a19e000aac2e4"
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
                \"public_key\": \"ed201509a611ad6d97b01d871e58ed00c8fd7c3917b6ca61a8c2833a19e000aac2e4\",
                \"private_key\": {
                    \"digest_function\": \"ed25519\",
                    \"payload\": \"3a7991af1abb77f3fd27cc148404a6ae4439d095a63591b77c788d53f708a02a1509a611ad6d97b01d871e58ed00c8fd7c3917b6ca61a8c2833a19e000aac2e4\"
                }
            }").expect("Failed to deserialize."),
            TestJson {
                public_key: PublicKey {
                    digest_function: ED_25519.to_string(),
                    payload: hex::decode(
                        "1509a611ad6d97b01d871e58ed00c8fd7c3917b6ca61a8c2833a19e000aac2e4"
                    )
                    .expect("Failed to decode public key.")
                },
                private_key: PrivateKey {
                    digest_function: ED_25519.to_string(),
                    payload: hex::decode("3a7991af1abb77f3fd27cc148404a6ae4439d095a63591b77c788d53f708a02a1509a611ad6d97b01d871e58ed00c8fd7c3917b6ca61a8c2833a19e000aac2e4")
                    .expect("Failed to decode private key"),
                }
            }
        )
    }
}
