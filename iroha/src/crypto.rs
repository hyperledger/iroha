//! This module contains structures and implementations related to the cryptographic parts of the
//! Iroha.
use parity_scale_codec::{Decode, Encode};
use serde::Deserialize;
use std::{
    collections::BTreeMap,
    convert::{TryFrom, TryInto},
    fmt::{self, Debug, Formatter},
};
use ursa::{
    blake2::{
        digest::{Input, VariableOutput},
        VarBlake2b,
    },
    keys::{PrivateKey as UrsaPrivateKey, PublicKey as UrsaPublicKey},
    signatures::{ed25519::Ed25519Sha512, SignatureScheme, Signer},
};

/// Represents hash of Iroha entities like `Block` or `Transaction.
pub type Hash = [u8; 32];

/// Pair of Public and Private keys.
#[derive(Clone, Debug, Deserialize, Default)]
pub struct KeyPair {
    /// Public Key.
    pub public_key: PublicKey,
    /// Private Key.
    pub private_key: PrivateKey,
}

/// Public Key used in signatures.
#[derive(
    Copy, Encode, Decode, Ord, PartialEq, Eq, PartialOrd, Debug, Clone, Hash, Default, Deserialize,
)]
pub struct PublicKey {
    inner: [u8; 32],
}

impl TryFrom<Vec<u8>> for PublicKey {
    type Error = String;

    fn try_from(vector: Vec<u8>) -> Result<Self, Self::Error> {
        if vector.len() > 32 {
            Err(format!(
                "Failed to build PublicKey from vector: {:?}, expected length 32, found {}.",
                &vector,
                vector.len()
            ))
        } else {
            let mut inner = [0; 32];
            inner.copy_from_slice(&vector);
            Ok(PublicKey { inner })
        }
    }
}

/// Private Key used in signatures.
#[derive(Clone, Debug, Deserialize, PartialEq, Default)]
pub struct PrivateKey {
    inner: Vec<u8>,
}

impl TryFrom<Vec<u8>> for PrivateKey {
    type Error = String;

    fn try_from(vector: Vec<u8>) -> Result<Self, Self::Error> {
        if vector.len() != 64 {
            Err(format!(
                "Failed to build PublicKey from vector: {:?}, expected length 32, found {}.",
                &vector,
                vector.len()
            ))
        } else {
            Ok(PrivateKey { inner: vector })
        }
    }
}

type Ed25519Signature = [u8; 64];

impl KeyPair {
    /// Generates a pair of Public and Private key.
    /// Returns `Err(String)` with error message if failed.
    pub fn generate() -> Result<Self, String> {
        let (public_key, ursa_private_key) = Ed25519Sha512
            .keypair(Option::None)
            .map_err(|e| format!("Failed to generate Ed25519Sha512 key pair: {}", e))?;
        let public_key: [u8; 32] = public_key[..]
            .try_into()
            .map_err(|e| format!("Public key should be [u8;32]: {}", e))?;
        let mut private_key = [0; 64];
        private_key.copy_from_slice(ursa_private_key.as_ref());
        Ok(KeyPair {
            public_key: PublicKey { inner: public_key },
            private_key: PrivateKey::try_from(private_key.to_vec()).map_err(|e| {
                format!(
                    "Failed to convert Ursa Private key to Iroha Private Key: {}",
                    e
                )
            })?,
        })
    }
}

/// Calculates hash of the given bytes.
pub fn hash(bytes: Vec<u8>) -> Hash {
    let vec_hash = VarBlake2b::new(32)
        .expect("Failed to initialize variable size hash")
        .chain(bytes)
        .vec_result();
    let mut hash = [0; 32];
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
        let private_key = UrsaPrivateKey(key_pair.private_key.inner.to_vec());
        let transaction_signature = Signer::new(&Ed25519Sha512, &private_key)
            .sign(payload)
            .map_err(|e| format!("Failed to sign payload: {}", e))?;
        let mut signature = [0; 64];
        signature.copy_from_slice(&transaction_signature);
        Ok(Signature {
            public_key: key_pair.public_key,
            signature,
        })
    }

    /// Verify `message` using signed data and `public_key`.
    pub fn verify(&self, message: &[u8]) -> Result<(), String> {
        Ed25519Sha512::new()
            .verify(
                message,
                &self.signature,
                &UrsaPublicKey(self.public_key.inner.to_vec()),
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
            .field("signature", &self.signature.to_vec())
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
        let _option = self.signatures.insert(signature.public_key, signature);
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
}
