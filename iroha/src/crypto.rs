use parity_scale_codec::{Decode, Encode};
use std::fmt::{self, Debug, Formatter};
use ursa::{
    blake2::{
        digest::{Input, VariableOutput},
        VarBlake2b,
    },
    keys::PublicKey as UrsaPublicKey,
    signatures::{ed25519::Ed25519Sha512, SignatureScheme},
};

pub type Hash = [u8; 32];
pub type PublicKey = [u8; 32];
type Ed25519Signature = [u8; 64];

pub struct Crypto;

impl Crypto {
    pub fn hash(bytes: Vec<u8>) -> Hash {
        let vec_hash = VarBlake2b::new(32)
            .expect("Failed to initialize variable size hash")
            .chain(bytes)
            .vec_result();
        let mut hash = [0; 32];
        hash.copy_from_slice(&vec_hash);
        hash
    }
}

#[derive(Clone, Encode, Decode)]
pub struct Signature {
    /// Ed25519 (Edwards-curve Digital Signature Algorithm scheme using SHA-512 and Curve25519)
    /// public-key of an approved authority.
    public_key: PublicKey,
    /// Ed25519 signature is placed here.
    signature: Ed25519Signature,
}

impl Signature {
    pub fn new(public_key: PublicKey, signature: Ed25519Signature) -> Signature {
        Signature {
            public_key,
            signature,
        }
    }

    pub fn verify(&self, message: &[u8]) -> Result<(), ()> {
        Ed25519Sha512::new()
            .verify(
                message,
                &self.signature,
                &UrsaPublicKey(self.public_key.to_vec()),
            )
            .map_err(|_| ())
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

#[cfg(test)]
mod tests {
    use super::*;

    use hex_literal::hex;
    use std::convert::TryInto;
    use ursa::{
        blake2::{
            digest::{Input, VariableOutput},
            VarBlake2b,
        },
        signatures::{ed25519::Ed25519Sha512, SignatureScheme, Signer},
    };

    #[test]
    fn create_signature() {
        let (public_key, private_key) = Ed25519Sha512
            .keypair(Option::None)
            .expect("Failed to generate key pair.");
        let signed_message = Signer::new(&Ed25519Sha512, &private_key)
            .sign(b"Test message to sign.")
            .expect("Failed to sign message.");
        let mut signature: Ed25519Signature = [0; 64];
        signature.copy_from_slice(&signed_message);
        let result = Signature::new(
            public_key[..]
                .try_into()
                .expect("Failed to transform public key."),
            signature,
        );
        assert_eq!(result.public_key, public_key[..]);
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
