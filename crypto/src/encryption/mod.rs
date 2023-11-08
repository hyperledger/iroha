//! A suite of Authenticated Encryption with Associated Data (AEAD) cryptographic ciphers.
//!
//! Each AEAD algorithm provides [`SymmetricEncryptor::encrypt_easy`] and [`SymmetricEncryptor::decrypt_easy`] methods which hides the complexity
//! of generating a secure nonce of appropriate size with the ciphertext.
//! The [`SymmetricEncryptor::encrypt_easy`] prepends the nonce to the front of the ciphertext and [`SymmetricEncryptor::decrypt_easy`] expects
//! the nonce to be prepended to the front of the ciphertext.
//!
//! More advanced users may use [`SymmetricEncryptor::encrypt`] and [`SymmetricEncryptor::decrypt`] directly. These two methods require the
//! caller to supply a nonce with sufficient entropy and should never be reused when encrypting
//! with the same `key`.
//!
//! The convenience struct [`SymmetricEncryptor`] exists to allow users to easily switch between
//! algorithms by using any algorithm that implements the [`Encryptor`] trait.
//!
//! [`ChaCha20Poly1305`] is the only algorithm currently supported,
//! as it is the only one used by the iroha p2p transport protocol.

mod chacha20poly1305;

use std::io::{Read, Write};

use aead::{
    generic_array::{typenum::Unsigned, ArrayLength, GenericArray},
    Aead, Error, KeyInit, Payload,
};
use rand::{rngs::OsRng, RngCore};

pub use self::chacha20poly1305::ChaCha20Poly1305;
use crate::SessionKey;

// Helpful for generating bytes using the operating system random number generator
fn random_vec(bytes: usize) -> Result<Vec<u8>, Error> {
    let mut value = vec![0u8; bytes];
    OsRng.fill_bytes(value.as_mut_slice());
    Ok(value)
}

fn random_bytes<T: ArrayLength<u8>>() -> Result<GenericArray<u8, T>, Error> {
    Ok(GenericArray::clone_from_slice(
        random_vec(T::to_usize())?.as_slice(),
    ))
}

fn read_buffer<I: Read>(buffer: &mut I) -> Result<Vec<u8>, Error> {
    let mut v = Vec::new();
    let bytes_read = buffer.read_to_end(&mut v).map_err(|_| Error)?;
    v.truncate(bytes_read);
    Ok(v)
}

/// A generic symmetric encryption wrapper
///
/// # Usage
///
/// ```
/// extern crate ursa;
/// use ursa::encryption::symm::prelude::*;
///
/// let encryptor = SymmetricEncryptor::<Aes128Gcm>::default();
/// let aad = b"Using Aes128Gcm to encrypt data";
/// let message = b"Hidden message";
/// let res = encryptor.encrypt_easy(aad.as_ref(), message.as_ref());
/// assert!(res.is_ok());
///
/// let ciphertext = res.unwrap();
/// let res = encryptor.decrypt_easy(aad.as_ref(), ciphertext.as_slice());
/// assert!(res.is_ok());
/// assert_eq!(res.unwrap().as_slice(), message);
/// ```
#[derive(Debug, Clone)]
pub struct SymmetricEncryptor<E: Encryptor> {
    encryptor: E,
}

impl<E: Encryptor> SymmetricEncryptor<E> {
    /// Create a new [`SymmetricEncryptor`] using the provided `encryptor`
    pub fn new(encryptor: E) -> Self {
        Self { encryptor }
    }

    /// Create a new [`SymmetricEncryptor`] from a [`SessionKey`]
    pub fn new_from_session_key(key: SessionKey) -> Self {
        Self::new(<E as KeyInit>::new(GenericArray::from_slice(&key.0)))
    }
    /// Create a new [`SymmetricEncryptor`] from key bytes
    pub fn new_with_key<A: AsRef<[u8]>>(key: A) -> Result<Self, Error> {
        Ok(Self {
            encryptor: <E as KeyInit>::new(GenericArray::from_slice(key.as_ref())),
        })
    }

    /// Encrypt `plaintext` and integrity protect `aad`. The result is the ciphertext.
    /// This method handles safely generating a `nonce` and prepends it to the ciphertext
    pub fn encrypt_easy<A: AsRef<[u8]>>(&self, aad: A, plaintext: A) -> Result<Vec<u8>, Error> {
        self.encryptor.encrypt_easy(aad, plaintext)
    }

    /// Encrypt `plaintext` and integrity protect `aad`. The result is the ciphertext.
    pub fn encrypt<A: AsRef<[u8]>>(
        &self,
        nonce: A,
        aad: A,
        plaintext: A,
    ) -> Result<Vec<u8>, Error> {
        let nonce = GenericArray::from_slice(nonce.as_ref());
        let payload = Payload {
            msg: plaintext.as_ref(),
            aad: aad.as_ref(),
        };
        self.encryptor.encrypt(nonce, payload)
    }

    /// Decrypt `ciphertext` using integrity protected `aad`. The result is the plaintext if successful
    /// or an error if the `ciphetext` cannot be decrypted due to tampering, an incorrect `aad` value,
    /// or incorrect key.
    /// `aad` must be the same value used in `encrypt_easy`. Expects the nonce to be prepended to
    /// the `ciphertext`
    pub fn decrypt_easy<A: AsRef<[u8]>>(&self, aad: A, ciphertext: A) -> Result<Vec<u8>, Error> {
        self.encryptor.decrypt_easy(aad, ciphertext)
    }

    /// Decrypt `ciphertext` using integrity protected `aad`. The result is the plaintext if successful
    /// or an error if the `ciphetext` cannot be decrypted due to tampering, an incorrect `aad` value,
    /// or incorrect key.
    /// `aad` must be the same value used in `encrypt_easy`.
    pub fn decrypt<A: AsRef<[u8]>>(
        &self,
        nonce: A,
        aad: A,
        ciphertext: A,
    ) -> Result<Vec<u8>, Error> {
        let nonce = GenericArray::from_slice(nonce.as_ref());
        let payload = Payload {
            msg: ciphertext.as_ref(),
            aad: aad.as_ref(),
        };
        self.encryptor.decrypt(nonce, payload)
    }

    /// Similar to `encrypt_easy` but reads from a stream instead of a slice
    pub fn encrypt_buffer<A: AsRef<[u8]>, I: Read, O: Write>(
        &self,
        aad: A,
        plaintext: &mut I,
        ciphertext: &mut O,
    ) -> Result<(), Error> {
        self.encryptor.encrypt_buffer(aad, plaintext, ciphertext)
    }

    /// Similar to `decrypt_easy` but reads from a stream instead of a slice
    pub fn decrypt_buffer<A: AsRef<[u8]>, I: Read, O: Write>(
        &self,
        aad: A,
        ciphertext: &mut I,
        plaintext: &mut O,
    ) -> Result<(), Error> {
        self.encryptor.decrypt_buffer(aad, ciphertext, plaintext)
    }
}

impl<E: Encryptor + Default> Default for SymmetricEncryptor<E> {
    fn default() -> Self {
        SymmetricEncryptor {
            encryptor: E::default(),
        }
    }
}

/// Generic encryptor trait that all ciphers should extend.
pub trait Encryptor: Aead + KeyInit {
    /// The minimum size that the ciphertext will yield from plaintext
    type MinSize: ArrayLength<u8>;

    /// A simple API to encrypt a message with authenticated associated data.
    ///
    /// This API handles nonce generation for you and prepends it in front of the ciphertext. Use [`Encryptor::decrypt_easy`] to decrypt the message encrypted this way.
    fn encrypt_easy<M: AsRef<[u8]>>(&self, aad: M, plaintext: M) -> Result<Vec<u8>, Error> {
        let nonce = Self::nonce_gen()?;
        let payload = Payload {
            msg: plaintext.as_ref(),
            aad: aad.as_ref(),
        };
        let ciphertext = self.encrypt(&nonce, payload)?;
        let mut result = nonce.to_vec();
        result.extend_from_slice(ciphertext.as_slice());
        Ok(result)
    }

    /// A simple API to decrypt a message with authenticated associated data.
    ///
    /// This API expects the nonce to be prepended to the ciphertext. Use [`Encryptor::encrypt_easy`] to encrypt the message this way.
    fn decrypt_easy<M: AsRef<[u8]>>(&self, aad: M, ciphertext: M) -> Result<Vec<u8>, Error> {
        let ciphertext = ciphertext.as_ref();
        if ciphertext.len() < Self::MinSize::to_usize() {
            return Err(Error);
        }

        let nonce = GenericArray::from_slice(&ciphertext[..Self::NonceSize::to_usize()]);
        let payload = Payload {
            msg: &ciphertext[Self::NonceSize::to_usize()..],
            aad: aad.as_ref(),
        };
        let plaintext = self.decrypt(&nonce, payload)?;
        Ok(plaintext)
    }

    /// Same as [`Encryptor::encrypt_easy`] but works with [`std::io`] streams instead of slices
    fn encrypt_buffer<M: AsRef<[u8]>, I: Read, O: Write>(
        &self,
        aad: M,
        plaintext: &mut I,
        ciphertext: &mut O,
    ) -> Result<(), Error> {
        let p = read_buffer(plaintext)?;
        let c = self.encrypt_easy(aad.as_ref(), p.as_slice())?;
        ciphertext.write_all(c.as_slice()).map_err(|_| Error)?;
        Ok(())
    }

    /// Same as [`Encryptor::decrypt_easy`] but works with [`std::io`] streams instead of slices
    fn decrypt_buffer<M: AsRef<[u8]>, I: Read, O: Write>(
        &self,
        aad: M,
        ciphertext: &mut I,
        plaintext: &mut O,
    ) -> Result<(), Error> {
        let c = read_buffer(ciphertext)?;
        let p = self.decrypt_easy(aad.as_ref(), c.as_slice())?;
        plaintext.write_all(p.as_slice()).map_err(|_| Error)?;
        Ok(())
    }

    /// Generate a new key for this encryptor
    fn key_gen() -> Result<GenericArray<u8, Self::KeySize>, Error> {
        random_bytes()
    }

    /// Generate a new nonce for this encryptor
    fn nonce_gen() -> Result<GenericArray<u8, Self::NonceSize>, Error> {
        random_bytes()
    }
}
