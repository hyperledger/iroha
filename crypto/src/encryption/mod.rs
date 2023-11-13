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

use aead::{
    generic_array::{typenum::Unsigned, ArrayLength, GenericArray},
    Aead, Error as AeadError, KeyInit, Payload,
};
use displaydoc::Display;
use rand::{rngs::OsRng, RngCore};
use thiserror::Error;

pub use self::chacha20poly1305::ChaCha20Poly1305;
use crate::SessionKey;

/// An error that can occur during encryption or decryption
#[derive(Error, Display, Debug)]
pub enum Error {
    /// Failed to generate nonce for an encryption operation
    NonceGeneration(#[source] rand::Error),
    /// Failed to encrypt data
    Encryption(AeadError),
    /// Failed to decrypt data
    Decryption(AeadError),
    /// Not enough data to decrypt message
    NotEnoughData,
}

// Helpful for generating bytes using the operating system random number generator
fn random_vec(bytes: usize) -> Result<Vec<u8>, Error> {
    let mut value = vec![0u8; bytes];
    OsRng
        .try_fill_bytes(value.as_mut_slice())
        // RustCrypto errors don't have any details, can't propagate the error
        .map_err(Error::NonceGeneration)?;
    Ok(value)
}

fn random_bytes<T: ArrayLength<u8>>() -> Result<GenericArray<u8, T>, Error> {
    Ok(GenericArray::clone_from_slice(
        random_vec(T::to_usize())?.as_slice(),
    ))
}

/// A generic symmetric encryption wrapper
///
/// # Usage
///
/// ```
/// use iroha_crypto::encryption::{SymmetricEncryptor, ChaCha20Poly1305};
///
/// let key: Vec<u8> = (0..0x20).collect();
/// let encryptor = SymmetricEncryptor::<ChaCha20Poly1305>::new_with_key(&key);
/// let aad = b"Using ChaCha20Poly1305 to encrypt data";
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
    pub fn new_from_session_key(key: &SessionKey) -> Self {
        Self::new(<E as KeyInit>::new(GenericArray::from_slice(&key.0)))
    }
    /// Create a new [`SymmetricEncryptor`] from key bytes
    pub fn new_with_key<A: AsRef<[u8]>>(key: A) -> Self {
        Self {
            encryptor: <E as KeyInit>::new(GenericArray::from_slice(key.as_ref())),
        }
    }

    /// Encrypt `plaintext` and integrity protect `aad`. The result is the ciphertext.
    /// This method handles safely generating a `nonce` and prepends it to the ciphertext
    ///
    /// # Errors
    ///
    /// This function will return an error if nonce generation or encryption fails
    pub fn encrypt_easy<A: AsRef<[u8]>>(&self, aad: A, plaintext: A) -> Result<Vec<u8>, Error> {
        self.encryptor.encrypt_easy(aad, plaintext)
    }

    /// Encrypt `plaintext` and integrity protect `aad`. The result is the ciphertext.
    ///
    /// # Errors
    ///
    /// This function will return an error if encryption fails
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
        self.encryptor
            .encrypt(nonce, payload)
            .map_err(Error::Encryption)
    }

    /// Decrypt `ciphertext` using integrity protected `aad`. The result is the plaintext if successful
    /// or an error if the `ciphetext` cannot be decrypted due to tampering, an incorrect `aad` value,
    /// or incorrect key.
    /// `aad` must be the same value used in `encrypt_easy`. Expects the nonce to be prepended to
    /// the `ciphertext`
    ///
    /// # Errors
    ///
    /// This function will return an error if decryption fails
    pub fn decrypt_easy<A: AsRef<[u8]>>(&self, aad: A, ciphertext: A) -> Result<Vec<u8>, Error> {
        self.encryptor.decrypt_easy(aad, ciphertext)
    }

    /// Decrypt `ciphertext` using integrity protected `aad`. The result is the plaintext if successful
    /// or an error if the `ciphetext` cannot be decrypted due to tampering, an incorrect `aad` value,
    /// or incorrect key.
    /// `aad` must be the same value used in `encrypt_easy`.
    ///
    /// # Errors
    ///
    /// This function will return an error if decryption fails
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
        self.encryptor
            .decrypt(nonce, payload)
            .map_err(Error::Decryption)
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
    ///
    /// # Errors
    ///
    /// This function will return an error if nonce generation or encryption fails
    fn encrypt_easy<M: AsRef<[u8]>>(&self, aad: M, plaintext: M) -> Result<Vec<u8>, Error> {
        let nonce = Self::nonce_gen()?;
        let payload = Payload {
            msg: plaintext.as_ref(),
            aad: aad.as_ref(),
        };
        let ciphertext = self.encrypt(&nonce, payload).map_err(Error::Encryption)?;
        let mut result = nonce.to_vec();
        result.extend_from_slice(ciphertext.as_slice());
        Ok(result)
    }

    /// A simple API to decrypt a message with authenticated associated data.
    ///
    /// This API expects the nonce to be prepended to the ciphertext. Use [`Encryptor::encrypt_easy`] to encrypt the message this way.
    ///
    /// # Errors
    ///
    /// This function will return an error if decryption fails
    fn decrypt_easy<M: AsRef<[u8]>>(&self, aad: M, ciphertext: M) -> Result<Vec<u8>, Error> {
        let ciphertext = ciphertext.as_ref();
        if ciphertext.len() < Self::MinSize::to_usize() {
            return Err(Error::NotEnoughData);
        }

        let nonce = GenericArray::from_slice(&ciphertext[..Self::NonceSize::to_usize()]);
        let payload = Payload {
            msg: &ciphertext[Self::NonceSize::to_usize()..],
            aad: aad.as_ref(),
        };
        let plaintext = self.decrypt(nonce, payload).map_err(Error::Decryption)?;
        Ok(plaintext)
    }

    /// Generate a new key for this encryptor
    ///
    /// # Errors
    ///
    /// This function will return an error if the operating system random number generator fails
    fn key_gen() -> Result<GenericArray<u8, Self::KeySize>, Error> {
        random_bytes()
    }

    /// Generate a new nonce for this encryptor
    ///
    /// # Errors
    ///
    /// This function will return an error if the operating system random number generator fails
    fn nonce_gen() -> Result<GenericArray<u8, Self::NonceSize>, Error> {
        random_bytes()
    }
}
