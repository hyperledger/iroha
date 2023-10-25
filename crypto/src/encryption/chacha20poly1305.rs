use aead::{
    generic_array::{
        typenum::{U0, U12, U16, U32, U36},
        GenericArray,
    },
    Aead, Error, NewAead, Payload,
};
use chacha20poly1305::ChaCha20Poly1305 as SysChaCha20Poly1305;

// use zeroize::Zeroize;
use super::Encryptor;

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct ChaCha20Poly1305 {
    key: GenericArray<u8, U32>,
}

impl Encryptor for ChaCha20Poly1305 {
    type MinSize = U36;
}

impl NewAead for ChaCha20Poly1305 {
    type KeySize = U32;

    fn new(key: &GenericArray<u8, Self::KeySize>) -> Self {
        Self { key: *key }
    }
}

impl Aead for ChaCha20Poly1305 {
    type NonceSize = U12;
    type TagSize = U16;
    type CiphertextOverhead = U0;

    fn encrypt<'msg, 'aad>(
        &self,
        nonce: &GenericArray<u8, Self::NonceSize>,
        plaintext: impl Into<Payload<'msg, 'aad>>,
    ) -> Result<Vec<u8>, Error> {
        let aead = SysChaCha20Poly1305::new(&self.key);
        let ciphertext = aead.encrypt(nonce, plaintext)?;
        Ok(ciphertext)
    }

    fn decrypt<'msg, 'aad>(
        &self,
        nonce: &GenericArray<u8, Self::NonceSize>,
        ciphertext: impl Into<Payload<'msg, 'aad>>,
    ) -> Result<Vec<u8>, Error> {
        let aead = SysChaCha20Poly1305::new(&self.key);
        let plaintext = aead.decrypt(nonce, ciphertext)?;
        Ok(plaintext)
    }
}

// default_impl!(ChaCha20Poly1305);
// drop_impl!(ChaCha20Poly1305);

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    #[test]
    fn encrypt_easy_works() {
        let aes = ChaCha20Poly1305::new(&ChaCha20Poly1305::key_gen().unwrap());
        let aad = Vec::new();
        let message = b"Hello and Goodbye!".to_vec();
        let res = aes.encrypt_easy(&aad, &message);
        assert!(res.is_ok());
        let ciphertext = res.unwrap();
        let res = aes.decrypt_easy(&aad, &ciphertext);
        assert!(res.is_ok());
        assert_eq!(message, res.unwrap());
    }

    #[test]
    fn encrypt_works() {
        let aes = ChaCha20Poly1305::new(&ChaCha20Poly1305::key_gen().unwrap());
        let nonce = ChaCha20Poly1305::nonce_gen().unwrap();
        let aad = b"encrypt test".to_vec();
        let message = b"Hello and Goodbye!".to_vec();
        let payload = Payload {
            msg: message.as_slice(),
            aad: aad.as_slice(),
        };
        let res = aes.encrypt(&nonce, payload);
        assert!(res.is_ok());
        let ciphertext = res.unwrap();
        let payload = Payload {
            msg: ciphertext.as_slice(),
            aad: aad.as_slice(),
        };
        let res = aes.decrypt(&nonce, payload);
        assert!(res.is_ok());
        assert_eq!(message, res.unwrap());
    }

    #[test]
    fn decrypt_should_fail() {
        let aes = ChaCha20Poly1305::new(&ChaCha20Poly1305::key_gen().unwrap());
        let aad = b"decrypt should fail".to_vec();
        let message = b"Hello and Goodbye!".to_vec();
        let res = aes.encrypt_easy(&aad, &message);
        assert!(res.is_ok());
        let mut ciphertext = res.unwrap();

        let aad = b"decrypt should succeed".to_vec();
        let res = aes.decrypt_easy(&aad, &ciphertext);
        assert!(res.is_err());

        let aad = b"decrypt should fail".to_vec();
        ciphertext[0] ^= ciphertext[1];
        let res = aes.decrypt_easy(&aad, &ciphertext);
        assert!(res.is_err());
    }

    #[test]
    fn buffer_works() {
        let aes = ChaCha20Poly1305::new(&ChaCha20Poly1305::key_gen().unwrap());
        let aad = b"buffer works".to_vec();
        let dummytext = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.";
        let mut ciphertext = Vec::new();
        let res = aes.encrypt_buffer(&aad, &mut Cursor::new(dummytext), &mut ciphertext);
        assert!(res.is_ok());
        let mut plaintext = Vec::new();
        let res = aes.decrypt_buffer(
            &aad,
            &mut Cursor::new(ciphertext.as_slice()),
            &mut plaintext,
        );
        assert!(res.is_ok());
        assert_eq!(dummytext.to_vec(), plaintext);
    }

    // #[test]
    // fn zeroed_on_drop() {
    //     let mut aes = ChaCha20Poly1305::new(&ChaCha20Poly1305::key_gen().unwrap());
    //     aes.zeroize();
    //
    //     fn as_bytes<T>(x: &T) -> &[u8] {
    //         use std::{mem, slice};
    //
    //         unsafe { slice::from_raw_parts(x as *const T as *const u8, mem::size_of_val(x)) }
    //     }
    //
    //     assert!(as_bytes(&aes.key).iter().all(|b| *b == 0u8));
    // }
}
