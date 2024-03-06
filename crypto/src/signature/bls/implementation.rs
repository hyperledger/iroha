#[cfg(not(feature = "std"))]
use alloc::{borrow::ToOwned as _, string::ToString as _, vec, vec::Vec};
use core::marker::PhantomData;

#[cfg(feature = "rand")]
use rand_chacha::rand_core::OsRng;
use sha2::Sha256;
// TODO: Better to use `SecretKey`, not `SecretKeyVT`, but it requires to implement
// interior mutability
use w3f_bls::{EngineBLS as _, PublicKey, SecretKeyVT as SecretKey, SerializableToBytes as _};
use zeroize::Zeroize as _;

pub(super) const MESSAGE_CONTEXT: &[u8; 20] = b"for signing messages";

use crate::{Algorithm, Error, KeyPairGenOption, ParseError};

pub trait BlsConfiguration {
    const ALGORITHM: Algorithm;
    type Engine: w3f_bls::EngineBLS;
}

pub struct BlsImpl<C: BlsConfiguration + ?Sized>(PhantomData<C>);

impl<C: BlsConfiguration + ?Sized> BlsImpl<C> {
    // the names are from an RFC, not a good idea to change them
    #[allow(clippy::similar_names)]
    pub fn keypair(
        mut option: KeyPairGenOption<SecretKey<C::Engine>>,
    ) -> (PublicKey<C::Engine>, SecretKey<C::Engine>) {
        let private_key = match option {
            #[cfg(feature = "rand")]
            KeyPairGenOption::Random => SecretKey::generate(OsRng),
            // Follows https://datatracker.ietf.org/doc/draft-irtf-cfrg-bls-signature/?include_text=1
            KeyPairGenOption::UseSeed(ref mut seed) => {
                let salt = b"BLS-SIG-KEYGEN-SALT-";
                let info = [0u8, C::Engine::SECRET_KEY_SIZE.try_into().unwrap()]; // key_info || I2OSP(L, 2)
                let mut ikm = vec![0u8; seed.len() + 1];
                ikm[..seed.len()].copy_from_slice(seed); // IKM || I2OSP(0, 1)
                seed.zeroize();
                let mut okm = vec![0u8; C::Engine::SECRET_KEY_SIZE];
                let h = hkdf::Hkdf::<Sha256>::new(Some(&salt[..]), &ikm);
                h.expand(&info[..], &mut okm)
                    .expect("`okm` has the correct length");

                SecretKey::<C::Engine>::from_seed(&okm)
            }
            KeyPairGenOption::FromPrivateKey(ref key) => key.clone(),
        };
        (private_key.into_public(), private_key)
    }

    pub fn sign(message: &[u8], sk: &SecretKey<C::Engine>) -> Vec<u8> {
        let message = w3f_bls::Message::new(MESSAGE_CONTEXT, message);
        sk.sign(&message).to_bytes()
    }

    pub fn verify(
        message: &[u8],
        signature: &[u8],
        pk: &PublicKey<C::Engine>,
    ) -> Result<(), Error> {
        let signature = w3f_bls::Signature::<C::Engine>::from_bytes(signature)
            .map_err(|_| ParseError("Failed to parse signature.".to_owned()))?;
        let message = w3f_bls::Message::new(MESSAGE_CONTEXT, message);

        if !signature.verify(&message, pk) {
            return Err(Error::BadSignature);
        }

        Ok(())
    }

    pub fn parse_public_key(payload: &[u8]) -> Result<PublicKey<C::Engine>, ParseError> {
        PublicKey::from_bytes(payload).map_err(|err| ParseError(err.to_string()))
    }

    pub fn parse_private_key(payload: &[u8]) -> Result<SecretKey<C::Engine>, ParseError> {
        SecretKey::from_bytes(payload).map_err(|err| ParseError(err.to_string()))
    }
}
