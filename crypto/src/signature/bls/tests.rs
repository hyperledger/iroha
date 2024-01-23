use w3f_bls::SerializableToBytes as _;

use super::{
    implementation::{BlsConfiguration, BlsImpl},
    normal::NormalConfiguration,
    small::SmallConfiguration,
};
use crate::KeyGenOption;

const MESSAGE_1: &[u8; 22] = b"This is a test message";
const MESSAGE_2: &[u8; 20] = b"Another test message";
const SEED: &[u8; 10] = &[1u8; 10];

#[allow(clippy::similar_names)]
fn test_keypair_generation_from_seed<C: BlsConfiguration>() {
    let (pk_1, sk_1) = BlsImpl::<C>::keypair(KeyGenOption::UseSeed(SEED.to_vec()));
    let (pk_2, sk_2) = BlsImpl::<C>::keypair(KeyGenOption::UseSeed(SEED.to_vec()));

    assert!(
        (pk_1, sk_1.to_bytes()) == (pk_2, sk_2.to_bytes()),
        "Keypairs are not equal"
    );
}

fn test_signature_verification<C: BlsConfiguration>() {
    let (pk, sk) = BlsImpl::<C>::keypair(KeyGenOption::Random);

    let signature_1 = BlsImpl::<C>::sign(MESSAGE_1, &sk);
    BlsImpl::<C>::verify(MESSAGE_1, &signature_1, &pk)
        .expect("Signature verification should succeed");
}

fn test_signature_verification_different_messages<C: BlsConfiguration>() {
    let (pk, sk) = BlsImpl::<C>::keypair(KeyGenOption::Random);

    let signature = BlsImpl::<C>::sign(MESSAGE_1, &sk);
    BlsImpl::<C>::verify(MESSAGE_2, &signature, &pk)
        .expect_err("Signature verification for wrong message should fail");
}

#[allow(clippy::similar_names)]
fn test_signature_verification_different_keys<C: BlsConfiguration>() {
    let (_pk_1, sk_1) = BlsImpl::<C>::keypair(KeyGenOption::Random);
    let (pk_2, _sk_2) = BlsImpl::<C>::keypair(KeyGenOption::Random);

    let signature = BlsImpl::<C>::sign(MESSAGE_1, &sk_1);
    BlsImpl::<C>::verify(MESSAGE_1, &signature, &pk_2)
        .expect_err("Signature verification for wrong public key should fail");
}

mod normal {
    use super::*;

    #[test]
    fn keypair_generation_from_seed() {
        test_keypair_generation_from_seed::<NormalConfiguration>();
    }

    #[test]
    fn signature_verification() {
        test_signature_verification::<NormalConfiguration>();
    }

    #[test]
    fn signature_verification_different_messages() {
        test_signature_verification_different_messages::<NormalConfiguration>();
    }

    #[test]
    fn signature_verification_different_keys() {
        test_signature_verification_different_keys::<NormalConfiguration>();
    }
}

mod small {
    use super::*;

    #[test]
    fn keypair_generation_from_seed() {
        test_keypair_generation_from_seed::<SmallConfiguration>();
    }

    #[test]
    fn signature_verification() {
        test_signature_verification::<SmallConfiguration>();
    }

    #[test]
    fn signature_verification_different_messages() {
        test_signature_verification_different_messages::<SmallConfiguration>();
    }

    #[test]
    fn signature_verification_different_keys() {
        test_signature_verification_different_keys::<SmallConfiguration>();
    }
}
