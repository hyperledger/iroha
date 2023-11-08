use amcl_wrapper::{
    constants::{GroupG1_SIZE, MODBYTES},
    field_elem::FieldElement,
    group_elem::GroupElement,
    types_g2::GroupG2_SIZE,
};

use super::{
    implementation::{BlsConfiguration, BlsImpl, Signature, MESSAGE_CONTEXT},
    normal::{normal_generate, NormalConfiguration, NormalGenerator, NormalSignature},
    small::{small_generate, SmallConfiguration, SmallGenerator, SmallSignature},
};
use crate::KeyGenOption;

const MESSAGE_1: &[u8; 22] = b"This is a test message";
const MESSAGE_2: &[u8; 20] = b"Another test message";
const SEED: &[u8; 10] = &[1u8; 10];

#[test]
fn size_check() {
    let msg = FieldElement::random();
    let g = NormalGenerator::generator();
    let (pk, sk) = normal_generate(&g);
    assert_eq!(sk.to_bytes().len(), MODBYTES);
    assert_eq!(pk.to_bytes().len(), GroupG1_SIZE);
    let sig = NormalSignature::new(msg.to_bytes().as_slice(), None, &sk);
    assert_eq!(sig.to_bytes().len(), GroupG2_SIZE);

    let g = SmallGenerator::generator();
    let (pk, sk) = small_generate(&g);
    assert_eq!(sk.to_bytes().len(), MODBYTES);
    assert_eq!(pk.to_bytes().len(), GroupG2_SIZE);
    let sig = SmallSignature::new(msg.to_bytes().as_slice(), None, &sk);
    assert_eq!(sig.to_bytes().len(), GroupG1_SIZE);
}

fn signature_generation_from_seed<C: BlsConfiguration>() {
    let keypair_1 = BlsImpl::<C>::new()
        .keypair(Some(KeyGenOption::UseSeed(SEED.to_vec())))
        .unwrap();
    let keypair_2 = BlsImpl::<C>::new()
        .keypair(Some(KeyGenOption::UseSeed(SEED.to_vec())))
        .unwrap();
    assert_eq!(keypair_1, keypair_2);
}

fn signature_verification<C: BlsConfiguration>() {
    let g = C::Generator::generator();
    let (pk, sk) = C::generate(&g);

    let signature_1 = Signature::<C>::new(&MESSAGE_1[..], None, &sk);
    assert!(signature_1.verify(&MESSAGE_1[..], None, &pk, &g));

    let signature_2 = Signature::<C>::new(&MESSAGE_2[..], Some(MESSAGE_CONTEXT), &sk);
    assert!(signature_2.verify(&MESSAGE_2[..], Some(MESSAGE_CONTEXT), &pk, &g));

    // Should fail for different messages
    assert!(!signature_1.verify(&MESSAGE_2[..], Some(MESSAGE_CONTEXT), &pk, &g));
    assert!(!signature_2.verify(&MESSAGE_1[..], None, &pk, &g));
}

#[test]
fn normal_signature_generation_from_seed() {
    signature_generation_from_seed::<NormalConfiguration>();
}

#[test]
fn normal_signature_verification() {
    signature_verification::<NormalConfiguration>();
}

#[test]
fn small_signature_generation_from_seed() {
    signature_generation_from_seed::<SmallConfiguration>();
}

#[test]
fn small_signature_verification() {
    signature_verification::<SmallConfiguration>();
}
