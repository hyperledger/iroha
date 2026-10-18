//! Exact Falcon-512 signer known-answer vector.
//!
//! The arrays below are copied verbatim from `fn-dsa-sign` 0.3.0 at
//! workspace commit `daf14859b5aa3f8d75c42966ba7de83e6eb59997`
//! (`src/lib.rs::KAT_512`, Unlicense). They are compiled only for tests.
#![allow(non_upper_case_globals)]
use super::table_assets::read_u16_le;
use super::*;
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;
/// Pinned signer fixture bytes shared by Falcon's test-only arithmetic controls.
pub(super) const KAT_512_BYTES: &[u8; 3_168] = include_bytes!("assets/kat512_v1.bin");
struct Kat512 {
    f: [i8; 512],
    g: [i8; 512],
    capital_f: [i8; 512],
    capital_g: [i8; 512],
    rnd: [u8; 96],
    sig_raw: [i16; 512],
}
const fn decode_kat_512(bytes: &[u8; 3_168]) -> Kat512 {
    let mut kat = Kat512 {
        f: [0; 512],
        g: [0; 512],
        capital_f: [0; 512],
        capital_g: [0; 512],
        rnd: [0; 96],
        sig_raw: [0; 512],
    };
    let mut index = 0;
    while index < 512 {
        kat.f[index] = bytes[index].cast_signed();
        kat.g[index] = bytes[512 + index].cast_signed();
        kat.capital_f[index] = bytes[1_024 + index].cast_signed();
        kat.capital_g[index] = bytes[1_536 + index].cast_signed();
        kat.sig_raw[index] = read_u16_le(bytes, 2_144 + index * 2).cast_signed();
        index += 1;
    }
    let mut rnd_index = 0;
    while rnd_index < 96 {
        kat.rnd[rnd_index] = bytes[2_048 + rnd_index];
        rnd_index += 1;
    }
    kat
}
const KAT_512: Kat512 = decode_kat_512(KAT_512_BYTES);
const KAT_512_f: [i8; 512] = KAT_512.f;
const KAT_512_g: [i8; 512] = KAT_512.g;
const KAT_512_F: [i8; 512] = KAT_512.capital_f;
const KAT_512_G: [i8; 512] = KAT_512.capital_g;
const KAT_512_RND: [u8; 40 + 56] = KAT_512.rnd;
const KAT_512_sig_raw: [i16; 512] = KAT_512.sig_raw;
// Keep the original Falcon hash-to-point routine test-only. Production Bootle
// targets are scoped by scope.rs; this only proves byte-for-byte compatibility
// with the pinned upstream signing KAT.
fn pinned_target() -> [u16; DEGREE] {
    let mut shake = comm::shake::SHAKE256::new();
    shake.inject(&KAT_512_RND[..40]);
    shake.inject(b"data1");
    shake.flip();
    let mut target = [0_u16; DEGREE];
    let mut index = 0;
    while index < DEGREE {
        let mut encoded = [0_u8; 2];
        shake.extract(&mut encoded);
        let mut candidate = u16::from_be_bytes(encoded);
        if candidate < 61_445 {
            while candidate >= MODULUS {
                candidate -= MODULUS;
            }
            target[index] = candidate;
            index += 1;
        }
    }
    target
}
fn pinned_trapdoor() -> Trapdoor {
    let mut public_key = vec![0_u16; DEGREE].into_boxed_slice();
    let mut temporary = Zeroizing::new(vec![0_u16; DEGREE].into_boxed_slice());
    comm::mq::mqpoly_div_small(
        LOG_DEGREE,
        &KAT_512_f,
        &KAT_512_g,
        public_key.as_mut(),
        temporary.as_mut(),
    );
    Trapdoor {
        f: Zeroizing::new(KAT_512_f.to_vec().into_boxed_slice()),
        g: Zeroizing::new(KAT_512_g.to_vec().into_boxed_slice()),
        capital_f: Zeroizing::new(KAT_512_F.to_vec().into_boxed_slice()),
        capital_g: Zeroizing::new(KAT_512_G.to_vec().into_boxed_slice()),
        h: Zeroizing::new(public_key),
    }
}
fn digest_u16_le(values: &[u16]) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(2 * values.len());
    for value in values {
        encoded.extend_from_slice(&value.to_le_bytes());
    }
    Sha256::digest(encoded).to_vec()
}
fn digest_i16_le(parts: &[&[i16]]) -> Vec<u8> {
    let capacity = parts.iter().map(|part| part.len()).sum::<usize>() * 2;
    let mut encoded = Zeroizing::new(Vec::with_capacity(capacity));
    for part in parts {
        for value in *part {
            encoded.extend_from_slice(&value.to_le_bytes());
        }
    }
    Sha256::digest(encoded.as_slice()).to_vec()
}
#[test]
fn pinned_upstream_signer_target_preimage_equation_and_norm_kat() {
    let target = pinned_target();
    assert_eq!(
        digest_u16_le(&target),
        hex::decode("25684a1e6b737b3bacc7e28d31d7b284fa765943aa192ada07a3ff1ceee92eed")
            .expect("hex")
    );
    let trapdoor = pinned_trapdoor();
    let seed: &[u8; 56] = KAT_512_RND[40..].try_into().expect("56-byte seed");
    let preimage =
        sample_preimage_from_seed(&trapdoor, &target, seed).expect("pinned Falcon preimage");
    assert_eq!(preimage.norm_squared, 27_596_801);
    assert!(preimage.norm_squared <= SIGNATURE_NORM_SQUARED_BOUND);
    assert_eq!(
        &preimage.first[..32],
        &[
            176, 37, -5, -160, 165, 81, 182, -170, 29, 57, 475, 508, -48, 14, -46, -45, 252, 115,
            -148, 196, -164, 70, -201, 129, -162, -163, -238, 121, 31, 89, -215, -130,
        ]
    );
    assert_eq!(preimage.second.as_ref(), &KAT_512_sig_raw);
    assert_eq!(
        digest_i16_le(&[preimage.first.as_ref()]),
        hex::decode("32cd444d2a166618472a8e10de914aaef2f8adc38f6b9d1868f740c37df1d8f7")
            .expect("hex")
    );
    assert_eq!(
        digest_i16_le(&[preimage.second.as_ref()]),
        hex::decode("ff4662454a95104f025748042a301925faa9ca47870900704b43a990dd238514")
            .expect("hex")
    );
    assert_eq!(
        digest_i16_le(&[preimage.first.as_ref(), preimage.second.as_ref()]),
        hex::decode("3a492511013d64db0035aad78c0cf2331ad361eb4f6dce47815a5c7dc0790e00")
            .expect("hex")
    );
    assert!(sign::preimage_equation_holds(
        &target,
        trapdoor.h.as_ref(),
        preimage.first.as_ref(),
        preimage.second.as_ref(),
    ));
}
#[test]
fn signer_rejects_noncanonical_target_and_zero_proposal_budget() {
    let trapdoor = pinned_trapdoor();
    let seed: &[u8; 56] = KAT_512_RND[40..].try_into().expect("56-byte seed");
    let target = pinned_target();
    let mut noncanonical = target;
    noncanonical[0] = MODULUS;
    assert!(sample_preimage_from_seed(&trapdoor, &noncanonical, seed).is_none());
    assert!(sign::sampler_exhausts_with_zero_budget_for_test(
        &trapdoor, &target, seed,
    ));
}
#[test]
fn signer_self_check_rejects_each_mutated_trapdoor_component() {
    let target = pinned_target();
    let seed: &[u8; 56] = KAT_512_RND[40..].try_into().expect("56-byte seed");
    let mut trapdoor = pinned_trapdoor();
    trapdoor.h[0] = (trapdoor.h[0] + 1) % MODULUS;
    assert!(sample_preimage_from_seed(&trapdoor, &target, seed).is_none());
    let mut trapdoor = pinned_trapdoor();
    trapdoor.f[0] += 1;
    assert!(sample_preimage_from_seed(&trapdoor, &target, seed).is_none());
    let mut trapdoor = pinned_trapdoor();
    trapdoor.g[0] += 1;
    assert!(sample_preimage_from_seed(&trapdoor, &target, seed).is_none());
    let mut trapdoor = pinned_trapdoor();
    trapdoor.capital_f[0] += 1;
    assert!(sample_preimage_from_seed(&trapdoor, &target, seed).is_none());
    let mut trapdoor = pinned_trapdoor();
    trapdoor.capital_g[0] += 1;
    assert!(sample_preimage_from_seed(&trapdoor, &target, seed).is_none());
}
