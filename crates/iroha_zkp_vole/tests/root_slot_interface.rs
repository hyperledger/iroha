//! Interface correspondence for the conditional joint root-slot adapter.
//!
//! The private adapter receives only the actual IV, the row's high-bit width and
//! an opaque classical block callback. It exposes the two root children and the
//! high-mask bits through five calls under that one callback. Real AES replies
//! are compared with the public source PRG; controlled replies check projection
//! and designated-slot semantics. This is not a primitive reduction, a random
//! permutation simulator, a proof of fresh-key independence or qualification.
//! It does not execute the whole prover or establish its continuation invariant.

use aes::{
    Block,
    cipher::{BlockEncrypt, KeyInit},
};
use iroha_zkp_vole::{
    hash::Namespace,
    params::{FAEST_256F, FAEST_256S, SecurityLevel},
    prg::Prg,
    transcript::derive_iv,
    vole::MASK_TWEAK,
};

#[derive(Debug, PartialEq, Eq)]
struct RootProjection {
    children: [u8; 64],
    high: Vec<u8>,
}

/// The selected slot has no key bytes or alternate primitive interface.
fn root_slot(
    iv: [u8; 16],
    high_bits: usize,
    mut eval: impl FnMut([u8; 16]) -> [u8; 16],
) -> RootProjection {
    assert!(matches!(high_bits, 80 | 60), "only the two reviewed rows");
    let low = u32::from_le_bytes(iv[..4].try_into().expect("low word"));
    let high = u32::from_le_bytes(iv[12..].try_into().expect("high word"));
    let mut children = [0u8; 64];
    for (counter, child_block) in children.chunks_exact_mut(16).enumerate() {
        let mut address = iv;
        address[..4].copy_from_slice(
            &low.wrapping_add(u32::try_from(counter).expect("four blocks"))
                .to_le_bytes(),
        );
        child_block.copy_from_slice(&eval(address));
    }
    let mut address = iv;
    address[12..].copy_from_slice(&high.wrapping_add(MASK_TWEAK).to_le_bytes());
    let last_block = eval(address);
    let mut high = last_block[..high_bits.div_ceil(8)].to_vec();
    *high.last_mut().expect("nonempty high mask") &= 0xff >> ((8 - high_bits % 8) % 8);
    RootProjection { children, high }
}

fn encrypt(cipher: &aes::soft::Aes256, address: [u8; 16]) -> [u8; 16] {
    let mut block = Block::from(address);
    cipher.encrypt_block(&mut block);
    block.into()
}

/// Independent address description using four complete LE words. The adapter
/// instead retains the supplied middle bytes and edits just the outer words.
fn encode_words(words: [u32; 4]) -> [u8; 16] {
    let mut address = [0u8; 16];
    for (target, word) in address.chunks_exact_mut(4).zip(words) {
        target.copy_from_slice(&word.to_le_bytes());
    }
    address
}

fn expected_addresses(iv: [u8; 16]) -> [[u8; 16]; 5] {
    let words: [u32; 4] = std::array::from_fn(|index| {
        u32::from_le_bytes(iv[index * 4..index * 4 + 4].try_into().expect("IV word"))
    });
    [
        encode_words(words),
        encode_words([words[0].wrapping_add(1), words[1], words[2], words[3]]),
        encode_words([words[0].wrapping_add(2), words[1], words[2], words[3]]),
        encode_words([words[0].wrapping_add(3), words[1], words[2], words[3]]),
        encode_words([
            words[0],
            words[1],
            words[2],
            words[3].wrapping_add(0x7fff_ffff),
        ]),
    ]
}

#[test]
fn joint_root_projection_matches_source_rows_and_both_prg_backends() {
    assert_eq!(MASK_TWEAK, 0x7fff_ffff);
    let key: [u8; 32] = std::array::from_fn(|index| u8::try_from(index).expect("key byte"));
    let cipher = aes::soft::Aes256::new_from_slice(&key).expect("AES-256 key");
    for role_tag in [0x31u8, 0x72] {
        // Source-shaped test namespaces, not production profile digests. H4 is
        // evaluated by the actual transcript implementation and is not patched.
        let mut prefix = b"PARL/FAEST/v1".to_vec();
        prefix.extend([role_tag; 64]);
        let namespace = Namespace::new(&prefix).expect("bounded namespace");
        let iv = derive_iv(namespace, SecurityLevel::L256, &[0x81; 16], &[0x24; 64])
            .expect("actual H4 invocation");
        for (params, expected_bits) in [(FAEST_256F, 80), (FAEST_256S, 60)] {
            let row = params.vole();
            assert_eq!(row.lambda(), SecurityLevel::L256);
            assert_eq!(row.n_mask(), 10);
            let high_bits = row.n_mask() * row.w_grind();
            assert_eq!(high_bits, expected_bits);
            let mut queries = Vec::new();
            let actual = root_slot(iv, high_bits, |address| {
                queries.push(address);
                encrypt(&cipher, address)
            });
            assert_eq!(queries, expected_addresses(iv));
            assert_eq!(queries.len(), 5);
            for (index, address) in queries.iter().enumerate() {
                assert!(!queries[..index].contains(address), "distinct root inputs");
            }
            for prg in [
                Prg::new_portable(&key).expect("portable key"),
                Prg::new(&key).expect("default key"),
            ] {
                let mut children = [0u8; 64];
                let mut high = vec![0u8; high_bits.div_ceil(8)];
                prg.fill(&iv, 0, &mut children).expect("root children");
                prg.fill_bits(&iv, MASK_TWEAK, high_bits, &mut high)
                    .expect("root high bits");
                assert_eq!(actual.children, children, "{:?}", prg.backend());
                assert_eq!(actual.high, high, "{:?}", prg.backend());
            }
        }
    }
}

#[test]
fn five_supplied_replies_preserve_wrapped_iv_and_exact_bit_projection() {
    let iv = encode_words([0xffff_fffe, 0x4433_2211, 0x8877_6655, 0x8000_0001]);
    let expected = [
        encode_words([0xffff_fffe, 0x4433_2211, 0x8877_6655, 0x8000_0001]),
        encode_words([0xffff_ffff, 0x4433_2211, 0x8877_6655, 0x8000_0001]),
        encode_words([0, 0x4433_2211, 0x8877_6655, 0x8000_0001]),
        encode_words([1, 0x4433_2211, 0x8877_6655, 0x8000_0001]),
        encode_words([0xffff_fffe, 0x4433_2211, 0x8877_6655, 0]),
    ];
    assert_eq!(expected_addresses(iv), expected);
    let replies = [[0x11; 16], [0x22; 16], [0x33; 16], [0x44; 16], [0xff; 16]];
    let expected_children: Vec<u8> = replies[..4].concat();
    for (high_bits, expected_high) in [
        (80, vec![0xff; 10]),
        (60, vec![0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x0f]),
    ] {
        let mut queries = Vec::new();
        let actual = root_slot(iv, high_bits, |address| {
            let reply = replies[queries.len()];
            queries.push(address);
            reply
        });
        assert_eq!(queries, expected);
        assert_eq!(queries.len(), 5);
        assert_eq!(actual.children.as_slice(), expected_children);
        assert_eq!(actual.high, expected_high);
    }
}

#[test]
fn an_equal_numeric_child_key_keeps_ordinary_aes_semantics() {
    // The fixture owner knows this key; the selected-slot adapter never receives
    // it. Force a returned child to equal it to exercise the alias branch without
    // assuming away collisions or attempting to estimate their probability.
    let key: [u8; 32] = std::array::from_fn(|index| u8::try_from(index).expect("key byte"));
    let cipher = aes::soft::Aes256::new_from_slice(&key).expect("AES-256 key");
    let iv = encode_words([7, 0x1020_3040, 0x5060_7080, 11]);
    let addresses = expected_addresses(iv);
    let actual_mask_block = encrypt(&cipher, addresses[4]);
    let mut replies = [[0x33; 16]; 5];
    replies[0].copy_from_slice(&key[..16]);
    replies[1].copy_from_slice(&key[16..]);
    replies[4] = actual_mask_block.map(|byte| byte ^ 0xff);

    // These are controlled interface replies, not a sampled ideal permutation.
    // Only this designated slot uses them; known-key public AES stays concrete.
    let mut calls = 0;
    let replaced = root_slot(iv, 80, |address| {
        assert_eq!(address, addresses[calls]);
        let reply = replies[calls];
        calls += 1;
        reply
    });
    assert_eq!(calls, 5);
    let child_key: [u8; 32] = replaced.children[..32].try_into().expect("first child");
    assert_eq!(child_key, key);
    let mut public_high = [0u8; 10];
    Prg::new_portable(&child_key)
        .expect("known child key")
        .fill_bits(&iv, MASK_TWEAK, 80, &mut public_high)
        .expect("ordinary known-key AES");
    assert_eq!(public_high, actual_mask_block[..10]);
    assert_eq!(calls, 5, "known-key use made no designated-slot request");
    for (&controlled, &concrete) in replaced.high.iter().zip(&public_high) {
        assert_eq!(controlled, concrete ^ 0xff);
    }

    // On the real branch, equal numeric keys do give the same AES values.
    let mut real_calls = 0;
    let real = root_slot(iv, 80, |address| {
        real_calls += 1;
        encrypt(&cipher, address)
    });
    assert_eq!(real_calls, 5);
    assert_eq!(real.high, public_high);
}
