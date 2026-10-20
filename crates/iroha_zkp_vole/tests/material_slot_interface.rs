//! Finite interface checks for selected affine-leaf and expanded-row slots.
//!
//! Private test adapters receive classical block callbacks rather than the
//! selected key bytes. Real callbacks are compared with the public backend;
//! controlled replies check affine inversion, cached openings and slot-specific
//! row effects. These are synthetic correspondence tests, not an executed ballot
//! prover, a random-permutation simulation, a fresh-entropy claim, a primitive
//! reduction, a continuation theorem or qualification. Rows are streamed: no
//! vector of every expanded row is retained.

use aes::{
    Block,
    cipher::{BlockEncrypt, KeyInit},
};
use iroha_zkp_vole::{
    bavc::{LeafInput, leaf_commit_as},
    field::{BinaryField, Gf256},
    hash::{Namespace, h0_as},
    params::{FAEST_256F, FAEST_256S, ProofParams, SecurityLevel, VoleParams},
    prg::Prg,
    transcript::derive_iv,
    universal_hash::leaf_hash_bytes,
    variant::Construction,
    vole::{SMALL_VOLE_TWEAK, convert_to_vole},
};

fn encrypt(cipher: &aes::soft::Aes256, address: [u8; 16]) -> [u8; 16] {
    let mut block = Block::from(address);
    cipher.encrypt_block(&mut block);
    block.into()
}

/// This adapter receives no selected-slot key bytes; it only calls `eval`.
fn fill_slot(
    iv: &[u8; 16],
    tweak: u32,
    bits: usize,
    out: &mut [u8],
    eval: &mut impl FnMut([u8; 16]) -> [u8; 16],
) {
    assert_eq!(out.len(), bits.div_ceil(8));
    let low = u32::from_le_bytes(iv[..4].try_into().expect("low IV word"));
    let high = u32::from_le_bytes(iv[12..].try_into().expect("high IV word"));
    for (counter, chunk) in out.chunks_mut(16).enumerate() {
        let mut address = *iv;
        address[..4].copy_from_slice(
            &low.wrapping_add(u32::try_from(counter).expect("bounded block count"))
                .to_le_bytes(),
        );
        address[12..].copy_from_slice(&high.wrapping_add(tweak).to_le_bytes());
        let block = eval(address);
        chunk.copy_from_slice(&block[..chunk.len()]);
    }
    if let Some(last) = out.last_mut() {
        *last &= 0xff >> ((8 - bits % 8) % 8);
    }
}

fn environment(role_tag: u8) -> ([u8; 16], [u8; 128]) {
    // Source-shaped namespaces, not production descriptor digests. Both H4 and
    // H0 are evaluated by the actual backend and remain unmodified.
    let mut prefix = b"PARL/FAEST/v1".to_vec();
    prefix.extend([role_tag; 64]);
    let namespace = Namespace::new(&prefix).expect("bounded namespace");
    let iv = derive_iv(namespace, SecurityLevel::L256, &[0x81; 16], &[0x24; 64])
        .expect("actual H4 invocation");
    let mut hash_key = [0; 128];
    h0_as(
        namespace,
        SecurityLevel::L256,
        Construction::Extended,
        &iv,
        &mut hash_key,
    )
    .expect("actual extended H0 invocation");
    (iv, hash_key)
}

/// The two source affine masks, with zero additive masks in the leaf hash.
fn affine_masks(sd: &[u8; 32], hash_key: &[u8; 128]) -> [u8; 112] {
    let mut input = [0; 128];
    input[..32].copy_from_slice(sd);
    let mut masks = [0; 112];
    leaf_hash_bytes::<Gf256>(&hash_key[..96], &input, &mut masks[..96])
        .expect("exact leaf-hash buffers");
    let seed = Gf256::from_bytes(sd).expect("256-bit seed");
    let h1 = Gf256::from_bytes(&hash_key[96..]).expect("256-bit affine key");
    masks[96..].copy_from_slice(&(seed * h1).to_bytes()[..16]);
    masks
}

#[derive(Debug, PartialEq, Eq)]
struct LeafProjection {
    sd: [u8; 32],
    com: [u8; 112],
}

impl LeafProjection {
    /// The transformed driver's opening uses the retained commitment and has
    /// no callback. This does not call or emulate arbitrary `Commitment::open`.
    fn opening(&self) -> &[u8; 112] {
        &self.com
    }
}

fn leaf_slot(
    iv: &[u8; 16],
    tweak: u32,
    hash_key: &[u8; 128],
    mut eval: impl FnMut([u8; 16]) -> [u8; 16],
) -> LeafProjection {
    let mut raw = [0; 144];
    fill_slot(iv, tweak, 144 * 8, &mut raw, &mut eval);
    let sd = raw[..32].try_into().expect("leaf seed");
    let masks = affine_masks(&sd, hash_key);
    let com = std::array::from_fn(|index| raw[32 + index] ^ masks[index]);
    LeafProjection { sd, com }
}

fn inverse_leaf(projection: &LeafProjection, hash_key: &[u8; 128]) -> [u8; 144] {
    let masks = affine_masks(&projection.sd, hash_key);
    let mut raw = [0; 144];
    raw[..32].copy_from_slice(&projection.sd);
    for (index, byte) in raw[32..].iter_mut().enumerate() {
        *byte = projection.com[index] ^ masks[index];
    }
    raw
}

#[test]
fn nine_block_leaf_projection_matches_source_and_retains_its_opening() {
    let key: [u8; 32] = std::array::from_fn(|index| u8::try_from(index).expect("key byte"));
    let cipher = aes::soft::Aes256::new_from_slice(&key).expect("AES-256 key");
    for role_tag in [0x31, 0x72] {
        let (iv, hash_key) = environment(role_tag);
        for params in [FAEST_256F, FAEST_256S] {
            let row = params.vole();
            for vector in [0, row.tau() - 1] {
                let tweak = u32::try_from(row.leaves() - 1 + vector).expect("leaf tweak");
                let mut calls = 0;
                let actual = leaf_slot(&iv, tweak, &hash_key, |address| {
                    calls += 1;
                    encrypt(&cipher, address)
                });
                assert_eq!(calls, 9);
                let mut sd = [0; 32];
                let mut com = [0; 112];
                leaf_commit_as(
                    Construction::Extended,
                    row,
                    &LeafInput {
                        node_key: &key,
                        iv: &iv,
                        tweak,
                        hash_key: &hash_key,
                    },
                    &mut sd,
                    &mut com,
                )
                .expect("actual affine leaf");
                assert_eq!(actual, LeafProjection { sd, com });
                assert_eq!(actual.opening(), &com);
                assert_eq!(actual.opening(), &com);
                assert_eq!(calls, 9, "cached opening has no primitive access");
            }
        }
    }
}

#[test]
fn affine_inverse_reconstructs_controlled_raw_replies_for_zero_and_nonzero_h0() {
    let (iv, nonzero_key) = environment(0x31);
    assert_ne!(nonzero_key, [0; 128]);
    for hash_key in [[0; 128], nonzero_key] {
        for seed_byte in [0, 0x3d] {
            let expected = LeafProjection {
                sd: [seed_byte; 32],
                com: std::array::from_fn(|index| u8::try_from(index).expect("commitment byte")),
            };
            let raw = inverse_leaf(&expected, &hash_key);
            if hash_key == [0; 128] || seed_byte == 0 {
                assert_eq!(&raw[32..], &expected.com);
            } else {
                assert_ne!(&raw[32..], &expected.com);
            }
            // Chosen replies need not form a permutation. This checks only the
            // affine bijection and exact nine-block projection, not its law.
            let mut calls = 0;
            let actual = leaf_slot(&iv, 6_399, &hash_key, |_| {
                let reply = raw[calls * 16..(calls + 1) * 16]
                    .try_into()
                    .expect("complete raw block");
                calls += 1;
                reply
            });
            assert_eq!(calls, 9);
            assert_eq!(actual, expected);
            assert_eq!(inverse_leaf(&actual, &hash_key), raw);
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
struct Fold {
    u: Vec<u8>,
    columns: Vec<u8>,
}

/// Independent XOR formula, rather than the source's stack-based fold. Exactly
/// one absent seed is supplied by the opaque callback; all known seeds use AES.
fn fold_with_selected_slot(
    row: &VoleParams,
    instance: usize,
    iv: &[u8; 16],
    bits: usize,
    seeds: &[Option<[u8; 32]>],
    mut eval: impl FnMut([u8; 16]) -> [u8; 16],
) -> Fold {
    assert_eq!(
        seeds.len(),
        row.leaves_of(instance).expect("valid instance")
    );
    assert_eq!(seeds.iter().filter(|seed| seed.is_none()).count(), 1);
    let depth = row.depth(instance).expect("valid depth");
    let width = bits.div_ceil(8);
    let tweak = SMALL_VOLE_TWEAK + u32::try_from(instance).expect("instance tweak");
    let mut result = Fold {
        u: vec![0; width],
        columns: vec![0; depth * width],
    };
    let mut current = vec![0; width];
    for (index, seed) in seeds.iter().enumerate() {
        match seed {
            Some(seed) => Prg::new_portable(seed)
                .expect("known seed")
                .fill_bits(iv, tweak, bits, &mut current)
                .expect("full known row"),
            None => fill_slot(iv, tweak, bits, &mut current, &mut eval),
        }
        for (target, byte) in result.u.iter_mut().zip(&current) {
            *target ^= byte;
        }
        for (column, target) in result.columns.chunks_exact_mut(width).enumerate() {
            if index & (1 << column) != 0 {
                for (target, byte) in target.iter_mut().zip(&current) {
                    *target ^= byte;
                }
            }
        }
    }
    result
}

#[test]
fn selected_row_matches_source_and_changes_only_its_index_columns() {
    // These are the ballot layout's 35,840 registration and 53,504 vote witness
    // bits. The backend has no dependency on that higher-level relation crate.
    let witnesses = [35_840, 53_504];
    let target_key = [0xa7; 32];
    let cipher = aes::soft::Aes256::new_from_slice(&target_key).expect("AES-256 key");
    let selected = 0b1011;
    let known_alias = 0b0100;
    for (params, expected_lengths) in [
        (FAEST_256F, [35_920, 53_584]),
        (FAEST_256S, [35_960, 53_624]),
    ] {
        let row = params.vole();
        let instance = row.tau() - 1;
        let count = row.leaves_of(instance).expect("last vector");
        let depth = row.depth(instance).expect("last vector depth");
        assert!(depth < row.d0(), "exercise a shorter vector");
        let mut seeds: Vec<Option<[u8; 32]>> = (0..count)
            .map(|index| {
                let mut seed = [0x59; 32];
                seed[..4].copy_from_slice(&u32::try_from(index).expect("leaf index").to_le_bytes());
                Some(seed)
            })
            .collect();
        seeds[selected] = None;
        seeds[known_alias] = Some(target_key);
        let source_seeds: Vec<u8> = seeds
            .iter()
            .flat_map(|seed| seed.unwrap_or(target_key))
            .collect();
        for (role, witness_bits) in witnesses.into_iter().enumerate() {
            let (iv, _) = environment([0x31, 0x72][role]);
            // A synthetic dimension descriptor: the constraint count is only
            // the minimum accepted here; no relation or proof is constructed.
            let dimensions =
                ProofParams::new(*row, witness_bits, witness_bits).expect("valid row dimensions");
            let bits = dimensions.ell_hat();
            assert_eq!(bits, expected_lengths[role]);
            assert_ne!(bits, witness_bits + row.n_mask() * depth);
            let blocks = bits.div_ceil(128);
            assert_eq!(blocks, [281, 419][role]);
            let width = bits.div_ceil(8);
            let mut source = Fold {
                u: vec![0; width],
                columns: vec![0; depth * width],
            };
            convert_to_vole(
                row,
                instance,
                &iv,
                &source_seeds,
                bits,
                &mut source.u,
                &mut source.columns,
            )
            .expect("actual source fold");
            let mut calls = 0;
            let real = fold_with_selected_slot(row, instance, &iv, bits, &seeds, |address| {
                calls += 1;
                encrypt(&cipher, address)
            });
            assert_eq!(calls, blocks);
            assert_eq!(real, source);

            // The callback changes only the absent seed's slot. In particular,
            // the known alias remains concrete AES despite equal numeric keys.
            let mut controlled_calls = 0;
            let changed = fold_with_selected_slot(row, instance, &iv, bits, &seeds, |address| {
                controlled_calls += 1;
                encrypt(&cipher, address).map(|byte| byte ^ 0xff)
            });
            assert_eq!(controlled_calls, blocks);
            assert!(changed.u.iter().zip(&real.u).all(|(a, b)| a ^ b == 0xff));
            for (column, (changed, real)) in changed
                .columns
                .chunks_exact(width)
                .zip(real.columns.chunks_exact(width))
                .enumerate()
            {
                let delta = if selected & (1 << column) != 0 {
                    0xff
                } else {
                    0
                };
                assert!(changed.iter().zip(real).all(|(a, b)| a ^ b == delta));
            }
        }
    }
}
