//! The extended variant (`iroha_zkp_vole::variant`): the affine-checked leaf
//! commitment against an independent recomputation, commitment round trips on the
//! two 256-bit rows, proofs of the toy relation of `tests/proof_generic.rs`, the
//! counter rule, the proof sizes and known-answer values.
//!
//! The extended variant is FAEST-derived and has no official vectors: the
//! known-answer values at the end are this implementation's own output, pinned so
//! that an independent implementation can be compared with it value by value.
//! Nothing here is a statement about its security.

use std::collections::HashSet;

use iroha_zkp_vole::{
    bavc::{
        self, BavcError, Input, LeafInput, commit_as, decommitment_bytes_as, leaf_commit_as,
        position_in_tree, reconstruct_as,
    },
    codec::{self, CodecError, Field},
    field::{Gf256, LambdaField},
    hash::{Namespace, h5_as},
    params::{FAEST_256F, FAEST_256S, IV_BYTES, ProofParams, VoleParams},
    prg::Prg,
    proof::{ProofContext, ProofError, prove, verify},
    quicksilver::{ConstraintSystem, Relation},
    randomness::Tape,
    transcript::{Challenge1Input, challenge_1_as, message_digest},
    variant::{Binding, Construction, EXTENDED_LAST_COUNTER, SALT_BYTES, Variant},
    vole,
};
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};
use zeroize::Zeroizing;

const EXTENDED: Construction = Construction::Extended;

fn shake256(parts: &[&[u8]], len: usize) -> Vec<u8> {
    let mut sponge = Shake256::default();
    for part in parts {
        sponge.update(part);
    }
    let mut out = vec![0u8; len];
    sponge.finalize_xof().read(&mut out);
    out
}

fn pattern(len: usize, step: u8, offset: u8) -> Vec<u8> {
    (0..len)
        .map(|at| {
            u8::try_from(at % 256)
                .expect("below 256")
                .wrapping_mul(step)
                .wrapping_add(offset)
        })
        .collect()
}

fn array<const N: usize>(step: u8, offset: u8) -> [u8; N] {
    pattern(N, step, offset).try_into().expect("N bytes")
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut text, byte| {
        write!(text, "{byte:02x}").expect("writing to a string");
        text
    })
}

/// The 77-byte prefix shape of the ballot profile.
fn prefix(role: &[u8]) -> Vec<u8> {
    let mut prefix = b"PARL/FAEST/v1".to_vec();
    prefix.extend(shake256(&[role], 64));
    prefix
}

// ---------------------------------------------------------------------------
// An independent field multiplication: schoolbook product of the coefficient
// vectors, one bit at a time, then reduction from the top degree down.
// ---------------------------------------------------------------------------

fn coefficient(bytes: &[u8], index: usize) -> bool {
    (bytes[index / 8] >> (index % 8)) & 1 == 1
}

/// `a * b` in `GF(2)[X] / (X^bits + sum_t X^t)`, byte `i` bit `j` being `X^{8i+j}`.
fn naive_mul(a: &[u8], b: &[u8], bits: usize, taps: &[usize]) -> Vec<u8> {
    assert_eq!((a.len(), b.len()), (bits / 8, bits / 8));
    let mut product = vec![false; 2 * bits];
    for i in 0..bits {
        for j in 0..bits {
            product[i + j] ^= coefficient(a, i) & coefficient(b, j);
        }
    }
    for degree in (bits..2 * bits).rev() {
        if product[degree] {
            product[degree] = false;
            for tap in taps {
                product[degree - bits + tap] ^= true;
            }
        }
    }
    let mut out = vec![0u8; bits / 8];
    for (index, _) in product.iter().enumerate().filter(|(_, set)| **set) {
        out[index / 8] |= 1 << (index % 8);
    }
    out
}

/// `X^256 + X^10 + X^5 + X^2 + 1`.
const TAPS_256: [usize; 4] = [10, 5, 2, 0];
/// `X^768 + X^19 + X^17 + X^4 + 1`.
const TAPS_768: [usize; 4] = [19, 17, 4, 0];

/// The extended leaf commitment recomputed from the generator output
/// `sd[32] || b0[96] || b1[16]` and the key `h0[96] || h1[32]`.
fn independent_leaf(expanded: &[u8], key: &[u8]) -> Vec<u8> {
    assert_eq!((expanded.len(), key.len()), (144, 128));
    let (sd, rest) = expanded.split_at(32);
    let (b0, b1) = rest.split_at(96);
    let (h0, h1) = key.split_at(96);
    // iota(sd) = sd || zero[64].
    let mut injected = sd.to_vec();
    injected.resize(96, 0);
    let mut com = naive_mul(&injected, h0, 768, &TAPS_768);
    for (byte, mask) in com.iter_mut().zip(b0) {
        *byte ^= mask;
    }
    let product = naive_mul(sd, h1, 256, &TAPS_256);
    com.extend(product[..16].iter().zip(b1).map(|(low, mask)| low ^ mask));
    com
}

fn expand(node_key: &[u8], iv: &[u8; IV_BYTES], tweak: u32) -> [u8; 144] {
    let mut expanded = [0u8; 144];
    Prg::new(node_key)
        .expect("valid key")
        .fill(iv, tweak, &mut expanded)
        .expect("short output");
    expanded
}

#[test]
fn the_naive_multiplication_knows_its_moduli() {
    let unit = |bits: usize, degree: usize| {
        let mut bytes = vec![0u8; bits / 8];
        bytes[degree / 8] = 1 << (degree % 8);
        bytes
    };
    // X * X^255 = X^10 + X^5 + X^2 + 1 and X * X^767 = X^19 + X^17 + X^4 + 1.
    let low = naive_mul(&unit(256, 1), &unit(256, 255), 256, &TAPS_256);
    assert_eq!(low[..2], [0x25, 0x04]);
    assert!(low[2..].iter().all(|&byte| byte == 0));
    let wide = naive_mul(&unit(768, 1), &unit(768, 767), 768, &TAPS_768);
    assert_eq!(wide[..3], [0x11, 0x00, 0x0a]);
    assert!(wide[3..].iter().all(|&byte| byte == 0));
    // One is neutral.
    let value = pattern(32, 37, 9);
    assert_eq!(naive_mul(&value, &unit(256, 0), 256, &TAPS_256), value);
}

#[test]
fn the_leaf_commitment_is_the_affine_pair_of_the_decision() {
    let vole = FAEST_256F.vole();
    let ivs: [[u8; 16]; 3] = [[0; 16], [0xff; 16], array(13, 5)];
    let keys: [Vec<u8>; 5] = [
        vec![0u8; 32],
        vec![0xffu8; 32],
        pattern(32, 3, 1),
        pattern(32, 101, 77),
        shake256(&[b"leaf key"], 32),
    ];
    // Hash keys: generic, h1 = 0, h1 = 1, h0 = 0, all ones.
    let mut hash_keys = vec![shake256(&[b"hash key"], 128), pattern(128, 59, 200)];
    let mut zero_h1 = hash_keys[0].clone();
    zero_h1[96..].fill(0);
    let mut one_h1 = zero_h1.clone();
    one_h1[96] = 1;
    let mut zero_h0 = hash_keys[0].clone();
    zero_h0[..96].fill(0);
    hash_keys.extend([zero_h1.clone(), one_h1, zero_h0, vec![0xff; 128]]);

    let mut checks = HashSet::new();
    for (round, node_key) in keys.iter().enumerate() {
        for (iv, tweak) in ivs.iter().zip([0u32, 6399, u32::MAX >> 1]) {
            let expanded = expand(node_key, iv, tweak);
            for hash_key in &hash_keys {
                let (mut sd, mut com) = ([0u8; 32], [0u8; 112]);
                let input = LeafInput {
                    node_key,
                    iv,
                    tweak,
                    hash_key,
                };
                leaf_commit_as(EXTENDED, vole, &input, &mut sd, &mut com).expect("valid call");
                assert_eq!(sd[..], expanded[..32], "round {round}");
                assert_eq!(
                    com[..],
                    independent_leaf(&expanded, hash_key)[..],
                    "round {round}"
                );
                // c0 is the FAEST leaf hash under h0 of the first 128 generator
                // bytes: the reference leaf commitment of the same key.
                let (mut plain_sd, mut plain) = ([0u8; 32], [0u8; 96]);
                bavc::leaf_commit(
                    vole,
                    node_key,
                    iv,
                    tweak,
                    &hash_key[..96],
                    &mut plain_sd,
                    &mut plain,
                )
                .expect("valid call");
                assert_eq!((plain_sd, &plain[..]), (sd, &com[..96]));
            }
            // With h1 = 0 the check is the mask b1 itself.
            let (mut sd, mut com) = ([0u8; 32], [0u8; 112]);
            let input = LeafInput {
                node_key,
                iv,
                tweak,
                hash_key: &zero_h1,
            };
            leaf_commit_as(EXTENDED, vole, &input, &mut sd, &mut com).expect("valid call");
            assert_eq!(com[96..], expanded[128..]);
            checks.insert(com[96..].to_vec());
        }
    }
    assert_eq!(checks.len(), keys.len() * ivs.len());
}

#[test]
fn the_check_separates_seeds_and_depends_on_the_mask_by_xor() {
    // c1 + b1 = low128(sd * h1). For a fixed non-zero h1 multiplication is a
    // bijection, so two distinct seeds collide in the low half with probability
    // 2^-128 each: 300 leaves give 300 distinct values.
    let vole = FAEST_256F.vole();
    let iv: [u8; 16] = array(7, 3);
    let hash_key = shake256(&[b"fixed key"], 128);
    assert!(hash_key[96..].iter().any(|&byte| byte != 0));
    let (mut seeds, mut lows) = (HashSet::new(), HashSet::new());
    for sample in 0u32..300 {
        let node_key = shake256(&[b"sample", &sample.to_le_bytes()], 32);
        let expanded = expand(&node_key, &iv, 17);
        let (mut sd, mut com) = ([0u8; 32], [0u8; 112]);
        let input = LeafInput {
            node_key: &node_key,
            iv: &iv,
            tweak: 17,
            hash_key: &hash_key,
        };
        leaf_commit_as(EXTENDED, vole, &input, &mut sd, &mut com).expect("valid call");
        let low: Vec<u8> = com[96..]
            .iter()
            .zip(&expanded[128..])
            .map(|(check, mask)| check ^ mask)
            .collect();
        assert_eq!(
            low[..],
            naive_mul(&sd, &hash_key[96..], 256, &TAPS_256)[..16]
        );
        seeds.insert(sd);
        lows.insert(low);
    }
    assert_eq!((seeds.len(), lows.len()), (300, 300));
}

#[test]
fn the_extended_leaf_exists_on_the_256_bit_three_block_rows_only() {
    use iroha_zkp_vole::{
        params::{FAEST_128F, FAEST_EM_256F},
        variant::VariantError,
    };
    let (mut sd, mut com) = ([0u8; 32], [0u8; 112]);
    let iv = [0u8; 16];
    let input = LeafInput {
        node_key: &[1; 32],
        iv: &iv,
        tweak: 0,
        hash_key: &[2; 128],
    };
    assert_eq!(
        leaf_commit_as(EXTENDED, FAEST_128F.vole(), &input, &mut sd, &mut com),
        Err(BavcError::Variant(VariantError::UnsupportedLevel {
            lambda: 128
        }))
    );
    let unsupported = BavcError::Variant(VariantError::UnsupportedLeafBlocks { n_leafcom: 2 });
    assert_eq!(
        leaf_commit_as(EXTENDED, FAEST_EM_256F.vole(), &input, &mut sd, &mut com),
        Err(unsupported)
    );
    assert_eq!(
        commit_as(
            Namespace::REFERENCE,
            EXTENDED,
            FAEST_EM_256F.vole(),
            &[0; 32],
            &iv
        )
        .err(),
        Some(unsupported)
    );
    assert_eq!(
        reconstruct_as(
            Namespace::REFERENCE,
            EXTENDED,
            FAEST_128F.vole(),
            &[],
            &[],
            &iv
        ),
        Err(BavcError::Variant(VariantError::UnsupportedLevel {
            lambda: 128
        }))
    );
    // Wrong buffer lengths of the extended rule.
    let vole = FAEST_256F.vole();
    let short = LeafInput {
        hash_key: &[2; 96],
        ..input
    };
    assert_eq!(
        leaf_commit_as(EXTENDED, vole, &short, &mut sd, &mut com),
        Err(BavcError::InvalidLength {
            input: Input::LeafHashKey,
            expected: 128,
            actual: 96
        })
    );
    assert_eq!(
        leaf_commit_as(EXTENDED, vole, &input, &mut sd, &mut com[..96]),
        Err(BavcError::InvalidLength {
            input: Input::LeafCommitment,
            expected: 112,
            actual: 96
        })
    );
}

/// The commitment recomputed with an independent SHAKE from the node keys:
/// `H_0` to 128 bytes, the public leaf function, the inner `H_1` over the
/// 112-byte leaf commitments in index order and the outer `H_1`.
fn independent_commitment(
    prefix: &[u8],
    vole: &VoleParams,
    keys: &[u8],
    iv: &[u8; IV_BYTES],
) -> Vec<u8> {
    let hash_key = shake256(&[prefix, iv, &[0x00]], 128);
    let mut outer = Vec::new();
    for vector in 0..vole.tau() {
        let tweak = u32::try_from(vole.leaves() - 1 + vector).expect("small");
        let mut inner = Vec::new();
        for index in 0..vole.leaves_of(vector).expect("vector below tau") {
            let node = position_in_tree(vole, vector, index).expect("valid leaf");
            let (mut sd, mut com) = ([0u8; 32], [0u8; 112]);
            let input = LeafInput {
                node_key: &keys[32 * node..32 * (node + 1)],
                iv,
                tweak,
                hash_key: &hash_key,
            };
            leaf_commit_as(EXTENDED, vole, &input, &mut sd, &mut com).expect("valid call");
            inner.extend_from_slice(&com);
        }
        outer.extend(shake256(&[prefix, &inner, &[0x01]], 64));
    }
    shake256(&[prefix, &outer, &[0x01]], 64)
}

#[test]
fn commitments_open_and_reconstruct_with_112_byte_leaf_commitments() {
    let prefix = prefix(b"BAVC");
    let namespace = Namespace::new(&prefix).expect("77 bytes");
    let iv: [u8; 16] = array(13, 5);
    for (set, opening_bytes) in [(FAEST_256F, 11_024), (FAEST_256S, 9_664)] {
        let vole = set.vole();
        let (tau, t_open) = (vole.tau(), vole.t_open());
        let root = pattern(32, 11, 3);
        let commitment = commit_as(namespace, EXTENDED, vole, &root, &iv).expect("valid call");
        assert_eq!(commitment.construction(), EXTENDED);
        assert_eq!(decommitment_bytes_as(EXTENDED, vole), opening_bytes);
        assert_eq!(opening_bytes, 112 * tau + 32 * t_open);
        assert_eq!(
            commitment.commitment(),
            independent_commitment(&prefix, vole, commitment.node_keys(), &iv)
        );
        // The tree and the seeds are those of the FAEST construction; only the
        // leaf commitments, and so the commitment, differ.
        let faest = bavc::commit_in(namespace, vole, &root, &iv).expect("valid call");
        assert_eq!(faest.construction(), Construction::Faest);
        assert_eq!(faest.node_keys(), commitment.node_keys());
        assert_eq!(faest.seeds(tau - 1), commitment.seeds(tau - 1));
        assert_ne!(faest.commitment(), commitment.commitment());

        let hash_key = shake256(&[&prefix, &iv, &[0x00]], 128);
        for same in [0u16, 5] {
            let hidden = vec![same; tau];
            let nodes = bavc::opening_nodes(vole, &hidden).expect("valid pattern");
            assert!(nodes < t_open, "{}: the pattern needs padding", set.name());
            let opening = commitment.open(&hidden).expect("within T_open");
            assert_eq!(opening.len(), opening_bytes);
            // The hidden commitments are the full 112 bytes of the hidden leaves.
            for (vector, com) in opening[..112 * tau].chunks_exact(112).enumerate() {
                let node = position_in_tree(vole, vector, usize::from(same)).expect("valid leaf");
                let tweak = u32::try_from(vole.leaves() - 1 + vector).expect("small");
                let expanded = expand(
                    &commitment.node_keys()[32 * node..32 * (node + 1)],
                    &iv,
                    tweak,
                );
                if vector % 11 == 0 {
                    assert_eq!(com, independent_leaf(&expanded, &hash_key));
                }
            }
            assert!(
                opening[112 * tau + 32 * nodes..]
                    .iter()
                    .all(|&byte| byte == 0)
            );

            let opened = reconstruct_as(namespace, EXTENDED, vole, &opening, &hidden, &iv)
                .expect("valid opening");
            assert_eq!(opened.commitment(), commitment.commitment());
            for vector in [0, tau / 2, tau - 1] {
                let expected = commitment.seeds(vector).expect("vector below tau");
                let seeds = opened.seeds(vector).expect("vector below tau");
                for (index, (seed, slot)) in expected
                    .chunks_exact(32)
                    .zip(seeds.chunks_exact(32))
                    .enumerate()
                {
                    if index == usize::from(same) {
                        assert_eq!(slot, [0u8; 32]);
                    } else {
                        assert_eq!(slot, seed);
                    }
                }
            }

            // The tamper cases need one pattern only.
            if same != 0 {
                continue;
            }
            // Tampering: c0, c1 (first and last byte), a sibling seed.
            let reconstructed = |opening: &[u8]| {
                reconstruct_as(namespace, EXTENDED, vole, opening, &hidden, &iv)
                    .map(|opened| opened.commitment() == commitment.commitment())
            };
            for (vector, at) in [(0, 0), (0, 96), (tau - 1, 95), (tau - 1, 111)] {
                let mut tampered = opening.clone();
                tampered[112 * vector + at] ^= 0x10;
                assert_eq!(reconstructed(&tampered), Ok(false), "com byte {at}");
            }
            for at in [112 * tau, 112 * tau + 32 * nodes - 1] {
                let mut tampered = opening.clone();
                tampered[at] ^= 1;
                assert_eq!(reconstructed(&tampered), Ok(false), "seed byte {at}");
            }
            // Padding.
            for at in [112 * tau + 32 * nodes, opening_bytes - 1] {
                let mut tampered = opening.clone();
                tampered[at] ^= 1;
                assert_eq!(reconstructed(&tampered), Err(BavcError::NonZeroPadding));
            }
            // Another pattern, namespace or iv gives another commitment.
            let mut moved = hidden.clone();
            moved[0] ^= 1;
            let other = reconstruct_as(namespace, EXTENDED, vole, &opening, &moved, &iv);
            assert!(other.is_ok_and(|opened| opened.commitment() != commitment.commitment()));
            let other = Namespace::new(b"another").expect("bounded");
            let foreign = reconstruct_as(other, EXTENDED, vole, &opening, &hidden, &iv);
            assert!(foreign.is_ok_and(|opened| opened.commitment() != commitment.commitment()));

            // The constructions do not mix: sizes differ by 16 bytes per vector.
            let invalid = |expected, actual| {
                Err(BavcError::InvalidLength {
                    input: Input::Decommitment,
                    expected,
                    actual,
                })
            };
            let faest_bytes = bavc::decommitment_bytes(vole);
            assert_eq!(faest_bytes + 16 * tau, opening_bytes);
            assert_eq!(
                bavc::reconstruct_in(namespace, vole, &opening, &hidden, &iv),
                invalid(faest_bytes, opening_bytes)
            );
            let plain = faest.open(&hidden).expect("within T_open");
            assert_eq!(
                reconstruct_as(namespace, EXTENDED, vole, &plain, &hidden, &iv),
                invalid(opening_bytes, faest_bytes)
            );
            // A FAEST opening stretched to the extended length does not
            // reconstruct the extended commitment either.
            let mut stretched = Vec::new();
            for com in plain[..96 * tau].chunks_exact(96) {
                stretched.extend_from_slice(com);
                stretched.extend_from_slice(&[0; 16]);
            }
            stretched.extend_from_slice(&plain[96 * tau..]);
            assert_eq!(reconstructed(&stretched), Ok(false));
        }
    }
}

// ---------------------------------------------------------------------------
// The toy relation of `tests/proof_generic.rs`, copied: constraints of degree 1,
// 2, 4 and 7, an identically zero one, field scalars and mixed degrees.
// ---------------------------------------------------------------------------

const ELL: usize = 320;
const SCALAR_SEED: u64 = 0x9e37_79b9_7f4a_7c15;

struct Toy;

fn public_bit(public: &[u8], index: usize) -> bool {
    public
        .get(index / 8)
        .is_some_and(|byte| (byte >> (index % 8)) & 1 == 1)
}

fn scalars<F: LambdaField>() -> [F; 16] {
    let seed = F::from_u64(SCALAR_SEED);
    let mut current = F::ONE;
    core::array::from_fn(|_| {
        current *= seed;
        current
    })
}

impl<F: LambdaField> Relation<F> for Toy {
    type PublicInput = [u8];

    fn witness_bits(&self) -> usize {
        ELL
    }

    fn constraints(&self) -> usize {
        31
    }

    fn emit<C: ConstraintSystem<Field = F>>(&self, public: &[u8], cs: &mut C) {
        let w = |index: usize| cs.witness(index);
        let mut out = Zeroizing::new(Vec::with_capacity(31));
        for i in 0..8 {
            let b = 128 + 3 * i;
            let sum = cs.add(cs.add(w(b), w(b + 1)), w(b + 2));
            out.push(cs.add_bit(sum, public_bit(public, i)));
        }
        for i in 0..8 {
            let b = 160 + 3 * i;
            let sum = cs.add(cs.mul(w(b), w(b + 1)), w(b + 2));
            out.push(cs.add_bit(sum, public_bit(public, 8 + i)));
        }
        for i in 0..8 {
            let b = 192 + 5 * i;
            let product = cs.mul(cs.mul(w(b), w(b + 1)), cs.mul(w(b + 2), w(b + 3)));
            out.push(cs.add_bit(cs.add(product, w(b + 4)), public_bit(public, 16 + i)));
        }
        for i in 0..4 {
            let b = 232 + 8 * i;
            let mut product = w(b);
            for j in 1..7 {
                product = cs.mul(product, w(b + j));
            }
            out.push(cs.add_bit(cs.add(product, w(b + 7)), public_bit(public, 24 + i)));
        }
        out.push(cs.mul(w(264), cs.zero()));
        let scalars = scalars::<F>();
        let mut target = F::ZERO;
        let mut sum = cs.zero();
        for (j, scalar) in scalars.into_iter().enumerate() {
            target += scalar.mul_bit(u8::from(public_bit(public, 32 + j)));
            sum = cs.add(sum, cs.scale(w(272 + j), scalar));
        }
        out.push(cs.add(sum, cs.constant(target)));
        let low = cs.mul(w(288), w(289));
        let high = cs.mul(cs.mul(w(290), w(291)), cs.mul(w(292), w(293)));
        out.push(cs.add_bit(cs.add(cs.add(low, high), w(294)), public_bit(public, 48)));
        for value in out.iter() {
            cs.constrain(*value);
        }
    }
}

/// A witness of [`Toy`] for `public`, as in `tests/proof_generic.rs`.
fn witness(public: &[u8], seed: u8) -> Vec<u8> {
    let mut bytes = shake256(&[b"proof_generic witness", &[seed]], ELL / 8);
    let get = |bytes: &[u8], index: usize| (bytes[index / 8] >> (index % 8)) & 1 == 1;
    let set = |bytes: &mut [u8], index: usize, bit: bool| {
        bytes[index / 8] &= !(1 << (index % 8));
        bytes[index / 8] |= u8::from(bit) << (index % 8);
    };
    let p = |index: usize| public_bit(public, index);
    for i in 0..8 {
        let b = 128 + 3 * i;
        let bit = get(&bytes, b) ^ get(&bytes, b + 1) ^ p(i);
        set(&mut bytes, b + 2, bit);
        let b = 160 + 3 * i;
        let bit = (get(&bytes, b) & get(&bytes, b + 1)) ^ p(8 + i);
        set(&mut bytes, b + 2, bit);
        let b = 192 + 5 * i;
        let bit = (b..b + 4).all(|index| get(&bytes, index)) ^ p(16 + i);
        set(&mut bytes, b + 4, bit);
    }
    for i in 0..4 {
        let b = 232 + 8 * i;
        if i % 2 == 0 {
            for index in b..b + 7 {
                set(&mut bytes, index, true);
            }
        }
        let bit = (b..b + 7).all(|index| get(&bytes, index)) ^ p(24 + i);
        set(&mut bytes, b + 7, bit);
    }
    for j in 0..16 {
        set(&mut bytes, 272 + j, p(32 + j));
    }
    let bit =
        (get(&bytes, 288) & get(&bytes, 289)) ^ (290..294).all(|index| get(&bytes, index)) ^ p(48);
    set(&mut bytes, 294, bit);
    bytes
}

fn salt_of(seed: u8) -> [u8; SALT_BYTES] {
    array(17, 0x40u8.wrapping_add(seed))
}

fn extended_tape(seed: u8, salt: &[u8; SALT_BYTES]) -> Tape {
    Tape::extended(
        iroha_zkp_vole::params::SecurityLevel::L256,
        &pattern(32, 11, 3u8.wrapping_add(seed)),
        &array(13, 5u8.wrapping_add(seed)),
        salt,
    )
    .expect("valid tape")
}

/// One extended proving setup.
struct Setup<'a> {
    context: ProofContext<'a>,
    params: ProofParams,
    public: Vec<u8>,
    mu: Vec<u8>,
    witness: Vec<u8>,
    proof: Vec<u8>,
}

fn setup<'a>(namespace: Namespace<'a>, vole: &VoleParams, seed: u8) -> Setup<'a> {
    let context = ProofContext::extended(namespace, *vole).expect("supported row");
    assert_eq!(context.variant(), Variant::Extended);
    let public = pattern(7, 29, seed);
    let mu =
        message_digest(namespace, vole.lambda(), &[b"toy statement", &public]).expect("valid call");
    let witness = witness(&public, seed);
    let proof = prove::<Gf256, _>(
        &context,
        &Toy,
        &public[..],
        &mu,
        &witness,
        &extended_tape(seed, &salt_of(seed)),
    )
    .expect("valid witness");
    let params = context.params_for::<Gf256, _>(&Toy).expect("valid row");
    Setup {
        context,
        params,
        public,
        mu,
        witness,
        proof,
    }
}

fn accepts(setup: &Setup<'_>, proof: &[u8]) -> Result<(), ProofError> {
    verify::<Gf256, _>(&setup.context, &Toy, &setup.public[..], &setup.mu, proof)
}

fn field_of<'p>(params: &ProofParams, proof: &'p [u8], field: Field) -> &'p [u8] {
    let at = field.offset_as(EXTENDED, params);
    &proof[at..at + field.bytes_as(EXTENDED, params)]
}

#[test]
fn honest_extended_proofs_verify_and_every_field_is_bound() {
    let prefix = prefix(b"REG");
    let namespace = Namespace::new(&prefix).expect("77 bytes");
    for (set, seed, len) in [(FAEST_256F, 2u8, 13_628), (FAEST_256S, 3, 11_818)] {
        let vole = set.vole();
        let setup = setup(namespace, vole, seed);
        let Setup { params, proof, .. } = &setup;
        assert_eq!(accepts(&setup, proof), Ok(()), "{}", set.name());
        assert_eq!(proof.len(), len);
        assert_eq!(setup.context.proof_bytes::<Gf256, _>(&Toy), Ok(len));
        assert_eq!(codec::proof_bytes_as(EXTENDED, params), len);
        assert_eq!(
            len,
            codec::proof_bytes(params) + SALT_BYTES + 16 * vole.tau()
        );
        assert_eq!(field_of(params, proof, Field::Salt), salt_of(seed));
        let fields = codec::decode_as(EXTENDED, params, proof).expect("canonical");
        assert_eq!(fields.salt, Some(&salt_of(seed)));
        assert!(fields.counter <= EXTENDED_LAST_COUNTER);

        // The salt of the proof is bound: any other salt is another H_5 and
        // another first challenge.
        let salt_at = Field::Salt.offset_as(EXTENDED, params);
        for (at, mask) in [(0, 1u8), (17, 0x40), (31, 0x80)] {
            let mut other = proof.clone();
            other[salt_at + at] ^= mask;
            assert_eq!(accepts(&setup, &other), Err(ProofError::ChallengeMismatch));
        }
        let mut swapped = proof.clone();
        swapped[salt_at..salt_at + 32].copy_from_slice(&salt_of(seed.wrapping_add(1)));
        assert_eq!(
            accepts(&setup, &swapped),
            Err(ProofError::ChallengeMismatch)
        );

        // One flipped bit anywhere: first, middle and last byte of every field.
        for field in Field::EXTENDED {
            let (at, bytes) = (
                field.offset_as(EXTENDED, params),
                field.bytes_as(EXTENDED, params),
            );
            assert!(bytes > 0, "{field:?}");
            for (offset, bit) in [(0, 0), (bytes / 2, 3), (bytes - 1, 7)] {
                let mut flipped = proof.clone();
                flipped[at + offset] ^= 1 << bit;
                assert!(
                    accepts(&setup, &flipped).is_err(),
                    "{}: {field:?} byte {offset} bit {bit}",
                    set.name()
                );
            }
        }
        // Inside the opening: c0 and c1 of a hidden commitment and a sibling key.
        let opening = Field::Decommitment.offset_as(EXTENDED, params);
        for at in [5, 96, 111, 112 * vole.tau() + 1] {
            let mut flipped = proof.clone();
            flipped[opening + at] ^= 4;
            assert_eq!(
                accepts(&setup, &flipped),
                Err(ProofError::ChallengeMismatch),
                "opening byte {at}"
            );
        }

        // Another statement, mu or prefix.
        let mut public = setup.public.clone();
        public[0] ^= 1;
        assert_eq!(
            verify::<Gf256, _>(&setup.context, &Toy, &public[..], &setup.mu, proof),
            Err(ProofError::ChallengeMismatch)
        );
        let other_prefix = prefix_of_other_role();
        let other = Namespace::new(&other_prefix).expect("77 bytes");
        let foreign = ProofContext::extended(other, *vole).expect("supported row");
        assert_eq!(
            verify::<Gf256, _>(&foreign, &Toy, &setup.public[..], &setup.mu, proof),
            Err(ProofError::ChallengeMismatch)
        );
    }
}

fn prefix_of_other_role() -> Vec<u8> {
    prefix(b"VOTE")
}

#[test]
fn proofs_of_one_variant_do_not_verify_in_another() {
    let prefix = prefix(b"REG");
    let namespace = Namespace::new(&prefix).expect("77 bytes");
    for (set, seed) in [(FAEST_256F, 4u8), (FAEST_256S, 5)] {
        let vole = set.vole();
        let extended = setup(namespace, vole, seed);
        let prefixed = ProofContext::new(namespace, *vole).expect("non-empty prefix");
        assert_eq!(prefixed.variant(), Variant::Prefixed);
        let plain_tape = Tape::explicit(
            vole.lambda(),
            &pattern(32, 11, 3u8.wrapping_add(seed)),
            &array(13, 5u8.wrapping_add(seed)),
        )
        .expect("valid tape");
        let plain = prove::<Gf256, _>(
            &prefixed,
            &Toy,
            &extended.public[..],
            &extended.mu,
            &extended.witness,
            &plain_tape,
        )
        .expect("valid witness");
        assert_eq!(
            verify::<Gf256, _>(&prefixed, &Toy, &extended.public[..], &extended.mu, &plain),
            Ok(())
        );
        // The lengths never coincide: 32 + 16 tau bytes apart.
        let (long, short) = (extended.proof.len(), plain.len());
        assert_eq!(long, short + 32 + 16 * vole.tau());
        let wrong_length = |expected, actual| {
            Err(ProofError::Codec(CodecError::InvalidLength {
                expected,
                actual,
            }))
        };
        assert_eq!(
            verify::<Gf256, _>(
                &prefixed,
                &Toy,
                &extended.public[..],
                &extended.mu,
                &extended.proof
            ),
            wrong_length(short, long)
        );
        assert_eq!(accepts(&extended, &plain), wrong_length(long, short));
        let reference = ProofContext::reference(*vole);
        assert_eq!(
            verify::<Gf256, _>(
                &reference,
                &Toy,
                &extended.public[..],
                &extended.mu,
                &extended.proof
            ),
            wrong_length(short, long)
        );
        // Same tree, same root, same iv: the two variants still share nothing a
        // verifier could reuse beyond the public corrections.
        let params = &extended.params;
        assert_eq!(
            field_of(params, &extended.proof, Field::Corrections),
            &plain[..Field::Corrections.bytes(params)]
        );
        // Cutting or padding to the other length does not help.
        let mut cut = extended.proof.clone();
        cut.truncate(short);
        assert!(
            verify::<Gf256, _>(&prefixed, &Toy, &extended.public[..], &extended.mu, &cut).is_err()
        );
        let mut padded = plain.clone();
        padded.resize(long, 0);
        assert!(accepts(&extended, &padded).is_err());
    }
}

#[test]
fn the_same_tape_gives_the_same_bytes_and_the_salt_alone_moves_what_follows_it() {
    let prefix = prefix(b"REG");
    let namespace = Namespace::new(&prefix).expect("77 bytes");
    for (set, seed) in [(FAEST_256F, 6u8), (FAEST_256S, 7)] {
        let vole = set.vole();
        let first = setup(namespace, vole, seed);
        let again = setup(namespace, vole, seed);
        assert_eq!(first.proof, again.proof);

        let other_salt = salt_of(seed.wrapping_add(100));
        let other = prove::<Gf256, _>(
            &first.context,
            &Toy,
            &first.public[..],
            &first.mu,
            &first.witness,
            &extended_tape(seed, &other_salt),
        )
        .expect("valid witness");
        assert_eq!(accepts(&first, &other), Ok(()));
        let params = &first.params;
        let unchanged = [Field::Corrections, Field::MaskedWitness, Field::IvPre];
        let changed = [
            Field::MultCorrections,
            Field::UTilde,
            Field::Coefficients,
            Field::Decommitment,
            Field::Challenge,
            Field::Salt,
        ];
        for field in unchanged {
            assert_eq!(
                field_of(params, &first.proof, field),
                field_of(params, &other, field),
                "{field:?}"
            );
        }
        for field in changed {
            assert_ne!(
                field_of(params, &first.proof, field),
                field_of(params, &other, field),
                "{field:?}"
            );
        }
        // Every field is in one of the two lists, except the counter, which may
        // or may not coincide.
        assert_eq!(unchanged.len() + changed.len() + 1, Field::EXTENDED.len());

        // The vector commitment is not in the proof: recompute it. It, u and the
        // corrections do not depend on the salt; c_mult does.
        let tables = vole.crt_tables().expect("embedded tables");
        let iv = iroha_zkp_vole::transcript::derive_iv(
            namespace,
            vole.lambda(),
            &array(13, 5u8.wrapping_add(seed)),
            &first.mu,
        )
        .expect("valid call");
        let root = pattern(32, 11, 3u8.wrapping_add(seed));
        let commit = |salt: &[u8; SALT_BYTES]| {
            vole::commit_as(
                namespace,
                Binding::Extended { salt },
                params,
                tables,
                &root,
                &iv,
            )
            .expect("valid call")
        };
        let (one, two) = (commit(&salt_of(seed)), commit(&other_salt));
        assert_eq!(one.commitment(), two.commitment());
        assert_eq!(one.corrections(), two.corrections());
        assert_eq!(one.u(), two.u());
        assert_ne!(one.mult_corrections(), two.mult_corrections());
        assert_eq!(
            one.corrections(),
            field_of(params, &first.proof, Field::Corrections)
        );
        assert_eq!(
            one.mult_corrections(),
            field_of(params, &first.proof, Field::MultCorrections)
        );
        // The verifier's side: the opening of the proof reconstructs that
        // commitment under either salt (the salt is not in the tree), but the
        // mask keys, which come from H_5, only under the proof's salt.
        let fields = codec::decode_as(EXTENDED, params, &first.proof).expect("canonical");
        let opening = vole::Opening {
            challenge: fields.challenge,
            decommitment: fields.decommitment,
            corrections: fields.corrections,
            mult_corrections: fields.mult_corrections,
        };
        let reconstruct =
            |binding| vole::reconstruct_as(namespace, binding, params, tables, &opening, &iv);
        let own = reconstruct(fields.binding()).expect("valid opening");
        let foreign = reconstruct(Binding::Extended { salt: &other_salt }).expect("valid opening");
        assert_eq!(own.commitment(), one.commitment());
        assert_eq!(foreign.commitment(), one.commitment());
        assert_eq!(own.q(), foreign.q());
        assert_ne!(own.q_masks(), foreign.q_masks());
        // The FAEST construction expects another opening length.
        assert!(matches!(
            reconstruct(Binding::Faest),
            Err(vole::VoleError::Bavc(BavcError::InvalidLength {
                input: Input::Decommitment,
                ..
            }))
        ));

        // The salted first challenge of the proof, recomputed with an independent
        // SHAKE: mu || com || c || c_mult || iv_pre || salt || 0x09.
        let iv_pre: [u8; 16] = array(13, 5u8.wrapping_add(seed));
        let challenge = challenge_1_as(
            namespace,
            Binding::Extended {
                salt: &salt_of(seed),
            },
            params,
            &Challenge1Input {
                mu: &first.mu,
                commitment: one.commitment(),
                corrections: one.corrections(),
                mult_corrections: one.mult_corrections(),
                iv_pre: &iv_pre,
            },
        )
        .expect("valid call");
        assert_eq!(
            challenge,
            shake256(
                &[
                    &prefix,
                    &first.mu,
                    one.commitment(),
                    one.corrections(),
                    one.mult_corrections(),
                    &iv_pre,
                    &salt_of(seed),
                    &[0x09]
                ],
                264
            )
        );
    }
}

#[test]
fn a_counter_above_the_limit_is_rejected_before_anything_else() {
    assert_eq!(EXTENDED_LAST_COUNTER, 0x000f_ffff);
    assert_eq!(EXTENDED.last_counter(), 0x000f_ffff);
    let prefix = prefix(b"REG");
    let namespace = Namespace::new(&prefix).expect("77 bytes");
    let setup = setup(namespace, FAEST_256F.vole(), 8);
    let params = &setup.params;
    let above = |counter| {
        Err(ProofError::Codec(CodecError::CounterOutOfRange {
            counter,
            last: 0x000f_ffff,
        }))
    };
    let with_counter = |proof: &[u8], counter: u32| {
        let mut proof = proof.to_vec();
        let at = Field::Counter.offset_as(EXTENDED, params);
        proof[at..].copy_from_slice(&counter.to_le_bytes());
        proof
    };
    let honest = codec::decode_as(EXTENDED, params, &setup.proof)
        .expect("canonical")
        .counter;
    // The valid proof with a counter that differs only above bit 20: the same low
    // 20 bits do not make it acceptable, and the rejection names the counter.
    for counter in [honest | 0x0010_0000, 0x0010_0000, u32::MAX] {
        assert_eq!(
            accepts(&setup, &with_counter(&setup.proof, counter)),
            above(counter)
        );
    }
    // Bodies that are rejected for four different reasons with a counter in range
    // are all rejected for the counter when it is out of range: the check runs
    // before the padding, the challenge and the reconstruction are looked at.
    let challenge = Field::Challenge.offset_as(EXTENDED, params);
    let mut grinding = setup.proof.clone();
    grinding[challenge + 31] |= 0x80;
    let mut padding = setup.proof.clone();
    padding[challenge - 1] |= 1;
    let mut opening = setup.proof.clone();
    opening[Field::Decommitment.offset_as(EXTENDED, params)] ^= 1;
    let mut statement = setup.proof.clone();
    statement[Field::MaskedWitness.offset_as(EXTENDED, params)] ^= 1;
    let in_range: [(&[u8], ProofError); 4] = [
        (
            &grinding,
            ProofError::Codec(CodecError::Challenge(BavcError::GrindingBitsSet)),
        ),
        (
            &padding,
            ProofError::Codec(CodecError::NonZeroPadding {
                field: Field::Decommitment,
            }),
        ),
        (&opening, ProofError::ChallengeMismatch),
        (&statement, ProofError::ChallengeMismatch),
    ];
    for (body, expected) in in_range {
        assert_eq!(accepts(&setup, body), Err(expected));
        assert_eq!(
            accepts(&setup, &with_counter(body, 0x0010_0000)),
            above(0x0010_0000)
        );
    }
    // The largest allowed counter is evaluated once like any other; minimality
    // is not checked, so the rejection is the ordinary mismatch.
    for counter in [EXTENDED_LAST_COUNTER, honest + 1] {
        assert_eq!(
            accepts(&setup, &with_counter(&setup.proof, counter)),
            Err(ProofError::ChallengeMismatch)
        );
    }
}

/// A relation with `ell` free witness bits and no constraint of its own.
struct Sized(usize);

impl Relation<Gf256> for Sized {
    type PublicInput = ();

    fn witness_bits(&self) -> usize {
        self.0
    }

    fn constraints(&self) -> usize {
        0
    }

    fn emit<C: ConstraintSystem<Field = Gf256>>(&self, _public: &(), _cs: &mut C) {}
}

#[test]
fn the_proof_lengths_are_those_of_the_decision() {
    let namespace = Namespace::new(b"sizes").expect("bounded");
    for (set, ell, expected) in [
        (FAEST_256F, 35_840, 160_148),
        (FAEST_256S, 35_840, 109_498),
        (FAEST_256F, 53_504, 233_012),
        (FAEST_256S, 53_504, 158_074),
    ] {
        let context = ProofContext::extended(namespace, *set.vole()).expect("supported row");
        assert_eq!(
            context.proof_bytes::<Gf256, _>(&Sized(ell)),
            Ok(expected),
            "{} at {ell}",
            set.name()
        );
        let prefixed = ProofContext::new(namespace, *set.vole()).expect("non-empty prefix");
        assert_eq!(
            prefixed.proof_bytes::<Gf256, _>(&Sized(ell)),
            Ok(expected - 32 - 16 * set.vole().tau())
        );
    }
    let context = ProofContext::extended(namespace, *FAEST_256F.vole()).expect("supported row");
    let params = context
        .params_for::<Gf256, _>(&Sized(35_840))
        .expect("valid row");
    let table: Vec<usize> = Field::EXTENDED
        .iter()
        .map(|field| field.bytes_as(EXTENDED, &params))
        .collect();
    assert_eq!(
        table,
        [143_360, 880, 128, 4_480, 192, 11_024, 32, 16, 32, 4]
    );
    assert_eq!(table.iter().sum::<usize>(), 160_148);
}

// ---------------------------------------------------------------------------
// Known-answer values for one fixed input. Run with `-- --nocapture` to print
// every intermediate value in hexadecimal.
// ---------------------------------------------------------------------------

#[test]
fn known_answer_values_of_the_extended_construction() {
    // Inputs: prefix[i] = 7 i + 1 (77 bytes), iv[i] = 0xa0 + i, root[i] = 3 i + 1,
    // salt[i] = 0xc0 + i, on the FAEST-256f row.
    let prefix = pattern(77, 7, 1);
    let namespace = Namespace::new(&prefix).expect("77 bytes");
    let iv: [u8; 16] = array(1, 0xa0);
    let root = pattern(32, 3, 1);
    let salt: [u8; SALT_BYTES] = array(1, 0xc0);
    let vole = FAEST_256F.vole();

    // H_0 = SHAKE256(prefix || iv || 00, 128) = h0[96] || h1[32].
    let h0 = shake256(&[&prefix, &iv, &[0x00]], 128);
    println!("h0_output = {}", hex(&h0));

    // Leaf (vector 0, index 0): node L - 1, tweak L - 1.
    let commitment = commit_as(namespace, EXTENDED, vole, &root, &iv).expect("valid call");
    let leaves = vole.leaves();
    assert_eq!(leaves, 6400);
    let node = position_in_tree(vole, 0, 0).expect("valid leaf");
    assert_eq!(node, leaves - 1);
    let node_key = &commitment.node_keys()[32 * node..32 * (node + 1)];
    let tweak = u32::try_from(leaves - 1).expect("small");
    let expanded = expand(node_key, &iv, tweak);
    let (mut sd, mut com) = ([0u8; 32], [0u8; 112]);
    let input = LeafInput {
        node_key,
        iv: &iv,
        tweak,
        hash_key: &h0,
    };
    leaf_commit_as(EXTENDED, vole, &input, &mut sd, &mut com).expect("valid call");
    assert_eq!(com[..], independent_leaf(&expanded, &h0)[..]);
    assert_eq!(commitment.seeds(0).expect("vector 0")[..32], sd);
    println!("leaf_node_key = {}", hex(node_key));
    println!("leaf_tweak = {tweak}");
    println!("leaf_sd = {}", hex(&expanded[..32]));
    println!("leaf_b0 = {}", hex(&expanded[32..128]));
    println!("leaf_b1 = {}", hex(&expanded[128..]));
    println!("leaf_c0 = {}", hex(&com[..96]));
    println!("leaf_c1 = {}", hex(&com[96..]));
    println!("bavc_commitment = {}", hex(commitment.commitment()));
    assert_eq!(
        commitment.commitment(),
        independent_commitment(&prefix, vole, commitment.node_keys(), &iv)
    );

    // H_5: gate 5, label[i] = 0x10 + i, 10 output bits.
    let label = pattern(32, 1, 0x10);
    let h5_input = [
        &prefix[..],
        &iv,
        &salt,
        &5u32.to_le_bytes(),
        &label,
        &[0x05],
    ]
    .concat();
    assert_eq!(h5_input.len(), 77 + 85);
    let squeezed = shake256(&[&h5_input], 2);
    let h5 = u16::from_le_bytes([squeezed[0], squeezed[1]]) & 0x03ff;
    assert_eq!(
        h5_as(
            namespace,
            vole.lambda(),
            Binding::Extended { salt: &salt },
            &iv,
            5,
            &label,
            10
        ),
        Ok(h5)
    );
    println!("h5_input = {}", hex(&h5_input));
    println!("h5_output = 0x{h5:04x}");

    // chall_1 at ell = 320 (C = 351): mu[i] = i, com as above, c[i] = 31 i + 7,
    // c_mult[i] = 17 i + 3, iv_pre[i] = 0xb0 + i.
    let params = ProofParams::new(*vole, 320, 351).expect("valid row");
    let mu = pattern(64, 1, 0);
    let corrections = pattern(vole::corrections_bytes(&params), 31, 7);
    let mult = pattern(vole::mult_corrections_bytes(vole), 17, 3);
    let iv_pre: [u8; 16] = array(1, 0xb0);
    let body = [
        &mu[..],
        commitment.commitment(),
        &corrections,
        &mult,
        &iv_pre,
        &salt,
    ]
    .concat();
    assert_eq!(body.len(), 64 + 64 + 32 * 40 + 880 + 16 + 32);
    let challenge = challenge_1_as(
        namespace,
        Binding::Extended { salt: &salt },
        &params,
        &Challenge1Input {
            mu: &mu,
            commitment: commitment.commitment(),
            corrections: &corrections,
            mult_corrections: &mult,
            iv_pre: &iv_pre,
        },
    )
    .expect("valid call");
    assert_eq!(challenge, shake256(&[&prefix, &body, &[0x09]], 264));
    // A digest of the exact sponge input, for comparing the input itself.
    let input_digest = shake256(&[b"chall_1 input", &prefix, &body, &[0x09]], 32);
    println!("chall1_input_bytes = {}", prefix.len() + body.len() + 1);
    println!("chall1_input_digest = {}", hex(&input_digest));
    println!("chall1_output = {}", hex(&challenge));

    // Pinned: this implementation's own values (see the module documentation).
    let pinned = shake256(
        &[
            &h0,
            &expanded,
            &com,
            commitment.commitment(),
            &squeezed,
            &challenge,
        ],
        16,
    );
    println!("pinned = {}", hex(&pinned));
    assert_eq!(hex(&pinned), PINNED);
}

/// SHAKE256 (16 bytes) of `H_0 || sd || b0 || b1 || c0 || c1 || com ||
/// H_5 squeezed bytes || chall_1` of the known-answer inputs.
const PINNED: &str = "ee83cd9d30ae8dbc488efb86cb2976fe";
