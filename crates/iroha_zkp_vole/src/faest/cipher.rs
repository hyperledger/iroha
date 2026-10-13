//! Rijndael with 128, 192 and 256-bit blocks and keys, written for witness
//! generation: every intermediate state is reachable and nothing is indexed or
//! branched on by a secret.
//!
//! The portable types of the `aes` crate do not expose round states and do not
//! cover the 192 and 256-bit blocks of the Even-Mansour sets, so the cipher is
//! implemented here. The S-box is computed, not looked up: the inverse in
//! `GF(2^8)` is `x^254` by a fixed sequence of constant-time multiplications
//! ([`BinaryField::invert_or_zero`] of [`Gf8`]) followed by the affine map as
//! rotations. `ShiftRows`, `MixColumns` and the key schedule depend on public
//! sizes and round indices only. Round keys, states and the witness are erased on
//! drop.
//!
//! Layout (FIPS 197 and the Rijndael submission): a state of `N_st` columns is
//! `4 * N_st` bytes in column-major order, byte `4c + r` being row `r` of column
//! `c`; `ShiftRows` rotates row `r` by `r` columns, and by `(0, 1, 3, 4)` for
//! `N_st = 8`.

use zeroize::{Zeroize, Zeroizing};

use crate::{
    field::{BinaryField, Gf8},
    params::{OwfKind, OwfParams},
};

/// Largest block in bytes (`N_st = 8`).
pub(super) const MAX_BLOCK_BYTES: usize = 32;

/// The AES S-box, without a table.
pub(super) fn sub_byte(byte: u8) -> u8 {
    let inverse = Gf8::new(byte).invert_or_zero().to_u8();
    inverse
        ^ inverse.rotate_left(1)
        ^ inverse.rotate_left(2)
        ^ inverse.rotate_left(3)
        ^ inverse.rotate_left(4)
        ^ 0x63
}

/// Columns by which `ShiftRows` rotates row `row` of a state of `n_st` columns.
pub(super) const fn shift(row: usize, n_st: usize) -> usize {
    if n_st == 8 && row >= 2 { row + 1 } else { row }
}

/// `Rcon[index] = x^index` in `GF(2^8)`. The index is public.
pub(super) fn round_constant(index: usize) -> u8 {
    let mut constant = Gf8::ONE;
    for _ in 0..index {
        constant = constant.mul_x();
    }
    constant.to_u8()
}

/// The Rijndael key expansion of `key` (`4 * N_k` bytes, `N_k >= 1`) for a cipher
/// of `n_st` columns and `rounds` rounds: `n_st * (rounds + 1)` words of four
/// bytes, word `i` at bytes `[4i, 4i + 4)`.
pub(super) fn expand_key(key: &[u8], n_st: usize, rounds: usize) -> Zeroizing<Vec<u8>> {
    let n_k = key.len() / 4;
    let words = n_st * (rounds + 1);
    let mut expanded = Zeroizing::new(vec![0u8; 4 * words]);
    if n_k == 0 || n_k > words {
        return expanded;
    }
    expanded[..4 * n_k].copy_from_slice(&key[..4 * n_k]);
    for i in n_k..words {
        let mut word = [0u8; 4];
        word.copy_from_slice(&expanded[4 * (i - 1)..4 * i]);
        if i % n_k == 0 {
            word.rotate_left(1);
            for byte in &mut word {
                *byte = sub_byte(*byte);
            }
            word[0] ^= round_constant(i / n_k - 1);
        } else if n_k > 6 && i % n_k == 4 {
            for byte in &mut word {
                *byte = sub_byte(*byte);
            }
        }
        for (offset, byte) in word.iter().enumerate() {
            expanded[4 * i + offset] = expanded[4 * (i - n_k) + offset] ^ byte;
        }
        word.zeroize();
    }
    expanded
}

/// `SubBytes` then `ShiftRows` on the first `4 * n_st` bytes of `state`.
fn sub_bytes_shift_rows(state: &mut [u8; MAX_BLOCK_BYTES], n_st: usize) {
    let mut substituted = [0u8; MAX_BLOCK_BYTES];
    for (out, byte) in substituted.iter_mut().zip(state.iter()).take(4 * n_st) {
        *out = sub_byte(*byte);
    }
    for row in 0..4 {
        let by = shift(row, n_st);
        for column in 0..n_st {
            state[4 * column + row] = substituted[4 * ((column + by) % n_st) + row];
        }
    }
    substituted.zeroize();
}

/// `MixColumns` on the first `4 * n_st` bytes of `state`.
fn mix_columns(state: &mut [u8; MAX_BLOCK_BYTES], n_st: usize) {
    for column in state.chunks_exact_mut(4).take(n_st) {
        let mut a = [column[0], column[1], column[2], column[3]].map(Gf8::new);
        let mut double = a.map(BinaryField::mul_x);
        for row in 0..4 {
            // 2 * a_r + 3 * a_{r+1} + a_{r+2} + a_{r+3}.
            let mixed = double[row]
                + double[(row + 1) % 4]
                + a[(row + 1) % 4]
                + a[(row + 2) % 4]
                + a[(row + 3) % 4];
            column[row] = mixed.to_u8();
        }
        a.zeroize();
        double.zeroize();
    }
}

/// XOR round key `round` into the first `4 * n_st` bytes of `state`.
fn add_round_key(state: &mut [u8; MAX_BLOCK_BYTES], round_keys: &[u8], round: usize, n_st: usize) {
    let block = 4 * n_st;
    for (byte, key) in state
        .iter_mut()
        .zip(round_keys.iter().skip(block * round))
        .take(block)
    {
        *byte ^= key;
    }
}

/// Encrypt the block `input` (`4 * n_st` bytes) under the expanded key
/// `round_keys`; `rounds` is even.
///
/// When `states` is given, the state after `ShiftRows` of every even round
/// `2, 4, .., rounds - 2` is appended to it: the states the one-way-function
/// witness commits to.
pub(super) fn encrypt(
    input: &[u8],
    round_keys: &[u8],
    n_st: usize,
    rounds: usize,
    mut states: Option<&mut Vec<u8>>,
) -> Zeroizing<[u8; MAX_BLOCK_BYTES]> {
    let block = 4 * n_st;
    let mut state = Zeroizing::new([0u8; MAX_BLOCK_BYTES]);
    for (byte, input) in state.iter_mut().zip(input).take(block) {
        *byte = *input;
    }
    add_round_key(&mut state, round_keys, 0, n_st);
    for round in 1..=rounds {
        sub_bytes_shift_rows(&mut state, n_st);
        if round < rounds {
            if round % 2 == 0
                && let Some(states) = states.as_deref_mut()
            {
                states.extend_from_slice(&state[..block]);
            }
            mix_columns(&mut state, n_st);
        }
        add_round_key(&mut state, round_keys, round, n_st);
    }
    state
}

/// The second block input of the two-block sets: `input` with bit 0 flipped.
fn second_input(input: &[u8]) -> [u8; 16] {
    let mut second = [0u8; 16];
    for (out, byte) in second.iter_mut().zip(input) {
        *out = *byte;
    }
    second[0] ^= 1;
    second
}

/// The one-way function: `y = AES_k(x) [|| AES_k(x + 1)]`, or
/// `y = Rijndael_x(k) + k` for the Even-Mansour sets.
///
/// `key` must be `lambda / 8` bytes and `input` [`OwfParams::input_bytes`] bytes;
/// the result is [`OwfParams::output_bytes`] bytes.
pub(super) fn evaluate(owf: OwfParams, key: &[u8], input: &[u8]) -> Vec<u8> {
    let (n_st, rounds) = (owf.n_st(), owf.rounds());
    let block = owf.n_st_bytes();
    let mut output = Vec::with_capacity(owf.output_bytes());
    match owf.kind() {
        OwfKind::Aes => {
            let round_keys = expand_key(key, n_st, rounds);
            output.extend_from_slice(&encrypt(input, &round_keys, n_st, rounds, None)[..block]);
            if owf.beta() == 2 {
                let second = second_input(input);
                output
                    .extend_from_slice(&encrypt(&second, &round_keys, n_st, rounds, None)[..block]);
            }
        }
        OwfKind::EvenMansour => {
            let round_keys = expand_key(input, n_st, rounds);
            let cipher = encrypt(key, &round_keys, n_st, rounds, None);
            output.extend(cipher.iter().zip(key).take(block).map(|(c, k)| c ^ k));
        }
    }
    output
}

/// The extended witness of `key` for the public `input`: [`OwfParams::ell`] bits
/// as bytes, bit `i` at bit `i mod 8` of byte `i / 8`.
///
/// FAEST: the key, then the `S_ke / 4` expanded-key words that come out of an
/// S-box layer, then the committed states of each block. FAEST-EM: the key, then
/// the committed states of the single block.
pub(super) fn extend_witness(owf: OwfParams, key: &[u8], input: &[u8]) -> Zeroizing<Vec<u8>> {
    let (n_st, n_k, rounds) = (owf.n_st(), owf.n_k(), owf.rounds());
    // The full capacity up front: the buffer never moves, so no unerased copy of
    // it is left behind.
    let mut witness = Zeroizing::new(Vec::with_capacity(owf.ell() / 8));
    witness.extend_from_slice(key);
    match owf.kind() {
        OwfKind::Aes => {
            let round_keys = expand_key(key, n_st, rounds);
            let step = if n_k == 6 { 6 } else { 4 };
            for word in (0..owf.s_ke() / 4).map(|index| n_k + index * step) {
                witness.extend_from_slice(&round_keys[4 * word..4 * word + 4]);
            }
            encrypt(input, &round_keys, n_st, rounds, Some(&mut witness));
            if owf.beta() == 2 {
                let second = second_input(input);
                encrypt(&second, &round_keys, n_st, rounds, Some(&mut witness));
            }
        }
        OwfKind::EvenMansour => {
            let round_keys = expand_key(input, n_st, rounds);
            encrypt(key, &round_keys, n_st, rounds, Some(&mut witness));
        }
    }
    witness
}

#[cfg(test)]
mod tests {
    use aes::cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray};

    use super::*;
    use crate::params::{FAEST_PARAMETER_SETS, SecurityLevel};

    fn hex(text: &str) -> Vec<u8> {
        (0..text.len() / 2)
            .map(|i| u8::from_str_radix(&text[2 * i..2 * i + 2], 16).expect("hex"))
            .collect()
    }

    /// The S-box by its definition, with data-dependent control flow.
    fn reference_sub_byte(byte: u8) -> u8 {
        let mut inverse = 0u8;
        for candidate in 1..=255u8 {
            if (Gf8::new(byte) * Gf8::new(candidate)).to_u8() == 1 {
                inverse = candidate;
            }
        }
        let mut out = 0u8;
        for i in 0..8 {
            let bit = (inverse >> i)
                ^ (inverse >> ((i + 4) % 8))
                ^ (inverse >> ((i + 5) % 8))
                ^ (inverse >> ((i + 6) % 8))
                ^ (inverse >> ((i + 7) % 8))
                ^ (0x63 >> i);
            out |= (bit & 1) << i;
        }
        out
    }

    #[test]
    fn the_s_box_is_the_aes_s_box() {
        for (input, output) in [(0x00u8, 0x63u8), (0x01, 0x7c), (0x53, 0xed), (0xff, 0x16)] {
            assert_eq!(sub_byte(input), output);
        }
        for byte in 0..=255u8 {
            assert_eq!(sub_byte(byte), reference_sub_byte(byte));
        }
    }

    #[test]
    fn shifts_and_round_constants_are_those_of_rijndael() {
        for n_st in [4, 6] {
            assert_eq!([0, 1, 2, 3].map(|row| shift(row, n_st)), [0, 1, 2, 3]);
        }
        assert_eq!([0, 1, 2, 3].map(|row| shift(row, 8)), [0, 1, 3, 4]);
        let constants: Vec<u8> = (0..12).map(round_constant).collect();
        assert_eq!(
            constants,
            [
                0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8
            ]
        );
    }

    #[test]
    fn the_key_expansion_matches_fips_197_appendix_a() {
        let expanded = expand_key(&hex("2b7e151628aed2a6abf7158809cf4f3c"), 4, 10);
        assert_eq!(expanded.len(), 176);
        assert_eq!(expanded[16..20], hex("a0fafe17"));
        assert_eq!(expanded[172..], hex("b6630ca6"));
        let expanded = expand_key(
            &hex("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b"),
            4,
            12,
        );
        assert_eq!(expanded.len(), 208);
        assert_eq!(expanded[24..28], hex("fe0c91f7"));
        assert_eq!(expanded[204..], hex("01002202"));
        let expanded = expand_key(
            &hex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"),
            4,
            14,
        );
        assert_eq!(expanded.len(), 240);
        assert_eq!(expanded[32..36], hex("9ba35411"));
        assert_eq!(expanded[236..], hex("706c631e"));
        // Degenerate keys give zeros instead of a panic.
        assert!(expand_key(&[1, 2, 3], 4, 10).iter().all(|&b| b == 0));
    }

    #[test]
    fn mix_columns_and_shift_rows_match_fips_197() {
        // Round 1 of the Appendix B example: after SubBytes, then ShiftRows, then
        // MixColumns.
        let mut state = [0u8; MAX_BLOCK_BYTES];
        state[..16].copy_from_slice(&hex("193de3bea0f4e22b9ac68d2ae9f84808"));
        sub_bytes_shift_rows(&mut state, 4);
        assert_eq!(state[..16], hex("d4bf5d30e0b452aeb84111f11e2798e5"));
        mix_columns(&mut state, 4);
        assert_eq!(state[..16], hex("046681e5e0cb199a48f8d37a2806264c"));
        add_round_key(&mut state, &hex("a0fafe1788542cb123a339392a6c7605"), 0, 4);
        assert_eq!(state[..16], hex("a49c7ff2689f352b6b5bea43026a5049"));
        assert!(state[16..].iter().all(|&b| b == 0));
    }

    #[test]
    fn four_column_encryption_agrees_with_the_aes_crate() {
        for (bytes, rounds) in [(16usize, 10usize), (24, 12), (32, 14)] {
            for salt in 0..4u8 {
                let key: Vec<u8> = (0u8..)
                    .take(bytes)
                    .map(|i| i.wrapping_mul(29) ^ salt.wrapping_mul(101))
                    .collect();
                let input: Vec<u8> = (0..16u8).map(|i| i.wrapping_mul(57) ^ salt).collect();
                let mut block = GenericArray::clone_from_slice(&input);
                match bytes {
                    16 => aes::soft::Aes128::new_from_slice(&key)
                        .expect("key")
                        .encrypt_block(&mut block),
                    24 => aes::soft::Aes192::new_from_slice(&key)
                        .expect("key")
                        .encrypt_block(&mut block),
                    _ => aes::soft::Aes256::new_from_slice(&key)
                        .expect("key")
                        .encrypt_block(&mut block),
                }
                let round_keys = expand_key(&key, 4, rounds);
                let mut states = Vec::new();
                let output = encrypt(&input, &round_keys, 4, rounds, Some(&mut states));
                assert_eq!(output[..16], block[..]);
                assert_eq!(states.len(), 16 * (rounds / 2 - 1));
                assert_eq!(
                    encrypt(&input, &round_keys, 4, rounds, None)[..16],
                    block[..]
                );
            }
        }
    }

    #[test]
    fn the_committed_states_are_those_after_shift_rows_of_the_even_rounds() {
        // FIPS 197 Appendix B: the state after ShiftRows of round 2.
        let round_keys = expand_key(&hex("2b7e151628aed2a6abf7158809cf4f3c"), 4, 10);
        let mut states = Vec::new();
        let output = encrypt(
            &hex("3243f6a8885a308d313198a2e0370734"),
            &round_keys,
            4,
            10,
            Some(&mut states),
        );
        assert_eq!(output[..16], hex("3925841d02dc09fbdc118597196a0b32"));
        assert_eq!(states[..16], hex("49db873b453953897f02d2f177de961a"));
        assert_eq!(states.len(), 64);
    }

    #[test]
    fn the_one_way_function_has_the_shape_of_every_set() {
        for set in FAEST_PARAMETER_SETS {
            let owf = *set.owf();
            let key: Vec<u8> = (0u8..)
                .take(owf.lambda().bytes())
                .map(|i| i ^ 0x5a)
                .collect();
            let input: Vec<u8> = (0u8..).take(owf.input_bytes()).map(|i| i ^ 0xc3).collect();
            let output = evaluate(owf, &key, &input);
            assert_eq!(output.len(), owf.output_bytes(), "{}", set.name());
            let witness = extend_witness(owf, &key, &input);
            assert_eq!(8 * witness.len(), owf.ell(), "{}", set.name());
            assert_eq!(witness[..key.len()], key[..]);
            match owf.kind() {
                OwfKind::Aes => {
                    // The first expanded word follows the key.
                    let round_keys = expand_key(&key, 4, owf.rounds());
                    assert_eq!(
                        witness[key.len()..key.len() + 4],
                        round_keys[key.len()..key.len() + 4]
                    );
                    if owf.lambda() == SecurityLevel::L128 {
                        assert_eq!(output.len(), 16);
                    } else {
                        // The two blocks are encryptions of different inputs.
                        assert_ne!(output[..16], output[16..]);
                        let second = second_input(&input);
                        assert_eq!(second[0], input[0] ^ 1);
                        assert_eq!(second[1..], input[1..]);
                    }
                }
                OwfKind::EvenMansour => {
                    // y + k is the encryption of k under the public key x.
                    let round_keys = expand_key(&input, owf.n_st(), owf.rounds());
                    let cipher = encrypt(&key, &round_keys, owf.n_st(), owf.rounds(), None);
                    let masked: Vec<u8> = output.iter().zip(&key).map(|(y, k)| y ^ k).collect();
                    assert_eq!(masked[..], cipher[..key.len()]);
                }
            }
        }
    }
}
