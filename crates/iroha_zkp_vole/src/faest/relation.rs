//! The one-way-function relation of FAEST v3.0 (specification section 7) as a
//! [`Relation`]: "the committed bits are an extended witness of a key `k` with
//! `OWF_k(x) = y`", for all twelve parameter sets.
//!
//! # Witness
//!
//! [`OwfParams::ell`] bits, produced by [`super::extend_witness`]:
//!
//! ```text
//! FAEST:     k (lambda bits)
//!            || the S_ke / 4 expanded-key words that leave an S-box layer
//!            || for each of the beta blocks: the states after ShiftRows of rounds 2, 4, .., R - 2
//! FAEST-EM:  k || the same states of the single block (cipher key x, plaintext k)
//! ```
//!
//! # Constraints, in order
//!
//! ```text
//! 1                 w[0] * w[1]                               key validity      degree 2
//! 2 * S_ke          key schedule (absent for FAEST-EM)                          degree 2
//! beta * S_enc / 2  encryption, block by block                                  degree 7
//! ```
//!
//! *Key schedule* (`KeyExpCstrnts`): the expanded key is rebuilt from the witness
//! by XORs (`KeyExpFwd`); for every S-box of the schedule the committed output
//! word gives, through XORs and the inverse affine map, the inverse `wbar` of the
//! S-box input byte `kbar` (`KeyExpBkwd`). With `khat`, `what` the bytes embedded
//! in `GF(2^lambda)` and `ksq`, `wsq` their squares (linear in the bits), each
//! S-box contributes `ksq * what + khat` and `khat * wsq + what`: `k^2 w = k` and
//! `k w^2 = w`, which hold exactly for `w = k^254`.
//!
//! *Encryption* (`EncCstrnts`): the cipher is cut at the committed states into
//! `R / 2` pairs of rounds. From the bits entering a pair, `SBoxEval` gives every
//! S-box output as a degree-7 polynomial in the bits (through the conjugates
//! `x^(2^j)`, each linear in the bits), followed by `ShiftRows`, `MixColumns` and
//! `AddRoundKey` on embedded bytes. From the committed state after the pair's
//! second `ShiftRows` (for the last pair: the output with the last round key
//! removed), `InverseShiftRows` and `InverseSBoxEval` give the same bytes as
//! `x^254` of the S-box input, again of degree 7. Each of the `4 * N_st` bytes
//! contributes the difference of the two.
//!
//! The engine lifts every constraint to degree `d_zk = 7` and homogenises sums of
//! different degrees ([`crate::quicksilver`]), which is the specification's
//! `DegLift` and its lifting of round-key bytes.
//!
//! # Secrets
//!
//! The sequence of operations depends on the parameter set only. For FAEST-EM the
//! round keys are public constants computed from `x`. Buffered values are kept in
//! erasing vectors allocated once per evaluation; the fixed-size scratch arrays of
//! the S-box, `MixColumns` and key-schedule steps are erased before the step that
//! filled them ends.

use zeroize::{Zeroize, Zeroizing};

use super::cipher;
use crate::{
    field::LambdaField,
    params::{OwfKind, OwfParams},
    quicksilver::{ConstraintSystem, Relation},
};

/// The bits of `chi_0 .. chi_8`, the coefficients of the S-box as a linearised
/// polynomial plus its constant (specification section 7.3).
const CHI: [u8; 9] = [0x05, 0x09, 0xf9, 0x25, 0xf4, 0x01, 0xb5, 0x8f, 0x63];

/// The one-way-function relation of one parameter set.
///
/// The public input is the public key `pk = x || y`
/// ([`OwfParams::public_key_bytes`] bytes). The relation is defined over the
/// field of its security level only: over another field, or for a public key of
/// another length, it emits nothing and the engine reports
/// [`crate::quicksilver::QuickSilverError::ConstraintCount`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OwfRelation {
    owf: OwfParams,
}

impl OwfRelation {
    /// The relation of the one-way function `owf`.
    pub const fn new(owf: OwfParams) -> Self {
        Self { owf }
    }

    /// The one-way-function parameters.
    pub const fn owf(&self) -> &OwfParams {
        &self.owf
    }
}

impl<F: LambdaField> Relation<F> for OwfRelation {
    type PublicInput = [u8];

    fn witness_bits(&self) -> usize {
        self.owf.ell()
    }

    fn constraints(&self) -> usize {
        self.owf.constraints() - self.owf.ell()
    }

    fn emit<C: ConstraintSystem<Field = F>>(&self, public: &[u8], system: &mut C) {
        if F::LEVEL != self.owf.lambda() || public.len() != self.owf.public_key_bytes() {
            return;
        }
        emit(self.owf, public, system);
    }
}

/// Bit `index` of the bit string `bytes`.
fn bit_of(bytes: &[u8], index: usize) -> bool {
    (bytes[index / 8] >> (index % 8)) & 1 == 1
}

/// The eight values of byte `index` of `bits`.
fn byte_of<V: Copy>(bits: &[V], index: usize) -> [V; 8] {
    core::array::from_fn(|i| bits[8 * index + i])
}

/// `ByteCombine`: `sum_i bits[i] * alpha_8^i`.
fn byte_combine<C: ConstraintSystem>(cs: &C, bits: &[C::Value; 8]) -> C::Value {
    let basis = <C::Field as LambdaField>::BYTE_COMBINE_BASIS;
    let mut acc = bits[0];
    for (bit, power) in bits.iter().zip(basis).skip(1) {
        acc = cs.add(acc, cs.scale(*bit, power));
    }
    acc
}

/// The bits of the square of the byte with bits `x` (squaring is linear).
fn square_bits<C: ConstraintSystem>(cs: &C, x: &[C::Value; 8]) -> [C::Value; 8] {
    let sum = |indices: &[usize]| {
        let mut acc = x[indices[0]];
        for &index in &indices[1..] {
            acc = cs.add(acc, x[index]);
        }
        acc
    };
    [
        sum(&[0, 4, 6]),
        sum(&[4, 6, 7]),
        sum(&[1, 5]),
        sum(&[4, 5, 6, 7]),
        sum(&[2, 4, 7]),
        sum(&[5, 6]),
        sum(&[3, 5]),
        sum(&[6, 7]),
    ]
}

/// The conjugates `b^(2^j)`, `j = 0 .. 8`, of the byte `b` with bits `x`, embedded
/// in the field. Each is linear in the bits.
fn conjugates<C: ConstraintSystem>(cs: &C, x: &[C::Value; 8]) -> [C::Value; 8] {
    let mut bits = *x;
    let mut out = [x[0]; 8];
    for (index, slot) in out.iter_mut().enumerate() {
        *slot = byte_combine(cs, &bits);
        if index < 7 {
            let mut squared = square_bits(cs, &bits);
            bits = squared;
            squared.zeroize();
        }
    }
    bits.zeroize();
    out
}

/// The inverse of the affine map of the S-box, on bits.
fn inverse_affine<C: ConstraintSystem>(cs: &C, x: &[C::Value; 8]) -> [C::Value; 8] {
    core::array::from_fn(|j| {
        let sum = cs.add(cs.add(x[(j + 7) % 8], x[(j + 5) % 8]), x[(j + 2) % 8]);
        if j == 0 || j == 2 {
            cs.add(sum, cs.one())
        } else {
            sum
        }
    })
}

/// The field constants of the gadgets.
struct Constants<F> {
    /// `ByteCombine(chi_i)`.
    zeta: [F; 9],
    /// `ByteCombine(0x02)`.
    two: F,
    /// `ByteCombine(0x03)`.
    three: F,
}

impl<F: LambdaField> Constants<F> {
    fn new() -> Self {
        Self {
            zeta: CHI.map(F::byte_combine_bits),
            two: F::byte_combine_bits(2),
            three: F::byte_combine_bits(3),
        }
    }
}

/// `SBoxEval`: the S-box output of the byte with bits `x`, embedded in the field,
/// as a polynomial of degree 7 in the bits.
///
/// With `c_j = b^(2^j)` the S-box is `zeta_8 + sum_j zeta_j * c_j^-1 * b^255`
/// evaluated through products of pairs: `p1_i = c_2i * c_2i+1`,
/// `f1_i = zeta_2i * c_2i+1 + zeta_2i+1 * c_2i`, and one more level of the same.
fn sbox_eval<C: ConstraintSystem>(
    cs: &C,
    constants: &Constants<C::Field>,
    x: &[C::Value; 8],
) -> C::Value {
    let zeta = &constants.zeta;
    let mut c = conjugates(cs, x);
    let mut p1: [C::Value; 4] = core::array::from_fn(|i| cs.mul(c[2 * i], c[2 * i + 1]));
    let mut f1: [C::Value; 4] = core::array::from_fn(|i| {
        cs.add(
            cs.scale(c[2 * i + 1], zeta[2 * i]),
            cs.scale(c[2 * i], zeta[2 * i + 1]),
        )
    });
    let mut p2: [C::Value; 2] = core::array::from_fn(|i| cs.mul(p1[2 * i], p1[2 * i + 1]));
    let mut f2: [C::Value; 2] = core::array::from_fn(|i| {
        cs.add(
            cs.mul(f1[2 * i], p1[2 * i + 1]),
            cs.mul(f1[2 * i + 1], p1[2 * i]),
        )
    });
    let sum = cs.add(cs.mul(f2[0], p2[1]), cs.mul(f2[1], p2[0]));
    c.zeroize();
    p1.zeroize();
    f1.zeroize();
    p2.zeroize();
    f2.zeroize();
    cs.add(sum, cs.constant(zeta[8]))
}

/// `InverseSBoxEval`: the S-box input of the byte with bits `x`, embedded in the
/// field, as a polynomial of degree 7 in the bits: `a^254 = a^2 * a^4 * .. *
/// a^128` for `a` the inverse affine image.
fn inverse_sbox_eval<C: ConstraintSystem>(cs: &C, x: &[C::Value; 8]) -> C::Value {
    let mut affine = inverse_affine(cs, x);
    let mut c = conjugates(cs, &affine);
    let mut acc = c[1];
    for conjugate in &c[2..] {
        acc = cs.mul(acc, *conjugate);
    }
    affine.zeroize();
    c.zeroize();
    acc
}

/// `BitwiseMixColumns` of the `n_st` columns in `bits`, into `out`.
fn bitwise_mix_columns<C: ConstraintSystem>(
    cs: &C,
    bits: &[C::Value],
    out: &mut [C::Value],
    n_st: usize,
) {
    for column in 0..n_st {
        let mut a: [[C::Value; 8]; 4] = core::array::from_fn(|row| byte_of(bits, 4 * column + row));
        // b_r = 2 * a_r.
        let mut b: [[C::Value; 8]; 4] = core::array::from_fn(|row| {
            let x = &a[row];
            [
                x[7],
                cs.add(x[0], x[7]),
                x[1],
                cs.add(x[2], x[7]),
                cs.add(x[3], x[7]),
                x[4],
                x[5],
                x[6],
            ]
        });
        for row in 0..4 {
            // 2 * a_r + 3 * a_{r+1} + a_{r+2} + a_{r+3}.
            let terms = [
                &b[row],
                &a[(row + 3) % 4],
                &a[(row + 2) % 4],
                &b[(row + 1) % 4],
                &a[(row + 1) % 4],
            ];
            for i in 0..8 {
                let mut acc = terms[0][i];
                for term in &terms[1..] {
                    acc = cs.add(acc, term[i]);
                }
                out[8 * (4 * column + row) + i] = acc;
            }
        }
        a.zeroize();
        b.zeroize();
    }
}

/// `KeyExpCstrnts`: push the bits of the whole expanded key onto `round_keys` and
/// emit the `2 * S_ke` key-schedule constraints.
fn key_schedule<C: ConstraintSystem>(owf: OwfParams, cs: &mut C, round_keys: &mut Vec<C::Value>) {
    let lambda = owf.lambda().bits();
    let (n_k, s_ke) = (owf.n_k(), owf.s_ke());
    let step = if lambda == 192 { 192 } else { 128 };

    // KeyExpFwd: words out of an S-box layer are committed, the others are XORs.
    for index in 0..lambda {
        round_keys.push(cs.witness(index));
    }
    let mut next = lambda;
    for word in n_k..4 * (owf.rounds() + 1) {
        if word % n_k == 0 || (n_k > 6 && word % n_k == 4) {
            for i in 0..32 {
                round_keys.push(cs.witness(next + i));
            }
            next += 32;
        } else {
            for i in 0..32 {
                let sum = cs.add(
                    round_keys[32 * (word - n_k) + i],
                    round_keys[32 * (word - 1) + i],
                );
                round_keys.push(sum);
            }
        }
    }

    // KeyExpBkwd: the S-box outputs, taken back through the affine map.
    let mut inverses = Zeroizing::new(Vec::with_capacity(8 * s_ke));
    let constant_every = 4 * (lambda / 128);
    let mut offset = 0;
    for sbox in 0..s_ke {
        let constant = if sbox % constant_every == 0 {
            cipher::round_constant(sbox / constant_every)
        } else {
            0
        };
        let mut output: [C::Value; 8] = core::array::from_fn(|i| {
            let sum = cs.add(
                cs.witness(lambda + 8 * sbox + i),
                round_keys[offset + 8 * (sbox % 4) + i],
            );
            if (constant >> i) & 1 == 1 {
                cs.add(sum, cs.one())
            } else {
                sum
            }
        });
        let mut inverse = inverse_affine(cs, &output);
        inverses.extend_from_slice(&inverse);
        inverse.zeroize();
        output.zeroize();
        if sbox % 4 == 3 {
            offset += step;
        }
    }

    let zero = cs.zero();
    let mut offset = 32 * (n_k - 1);
    let mut rotate = true;
    for word in 0..s_ke / 4 {
        let (mut k_hat, mut k_sq, mut w_hat, mut w_sq) =
            ([zero; 4], [zero; 4], [zero; 4], [zero; 4]);
        for row in 0..4 {
            let rotated = if rotate { (row + 3) % 4 } else { row };
            let mut k_bits = byte_of(&round_keys[offset..], row);
            let mut w_bits = byte_of(&inverses[32 * word..], row);
            let mut k_squared = square_bits(cs, &k_bits);
            let mut w_squared = square_bits(cs, &w_bits);
            k_hat[rotated] = byte_combine(cs, &k_bits);
            k_sq[rotated] = byte_combine(cs, &k_squared);
            w_hat[row] = byte_combine(cs, &w_bits);
            w_sq[row] = byte_combine(cs, &w_squared);
            k_bits.zeroize();
            w_bits.zeroize();
            k_squared.zeroize();
            w_squared.zeroize();
        }
        if lambda == 256 {
            rotate = !rotate;
        }
        for row in 0..4 {
            cs.constrain(cs.add(cs.mul(k_sq[row], w_hat[row]), k_hat[row]));
            cs.constrain(cs.add(cs.mul(k_hat[row], w_sq[row]), w_hat[row]));
        }
        k_hat.zeroize();
        k_sq.zeroize();
        w_hat.zeroize();
        w_sq.zeroize();
        offset += step;
    }
}

/// Emit the constraints of the relation of `owf` for the public key `public`,
/// whose length the caller checked.
fn emit<C: ConstraintSystem>(owf: OwfParams, public: &[u8], cs: &mut C) {
    let (n_st, rounds) = (owf.n_st(), owf.rounds());
    let (bytes, bits) = (owf.n_st_bytes(), owf.n_st_bits());
    let (x, y) = public.split_at(owf.input_bytes());
    let even_mansour = owf.kind() == OwfKind::EvenMansour;
    let constants = Constants::<C::Field>::new();

    // Key validity: not both of the first two key bits.
    cs.constrain(cs.mul(cs.witness(0), cs.witness(1)));

    let mut round_keys = Zeroizing::new(Vec::with_capacity((rounds + 1) * bits));
    if even_mansour {
        let expanded = cipher::expand_key(x, n_st, rounds);
        for index in 0..(rounds + 1) * bits {
            round_keys.push(cs.bit(bit_of(&expanded, index)));
        }
    } else {
        key_schedule(owf, cs, &mut round_keys);
    }

    let zero = cs.zero();
    let mut state = Zeroizing::new(vec![zero; bits]);
    let mut committed = Zeroizing::new(vec![zero; bits]);
    let mut forward = Zeroizing::new(vec![zero; bytes]);
    let mut shifted = Zeroizing::new(vec![zero; bytes]);

    for block in 0..owf.beta() {
        let base = owf.ell_ke() + block * owf.ell_enc();
        for index in 0..bits {
            let input = if even_mansour {
                cs.witness(index)
            } else {
                // The second block encrypts x with its first bit flipped.
                cs.bit(bit_of(x, index) ^ (block == 1 && index == 0))
            };
            state[index] = cs.add(input, round_keys[index]);
        }
        for pair in 0..rounds / 2 {
            let last = pair == rounds / 2 - 1;

            // Forward from the bits entering the pair: SubBytes, ShiftRows,
            // MixColumns and AddRoundKey on embedded bytes.
            for index in 0..bytes {
                let mut input = byte_of(&state, index);
                shifted[index] = sbox_eval(cs, &constants, &input);
                input.zeroize();
            }
            for row in 0..4 {
                let by = cipher::shift(row, n_st);
                for column in 0..n_st {
                    forward[4 * column + row] = shifted[4 * ((column + by) % n_st) + row];
                }
            }
            for column in 0..n_st {
                let mut a: [C::Value; 4] = core::array::from_fn(|row| forward[4 * column + row]);
                let mut double = a.map(|value| cs.scale(value, constants.two));
                let mut triple = a.map(|value| cs.scale(value, constants.three));
                for row in 0..4 {
                    let mixed = cs.add(
                        cs.add(double[row], triple[(row + 1) % 4]),
                        cs.add(a[(row + 2) % 4], a[(row + 3) % 4]),
                    );
                    shifted[4 * column + row] = mixed;
                }
                a.zeroize();
                double.zeroize();
                triple.zeroize();
            }
            let key = &round_keys[(2 * pair + 1) * bits..];
            for index in 0..bytes {
                let mut key_bits = byte_of(key, index);
                forward[index] = cs.add(shifted[index], byte_combine(cs, &key_bits));
                key_bits.zeroize();
            }

            // The state after the second ShiftRows of the pair.
            for index in 0..bits {
                committed[index] = if last {
                    let output = if even_mansour {
                        cs.add_bit(cs.witness(index), bit_of(y, index))
                    } else {
                        cs.bit(bit_of(y, block * bits + index))
                    };
                    cs.add(output, round_keys[rounds * bits + index])
                } else {
                    cs.witness(base + pair * bits + index)
                };
            }

            // Backward through InverseShiftRows and the inverse S-box.
            for index in 0..bytes {
                let (column, row) = (index / 4, index % 4);
                let source = 4 * ((column + n_st - cipher::shift(row, n_st)) % n_st) + row;
                let mut output = byte_of(&committed, source);
                let backward = inverse_sbox_eval(cs, &output);
                output.zeroize();
                cs.constrain(cs.add(backward, forward[index]));
            }

            if !last {
                bitwise_mix_columns(cs, &committed, &mut state, n_st);
                let key = &round_keys[(2 * pair + 2) * bits..];
                for index in 0..bits {
                    state[index] = cs.add(state[index], key[index]);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        field::{BinaryField, Gf8, Gf128, Gf192, Gf256},
        params::{FAEST_PARAMETER_SETS, FaestParams, SecurityLevel},
        quicksilver::{self, QuickSilverError, tests as engine},
    };

    /// A deterministic byte string.
    fn pattern(len: usize, salt: u8) -> Vec<u8> {
        let mut state = 0x9e37_79b9_u32 ^ (u32::from(salt) << 8);
        (0..len)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                state.to_le_bytes()[1]
            })
            .collect()
    }

    /// A valid key, the public key and the extended witness of `set`.
    fn instance(set: &FaestParams, salt: u8) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let owf = *set.owf();
        let mut key = pattern(owf.lambda().bytes(), salt);
        key[0] &= 0xfe;
        let mut public = pattern(owf.input_bytes(), salt.wrapping_add(100));
        let output = cipher::evaluate(owf, &key, &public);
        let witness = cipher::extend_witness(owf, &key, &public).to_vec();
        public.extend_from_slice(&output);
        (key, public, witness)
    }

    /// Run `check` with the field of `set`.
    macro_rules! with_field {
        ($set:expr, $check:ident ( $($argument:expr),* )) => {
            match $set.owf().lambda() {
                SecurityLevel::L128 => $check::<Gf128>($($argument),*),
                SecurityLevel::L192 => $check::<Gf192>($($argument),*),
                SecurityLevel::L256 => $check::<Gf256>($($argument),*),
            }
        };
    }

    #[test]
    fn the_sizes_are_those_of_the_parameter_table() {
        for set in FAEST_PARAMETER_SETS {
            let relation = OwfRelation::new(*set.owf());
            assert_eq!(relation.owf(), set.owf());
            assert_eq!(
                Relation::<Gf128>::witness_bits(&relation),
                set.proof().witness_bits()
            );
            assert_eq!(
                Relation::<Gf128>::witness_bits(&relation)
                    + Relation::<Gf128>::constraints(&relation),
                set.proof().constraints()
            );
        }
    }

    /// A relation that exposes one gadget on eight witness coordinates so that
    /// the engine's evaluators can run it.
    struct Gadget(u8);

    impl<F: LambdaField> Relation<F> for Gadget {
        type PublicInput = [u8];

        fn witness_bits(&self) -> usize {
            8
        }

        fn constraints(&self) -> usize {
            match self.0 {
                0 | 4 => 8,
                _ => 1,
            }
        }

        /// The public input is the expected byte; each constraint is the gadget
        /// output plus its expected value.
        fn emit<C: ConstraintSystem<Field = F>>(&self, public: &[u8], cs: &mut C) {
            let x: [C::Value; 8] = core::array::from_fn(|i| cs.witness(i));
            let expected = F::byte_combine_bits(public[0]);
            match self.0 {
                // SquareBits, bit by bit.
                0 => {
                    for (i, bit) in square_bits(cs, &x).into_iter().enumerate() {
                        cs.constrain(cs.add_bit(bit, bit_of(public, i)));
                    }
                }
                1 => cs.constrain(cs.add(byte_combine(cs, &x), cs.constant(expected))),
                2 => {
                    let output = sbox_eval(cs, &Constants::new(), &x);
                    cs.constrain(cs.add(output, cs.constant(expected)));
                }
                3 => {
                    let output = inverse_sbox_eval(cs, &x);
                    cs.constrain(cs.add(output, cs.constant(expected)));
                }
                // InverseAffine, bit by bit.
                4 => {
                    for (i, bit) in inverse_affine(cs, &x).into_iter().enumerate() {
                        cs.constrain(cs.add_bit(bit, bit_of(public, i)));
                    }
                }
                // The last conjugate, b^128.
                _ => cs.constrain(cs.add(conjugates(cs, &x)[7], cs.constant(expected))),
            }
        }
    }

    fn inverse_sub_byte(byte: u8) -> u8 {
        (0..=255u8)
            .find(|candidate| cipher::sub_byte(*candidate) == byte)
            .expect("the S-box is a permutation")
    }

    #[test]
    fn the_gadgets_compute_the_byte_operations_they_are_named_after() {
        fn check<F: LambdaField>() {
            for byte in (0..=255u8).step_by(3).chain([1, 2, 0x53, 0xff]) {
                let element = Gf8::new(byte);
                let power_128 = (0..7).fold(element, |acc, _| acc.square());
                let inverse = inverse_sub_byte(byte);
                // The inverse affine image of b is the inverse of the S-box
                // input: S(a) = Affine(a^-1).
                let before_affine = Gf8::new(inverse).invert_or_zero().to_u8();
                for (gadget, expected) in [
                    (0u8, element.square().to_u8()),
                    (1, byte),
                    (2, cipher::sub_byte(byte)),
                    (3, inverse),
                    (4, before_affine),
                    (5, power_128.to_u8()),
                ] {
                    assert_eq!(
                        quicksilver::is_satisfied::<F, _>(
                            &Gadget(gadget),
                            &[expected][..],
                            &[byte]
                        ),
                        Ok(true),
                        "gadget {gadget} on {byte:#04x}"
                    );
                    assert_eq!(
                        quicksilver::is_satisfied::<F, _>(
                            &Gadget(gadget),
                            &[expected ^ 0x10][..],
                            &[byte]
                        ),
                        Ok(false),
                        "gadget {gadget} on {byte:#04x}"
                    );
                }
            }
        }
        check::<Gf128>();
        check::<Gf192>();
        check::<Gf256>();
    }

    #[test]
    fn bitwise_mix_columns_is_mix_columns_on_bits() {
        /// `BitwiseMixColumns` of 32 witness bits against the public expected
        /// column.
        struct Column;
        impl<F: LambdaField> Relation<F> for Column {
            type PublicInput = [u8];
            fn witness_bits(&self) -> usize {
                32
            }
            fn constraints(&self) -> usize {
                32
            }
            fn emit<C: ConstraintSystem<Field = F>>(&self, public: &[u8], cs: &mut C) {
                let bits: Vec<C::Value> = (0..32).map(|i| cs.witness(i)).collect();
                let mut out = vec![cs.zero(); 32];
                bitwise_mix_columns(cs, &bits, &mut out, 1);
                for (i, bit) in out.into_iter().enumerate() {
                    cs.constrain(cs.add_bit(bit, bit_of(public, i)));
                }
            }
        }
        // FIPS 197 Appendix B, round 1, first column.
        let (input, output) = ([0xd4u8, 0xbf, 0x5d, 0x30], [0x04u8, 0x66, 0x81, 0xe5]);
        assert_eq!(
            quicksilver::is_satisfied::<Gf128, _>(&Column, &output[..], &input),
            Ok(true)
        );
        assert_eq!(
            quicksilver::violated_constraints::<Gf128, _>(
                &Column,
                &[0x05, 0x66, 0x81, 0xe5][..],
                &input
            ),
            Ok(vec![32])
        );
    }

    #[test]
    fn the_honest_witness_satisfies_the_relation_and_single_bit_flips_do_not() {
        fn check<F: LambdaField>(set: &FaestParams) {
            let relation = OwfRelation::new(*set.owf());
            let ell = set.owf().ell();
            for salt in 0..2 {
                let (_, public, witness) = instance(set, salt);
                assert_eq!(
                    quicksilver::violated_constraints::<F, _>(&relation, &public[..], &witness),
                    Ok(Vec::new()),
                    "{}",
                    set.name()
                );
                // A sample of positions in every part of the witness.
                for bit in (0..ell).step_by(ell / 23).chain([1, ell - 1]) {
                    let mut broken = witness.clone();
                    broken[bit / 8] ^= 1 << (bit % 8);
                    assert_eq!(
                        quicksilver::is_satisfied::<F, _>(&relation, &public[..], &broken),
                        Ok(false),
                        "{} bit {bit}",
                        set.name()
                    );
                }
                // Another statement: a flipped bit of x or of y.
                for bit in [0, 8 * public.len() - 1] {
                    let mut other = public.clone();
                    other[bit / 8] ^= 1 << (bit % 8);
                    assert_eq!(
                        quicksilver::is_satisfied::<F, _>(&relation, &other[..], &witness),
                        Ok(false),
                        "{} public bit {bit}",
                        set.name()
                    );
                }
            }
        }
        for set in &FAEST_PARAMETER_SETS {
            with_field!(set, check(set));
        }
    }

    #[test]
    fn a_key_with_both_leading_bits_set_violates_exactly_the_first_constraint() {
        fn check<F: LambdaField>(set: &FaestParams) {
            let owf = *set.owf();
            let mut key = pattern(owf.lambda().bytes(), 9);
            key[0] |= 3;
            let mut public = pattern(owf.input_bytes(), 10);
            let output = cipher::evaluate(owf, &key, &public);
            let witness = cipher::extend_witness(owf, &key, &public);
            public.extend_from_slice(&output);
            assert_eq!(
                quicksilver::violated_constraints::<F, _>(
                    &OwfRelation::new(owf),
                    &public[..],
                    &witness
                ),
                Ok(vec![owf.ell()]),
                "{}",
                set.name()
            );
        }
        for set in &FAEST_PARAMETER_SETS {
            with_field!(set, check(set));
        }
    }

    #[test]
    fn the_three_evaluators_agree_on_field_valued_witnesses() {
        fn check<F: LambdaField>(set: &FaestParams, seed: u64) {
            let relation = OwfRelation::new(*set.owf());
            let public = pattern(set.owf().public_key_bytes(), 77);
            // Random field elements, not bits: the identities are polynomial.
            let values: Vec<F> = (0u64..)
                .take(set.owf().ell())
                .map(|i| engine::element::<F>(seed + 5000 + i))
                .collect();
            let streams = engine::evaluators::<F, _>(&relation, &public[..], values, seed);
            assert_eq!(streams.polynomials.len(), set.proof().constraints());
            assert_eq!(streams.keys.len(), set.proof().constraints());
            assert_eq!(streams.plain.len(), set.proof().constraints());
            let mut non_zero = 0;
            for ((polynomial, key), plain) in streams
                .polynomials
                .iter()
                .zip(&streams.keys)
                .zip(&streams.plain)
            {
                assert_eq!(engine::evaluate(polynomial, streams.delta), *key);
                assert_eq!(polynomial[quicksilver::DEGREE], *plain);
                non_zero += usize::from(!plain.is_zero());
            }
            // Random values violate every constraint.
            assert_eq!(non_zero, set.proof().constraints(), "{}", set.name());
        }
        // The relation depends on the family and the level only: the f sets cover
        // all six.
        for (seed, set) in (1u64..).zip(&FAEST_PARAMETER_SETS) {
            if set.name().ends_with('f') {
                with_field!(set, check(set, seed));
            }
        }
    }

    #[test]
    fn a_wrong_field_or_public_key_length_is_a_count_error() {
        let set = &crate::params::FAEST_128F;
        let relation = OwfRelation::new(*set.owf());
        let (_, public, witness) = instance(set, 3);
        let count = set.proof().constraints() - set.proof().witness_bits();
        assert_eq!(
            quicksilver::is_satisfied::<Gf128, _>(&relation, &public[1..], &witness),
            Err(QuickSilverError::ConstraintCount {
                expected: set.proof().constraints(),
                actual: set.proof().witness_bits(),
            })
        );
        assert_eq!(
            quicksilver::is_satisfied::<Gf256, _>(&relation, &public[..], &witness),
            Err(QuickSilverError::ConstraintCount {
                expected: set.proof().constraints(),
                actual: set.proof().witness_bits(),
            })
        );
        assert_eq!(count, 161);
    }
}
