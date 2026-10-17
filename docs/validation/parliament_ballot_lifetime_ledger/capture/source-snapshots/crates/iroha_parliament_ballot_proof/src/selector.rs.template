//! The two 32-entry selector vectors of the vote relation and the public
//! multiplexer over the sealed list (evaluation record section 6.3).
//!
//! List position `i` is encoded as `a_(i div 32) = 1`, `b_(i mod 32) = 1` and
//! zero elsewhere. The constraints, in stream order:
//!
//! ```text
//! (SP)  a_j * (sum_{k<j} a_k) = 0        j = 0 .. 31   (j = 0 is identically zero and kept)
//! (SS)  1 + sum_j a_j = 0
//! (SP)  b_j * (sum_{k<j} b_k) = 0        j = 0 .. 31
//! (SS)  1 + sum_j b_j = 0
//! (SR)  1 + sum_{i<S} p_i = 0,           p_i = a_(i div 32) * b_(i mod 32)
//! ```
//!
//! and the multiplexer `sum_{i<S} p_i * C_i[t]` that the commitment output is
//! equated to. The products `p_i` exist for `i < S` only, so no position outside
//! the list can be selected. The list is public: its bits choose which products
//! are added and never multiply anything.

use iroha_zkp_vole::quicksilver::ConstraintSystem;
use zeroize::Zeroize;

use crate::{
    framing::COMMITMENT_BYTES,
    keccak_relation::bit_of,
    layout::{SELECTOR_A_OFFSET, SELECTOR_B_OFFSET, SELECTOR_BITS},
};

/// The selector words `(a, b)` of list position `index`: bit `j` of `a` is `a_j`.
/// A position of 1,024 or more has no encoding and gives all-zero words, which no
/// witness check accepts.
///
/// The position is secret (it is the voter's anonymity): the words are computed
/// with shifts and masks only, and the caller erases them.
pub fn selector_words(index: u16) -> [u32; 2] {
    let high = u32::from(index >> 5);
    let low = u32::from(index & 31);
    // All ones when the position has an encoding, zero otherwise.
    let valid = u32::from(high < 32).wrapping_neg();
    [valid & (1u32 << (high & 31)), valid & (1u32 << low)]
}

/// Emit the prefix and sum constraints of `a`, then of `b`, then the range
/// constraint, for a list of `size` entries, and leave the products
/// `p_0 .. p_(size-1)` in `products`.
///
/// Emits `2 * 33 + 1` constraints. `products` must hold at least `size` values
/// and `size` must be at most 1,024; otherwise fewer products are formed and the
/// backend reports the malformed stream.
pub fn emit_selectors<C: ConstraintSystem>(cs: &mut C, size: usize, products: &mut [C::Value]) {
    for offset in [SELECTOR_A_OFFSET, SELECTOR_B_OFFSET] {
        // sum_{k<j} sel_k, starting from the public constant 0.
        let mut prefix = cs.zero();
        for j in 0..SELECTOR_BITS {
            let selector = cs.witness(offset + j);
            let constraint = cs.mul(selector, prefix);
            cs.constrain(constraint);
            prefix = cs.add(prefix, selector);
        }
        let mut sum = cs.add_bit(prefix, true);
        cs.constrain(sum);
        prefix.zeroize();
        sum.zeroize();
    }
    let mut total = cs.zero();
    let positions = size.min(SELECTOR_BITS * SELECTOR_BITS);
    for (i, slot) in products.iter_mut().enumerate().take(positions) {
        let product = cs.mul(
            cs.witness(SELECTOR_A_OFFSET + i / SELECTOR_BITS),
            cs.witness(SELECTOR_B_OFFSET + i % SELECTOR_BITS),
        );
        *slot = product;
        total = cs.add(total, product);
    }
    let mut range = cs.add_bit(total, true);
    cs.constrain(range);
    total.zeroize();
    range.zeroize();
}

/// The multiplexer value `sum_{i<size, C_i[t] = 1} p_i` for output bit `t`, where
/// `list` is the concatenation of the 128-byte entries. An empty sum is the
/// constant 0.
pub fn multiplex<C: ConstraintSystem>(
    cs: &C,
    list: &[u8],
    t: usize,
    products: &[C::Value],
) -> C::Value {
    let mut sum = cs.zero();
    for (entry, product) in list.chunks_exact(COMMITMENT_BYTES).zip(products) {
        if bit_of(entry, t) {
            sum = cs.add(sum, *product);
        }
    }
    sum
}

#[cfg(test)]
mod tests {
    use iroha_zkp_vole::{
        field::Gf256,
        quicksilver::{Relation, violated_constraints},
    };
    use zeroize::Zeroizing;

    use super::*;
    use crate::layout::VOTE_WITNESS_BITS;

    #[test]
    fn selector_words_are_one_hot_for_every_encodable_position() {
        for index in 0..1024u16 {
            let [a, b] = selector_words(index);
            assert_eq!(a, 1 << (index / 32));
            assert_eq!(b, 1 << (index % 32));
        }
        for index in [1024u16, 1025, 2047, 2048, 4096, u16::MAX] {
            assert_eq!(selector_words(index), [0, 0]);
        }
    }

    /// The selector constraints alone, then one constraint per bit of a 16-bit
    /// "commitment" that the multiplexer must equal: public input = (list, the
    /// expected selected entry). The witness has the vote layout.
    struct Selectors {
        size: usize,
    }

    const TEST_BITS: usize = 16;

    impl Relation<Gf256> for Selectors {
        type PublicInput = (Vec<u8>, [u8; 2]);

        fn witness_bits(&self) -> usize {
            VOTE_WITNESS_BITS
        }

        fn constraints(&self) -> usize {
            2 * 33 + 1 + TEST_BITS
        }

        fn emit<C: ConstraintSystem<Field = Gf256>>(&self, public: &Self::PublicInput, cs: &mut C) {
            let mut products = Zeroizing::new(vec![cs.zero(); self.size]);
            emit_selectors(cs, self.size, &mut products);
            for t in 0..TEST_BITS {
                let selected = multiplex(cs, &public.0, t, &products);
                let constraint = cs.add_bit(selected, bit_of(&public.1, t));
                cs.constrain(constraint);
            }
        }
    }

    fn witness(a: u32, b: u32) -> Vec<u8> {
        let mut bytes = vec![0u8; VOTE_WITNESS_BITS / 8];
        bytes[SELECTOR_A_OFFSET / 8..][..4].copy_from_slice(&a.to_le_bytes());
        bytes[SELECTOR_B_OFFSET / 8..][..4].copy_from_slice(&b.to_le_bytes());
        bytes
    }

    /// A list whose entry `i` starts with the two bytes of `i + 1`.
    fn list(size: usize) -> Vec<u8> {
        let mut out = vec![0u8; size * COMMITMENT_BYTES];
        for (i, entry) in out.chunks_exact_mut(COMMITMENT_BYTES).enumerate() {
            entry[..2].copy_from_slice(&u16::try_from(i + 1).expect("small").to_le_bytes());
        }
        out
    }

    fn violated(size: usize, a: u32, b: u32, expected: usize) -> Vec<usize> {
        let public = (
            list(size),
            u16::try_from(expected).expect("small").to_le_bytes(),
        );
        violated_constraints::<Gf256, _>(&Selectors { size }, &public, &witness(a, b))
            .expect("well-formed relation")
            .into_iter()
            .map(|index| index - VOTE_WITNESS_BITS)
            .collect()
    }

    /// Stream positions inside this test relation.
    const A_SUM: usize = 32;
    const B_SUM: usize = 65;
    const RANGE: usize = 66;

    #[test]
    fn every_position_of_the_list_selects_exactly_its_entry() {
        for size in [3usize, 33, 500, 1000] {
            for index in [0, 1, size / 2, size - 1] {
                let [a, b] = selector_words(u16::try_from(index).expect("small"));
                assert_eq!(violated(size, a, b, index + 1), Vec::<usize>::new());
                // The neighbouring entry is not what the selectors select.
                assert!(
                    violated(size, a, b, index + 2)
                        .iter()
                        .all(|constraint| *constraint > RANGE)
                );
                assert!(!violated(size, a, b, index + 2).is_empty());
            }
        }
    }

    #[test]
    fn positions_outside_the_list_fail_the_range_constraint() {
        for (size, index) in [
            (3usize, 3u16),
            (3, 1023),
            (500, 500),
            (1000, 1000),
            (1000, 1023),
        ] {
            let [a, b] = selector_words(index);
            let bad = violated(size, a, b, 0);
            assert_eq!(bad, vec![RANGE], "S = {size}, i = {index}");
        }
    }

    #[test]
    fn the_prefix_form_rejects_every_vector_that_is_not_one_hot() {
        let size = 1000;
        // No bit, and all-zero words in general: both sums and the range fail.
        assert_eq!(violated(size, 0, 0, 0), vec![A_SUM, B_SUM, RANGE]);
        // Two bits of a: the second sees a prefix of one; even parity fails the sum.
        // Positions 5 and 37 are both selected, so the range sum is even.
        assert_eq!(
            violated(size, 0b11, 1 << 5, (5 + 1) ^ (37 + 1)),
            vec![1, A_SUM, RANGE]
        );
        // Three bits of a: odd parity passes the sum, the prefix catches bits 2
        // (prefix 1) but not 3 (prefix 0); three selected entries XOR together.
        assert_eq!(
            violated(size, 0b111, 1 << 5, (5 + 1) ^ (37 + 1) ^ (69 + 1)),
            vec![1]
        );
        // Two and three bits of b.
        assert_eq!(
            violated(size, 1, 0b1_0001, 1 ^ (4 + 1)),
            vec![33 + 4, B_SUM, RANGE]
        );
        assert_eq!(
            violated(size, 1, 0b1_0101, 1 ^ (2 + 1) ^ (4 + 1)),
            vec![33 + 2]
        );
        // Bits 0 and 31 of a, where position 31 * 32 + 5 = 997 is inside the list.
        assert_eq!(
            violated(size, 0x8000_0001, 1 << 5, (5 + 1) ^ (997 + 1)),
            vec![31, A_SUM, RANGE]
        );
    }

    #[test]
    fn an_empty_multiplexer_row_is_the_constant_zero() {
        // Bit 15 is set in no entry of a short list.
        let [a, b] = selector_words(2);
        assert_eq!(violated(3, a, b, 3), Vec::<usize>::new());
        // A list shorter than the declared size forms fewer products: with a
        // product buffer of the declared size the multiplexer simply ends early.
        let public = (list(2), 3u16.to_le_bytes());
        let bad = violated_constraints::<Gf256, _>(&Selectors { size: 3 }, &public, &witness(a, b))
            .expect("well-formed relation");
        assert!(!bad.is_empty());
    }
}
