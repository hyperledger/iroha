//! One 132-byte SHAKE256 evaluation, twice: as a constant-time computation that
//! yields the eleven committed Keccak states of the witness, and as the constraint
//! gadget of a forward two-round group on the backend's [`ConstraintSystem`].
//!
//! Conventions (FIPS 202; evaluation record section 6.3): state bit
//! `t = 64 * (x + 5 * y) + z` is bit `z` of lane `x + 5 * y`, lanes and bytes are
//! little-endian. The unpadded message is `tag[4] || P16[16] || sk[48] || x[64]`;
//! `1f 00 00 80` completes the 136-byte rate block and 64 zero capacity bytes
//! follow, so secret bit `j` is initial-state bit `160 + j` and every other bit of
//! the initial state is public. One permutation is enough for every output used
//! here (at most 128 bytes).
//!
//! The round function is `R_r = iota_r . chi . pi . rho . theta`; a group is
//! `G_g = R_(2g-1) . R_(2g-2)`, of degree four in its inputs. The states after
//! 2, 4, ..., 22 rounds are witness; the last group is evaluated as expressions.
//!
//! Nothing here branches on, or indexes by, a secret: the lane computation is
//! XOR, AND, NOT and rotations by public amounts, and the gadget performs the
//! same operations for every witness.

use iroha_zkp_vole::quicksilver::ConstraintSystem;
use zeroize::{Zeroize, Zeroizing};

use crate::{
    layout::{GROUPS, SECRET_BITS, SECRET_OFFSET, SECRET_STATE_OFFSET, STATE_BITS},
    profile::P16,
};

/// Rounds of Keccak-f\[1600\].
pub const ROUNDS: usize = 24;
/// Lanes of the state.
pub const LANES: usize = 25;
/// Bytes of the state.
pub const STATE_BYTES: usize = STATE_BITS / 8;
/// Bytes of the SHAKE256 rate.
pub const RATE_BYTES: usize = 136;
/// Bytes of the unpadded message of every evaluation.
pub const MESSAGE_BYTES: usize = 132;
/// Bytes of the credential secret inside the message.
pub const SECRET_BYTES: usize = SECRET_BITS / 8;
/// Byte offset of the secret inside the message and the state.
const SECRET_BYTE_OFFSET: usize = SECRET_STATE_OFFSET / 8;
/// Byte offset of the 64-byte public input inside the message.
const INPUT_BYTE_OFFSET: usize = SECRET_BYTE_OFFSET + SECRET_BYTES;

/// The round constants `RC[0..24]` (FIPS 202 Algorithm 5).
pub const ROUND_CONSTANTS: [u64; ROUNDS] = [
    0x0000_0000_0000_0001,
    0x0000_0000_0000_8082,
    0x8000_0000_0000_808a,
    0x8000_0000_8000_8000,
    0x0000_0000_0000_808b,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8009,
    0x0000_0000_0000_008a,
    0x0000_0000_0000_0088,
    0x0000_0000_8000_8009,
    0x0000_0000_8000_000a,
    0x0000_0000_8000_808b,
    0x8000_0000_0000_008b,
    0x8000_0000_0000_8089,
    0x8000_0000_0000_8003,
    0x8000_0000_0000_8002,
    0x8000_0000_0000_0080,
    0x0000_0000_0000_800a,
    0x8000_0000_8000_000a,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8080,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8008,
];

/// The rotation offsets of rho, indexed `[x][y]` (FIPS 202 Algorithm 2).
pub const RHO_OFFSETS: [[u32; 5]; 5] = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14],
];

/// XOR `bytes` into `lanes` starting at state byte `offset`.
fn xor_bytes(lanes: &mut [u64; LANES], offset: usize, bytes: &[u8]) {
    for (index, byte) in bytes.iter().enumerate() {
        let at = offset + index;
        if let Some(lane) = lanes.get_mut(at / 8) {
            *lane ^= u64::from(*byte) << (8 * (at % 8));
        }
    }
}

/// Copy the first `out.len()` state bytes of `lanes` (at most 200).
fn read_bytes(lanes: &[u64; LANES], out: &mut [u8]) {
    for (index, byte) in out.iter_mut().enumerate() {
        if let Some(lane) = lanes.get(index / 8) {
            *byte = lane.to_le_bytes()[index % 8];
        }
    }
}

/// One Keccak round with the round constant `constant`, on lanes `x + 5 * y`.
fn round_lanes(lanes: &mut [u64; LANES], constant: u64) {
    let mut parity = [0u64; 5];
    for (x, slot) in parity.iter_mut().enumerate() {
        *slot = lanes[x] ^ lanes[x + 5] ^ lanes[x + 10] ^ lanes[x + 15] ^ lanes[x + 20];
    }
    for x in 0..5 {
        let column = parity[(x + 4) % 5] ^ parity[(x + 1) % 5].rotate_left(1);
        for y in 0..5 {
            lanes[x + 5 * y] ^= column;
        }
    }
    let mut moved = [0u64; LANES];
    for x in 0..5 {
        for y in 0..5 {
            let source_x = (x + 3 * y) % 5;
            moved[x + 5 * y] = lanes[source_x + 5 * x].rotate_left(RHO_OFFSETS[source_x][x]);
        }
    }
    for y in 0..5 {
        for x in 0..5 {
            lanes[x + 5 * y] =
                moved[x + 5 * y] ^ (!moved[(x + 1) % 5 + 5 * y] & moved[(x + 2) % 5 + 5 * y]);
        }
    }
    lanes[0] ^= constant;
    parity.zeroize();
    moved.zeroize();
}

/// The public part of the initial state of one evaluation: the rate block
/// `tag || P16 || 0^48 || input || 1f 00 00 80` followed by 64 zero bytes. The 48
/// bytes where the secret goes are zero.
pub fn public_block(tag: [u8; 4], input: &[u8; 64]) -> [u8; STATE_BYTES] {
    let mut block = [0u8; STATE_BYTES];
    block[..4].copy_from_slice(&tag);
    block[4..SECRET_BYTE_OFFSET].copy_from_slice(&P16);
    block[INPUT_BYTE_OFFSET..MESSAGE_BYTES].copy_from_slice(input);
    block[MESSAGE_BYTES] = 0x1f;
    block[RATE_BYTES - 1] = 0x80;
    block
}

/// Bit `t` of a public byte string, in the bit order of the record.
pub fn bit_of(bytes: &[u8], t: usize) -> bool {
    bytes
        .get(t / 8)
        .is_some_and(|byte| (byte >> (t % 8)) & 1 == 1)
}

/// The states of one evaluation the witness and the outputs need. **Secret**;
/// erased on drop.
pub struct Evaluation {
    /// The states after 2, 4, ..., 22 rounds.
    states: [[u64; LANES]; GROUPS],
    /// The state after 24 rounds.
    output: [u64; LANES],
}

impl core::fmt::Debug for Evaluation {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Evaluation").finish_non_exhaustive()
    }
}

impl Zeroize for Evaluation {
    fn zeroize(&mut self) {
        for state in &mut self.states {
            state.zeroize();
        }
        self.output.zeroize();
    }
}

impl Drop for Evaluation {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl Evaluation {
    /// Write the committed state after `2 * group` rounds (`group` in `1 ..= 11`)
    /// as its 200 bytes; `out` beyond 200 bytes, and any `out` for a group out of
    /// range, is left untouched.
    pub fn write_state(&self, group: usize, out: &mut [u8]) {
        if let Some(state) = group.checked_sub(1).and_then(|g| self.states.get(g)) {
            read_bytes(state, out);
        }
    }

    /// Write the first `out.len()` bytes of the SHAKE256 output (at most the 136
    /// bytes of one rate block; the rest of a longer `out` is left untouched).
    pub fn squeeze(&self, out: &mut [u8]) {
        let len = out.len().min(RATE_BYTES);
        read_bytes(&self.output, &mut out[..len]);
    }
}

/// Run Keccak-f\[1600\] on the initial state `block` with `secret` at state bytes
/// `[20, 68)` and keep the states after 2, 4, ..., 22 and 24 rounds.
///
/// `block` is a [`public_block`]; the secret is added (XOR) into it, so those 48
/// bytes of `block` must be zero. Constant time in `secret`.
pub fn evaluate(block: &[u8; STATE_BYTES], secret: &[u8; SECRET_BYTES]) -> Evaluation {
    let mut lanes = [0u64; LANES];
    xor_bytes(&mut lanes, 0, block);
    xor_bytes(&mut lanes, SECRET_BYTE_OFFSET, secret);
    let mut evaluation = Evaluation {
        states: [[0; LANES]; GROUPS],
        output: [0; LANES],
    };
    for (round, constant) in ROUND_CONSTANTS.iter().enumerate() {
        round_lanes(&mut lanes, *constant);
        if round % 2 == 1
            && let Some(state) = evaluation.states.get_mut(round / 2)
        {
            *state = lanes;
        }
    }
    evaluation.output = lanes;
    lanes.zeroize();
    evaluation
}

/// For every state bit `t` after pi and rho, the bit of the theta output it is a
/// copy of: with `t = 64 * (x + 5 * y) + z`, `x' = (x + 3 * y) mod 5`, `y' = x`,
/// the source is `64 * (x' + 5 * y') + ((z - RHO[x'][y']) mod 64)`.
pub fn linear_source() -> Vec<usize> {
    let mut source = vec![0usize; STATE_BITS];
    for y in 0..5 {
        for x in 0..5 {
            let (source_x, source_y) = ((x + 3 * y) % 5, x);
            let rotation = RHO_OFFSETS[source_x][source_y] as usize;
            for z in 0..64 {
                source[64 * (x + 5 * y) + z] =
                    64 * (source_x + 5 * source_y) + (z + 64 - rotation) % 64;
            }
        }
    }
    source
}

/// The value buffers of the round gadget: one state, its image under theta, the
/// column parities and the theta column terms. Allocated once per
/// `Relation::emit` and erased on drop, as the backend requires of secret values.
pub struct Scratch<V: Zeroize> {
    /// The current state: input of the next round, then its output.
    state: Zeroizing<Vec<V>>,
    theta: Zeroizing<Vec<V>>,
    parity: Zeroizing<Vec<V>>,
    column: Zeroizing<Vec<V>>,
    /// [`linear_source`]. Public.
    source: Vec<usize>,
}

impl<V: Zeroize> core::fmt::Debug for Scratch<V> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Scratch").finish_non_exhaustive()
    }
}

impl<V: Copy + Zeroize> Scratch<V> {
    /// Buffers filled with `zero`.
    pub fn new(zero: V) -> Self {
        Self {
            state: Zeroizing::new(vec![zero; STATE_BITS]),
            theta: Zeroizing::new(vec![zero; STATE_BITS]),
            parity: Zeroizing::new(vec![zero; 320]),
            column: Zeroizing::new(vec![zero; 320]),
            source: linear_source(),
        }
    }

    /// The current state, 1,600 values.
    pub fn state(&self) -> &[V] {
        &self.state
    }

    /// The current state, to load the input of a group.
    pub fn state_mut(&mut self) -> &mut [V] {
        &mut self.state
    }
}

/// Replace the state in `scratch` by its image under round `round`
/// (`0 ..= 23`), computing the first `limit` coordinates of the output only; the
/// coordinates from `limit` on are left unspecified. A degree-`d` input gives a
/// degree-`2d` output.
pub fn round<C: ConstraintSystem>(
    cs: &C,
    scratch: &mut Scratch<C::Value>,
    round: usize,
    limit: usize,
) {
    let Scratch {
        state,
        theta,
        parity,
        column,
        source,
    } = scratch;
    // theta: column parities, then the term added to every bit of a column.
    for i in 0..320 {
        let low = cs.add(cs.add(state[i], state[i + 320]), state[i + 640]);
        parity[i] = cs.add(cs.add(low, state[i + 960]), state[i + 1280]);
    }
    for x in 0..5 {
        for z in 0..64 {
            column[64 * x + z] = cs.add(
                parity[64 * ((x + 4) % 5) + z],
                parity[64 * ((x + 1) % 5) + (z + 63) % 64],
            );
        }
    }
    for t in 0..STATE_BITS {
        theta[t] = cs.add(state[t], column[t % 320]);
    }
    // rho and pi are the bit permutation `source`; chi is the only product.
    let constant = ROUND_CONSTANTS.get(round).copied().unwrap_or(0);
    for t in 0..limit.min(STATE_BITS) {
        let (z, lane) = (t % 64, t / 64);
        let (x, row) = (lane % 5, lane - lane % 5);
        let next = 64 * (row + (x + 1) % 5) + z;
        let after = 64 * (row + (x + 2) % 5) + z;
        let product = cs.mul(cs.add_bit(theta[source[next]], true), theta[source[after]]);
        let mut value = cs.add(theta[source[t]], product);
        // iota: the round constant on lane (0, 0).
        if t < 64 && (constant >> t) & 1 == 1 {
            value = cs.add_bit(value, true);
        }
        state[t] = value;
    }
}

/// Replace the state in `scratch` by its image under the two-round group
/// `G_group = R_(2 group - 1) . R_(2 group - 2)` (`group` in `1 ..= 12`),
/// computing the first `limit` output coordinates only. A degree-1 input gives a
/// degree-4 output.
pub fn group<C: ConstraintSystem>(
    cs: &C,
    scratch: &mut Scratch<C::Value>,
    group: usize,
    limit: usize,
) {
    let first = group.saturating_mul(2).saturating_sub(2);
    round(cs, scratch, first, STATE_BITS);
    round(cs, scratch, first + 1, limit);
}

/// Emit the 17,600 transition constraints (T) of one permutation and leave the
/// first `output_bits` coordinates of `O = G_12(A^(22))` in `scratch`.
///
/// `block` is the public part of the initial state; the secret wires are witness
/// coordinates `[256, 640)`; the committed states start at witness bit `offset`.
/// Constraint `1600 (g - 1) + t` is `A^(2g)[t] + G_g(A^(2g-2))[t]`.
pub fn emit_transitions<C: ConstraintSystem>(
    cs: &mut C,
    scratch: &mut Scratch<C::Value>,
    block: &[u8; STATE_BYTES],
    offset: usize,
    output_bits: usize,
) {
    let secret_wires = SECRET_STATE_OFFSET..SECRET_STATE_OFFSET + SECRET_BITS;
    for (t, slot) in scratch.state_mut().iter_mut().enumerate() {
        *slot = if secret_wires.contains(&t) {
            cs.witness(SECRET_OFFSET + t - SECRET_STATE_OFFSET)
        } else {
            cs.bit(bit_of(block, t))
        };
    }
    for g in 1..=GROUPS {
        group(cs, scratch, g, STATE_BITS);
        let base = offset + STATE_BITS * (g - 1);
        for (t, slot) in scratch.state_mut().iter_mut().enumerate() {
            let committed = cs.witness(base + t);
            let constraint = cs.add(committed, *slot);
            cs.constrain(constraint);
            *slot = committed;
        }
    }
    group(cs, scratch, GROUPS + 1, output_bits);
}

#[cfg(test)]
mod tests {
    use iroha_zkp_vole::{field::Gf256, quicksilver::Relation};

    use super::*;

    /// FIPS 202 Algorithm 5.
    fn rc_bit(t: usize) -> u64 {
        if t.is_multiple_of(255) {
            return 1;
        }
        let mut r: u16 = 1;
        for _ in 0..t % 255 {
            r <<= 1;
            if r & 0x100 != 0 {
                r ^= 0x171;
            }
        }
        u64::from(r & 1)
    }

    #[test]
    fn the_tables_are_those_of_fips_202() {
        for (round, constant) in ROUND_CONSTANTS.iter().enumerate() {
            let mut expected = 0u64;
            for j in 0..7 {
                expected |= rc_bit(j + 7 * round) << ((1u32 << j) - 1);
            }
            assert_eq!(*constant, expected, "round {round}");
        }
        let mut offsets = [[0u32; 5]; 5];
        let (mut x, mut y) = (1usize, 0usize);
        for t in 0..24u32 {
            offsets[x][y] = ((t + 1) * (t + 2) / 2) % 64;
            (x, y) = (y, (2 * x + 3 * y) % 5);
        }
        assert_eq!(RHO_OFFSETS, offsets);
        let source = linear_source();
        assert_eq!(source[..4], [0, 1, 2, 3]);
        assert_eq!(source[64], 404);
        assert_eq!(source[1599], 1405);
        let mut seen = vec![false; STATE_BITS];
        for bit in &source {
            assert!(!seen[*bit]);
            seen[*bit] = true;
        }
    }

    fn sample(seed: u8, len: usize) -> Vec<u8> {
        use sha3::digest::{ExtendableOutput, Update, XofReader};
        let mut sponge = sha3::Shake128::default();
        sponge.update(&[seed]);
        let mut out = vec![0u8; len];
        sponge.finalize_xof().read(&mut out);
        out
    }

    fn inputs(seed: u8) -> ([u8; 4], [u8; 48], [u8; 64]) {
        let bytes = sample(seed, 116);
        let mut tag = [0u8; 4];
        let mut secret = [0u8; 48];
        let mut input = [0u8; 64];
        tag.copy_from_slice(&bytes[..4]);
        secret.copy_from_slice(&bytes[4..52]);
        input.copy_from_slice(&bytes[52..]);
        (tag, secret, input)
    }

    #[test]
    fn the_block_and_the_bit_order_are_the_record_s() {
        let block = public_block(*b"PCR1", &[0xee; 64]);
        assert_eq!(&block[..4], b"PCR1");
        assert_eq!(block[4..20], P16);
        assert_eq!(block[20..68], [0u8; 48]);
        assert_eq!(block[68..132], [0xee; 64]);
        assert_eq!(block[132..136], [0x1f, 0, 0, 0x80]);
        assert_eq!(block[136..], [0u8; 64]);
        assert!(bit_of(&[0b0000_0100, 0x80], 2));
        assert!(!bit_of(&[0b0000_0100, 0x80], 3));
        assert!(bit_of(&[0b0000_0100, 0x80], 15));
        assert!(!bit_of(&[0xff], 8));
    }

    #[test]
    fn the_evaluation_is_shake256_of_the_132_byte_message() {
        use sha3::digest::{ExtendableOutput, Update, XofReader};
        for seed in 0..8u8 {
            let (tag, secret, input) = inputs(seed);
            let mut message = Vec::new();
            message.extend_from_slice(&tag);
            message.extend_from_slice(&P16);
            message.extend_from_slice(&secret);
            message.extend_from_slice(&input);
            assert_eq!(message.len(), MESSAGE_BYTES);
            let mut expected = [0u8; 136];
            let mut sponge = sha3::Shake256::default();
            sponge.update(&message);
            sponge.finalize_xof().read(&mut expected);
            let evaluation = evaluate(&public_block(tag, &input), &secret);
            for len in [0usize, 1, 64, 128, 136] {
                let mut out = vec![0u8; len];
                evaluation.squeeze(&mut out);
                assert_eq!(out, expected[..len]);
            }
            // Longer requests are not served beyond one rate block.
            let mut long = [0xaau8; 140];
            evaluation.squeeze(&mut long);
            assert_eq!(long[..136], expected);
            assert_eq!(long[136..], [0xaa; 4]);
        }
    }

    #[test]
    fn the_committed_states_are_the_states_after_every_second_round() {
        let (tag, secret, input) = inputs(9);
        let block = public_block(tag, &input);
        let evaluation = evaluate(&block, &secret);
        let mut lanes = [0u64; LANES];
        xor_bytes(&mut lanes, 0, &block);
        xor_bytes(&mut lanes, 20, &secret);
        // The backend's sponge uses the same permutation: compare the final state
        // through SHAKE (previous test) and the intermediate ones round by round.
        for group in 1..=GROUPS {
            round_lanes(&mut lanes, ROUND_CONSTANTS[2 * group - 2]);
            round_lanes(&mut lanes, ROUND_CONSTANTS[2 * group - 1]);
            let mut expected = [0u8; STATE_BYTES];
            read_bytes(&lanes, &mut expected);
            let mut state = [0u8; STATE_BYTES];
            evaluation.write_state(group, &mut state);
            assert_eq!(state, expected, "group {group}");
        }
        let mut untouched = [0x55u8; STATE_BYTES];
        evaluation.write_state(0, &mut untouched);
        evaluation.write_state(12, &mut untouched);
        assert_eq!(untouched, [0x55; STATE_BYTES]);
        let mut erased = evaluate(&block, &secret);
        erased.zeroize();
        let mut out = [1u8; 8];
        erased.squeeze(&mut out);
        assert_eq!(out, [0; 8]);
        assert_eq!(format!("{evaluation:?}"), "Evaluation { .. }");
    }

    /// One group as a relation: the witness is a 1,600-bit input state and the
    /// public input the expected output state of the group.
    struct GroupRelation(usize);

    impl Relation<Gf256> for GroupRelation {
        type PublicInput = [u8];

        fn witness_bits(&self) -> usize {
            STATE_BITS
        }

        fn constraints(&self) -> usize {
            STATE_BITS
        }

        fn emit<C: ConstraintSystem<Field = Gf256>>(&self, public: &[u8], cs: &mut C) {
            let mut scratch = Scratch::new(cs.zero());
            for (t, slot) in scratch.state_mut().iter_mut().enumerate() {
                *slot = cs.witness(t);
            }
            group(cs, &mut scratch, self.0, STATE_BITS);
            for t in 0..STATE_BITS {
                let constraint = cs.add_bit(scratch.state()[t], bit_of(public, t));
                cs.constrain(constraint);
            }
        }
    }

    #[test]
    fn the_group_gadget_computes_two_keccak_rounds() {
        use iroha_zkp_vole::quicksilver::{is_satisfied, violated_constraints};
        for group in [1usize, 2, 7, 12] {
            let input = sample(u8::try_from(group).expect("small"), STATE_BYTES);
            let mut lanes = [0u64; LANES];
            xor_bytes(&mut lanes, 0, &input);
            round_lanes(&mut lanes, ROUND_CONSTANTS[2 * group - 2]);
            round_lanes(&mut lanes, ROUND_CONSTANTS[2 * group - 1]);
            let mut output = [0u8; STATE_BYTES];
            read_bytes(&lanes, &mut output);
            let relation = GroupRelation(group);
            assert_eq!(
                is_satisfied::<Gf256, _>(&relation, &output[..], &input),
                Ok(true),
                "group {group}"
            );
            // A flipped output bit violates exactly its own coordinate.
            let mut wrong = output;
            wrong[100] ^= 0x10;
            assert_eq!(
                violated_constraints::<Gf256, _>(&relation, &wrong[..], &input),
                Ok(vec![STATE_BITS + 804])
            );
        }
        // The round constants matter: group 1 is not group 2.
        let input = sample(77, STATE_BYTES);
        let mut lanes = [0u64; LANES];
        xor_bytes(&mut lanes, 0, &input);
        round_lanes(&mut lanes, ROUND_CONSTANTS[0]);
        round_lanes(&mut lanes, ROUND_CONSTANTS[1]);
        let mut output = [0u8; STATE_BYTES];
        read_bytes(&lanes, &mut output);
        assert_eq!(
            is_satisfied::<Gf256, _>(&GroupRelation(2), &output[..], &input),
            Ok(false)
        );
    }

    /// One round with a limit: only the first coordinates are constrained.
    struct RoundRelation(usize, usize);

    impl Relation<Gf256> for RoundRelation {
        type PublicInput = [u8];

        fn witness_bits(&self) -> usize {
            STATE_BITS
        }

        fn constraints(&self) -> usize {
            self.1
        }

        fn emit<C: ConstraintSystem<Field = Gf256>>(&self, public: &[u8], cs: &mut C) {
            let mut scratch = Scratch::new(cs.zero());
            for (t, slot) in scratch.state_mut().iter_mut().enumerate() {
                *slot = cs.witness(t);
            }
            round(cs, &mut scratch, self.0, self.1);
            for t in 0..self.1 {
                let constraint = cs.add_bit(scratch.state()[t], bit_of(public, t));
                cs.constrain(constraint);
            }
        }
    }

    #[test]
    fn the_round_gadget_computes_one_round_up_to_its_limit() {
        use iroha_zkp_vole::quicksilver::is_satisfied;
        for (index, limit) in [(0usize, STATE_BITS), (23, 512), (5, 1024), (24, 64)] {
            let input = sample(u8::try_from(index + 100).expect("small"), STATE_BYTES);
            let mut lanes = [0u64; LANES];
            xor_bytes(&mut lanes, 0, &input);
            // A round index out of range has no round constant.
            round_lanes(&mut lanes, ROUND_CONSTANTS.get(index).copied().unwrap_or(0));
            let mut output = [0u8; STATE_BYTES];
            read_bytes(&lanes, &mut output);
            assert_eq!(
                is_satisfied::<Gf256, _>(&RoundRelation(index, limit), &output[..], &input),
                Ok(true),
                "round {index}"
            );
        }
    }
}
