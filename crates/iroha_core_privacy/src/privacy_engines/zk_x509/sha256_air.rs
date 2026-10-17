//! Test-only SHA-256 Boolean-circuit oracle for the zk-X509 AIR.
//!
//! Every nonlinear operation is lowered to the degree-bounded Boolean gates in
//! [`super::air`]. Rotations and shifts are wire aliases; every modular
//! addition is a chain of constrained one-bit full adders. This module is the
//! deterministic witness compiler intended for certificate, CRL, sparse-tree,
//! transcript, and projection hashing in differential tests. The release
//! prover uses the word-oriented SHA AIR and never compiles this oracle.
//!
//! The global wire-copy argument binds execution-order gate accesses to the
//! address-sorted SHA word-memory table, and the SHA call-bus STARK binds those
//! words across aggregate segments.
use super::air::{BooleanGateAirRowV1, ZkX509AirErrorV1};
use crate::privacy_engines::transparent_stark::GoldilocksFieldV1 as F;
use thiserror::Error;
const SHA256_INITIAL_STATE_V1: [u32; 8] = [
    0x6a09_e667,
    0xbb67_ae85,
    0x3c6e_f372,
    0xa54f_f53a,
    0x510e_527f,
    0x9b05_688c,
    0x1f83_d9ab,
    0x5be0_cd19,
];
const SHA256_ROUND_CONSTANTS_V1: [u32; 64] = [
    0x428a_2f98,
    0x7137_4491,
    0xb5c0_fbcf,
    0xe9b5_dba5,
    0x3956_c25b,
    0x59f1_11f1,
    0x923f_82a4,
    0xab1c_5ed5,
    0xd807_aa98,
    0x1283_5b01,
    0x2431_85be,
    0x550c_7dc3,
    0x72be_5d74,
    0x80de_b1fe,
    0x9bdc_06a7,
    0xc19b_f174,
    0xe49b_69c1,
    0xefbe_4786,
    0x0fc1_9dc6,
    0x240c_a1cc,
    0x2de9_2c6f,
    0x4a74_84aa,
    0x5cb0_a9dc,
    0x76f9_88da,
    0x983e_5152,
    0xa831_c66d,
    0xb003_27c8,
    0xbf59_7fc7,
    0xc6e0_0bf3,
    0xd5a7_9147,
    0x06ca_6351,
    0x1429_2967,
    0x27b7_0a85,
    0x2e1b_2138,
    0x4d2c_6dfc,
    0x5338_0d13,
    0x650a_7354,
    0x766a_0abb,
    0x81c2_c92e,
    0x9272_2c85,
    0xa2bf_e8a1,
    0xa81a_664b,
    0xc24b_8b70,
    0xc76c_51a3,
    0xd192_e819,
    0xd699_0624,
    0xf40e_3585,
    0x106a_a070,
    0x19a4_c116,
    0x1e37_6c08,
    0x2748_774c,
    0x34b0_bcb5,
    0x391c_0cb3,
    0x4ed8_aa4a,
    0x5b9c_ca4f,
    0x682e_6ff3,
    0x748f_82ee,
    0x78a5_636f,
    0x84c8_7814,
    0x8cc7_0208,
    0x90be_fffa,
    0xa450_6ceb,
    0xbef9_a3f7,
    0xc671_78f2,
];
const SHA256_GATE_ROWS_PER_BLOCK_V1: usize = 55_552;
type WireV1 = usize;
type WordV1 = [WireV1; 32];
/// Deterministic SHA-256 circuit construction or validation failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum ZkX509Sha256AirErrorV1 {
    /// SHA-256 bit-length or padding arithmetic overflowed.
    #[error("zk-X509 SHA-256 AIR input is too large")]
    InputTooLarge,
    /// One local Boolean AIR row is invalid.
    #[error("zk-X509 SHA-256 AIR gate is invalid")]
    Gate,
    /// A gate row is not bound to the referenced wire values.
    #[error("zk-X509 SHA-256 AIR wire binding is invalid")]
    WireBinding,
    /// Circuit wires are not in the sole canonical acyclic allocation order.
    #[error("zk-X509 SHA-256 AIR circuit shape is non-canonical")]
    CircuitShape,
    /// Private input wires do not contain the sole SHA-256 padding of the
    /// declared message length.
    #[error("zk-X509 SHA-256 AIR padding is non-canonical")]
    Padding,
    /// Output wires do not reconstruct the stored SHA-256 digest.
    #[error("zk-X509 SHA-256 AIR output digest is invalid")]
    OutputDigest,
}
impl From<ZkX509AirErrorV1> for ZkX509Sha256AirErrorV1 {
    fn from(_: ZkX509AirErrorV1) -> Self {
        Self::Gate
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum GateKindV1 {
    And,
    Xor,
    FullAdder,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CircuitGateV1 {
    kind: GateKindV1,
    left: WireV1,
    right: WireV1,
    carry_in: WireV1,
    out: WireV1,
    carry_out: WireV1,
    row: BooleanGateAirRowV1,
}
/// Complete padded SHA-256 circuit witness.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ZkX509Sha256CircuitV1 {
    wires: Vec<F>,
    input_wires: Vec<WireV1>,
    gates: Vec<CircuitGateV1>,
    output_words: [WordV1; 8],
    message_len: usize,
    digest: [u8; 32],
}
impl ZkX509Sha256CircuitV1 {
    /// Final SHA-256 digest reconstructed from constrained output wires.
    pub(crate) const fn digest(&self) -> [u8; 32] {
        self.digest
    }
    /// Number of nonlinear degree-bounded AIR gate rows.
    pub(crate) fn gate_rows(&self) -> usize {
        self.gates.len()
    }
    /// Number of private padded-message input bits.
    pub(crate) fn input_wires(&self) -> usize {
        self.input_wires.len()
    }
    /// Number of unpadded private message bytes.
    pub(crate) const fn message_len(&self) -> usize {
        self.message_len
    }
    /// Differentially validate every local gate and exact wire binding.
    pub(crate) fn validate(&self) -> Result<(), ZkX509Sha256AirErrorV1> {
        if self.wires.get(0) != Some(&F::ZERO)
            || self.wires.get(1) != Some(&F::ONE)
            || self
                .wires
                .iter()
                .any(|value| !matches!(*value, F::ZERO | F::ONE))
        {
            return Err(ZkX509Sha256AirErrorV1::WireBinding);
        }
        let padded_len = self
            .input_wires
            .len()
            .checked_div(8)
            .ok_or(ZkX509Sha256AirErrorV1::CircuitShape)?;
        let input_end = 2_usize
            .checked_add(self.input_wires.len())
            .ok_or(ZkX509Sha256AirErrorV1::CircuitShape)?;
        if self.input_wires.len() % 512 != 0
            || self.input_wires.len() != padded_len.saturating_mul(8)
            || self.input_wires.iter().copied().ne(2..input_end)
        {
            return Err(ZkX509Sha256AirErrorV1::CircuitShape);
        }
        let mut padded = Vec::new();
        padded
            .try_reserve_exact(padded_len)
            .map_err(|_| ZkX509Sha256AirErrorV1::InputTooLarge)?;
        for word_wires in self.input_wires.chunks_exact(32) {
            let mut word = 0_u32;
            for (bit, wire) in word_wires.iter().copied().enumerate() {
                if self.wires[wire] == F::ONE {
                    word |= 1_u32 << bit;
                }
            }
            padded.extend_from_slice(&word.to_be_bytes());
        }
        let message = padded
            .get(..self.message_len)
            .ok_or(ZkX509Sha256AirErrorV1::Padding)?;
        if sha256_padding_v1(message)? != padded {
            return Err(ZkX509Sha256AirErrorV1::Padding);
        }
        // Satisfied gate equations only prove some Boolean circuit. Recompile
        // the fixed SHA-256 topology for this exact message length and require
        // every selector role, address, and output wire to match it.
        let canonical = build_sha256_circuit_unchecked_v1(message)?;
        if self.output_words != canonical.output_words
            || self.gates.len() != canonical.gates.len()
            || self
                .gates
                .iter()
                .zip(&canonical.gates)
                .any(|(actual, expected)| {
                    actual.kind != expected.kind
                        || actual.left != expected.left
                        || actual.right != expected.right
                        || actual.carry_in != expected.carry_in
                        || actual.out != expected.out
                        || actual.carry_out != expected.carry_out
                })
        {
            return Err(ZkX509Sha256AirErrorV1::CircuitShape);
        }
        drop(canonical);
        let mut next_fresh_wire = input_end;
        for gate in &self.gates {
            gate.row.validate()?;
            let expected_kind = if gate.row.select_and == F::ONE {
                GateKindV1::And
            } else if gate.row.select_xor == F::ONE {
                GateKindV1::Xor
            } else {
                GateKindV1::FullAdder
            };
            let canonical_outputs = match gate.kind {
                GateKindV1::And | GateKindV1::Xor => {
                    gate.carry_in == 0
                        && gate.out == next_fresh_wire
                        && gate.carry_out == 0
                        && next_fresh_wire.checked_add(1).is_some_and(|next| {
                            next_fresh_wire = next;
                            true
                        })
                }
                GateKindV1::FullAdder => {
                    gate.out == next_fresh_wire
                        && gate.carry_out == next_fresh_wire.saturating_add(1)
                        && next_fresh_wire.checked_add(2).is_some_and(|next| {
                            next_fresh_wire = next;
                            true
                        })
                }
            };
            if !canonical_outputs
                || gate.left >= gate.out
                || gate.right >= gate.out
                || gate.carry_in >= gate.out
                || gate.kind != expected_kind
                || self.wires.get(gate.left).copied() != Some(gate.row.left)
                || self.wires.get(gate.right).copied() != Some(gate.row.right)
                || self.wires.get(gate.carry_in).copied() != Some(gate.row.carry_in)
                || self.wires.get(gate.out).copied() != Some(gate.row.out)
                || self.wires.get(gate.carry_out).copied() != Some(gate.row.carry_out)
            {
                return Err(ZkX509Sha256AirErrorV1::WireBinding);
            }
        }
        if next_fresh_wire != self.wires.len() {
            return Err(ZkX509Sha256AirErrorV1::CircuitShape);
        }
        if digest_from_words_v1(&self.wires, &self.output_words)? != self.digest {
            return Err(ZkX509Sha256AirErrorV1::OutputDigest);
        }
        Ok(())
    }
}
struct CircuitBuilderV1 {
    wires: Vec<F>,
    input_wires: Vec<WireV1>,
    gates: Vec<CircuitGateV1>,
}
impl CircuitBuilderV1 {
    fn new() -> Self {
        Self {
            // Stable constant-zero and constant-one wire addresses.
            wires: vec![F::ZERO, F::ONE],
            input_wires: Vec::new(),
            gates: Vec::new(),
        }
    }
    const fn zero(&self) -> WireV1 {
        0
    }
    const fn one(&self) -> WireV1 {
        1
    }
    fn value(&self, wire: WireV1) -> bool {
        self.wires[wire] == F::ONE
    }
    fn push_wire(&mut self, value: bool) -> WireV1 {
        let wire = self.wires.len();
        self.wires.push(F(u64::from(value)));
        wire
    }
    fn input_bit(&mut self, value: bool) -> WireV1 {
        let wire = self.push_wire(value);
        self.input_wires.push(wire);
        wire
    }
    fn constant_word(&self, value: u32) -> WordV1 {
        core::array::from_fn(|bit| {
            if value & (1_u32 << bit) == 0 {
                self.zero()
            } else {
                self.one()
            }
        })
    }
    fn input_word(&mut self, value: u32) -> WordV1 {
        core::array::from_fn(|bit| self.input_bit(value & (1_u32 << bit) != 0))
    }
    fn and(&mut self, left: WireV1, right: WireV1) -> WireV1 {
        let row = BooleanGateAirRowV1::and(self.value(left), self.value(right));
        let out = self.push_wire(row.out == F::ONE);
        self.gates.push(CircuitGateV1 {
            kind: GateKindV1::And,
            left,
            right,
            carry_in: self.zero(),
            out,
            carry_out: self.zero(),
            row,
        });
        out
    }
    fn xor(&mut self, left: WireV1, right: WireV1) -> WireV1 {
        let row = BooleanGateAirRowV1::xor(self.value(left), self.value(right));
        let out = self.push_wire(row.out == F::ONE);
        self.gates.push(CircuitGateV1 {
            kind: GateKindV1::Xor,
            left,
            right,
            carry_in: self.zero(),
            out,
            carry_out: self.zero(),
            row,
        });
        out
    }
    fn full_adder(&mut self, left: WireV1, right: WireV1, carry_in: WireV1) -> (WireV1, WireV1) {
        let row = BooleanGateAirRowV1::full_adder(
            self.value(left),
            self.value(right),
            self.value(carry_in),
        );
        let out = self.push_wire(row.out == F::ONE);
        let carry_out = self.push_wire(row.carry_out == F::ONE);
        self.gates.push(CircuitGateV1 {
            kind: GateKindV1::FullAdder,
            left,
            right,
            carry_in,
            out,
            carry_out,
            row,
        });
        (out, carry_out)
    }
    fn xor_words(&mut self, left: WordV1, right: WordV1) -> WordV1 {
        core::array::from_fn(|bit| self.xor(left[bit], right[bit]))
    }
    fn xor_three_words(&mut self, first: WordV1, second: WordV1, third: WordV1) -> WordV1 {
        let partial = self.xor_words(first, second);
        self.xor_words(partial, third)
    }
    fn add_words(&mut self, left: WordV1, right: WordV1) -> WordV1 {
        let mut carry = self.zero();
        core::array::from_fn(|bit| {
            let (sum, next_carry) = self.full_adder(left[bit], right[bit], carry);
            carry = next_carry;
            sum
        })
    }
    fn add_many_words(&mut self, words: &[WordV1]) -> WordV1 {
        words
            .iter()
            .copied()
            .fold(self.constant_word(0), |sum, word| self.add_words(sum, word))
    }
    fn not_word(&mut self, word: WordV1) -> WordV1 {
        core::array::from_fn(|bit| self.xor(word[bit], self.one()))
    }
    fn choose(&mut self, x: WordV1, y: WordV1, z: WordV1) -> WordV1 {
        let not_x = self.not_word(x);
        core::array::from_fn(|bit| {
            let left = self.and(x[bit], y[bit]);
            let right = self.and(not_x[bit], z[bit]);
            self.xor(left, right)
        })
    }
    fn majority(&mut self, x: WordV1, y: WordV1, z: WordV1) -> WordV1 {
        core::array::from_fn(|bit| {
            let xy = self.and(x[bit], y[bit]);
            let xz = self.and(x[bit], z[bit]);
            let yz = self.and(y[bit], z[bit]);
            let partial = self.xor(xy, xz);
            self.xor(partial, yz)
        })
    }
}
/// Compile and witness the complete padded SHA-256 circuit.
pub fn build_sha256_circuit_v1(
    message: &[u8],
) -> Result<ZkX509Sha256CircuitV1, ZkX509Sha256AirErrorV1> {
    let circuit = build_sha256_circuit_unchecked_v1(message)?;
    circuit.validate()?;
    Ok(circuit)
}
/// Exact local Boolean-gate rows required for a message length.
pub fn sha256_gate_rows_for_message_len_v1(
    message_len: usize,
) -> Result<usize, ZkX509Sha256AirErrorV1> {
    let (_, padded_len) = sha256_padding_shape_v1(message_len)?;
    padded_len
        .checked_div(64)
        .and_then(|blocks| blocks.checked_mul(SHA256_GATE_ROWS_PER_BLOCK_V1))
        .ok_or(ZkX509Sha256AirErrorV1::InputTooLarge)
}
fn build_sha256_circuit_unchecked_v1(
    message: &[u8],
) -> Result<ZkX509Sha256CircuitV1, ZkX509Sha256AirErrorV1> {
    let padded = sha256_padding_v1(message)?;
    let mut builder = CircuitBuilderV1::new();
    let mut state = SHA256_INITIAL_STATE_V1.map(|word| builder.constant_word(word));
    let input_words: Vec<_> = padded
        .chunks_exact(4)
        .map(|bytes| {
            builder.input_word(u32::from_be_bytes(
                bytes
                    .try_into()
                    .expect("SHA-256 word chunk is exactly four bytes"),
            ))
        })
        .collect();
    for block in input_words.chunks_exact(16) {
        let mut schedule = Vec::with_capacity(64);
        schedule.extend_from_slice(block);
        for index in 16..64 {
            let sigma_zero = builder.xor_three_words(
                rotate_right_v1(schedule[index - 15], 7),
                rotate_right_v1(schedule[index - 15], 18),
                shift_right_v1(schedule[index - 15], 3, builder.zero()),
            );
            let sigma_one = builder.xor_three_words(
                rotate_right_v1(schedule[index - 2], 17),
                rotate_right_v1(schedule[index - 2], 19),
                shift_right_v1(schedule[index - 2], 10, builder.zero()),
            );
            schedule.push(builder.add_many_words(&[
                schedule[index - 16],
                sigma_zero,
                schedule[index - 7],
                sigma_one,
            ]));
        }
        let mut work = state;
        for round in 0..64 {
            let big_sigma_one = builder.xor_three_words(
                rotate_right_v1(work[4], 6),
                rotate_right_v1(work[4], 11),
                rotate_right_v1(work[4], 25),
            );
            let choose = builder.choose(work[4], work[5], work[6]);
            let round_constant = builder.constant_word(SHA256_ROUND_CONSTANTS_V1[round]);
            let t1 = builder.add_many_words(&[
                work[7],
                big_sigma_one,
                choose,
                round_constant,
                schedule[round],
            ]);
            let big_sigma_zero = builder.xor_three_words(
                rotate_right_v1(work[0], 2),
                rotate_right_v1(work[0], 13),
                rotate_right_v1(work[0], 22),
            );
            let majority = builder.majority(work[0], work[1], work[2]);
            let t2 = builder.add_words(big_sigma_zero, majority);
            work = [
                builder.add_words(t1, t2),
                work[0],
                work[1],
                work[2],
                builder.add_words(work[3], t1),
                work[4],
                work[5],
                work[6],
            ];
        }
        state = core::array::from_fn(|index| builder.add_words(state[index], work[index]));
    }
    let digest = digest_from_words_v1(&builder.wires, &state)?;
    let circuit = ZkX509Sha256CircuitV1 {
        wires: builder.wires,
        input_wires: builder.input_wires,
        gates: builder.gates,
        output_words: state,
        message_len: message.len(),
        digest,
    };
    Ok(circuit)
}
fn rotate_right_v1(word: WordV1, distance: usize) -> WordV1 {
    core::array::from_fn(|bit| word[(bit + distance) % 32])
}
fn shift_right_v1(word: WordV1, distance: usize, zero: WireV1) -> WordV1 {
    core::array::from_fn(|bit| word.get(bit + distance).copied().unwrap_or(zero))
}
fn sha256_padding_v1(message: &[u8]) -> Result<Vec<u8>, ZkX509Sha256AirErrorV1> {
    let (bit_length, capacity) = sha256_padding_shape_v1(message.len())?;
    let with_marker = message
        .len()
        .checked_add(1)
        .ok_or(ZkX509Sha256AirErrorV1::InputTooLarge)?;
    let zero_padding = capacity
        .checked_sub(with_marker)
        .and_then(|remaining| remaining.checked_sub(8))
        .ok_or(ZkX509Sha256AirErrorV1::InputTooLarge)?;
    let mut padded = Vec::new();
    padded
        .try_reserve_exact(capacity)
        .map_err(|_| ZkX509Sha256AirErrorV1::InputTooLarge)?;
    padded.extend_from_slice(message);
    padded.push(0x80);
    padded.resize(with_marker + zero_padding, 0);
    padded.extend_from_slice(&bit_length.to_be_bytes());
    Ok(padded)
}
fn sha256_padding_shape_v1(message_len: usize) -> Result<(u64, usize), ZkX509Sha256AirErrorV1> {
    let bit_length = u64::try_from(message_len)
        .ok()
        .and_then(|length| length.checked_mul(8))
        .ok_or(ZkX509Sha256AirErrorV1::InputTooLarge)?;
    let with_marker = message_len
        .checked_add(1)
        .ok_or(ZkX509Sha256AirErrorV1::InputTooLarge)?;
    let remainder = with_marker % 64;
    let zero_padding = if remainder <= 56 {
        56 - remainder
    } else {
        64 + 56 - remainder
    };
    let capacity = with_marker
        .checked_add(zero_padding)
        .and_then(|length| length.checked_add(8))
        .ok_or(ZkX509Sha256AirErrorV1::InputTooLarge)?;
    Ok((bit_length, capacity))
}
fn digest_from_words_v1(
    wires: &[F],
    words: &[WordV1; 8],
) -> Result<[u8; 32], ZkX509Sha256AirErrorV1> {
    let mut digest = [0_u8; 32];
    for (index, word) in words.iter().enumerate() {
        let mut value = 0_u32;
        for (bit, wire) in word.iter().copied().enumerate() {
            match wires.get(wire).copied() {
                Some(F::ZERO) => {}
                Some(F::ONE) => value |= 1_u32 << bit,
                _ => return Err(ZkX509Sha256AirErrorV1::WireBinding),
            }
        }
        digest[index * 4..(index + 1) * 4].copy_from_slice(&value.to_be_bytes());
    }
    Ok(digest)
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::privacy_engines::zk_x509::{
        profile::ZK_X509_MAX_CRL_BYTES_V1,
        sha256_word_air::{
            SHA256_WORD_FIXED_BATCH_SEGMENT_COUNT_V1, SHA256_WORD_FIXED_BATCH_SEGMENT_ROWS_V1,
        },
    };
    use sha2::{Digest as _, Sha256};
    #[test]
    fn complete_sha256_gate_schedule_matches_independent_implementation() {
        for message in [
            Vec::new(),
            b"a".to_vec(),
            b"abc".to_vec(),
            vec![0x11; 55],
            vec![0x22; 56],
            vec![0x33; 63],
            vec![0x44; 64],
            vec![0x55; 65],
        ] {
            let circuit = build_sha256_circuit_v1(&message).expect("SHA-256 circuit");
            assert_eq!(circuit.digest(), <[u8; 32]>::from(Sha256::digest(&message)));
            assert_eq!(
                circuit.input_wires(),
                message.len().saturating_add(9).div_ceil(64) * 512
            );
            assert_eq!(circuit.message_len(), message.len());
            assert_eq!(
                circuit.gate_rows(),
                sha256_gate_rows_for_message_len_v1(message.len()).expect("row count")
            );
            circuit.validate().expect("complete valid circuit");
        }
    }
    #[test]
    fn local_boolean_schedule_cannot_be_confused_with_release_resource_readiness() {
        let crl_rows =
            sha256_gate_rows_for_message_len_v1(ZK_X509_MAX_CRL_BYTES_V1).expect("bounded CRL");
        assert_eq!(crl_rows, 3_610_880);
        let compiled_sha_capacity = u64::try_from(
            SHA256_WORD_FIXED_BATCH_SEGMENT_ROWS_V1
                .checked_mul(SHA256_WORD_FIXED_BATCH_SEGMENT_COUNT_V1)
                .expect("fixed batch row capacity"),
        )
        .expect("fixed batch capacity fits u64");
        assert_eq!(compiled_sha_capacity, 2_621_440);
        assert!(u64::try_from(crl_rows).expect("row count fits u64") > compiled_sha_capacity);
    }
    #[test]
    fn gate_and_wire_mutations_fail_closed() {
        let circuit = build_sha256_circuit_v1(b"adversarial").expect("SHA-256 circuit");
        let mut changed = circuit.clone();
        changed.gates[137].row.out = changed.gates[137].row.out.add(F::ONE);
        assert!(matches!(
            changed.validate(),
            Err(ZkX509Sha256AirErrorV1::Gate | ZkX509Sha256AirErrorV1::WireBinding)
        ));
        let mut changed = circuit.clone();
        let output = changed.gates[219].out;
        changed.wires[output] = changed.wires[output].add(F::ONE);
        assert_eq!(changed.validate(), Err(ZkX509Sha256AirErrorV1::WireBinding));
        let mut changed = circuit.clone();
        changed.input_wires.swap(0, 1);
        assert_eq!(
            changed.validate(),
            Err(ZkX509Sha256AirErrorV1::CircuitShape)
        );
        let mut changed = circuit.clone();
        changed.gates[219].out = changed.gates[218].out;
        assert_eq!(
            changed.validate(),
            Err(ZkX509Sha256AirErrorV1::CircuitShape)
        );
        let mut changed = circuit.clone();
        changed.output_words[0] = [0; 32];
        changed.digest[..4].fill(0);
        assert_eq!(
            changed.validate(),
            Err(ZkX509Sha256AirErrorV1::CircuitShape)
        );
        let mut changed = circuit.clone();
        changed.message_len = changed.message_len.saturating_add(1);
        assert_eq!(changed.validate(), Err(ZkX509Sha256AirErrorV1::Padding));
        let mut changed = circuit.clone();
        let marker_word = changed.input_wires[64..96].to_vec();
        let marker_high_bit = marker_word[7];
        changed.wires[marker_high_bit] = F::ZERO;
        assert_eq!(changed.validate(), Err(ZkX509Sha256AirErrorV1::Padding));
        let mut changed = circuit;
        changed.digest[0] ^= 1;
        assert_eq!(
            changed.validate(),
            Err(ZkX509Sha256AirErrorV1::OutputDigest)
        );
    }
}
