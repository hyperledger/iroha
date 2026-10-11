//! Constrained, unkeyed BLAKE2b-256 (RFC 7693) over assigned bytes.
//!
//! This deliberately simple bit circuit uses four-bit XOR and addition rows.
//! Rotations permute constrained bit cells; every subsequent use copies those
//! cells. Addition constrains each nibble and its boolean carry, including the
//! discarded final carry, so reduction modulo `2^64` cannot hide field wrap.
//! The complete-message wrappers fix parameter words, counters, final flags
//! and padding structurally. The streaming primitive instead constrains its
//! assigned counters and final bit, for callers proving a block schedule.
//! No native digest or host verification result is accepted.
//!
//! Message length is part of the circuit shape, not a witness. Callers must
//! bind the supplied byte cells to their application's authenticated encoding;
//! hashing a free message does not authenticate that message. This primitive
//! does not prove consensus, signatures, inclusion or finality by itself.
//!
//! A compression occupies 15,664 rows and 206,400 advice cells. Byte input and
//! output each cost one row and nine cells; a chip also assigns two constant
//! bits once. There are fourteen equality-enabled advice columns, three
//! selectors plus a streaming word-codec selector, no lookups, and maximum
//! gate degree three. This layout favors
//! auditability over prover cost; long messages need a large evaluation domain.

use iroha_pasta::PastaField;
use iroha_plonk::{
    cs::{Advice, Column, ConstraintSystem, Expression, Fixed, Rotation, Selector},
    frontend::{Error, Region, Value},
};

use crate::cells::{Bit, RowCursor, U64, Word, assign_constant, assign_word, copy_word, low_word};

/// Number of exclusively owned advice columns.
pub const BLAKE2B_ADVICE_COLUMNS: usize = 14;
/// Rows occupied by one 128-byte compression, excluding byte codecs.
pub const BLAKE2B_COMPRESSION_ROWS: usize = 15_664;
/// Assigned advice cells in one compression, excluding byte codecs.
pub const BLAKE2B_COMPRESSION_CELLS: usize = 206_400;

const IV: [u64; 8] = [
    0x6a09_e667_f3bc_c908,
    0xbb67_ae85_84ca_a73b,
    0x3c6e_f372_fe94_f82b,
    0xa54f_f53a_5f1d_36f1,
    0x510e_527f_ade6_82d1,
    0x9b05_688c_2b3e_6c1f,
    0x1f83_d9ab_fb41_bd6b,
    0x5be0_cd19_137e_2179,
];

const SIGMA: [[usize; 16]; 10] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
];

/// Columns and gates of the BLAKE2b-256 chip.
#[derive(Clone, Copy, Debug)]
pub struct Blake2bConfig {
    advice: [Column<Advice>; BLAKE2B_ADVICE_COLUMNS],
    byte: Selector,
    xor: Selector,
    add: Selector,
    pack: Selector,
}

impl Blake2bConfig {
    /// Configure four-bit XOR/addition and an eight-bit byte codec.
    ///
    /// Advice columns belong exclusively to this chip. `constants` can be
    /// shared with other chips using the floor planner's constant allocator.
    pub fn configure<F: PastaField>(
        meta: &mut ConstraintSystem<F>,
        advice: [Column<Advice>; BLAKE2B_ADVICE_COLUMNS],
        constants: Column<Fixed>,
    ) -> Self {
        for column in advice {
            meta.enable_equality(column);
        }
        meta.enable_constant(constants);
        let byte = meta.selector();
        let xor = meta.selector();
        let add = meta.selector();
        let pack = meta.selector();
        meta.create_gate("blake2b u64 byte packing", |cells| {
            let q = cells.query_selector(pack);
            let word = cells.query_advice(advice[0], Rotation::cur());
            let packed = (0..8).fold(Expression::Constant(F::ZERO), |sum, i| {
                sum + cells.query_advice(advice[i + 1], Rotation::cur())
                    * Expression::Constant(F::from(1_u64 << (8 * i)))
            });
            // All eight bytes are separately range-checked by the byte gate.
            vec![("u64 packing", q * (word - packed))]
        });
        meta.create_gate("blake2b byte", |cells| {
            let q = cells.query_selector(byte);
            let value = cells.query_advice(advice[0], Rotation::cur());
            let bits: [_; 8] =
                core::array::from_fn(|i| cells.query_advice(advice[i + 1], Rotation::cur()));
            let one = Expression::Constant(F::ONE);
            let mut constraints = bits
                .iter()
                .map(|bit| {
                    (
                        "boolean byte bit",
                        q.clone() * bit.clone() * (bit.clone() - one.clone()),
                    )
                })
                .collect::<Vec<_>>();
            let packed = bits
                .into_iter()
                .enumerate()
                .fold(Expression::Constant(F::ZERO), |sum, (i, bit)| {
                    sum + bit * Expression::Constant(F::from(1_u64 << i))
                });
            constraints.push(("byte decomposition", q * (value - packed)));
            constraints
        });
        meta.create_gate("blake2b xor", |cells| {
            let q = cells.query_selector(xor);
            (0..4)
                .map(|i| {
                    let a = cells.query_advice(advice[i], Rotation::cur());
                    let b = cells.query_advice(advice[i + 4], Rotation::cur());
                    let out = cells.query_advice(advice[i + 8], Rotation::cur());
                    // a and b are copied from Bit cells. Their booleanity
                    // makes this equation also prove out is boolean.
                    (
                        "xor bit",
                        q.clone()
                            * (out - a.clone() - b.clone()
                                + a * b * Expression::Constant(F::from(2))),
                    )
                })
                .collect::<Vec<_>>()
        });
        meta.create_gate("blake2b add nibble", |cells| {
            let q = cells.query_selector(add);
            let a: [_; 4] =
                core::array::from_fn(|i| cells.query_advice(advice[i], Rotation::cur()));
            let b: [_; 4] =
                core::array::from_fn(|i| cells.query_advice(advice[i + 4], Rotation::cur()));
            let out: [_; 4] =
                core::array::from_fn(|i| cells.query_advice(advice[i + 8], Rotation::cur()));
            let carry_in = cells.query_advice(advice[12], Rotation::cur());
            let carry_out = cells.query_advice(advice[13], Rotation::cur());
            let one = Expression::Constant(F::ONE);
            let mut constraints = out
                .iter()
                .chain(core::iter::once(&carry_out))
                .map(|bit| {
                    (
                        "boolean sum or carry",
                        q.clone() * bit.clone() * (bit.clone() - one.clone()),
                    )
                })
                .collect::<Vec<_>>();
            let mut sum = carry_in - carry_out * Expression::Constant(F::from(16));
            for i in 0..4 {
                sum = sum
                    + (a[i].clone() + b[i].clone() - out[i].clone())
                        * Expression::Constant(F::from(1_u64 << i));
            }
            constraints.push(("integer nibble addition", q * sum));
            constraints
        });
        Self {
            advice,
            byte,
            xor,
            add,
            pack,
        }
    }
}

/// Thirty-two constrained digest bytes in the native `BLAKE2b` output order.
#[derive(Clone, Debug)]
pub struct Blake2bDigest<F: PastaField> {
    bytes: [Word<F>; 32],
}

impl<F: PastaField> Blake2bDigest<F> {
    /// Range-checked bytes, ready for another hash or an instance binding.
    #[must_use]
    pub const fn bytes(&self) -> &[Word<F>; 32] {
        &self.bytes
    }
}

/// A word's little-endian bits. Only constrained bits may enter this type.
#[derive(Clone, Debug)]
struct Bits64<F: PastaField>([Bit<F>; 64]);

/// Eight constrained `BLAKE2b` chaining words, suitable for recursive linkage.
///
/// A state imported from witness words is only range-checked. The surrounding
/// relation must authenticate the previous state or equate it to the initial
/// state; an arbitrary chaining state is not an authenticated hash prefix.
#[derive(Clone, Debug)]
pub struct Blake2bState<F: PastaField>([Bits64<F>; 8]);

impl<F: PastaField> Bits64<F> {
    fn rotate_right(&self, amount: usize) -> Self {
        Self(core::array::from_fn(|i| self.0[(i + amount) % 64].clone()))
    }
}

/// BLAKE2b-256 on fixed-public-length messages of assigned bytes.
#[derive(Debug)]
pub struct Blake2bChip<'a, F: PastaField> {
    config: &'a Blake2bConfig,
    rows: RowCursor,
    constants: Option<[Bit<F>; 2]>,
}

impl<'a, F: PastaField> Blake2bChip<'a, F> {
    /// Start a chip on its exclusively owned columns at row zero.
    #[must_use]
    pub fn new(config: &'a Blake2bConfig) -> Self {
        Self::with_rows(config, RowCursor::default())
    }

    /// Start within an explicitly reserved row interval.
    #[must_use]
    pub const fn with_rows(config: &'a Blake2bConfig, rows: RowCursor) -> Self {
        Self {
            config,
            rows,
            constants: None,
        }
    }

    /// First unassigned absolute row in the chip's columns.
    #[must_use]
    pub const fn next_row(&self) -> usize {
        self.rows.next_row()
    }

    /// Hash unkeyed bytes to the raw 32-byte RFC 7693 digest.
    ///
    /// `input.len()` is part of the verification-key shape. Every input cell
    /// is constrained to a byte. Empty messages use one final zero block;
    /// exact multiples of 128 bytes have no extra block.
    ///
    /// # Errors
    /// Layout/bounds errors. A non-byte input yields an unsatisfied circuit.
    pub fn hash(
        &mut self,
        region: &mut Region<'_, F>,
        input: &[Word<F>],
    ) -> Result<Blake2bDigest<F>, Error> {
        self.hash_inner(region, input, false)
    }

    /// Hash as `iroha_crypto::Hash::new`: raw BLAKE2b-256 with byte 31's
    /// least-significant bit forced to one. The other 255 bits stay linked.
    ///
    /// # Errors
    /// The same layout/bounds errors as [`Self::hash`].
    pub fn hash_marked(
        &mut self,
        region: &mut Region<'_, F>,
        input: &[Word<F>],
    ) -> Result<Blake2bDigest<F>, Error> {
        self.hash_inner(region, input, true)
    }

    /// The fixed unkeyed BLAKE2b-256 IV, including its parameter block.
    ///
    /// # Errors
    /// Constant assignment or row-bound failure.
    pub fn initial_state(&mut self, region: &mut Region<'_, F>) -> Result<Blake2bState<F>, Error> {
        let bits = self.constants(region)?;
        // digest_length=32, key_length=0, fanout=1, depth=1; all other
        // parameter-block words are zero (sequential, unkeyed hashing).
        Ok(Blake2bState(core::array::from_fn(|i| {
            Self::constant_word(&bits, IV[i] ^ if i == 0 { 0x0101_0020 } else { 0 })
        })))
    }

    /// Import eight assigned words, constraining each to an unsigned 64-bit
    /// integer and linking every internal bit to that word.
    ///
    /// This does not authenticate the state: recursive callers must bind the
    /// supplied words to the preceding step's exports. Costs 72 rows/648 cells.
    ///
    /// # Errors
    /// Layout/bounds failure. Out-of-range inputs make the circuit unsatisfied.
    pub fn state_from_words(
        &mut self,
        region: &mut Region<'_, F>,
        words: &[Word<F>; 8],
    ) -> Result<Blake2bState<F>, Error> {
        let words = words
            .iter()
            .map(|word| self.input_word(region, word))
            .collect::<Result<Vec<_>, _>>()?
            .try_into()
            .map_err(|_| Error::Synthesis)?;
        Ok(Blake2bState(words))
    }

    /// Export all eight chaining words as constrained `u64` cells.
    ///
    /// Use all eight words to bind a continuation; the 32-byte digest alone
    /// loses half of the chaining state. Costs 72 rows/648 cells.
    ///
    /// # Errors
    /// Layout/bounds failure.
    pub fn state_words(
        &mut self,
        region: &mut Region<'_, F>,
        state: &Blake2bState<F>,
    ) -> Result<[U64<F>; 8], Error> {
        state
            .0
            .iter()
            .map(|word| self.output_word(region, word))
            .collect::<Result<Vec<_>, _>>()?
            .try_into()
            .map_err(|_| Error::Synthesis)
    }

    /// Compress one fixed 128-byte block with assigned low/high `u64` byte
    /// counter words and an assigned final-block bit.
    ///
    /// Each counter word and block byte is range-checked and linked to its
    /// input cell. The final bit is copied into every bit of the final mask.
    /// The relation using this primitive must enforce the initial state,
    /// running byte count, zero padding, and exactly one final block at the
    /// end of its stream. This API alone imposes no schedule or length claim.
    /// A block costs 15,810 rows/207,714 cells, excluding initial constant bits.
    ///
    /// # Errors
    /// Layout/bounds failure. Invalid byte/u64 inputs are unsatisfied.
    pub fn compress_block(
        &mut self,
        region: &mut Region<'_, F>,
        state: &Blake2bState<F>,
        block: &[Word<F>; 128],
        counter: &[Word<F>; 2],
        last: &Bit<F>,
    ) -> Result<Blake2bState<F>, Error> {
        let bits = self.constants(region)?;
        let bytes = block
            .iter()
            .map(|word| self.input_byte(region, word))
            .collect::<Result<Vec<_>, _>>()?;
        let message = core::array::from_fn(|word| {
            Bits64(core::array::from_fn(|bit| {
                bytes[word * 8 + bit / 8][bit % 8].clone()
            }))
        });
        let low = self.input_word(region, &counter[0])?;
        let high = self.input_word(region, &counter[1])?;
        let words = self.compress(region, &state.0, &message, [&low, &high], last, &bits)?;
        Ok(Blake2bState(words))
    }

    /// Encode the first four chaining words as the raw digest bytes.
    ///
    /// This codec does not prove the state is final; its producer's relation
    /// must establish that fact. Costs 32 rows/288 cells.
    ///
    /// # Errors
    /// Layout/bounds failure.
    pub fn digest(
        &mut self,
        region: &mut Region<'_, F>,
        state: &Blake2bState<F>,
    ) -> Result<Blake2bDigest<F>, Error> {
        self.encode_digest(region, state, false)
    }

    /// Encode a final state with Iroha's byte-31 marker bit forced to one.
    ///
    /// As with [`Self::digest`], the surrounding relation must prove finality
    /// of the hash stream (separate from consensus finality).
    ///
    /// # Errors
    /// Layout/bounds failure.
    pub fn digest_marked(
        &mut self,
        region: &mut Region<'_, F>,
        state: &Blake2bState<F>,
    ) -> Result<Blake2bDigest<F>, Error> {
        self.encode_digest(region, state, true)
    }

    fn input_word(
        &mut self,
        region: &mut Region<'_, F>,
        word: &Word<F>,
    ) -> Result<Bits64<F>, Error> {
        let row = self.rows.take(1)?;
        self.config.pack.enable(region, row)?;
        copy_word(region, word, self.config.advice[0], row)?;
        let integer = word.value().map(|word| word.to_canonical_limbs()[0]);
        let bytes = (0..8)
            .map(|i| {
                let byte = assign_word(
                    region,
                    self.config.advice[i + 1],
                    row,
                    integer.map(|word| F::from((word >> (8 * i)) & 255)),
                )?;
                self.input_byte(region, &byte)
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Bits64(core::array::from_fn(|i| {
            bytes[i / 8][i % 8].clone()
        })))
    }

    fn output_word(
        &mut self,
        region: &mut Region<'_, F>,
        word: &Bits64<F>,
    ) -> Result<U64<F>, Error> {
        let bytes = (0..8)
            .map(|i| {
                self.output_byte(
                    region,
                    &core::array::from_fn(|bit| word.0[i * 8 + bit].clone()),
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        let row = self.rows.take(1)?;
        self.config.pack.enable(region, row)?;
        let mut value = Value::known(F::ZERO);
        for (i, byte) in bytes.iter().enumerate() {
            copy_word(region, byte, self.config.advice[i + 1], row)?;
            value = value
                .zip(byte.value())
                .map(|(sum, byte)| sum + byte * F::from(1_u64 << (8 * i)));
        }
        Ok(U64::new(assign_word(
            region,
            self.config.advice[0],
            row,
            value,
        )?))
    }

    fn constants(&mut self, region: &mut Region<'_, F>) -> Result<[Bit<F>; 2], Error> {
        if let Some(bits) = &self.constants {
            return Ok(bits.clone());
        }
        let row = self.rows.take(2)?;
        let zero = Bit::new(assign_constant(
            region,
            self.config.advice[0],
            row,
            F::ZERO,
        )?);
        let one = Bit::new(assign_constant(
            region,
            self.config.advice[0],
            row + 1,
            F::ONE,
        )?);
        let bits = [zero, one];
        self.constants = Some(bits.clone());
        Ok(bits)
    }

    fn constant_word(bits: &[Bit<F>; 2], value: u64) -> Bits64<F> {
        Bits64(core::array::from_fn(|i| {
            bits[((value >> i) & 1) as usize].clone()
        }))
    }

    fn input_byte(
        &mut self,
        region: &mut Region<'_, F>,
        word: &Word<F>,
    ) -> Result<[Bit<F>; 8], Error> {
        let row = self.rows.take(1)?;
        self.config.byte.enable(region, row)?;
        copy_word(region, word, self.config.advice[0], row)?;
        let value = word.value().map(|value| value.to_canonical_limbs()[0]);
        (0..8)
            .map(|i| {
                assign_word(
                    region,
                    self.config.advice[i + 1],
                    row,
                    value.map(|value| F::from((value >> i) & 1)),
                )
                .map(Bit::new)
            })
            .collect::<Result<Vec<_>, _>>()?
            .try_into()
            .map_err(|_| Error::Synthesis)
    }

    fn output_byte(
        &mut self,
        region: &mut Region<'_, F>,
        bits: &[Bit<F>; 8],
    ) -> Result<Word<F>, Error> {
        let row = self.rows.take(1)?;
        self.config.byte.enable(region, row)?;
        let mut value = Value::known(F::ZERO);
        for (i, bit) in bits.iter().enumerate() {
            copy_word(region, bit.word(), self.config.advice[i + 1], row)?;
            value = value
                .zip(bit.word().value())
                .map(|(sum, bit)| sum + bit * F::from(1_u64 << i));
        }
        assign_word(region, self.config.advice[0], row, value)
    }

    fn xor_nibble(
        &mut self,
        region: &mut Region<'_, F>,
        a: &[Bit<F>],
        b: &[Bit<F>],
    ) -> Result<[Bit<F>; 4], Error> {
        let row = self.rows.take(1)?;
        self.config.xor.enable(region, row)?;
        (0..4)
            .map(|i| {
                copy_word(region, a[i].word(), self.config.advice[i], row)?;
                copy_word(region, b[i].word(), self.config.advice[i + 4], row)?;
                let value = a[i]
                    .word()
                    .value()
                    .zip(b[i].word().value())
                    .map(|(a, b)| a + b - F::from(2) * a * b);
                assign_word(region, self.config.advice[i + 8], row, value).map(Bit::new)
            })
            .collect::<Result<Vec<_>, _>>()?
            .try_into()
            .map_err(|_| Error::Synthesis)
    }

    fn xor(
        &mut self,
        region: &mut Region<'_, F>,
        a: &Bits64<F>,
        b: &Bits64<F>,
    ) -> Result<Bits64<F>, Error> {
        let mut output = Vec::with_capacity(64);
        for start in (0..64).step_by(4) {
            output.extend(self.xor_nibble(
                region,
                &a.0[start..start + 4],
                &b.0[start..start + 4],
            )?);
        }
        Ok(Bits64(output.try_into().map_err(|_| Error::Synthesis)?))
    }

    fn add_nibble(
        &mut self,
        region: &mut Region<'_, F>,
        a: &[Bit<F>],
        b: &[Bit<F>],
        carry: &Bit<F>,
    ) -> Result<([Bit<F>; 4], Bit<F>), Error> {
        let row = self.rows.take(1)?;
        self.config.add.enable(region, row)?;
        copy_word(region, carry.word(), self.config.advice[12], row)?;
        let mut sum = carry.word().value();
        for i in 0..4 {
            copy_word(region, a[i].word(), self.config.advice[i], row)?;
            copy_word(region, b[i].word(), self.config.advice[i + 4], row)?;
            sum = sum
                .zip(a[i].word().value())
                .zip(b[i].word().value())
                .map(|((sum, a), b)| sum + (a + b) * F::from(1_u64 << i));
        }
        let integer = sum.map(|value| value.to_canonical_limbs()[0]);
        let bits = (0..4)
            .map(|i| {
                assign_word(
                    region,
                    self.config.advice[i + 8],
                    row,
                    integer.map(|sum| F::from((sum >> i) & 1)),
                )
                .map(Bit::new)
            })
            .collect::<Result<Vec<_>, _>>()?
            .try_into()
            .map_err(|_| Error::Synthesis)?;
        let carry = Bit::new(assign_word(
            region,
            self.config.advice[13],
            row,
            integer.map(|sum| F::from(sum >> 4)),
        )?);
        Ok((bits, carry))
    }

    fn add(
        &mut self,
        region: &mut Region<'_, F>,
        a: &Bits64<F>,
        b: &Bits64<F>,
        zero: &Bit<F>,
    ) -> Result<Bits64<F>, Error> {
        let mut carry = zero.clone();
        let mut output = Vec::with_capacity(64);
        for start in (0..64).step_by(4) {
            let (bits, next) = self.add_nibble(
                region,
                &a.0[start..start + 4],
                &b.0[start..start + 4],
                &carry,
            )?;
            output.extend(bits);
            carry = next;
        }
        Ok(Bits64(output.try_into().map_err(|_| Error::Synthesis)?))
    }

    fn mix(
        &mut self,
        region: &mut Region<'_, F>,
        state: &mut [Bits64<F>; 16],
        indices: [usize; 4],
        message: [&Bits64<F>; 2],
        zero: &Bit<F>,
    ) -> Result<(), Error> {
        let [a, b, c, d] = indices;
        for (message, rotations) in message.into_iter().zip([[32, 24], [16, 63]]) {
            let ab = self.add(region, &state[a], &state[b], zero)?;
            state[a] = self.add(region, &ab, message, zero)?;
            state[d] = self
                .xor(region, &state[d], &state[a])?
                .rotate_right(rotations[0]);
            state[c] = self.add(region, &state[c], &state[d], zero)?;
            state[b] = self
                .xor(region, &state[b], &state[c])?
                .rotate_right(rotations[1]);
        }
        Ok(())
    }

    fn compress(
        &mut self,
        region: &mut Region<'_, F>,
        h: &[Bits64<F>; 8],
        message: &[Bits64<F>; 16],
        counter: [&Bits64<F>; 2],
        last: &Bit<F>,
        bits: &[Bit<F>; 2],
    ) -> Result<[Bits64<F>; 8], Error> {
        let mut v: [_; 16] = core::array::from_fn(|i| {
            if i < 8 {
                h[i].clone()
            } else {
                Self::constant_word(bits, IV[i - 8])
            }
        });
        v[12] = self.xor(region, &v[12], counter[0])?;
        v[13] = self.xor(region, &v[13], counter[1])?;
        v[14] = self.xor(
            region,
            &v[14],
            &Bits64(core::array::from_fn(|_| last.clone())),
        )?;
        for round in 0..12 {
            let schedule = SIGMA[round % 10];
            for (i, indices) in [
                [0, 4, 8, 12],
                [1, 5, 9, 13],
                [2, 6, 10, 14],
                [3, 7, 11, 15],
                [0, 5, 10, 15],
                [1, 6, 11, 12],
                [2, 7, 8, 13],
                [3, 4, 9, 14],
            ]
            .into_iter()
            .enumerate()
            {
                self.mix(
                    region,
                    &mut v,
                    indices,
                    [&message[schedule[2 * i]], &message[schedule[2 * i + 1]]],
                    &bits[0],
                )?;
            }
        }
        (0..8)
            .map(|i| {
                let intermediate = self.xor(region, &h[i], &v[i])?;
                self.xor(region, &intermediate, &v[i + 8])
            })
            .collect::<Result<Vec<_>, _>>()?
            .try_into()
            .map_err(|_| Error::Synthesis)
    }

    fn hash_inner(
        &mut self,
        region: &mut Region<'_, F>,
        input: &[Word<F>],
        marked: bool,
    ) -> Result<Blake2bDigest<F>, Error> {
        let bits = self.constants(region)?;
        let mut state = self.initial_state(region)?;
        let input = input
            .iter()
            .map(|word| self.input_byte(region, word))
            .collect::<Result<Vec<_>, _>>()?;
        let blocks = input.len().div_ceil(128).max(1);
        for block in 0..blocks {
            let start = block.checked_mul(128).ok_or(Error::BoundsFailure)?;
            let bytes = &input[start..input.len().min(start.saturating_add(128))];
            let message = core::array::from_fn(|word| {
                Bits64(core::array::from_fn(|bit| {
                    let byte = word * 8 + bit / 8;
                    bytes
                        .get(byte)
                        .map_or_else(|| bits[0].clone(), |bits| bits[bit % 8].clone())
                }))
            });
            let counter = (start as u128) + (bytes.len() as u128);
            let low = Self::constant_word(&bits, low_word(counter));
            let high = Self::constant_word(&bits, (counter >> 64) as u64);
            state = Blake2bState(self.compress(
                region,
                &state.0,
                &message,
                [&low, &high],
                &bits[usize::from(block + 1 == blocks)],
                &bits,
            )?);
        }
        self.encode_digest(region, &state, marked)
    }

    fn encode_digest(
        &mut self,
        region: &mut Region<'_, F>,
        state: &Blake2bState<F>,
        marked: bool,
    ) -> Result<Blake2bDigest<F>, Error> {
        let bits = self.constants(region)?;
        let bytes = (0..32)
            .map(|byte| {
                let mut output =
                    core::array::from_fn(|bit| state.0[byte / 8].0[(byte % 8) * 8 + bit].clone());
                if marked && byte == 31 {
                    output[0] = bits[1].clone();
                }
                self.output_byte(region, &output)
            })
            .collect::<Result<Vec<_>, _>>()?
            .try_into()
            .map_err(|_| Error::Synthesis)?;
        Ok(Blake2bDigest { bytes })
    }
}

#[cfg(test)]
mod tests;
