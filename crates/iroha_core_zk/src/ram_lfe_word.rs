//! Compact constrained ARX words for the unavailable RAM-LFE relation.
//!
//! This internal prototype uses six advice columns and one 3,905-row finite
//! operation table. Additions constrain every radix-16 carry; rotations copy whole nibbles
//! and constrain the remaining bit split. No native hash callback supplies a
//! relation. Only the returned cells, never a host-computed word, bind consumers.
//!
//! Owned host word values clear on drop. Native assignment/prover buffers
//! and compiler-created temporaries are outside this owner's erasure claim.
//! TODO: Complete constrained CRC64, BLAKE3 and Blake2b framing, the BFV machine,
//! resource qualification and independent review before any proof admission.

use ff::Field;
use iroha_pasta::Fp as Scalar;
use iroha_plonk::{
    cs::{Advice, Column, ConstraintSystem, Expression, Fixed, Rotation, Selector, TableColumn},
    frontend::{Cell, Error, Layouter, Region, Value},
};
use zeroize::{Zeroize, Zeroizing};

const LOAD: u64 = 1;
const XOR: u64 = 2;
const ADD: u64 = 3;
const ROTATE: u64 = 4;
const TABLE_ROWS: usize = 1 + 16 + 256 + 3 * 16 + (2 + 4 + 8) * 16 * 16;

/// One lookup argument, current-row queries only, for every exact operation.
#[derive(Clone, Debug)]
struct WordConfig {
    advice: [Column<Advice>; 6],
    table: [TableColumn; 7],
    operation: Column<Fixed>,
    add: Selector,
    active: Selector,
}

impl WordConfig {
    fn configure(meta: &mut ConstraintSystem<Scalar>) -> Self {
        let advice = std::array::from_fn(|_| meta.advice_column());
        for &column in &advice {
            meta.enable_equality(column);
        }
        let constants = meta.fixed_column();
        meta.enable_constant(constants);
        let table = std::array::from_fn(|_| meta.lookup_table_column());
        let operation = meta.fixed_column();
        let add = meta.complex_selector();
        let active = meta.complex_selector();
        meta.lookup("exact integer ARX tuple", |meta| {
            // Both selectors are fixed by the circuit. Subtraction leaves
            // unused rows at the zero tuple without increasing lookup degree.
            let not_add = meta.query_selector(active) - meta.query_selector(add);
            std::iter::once((meta.query_fixed(operation, Rotation::cur()), table[0]))
                .chain(
                    advice
                        .iter()
                        .zip(&table[1..])
                        .enumerate()
                        .map(|(i, (&advice, &table))| {
                            let value = meta.query_advice(advice, Rotation::cur());
                            let value = if matches!(i, 0 | 1 | 2 | 4) {
                                not_add.clone() * value
                            } else {
                                meta.query_selector(active) * value
                            };
                            (value, table)
                        }),
                )
                .collect()
        });
        meta.create_gate("addition of already-proven integer word cells", |meta| {
            let values: Vec<_> = advice
                .iter()
                .map(|&column| meta.query_advice(column, Rotation::cur()))
                .collect();
            vec![
                meta.query_selector(add)
                    * (values[0].clone()
                        + values[1].clone()
                        + values[2].clone()
                        + values[4].clone()
                        - values[3].clone()
                        - Expression::Constant(Scalar::from(16)) * values[5].clone()),
            ]
        });
        Self {
            advice,
            table,
            operation,
            add,
            active,
        }
    }

    fn load_table(&self, layouter: &mut impl Layouter<Scalar>) -> Result<(), Error> {
        layouter.assign_table(
            || "complete integer ARX table",
            |mut table| {
                let mut row = 0;
                let mut put = |tuple: [u64; 7]| -> Result<(), Error> {
                    for (&column, value) in self.table.iter().zip(tuple) {
                        table.assign_cell(
                            || "ARX tuple",
                            column,
                            row,
                            || Value::known(Scalar::from(value)),
                        )?;
                    }
                    row += 1;
                    Ok(())
                };
                put([0; 7])?;
                for a in 0..16 {
                    put([LOAD, a, 0, 0, 0, 0, 0])?;
                }
                for a in 0..16 {
                    for b in 0..16 {
                        put([XOR, a, b, 0, a ^ b, 0, 0])?;
                    }
                }
                // Addition inputs carry provenance through copy constraints. Only
                // its new output nibble and outgoing carry require table membership.
                for output in 0..16 {
                    for carry in 0..3 {
                        put([ADD, 0, 0, 0, output, 0, carry])?;
                    }
                }
                for bits in 1..4 {
                    for a in 0..16 {
                        for b in 0..16 {
                            for next_low in 0..(1 << bits) {
                                let x = a ^ b;
                                let lo = x & ((1 << bits) - 1);
                                let hi = x >> bits;
                                put([
                                    ROTATE + bits - 1,
                                    a,
                                    b,
                                    lo,
                                    hi + (next_low << (4 - bits)),
                                    next_low,
                                    hi,
                                ])?;
                            }
                        }
                    }
                }
                assert_eq!(row, TABLE_ROWS);
                Ok(())
            },
        )
    }
}

/// One owned word and the exact cells proving its canonical nibbles.
/// The private fields prevent an unbound host value from becoming a word token.
struct Word<const N: usize> {
    cells: [Cell; N],
    value: Zeroizing<u64>,
}

impl<const N: usize> Word<N> {
    fn duplicate(&self) -> Self {
        Self {
            cells: self.cells,
            value: Zeroizing::new(*self.value),
        }
    }
}

impl<const N: usize> Drop for Word<N> {
    fn drop(&mut self) {
        self.value.zeroize();
        CLEARED_WORDS.with(|count| count.set(count.get() + usize::from(*self.value == 0)));
    }
}

thread_local! {
    // Counts actual zero observations inside Drop; retains no private values.
    static CLEARED_WORDS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Direct assignment mutation used only by this internal prototype's controls.
#[derive(Clone, Copy, Debug)]
struct Fault {
    row: usize,
    column: usize,
    value: Scalar,
}

/// One bounded region; its cursor measures the actual operation layout.
struct WordRegion<'a, 'r> {
    config: &'a WordConfig,
    region: &'a mut Region<'r, Scalar>,
    offset: usize,
    faults: &'a [Fault],
}

impl WordRegion<'_, '_> {
    /// Exact compression arithmetic only. The eventual framed hash owner must
    /// constrain block lengths, chunk/tree flags and counters to their roles.
    fn blake3_compress(
        &mut self,
        chaining: &[Word<8>; 8],
        message: &[Word<8>; 16],
        counter: &[Word<8>; 2],
        block_len: &Word<8>,
        flags: &Word<8>,
    ) -> Result<[Word<8>; 16], Error> {
        let mut state = Vec::with_capacity(16);
        state.extend(chaining.iter().map(Word::duplicate));
        for value in [0x6a09_e667, 0xbb67_ae85, 0x3c6e_f372, 0xa54f_f53a] {
            state.push(self.load::<8>(value, true)?);
        }
        state.extend(counter.iter().map(Word::duplicate));
        state.push(block_len.duplicate());
        state.push(flags.duplicate());
        let zero = self.load::<8>(0, true)?;
        let mut schedule: [usize; 16] = std::array::from_fn(|i| i);
        const PERMUTATION: [usize; 16] = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];
        for _ in 0..7 {
            for (i, [a, b, c, d]) in [
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
                state[a] = self.add(&state[a], &state[b], &message[schedule[2 * i]])?;
                state[d] = self.xor_rotate_right(&state[d], &state[a], 16)?;
                state[c] = self.add(&state[c], &state[d], &zero)?;
                state[b] = self.xor_rotate_right(&state[b], &state[c], 12)?;
                state[a] = self.add(&state[a], &state[b], &message[schedule[2 * i + 1]])?;
                state[d] = self.xor_rotate_right(&state[d], &state[a], 8)?;
                state[c] = self.add(&state[c], &state[d], &zero)?;
                state[b] = self.xor_rotate_right(&state[b], &state[c], 7)?;
            }
            schedule = std::array::from_fn(|i| schedule[PERMUTATION[i]]);
        }
        let mut output = Vec::with_capacity(16);
        for i in 0..8 {
            output.push(self.xor(&state[i], &state[i + 8])?);
        }
        for i in 0..8 {
            output.push(self.xor(&state[i + 8], &chaining[i])?);
        }
        Ok(output
            .try_into()
            .unwrap_or_else(|_| unreachable!("sixteen compression words")))
    }

    fn assign(&mut self, row: usize, column: usize, value: u64) -> Result<Cell, Error> {
        let value = self
            .faults
            .iter()
            .find(|fault| fault.row == row && fault.column == column)
            .map_or(Scalar::from(value), |fault| fault.value);
        Ok(self
            .region
            .assign_advice(self.config.advice[column], row, Value::known(value))?
            .cell())
    }

    fn tuple(&mut self, row: usize, operation: u64, values: [u64; 6]) -> Result<[Cell; 6], Error> {
        self.region
            .assign_fixed(self.config.operation, row, Scalar::from(operation))?;
        self.config.active.enable(self.region, row)?;
        let cells: Vec<_> = values
            .into_iter()
            .enumerate()
            .map(|(column, value)| self.assign(row, column, value))
            .collect::<Result<_, _>>()?;
        Ok(cells.try_into().expect("six word cells"))
    }

    fn load<const N: usize>(&mut self, value: u64, constant: bool) -> Result<Word<N>, Error> {
        if !matches!(N, 8 | 16) || (N == 8 && value > u64::from(u32::MAX)) {
            return Err(Error::Synthesis);
        }
        let mut cells = Vec::with_capacity(N);
        for i in 0..N {
            let nibble = (value >> (4 * i)) & 15;
            let cell = self.tuple(self.offset + i, LOAD, [nibble, 0, 0, 0, 0, 0])?[0];
            if constant {
                self.region.constrain_constant(cell, Scalar::from(nibble))?;
            }
            cells.push(cell);
        }
        self.offset += N;
        Ok(Word {
            cells: cells.try_into().expect("fixed word width"),
            value: Zeroizing::new(value),
        })
    }

    fn xor<const N: usize>(&mut self, a: &Word<N>, b: &Word<N>) -> Result<Word<N>, Error> {
        let output = Zeroizing::new(*a.value ^ *b.value);
        let mut cells = Vec::with_capacity(N);
        for i in 0..N {
            let assigned = self.tuple(
                self.offset + i,
                XOR,
                [
                    (*a.value >> (4 * i)) & 15,
                    (*b.value >> (4 * i)) & 15,
                    0,
                    (*output >> (4 * i)) & 15,
                    0,
                    0,
                ],
            )?;
            self.region.constrain_equal(assigned[0], a.cells[i])?;
            self.region.constrain_equal(assigned[1], b.cells[i])?;
            cells.push(assigned[3]);
        }
        self.offset += N;
        Ok(Word {
            cells: cells.try_into().expect("fixed word width"),
            value: output,
        })
    }

    fn add<const N: usize>(
        &mut self,
        a: &Word<N>,
        b: &Word<N>,
        c: &Word<N>,
    ) -> Result<Word<N>, Error> {
        let mut output = Zeroizing::new(0_u64);
        let mut carry = Zeroizing::new(0_u64);
        let mut cells = Vec::with_capacity(N);
        let mut previous_carry = None;
        for i in 0..N {
            let terms = Zeroizing::new([
                (*a.value >> (4 * i)) & 15,
                (*b.value >> (4 * i)) & 15,
                (*c.value >> (4 * i)) & 15,
            ]);
            let sum = Zeroizing::new(terms.iter().sum::<u64>() + *carry);
            *output |= (*sum & 15) << (4 * i);
            self.config.add.enable(self.region, self.offset + i)?;
            let assigned = self.tuple(
                self.offset + i,
                ADD,
                [terms[0], terms[1], terms[2], *sum & 15, *carry, *sum >> 4],
            )?;
            for (column, word) in [a, b, c].into_iter().enumerate() {
                self.region
                    .constrain_equal(assigned[column], word.cells[i])?;
            }
            if let Some(previous) = previous_carry {
                self.region.constrain_equal(assigned[4], previous)?;
            } else {
                self.region.constrain_constant(assigned[4], Scalar::ZERO)?;
            }
            previous_carry = Some(assigned[5]);
            *carry = *sum >> 4;
            cells.push(assigned[3]);
        }
        self.offset += N;
        Ok(Word {
            cells: cells.try_into().expect("fixed word width"),
            value: output,
        })
    }

    fn rotate_right<const N: usize>(
        &mut self,
        word: &Word<N>,
        bits: u32,
    ) -> Result<Word<N>, Error> {
        self.rotate_xor(word, None, bits)
    }

    fn xor_rotate_right<const N: usize>(
        &mut self,
        a: &Word<N>,
        b: &Word<N>,
        bits: u32,
    ) -> Result<Word<N>, Error> {
        self.rotate_xor(a, Some(b), bits)
    }

    fn rotate_xor<const N: usize>(
        &mut self,
        a: &Word<N>,
        b: Option<&Word<N>>,
        bits: u32,
    ) -> Result<Word<N>, Error> {
        let bits = bits % ((4 * N) as u32);
        let whole = (bits / 4) as usize;
        let remainder = bits % 4;
        if remainder == 0 {
            if let Some(b) = b {
                let xored = self.xor(a, b)?;
                return self.rotate_xor(&xored, None, bits);
            }
            let value = Zeroizing::new(if N == 8 {
                u64::from((*a.value as u32).rotate_right(bits))
            } else {
                a.value.rotate_right(bits)
            });
            return Ok(Word {
                cells: std::array::from_fn(|i| a.cells[(i + whole) % N]),
                value,
            });
        }
        let input = Zeroizing::new(*a.value ^ b.map_or(0, |word| *word.value));
        let output = Zeroizing::new(if N == 8 {
            u64::from((*input as u32).rotate_right(bits))
        } else {
            input.rotate_right(bits)
        });
        let mut cells = Vec::with_capacity(N);
        let mut low_cells = Vec::with_capacity(N);
        let mut next_low_cells = Vec::with_capacity(N);
        for i in 0..N {
            let source = (i + whole) % N;
            let a_nibble = (*a.value >> (4 * source)) & 15;
            let b_nibble = b.map_or(0, |word| (*word.value >> (4 * source)) & 15);
            let nibble = a_nibble ^ b_nibble;
            let low = nibble & ((1 << remainder) - 1);
            let next_low = (*input >> (4 * ((source + 1) % N))) & ((1 << remainder) - 1);
            let assigned = self.tuple(
                self.offset + i,
                ROTATE + u64::from(remainder) - 1,
                [
                    a_nibble,
                    b_nibble,
                    low,
                    (*output >> (4 * i)) & 15,
                    next_low,
                    nibble >> remainder,
                ],
            )?;
            self.region.constrain_equal(assigned[0], a.cells[source])?;
            if let Some(b) = b {
                self.region.constrain_equal(assigned[1], b.cells[source])?;
            } else {
                self.region.constrain_constant(assigned[1], Scalar::ZERO)?;
            }
            low_cells.push(assigned[2]);
            next_low_cells.push(assigned[4]);
            cells.push(assigned[3]);
        }
        for i in 0..N {
            self.region
                .constrain_equal(next_low_cells[i], low_cells[(i + 1) % N])?;
        }
        self.offset += N;
        Ok(Word {
            cells: cells.try_into().expect("fixed word width"),
            value: output,
        })
    }
}

#[path = "ram_lfe_word_tests.rs"]
mod tests;
