//! Test-only byte-layout experiment for the unavailable RAM-LFE relation.
//!
//! Two lookups share a finite table of bytes, nibble XOR, addition results,
//! and exact rotation split/rejoin tuples. Only typed, constrained byte cells
//! enter arithmetic. This is a capacity experiment, with no proof admission.
//! TODO: Qualify a complete private relation and all retained witness clearing.

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
const SPLIT: u64 = 4;
const JOIN: u64 = 11;
const TABLE_ROWS: usize = 1 + 256 + 256 + 3 * 256 + 7 * 2 * 256;
const HASH_TABLE_ROWS: usize = 1 + 256 + 256 + 3 * 256 + 3 * 2 * 256;

#[derive(Clone, Debug)]
struct ByteConfig {
    advice: [Column<Advice>; 6],
    table: [TableColumn; 4],
    operation: Column<Fixed>,
    selectors: [Selector; 4],
    all_rotations: bool,
}

impl ByteConfig {
    fn configure(
        meta: &mut ConstraintSystem<Scalar>,
        minimum_degree: usize,
        all_rotations: bool,
    ) -> Self {
        let advice = std::array::from_fn(|_| meta.advice_column());
        for column in advice {
            meta.enable_equality(column);
        }
        let constant = meta.fixed_column();
        meta.enable_constant(constant);
        let table = std::array::from_fn(|_| meta.lookup_table_column());
        let operation = meta.fixed_column();
        let selectors = std::array::from_fn(|_| meta.complex_selector());
        for second in [false, true] {
            meta.lookup("finite byte operations", |meta| {
                let v: [_; 6] =
                    std::array::from_fn(|i| meta.query_advice(advice[i], Rotation::cur()));
                let [load, xor, add, rotate] = selectors.map(|q| meta.query_selector(q));
                let tag = meta.query_fixed(operation, Rotation::cur());
                let sixteen = Expression::Constant(Scalar::from(16));
                let inputs = if second {
                    [
                        xor.clone() * Expression::Constant(Scalar::from(XOR))
                            + rotate.clone() * (tag + Expression::Constant(Scalar::from(7))),
                        xor.clone() * v[3].clone() + rotate.clone() * v[2].clone(),
                        xor.clone() * v[4].clone() + rotate.clone() * v[3].clone(),
                        xor * v[5].clone() + rotate * v[4].clone(),
                    ]
                } else {
                    [
                        tag,
                        load * v[0].clone()
                            + xor.clone() * (v[0].clone() - sixteen.clone() * v[3].clone())
                            + add.clone() * v[3].clone()
                            + rotate.clone() * v[0].clone(),
                        xor.clone() * (v[1].clone() - sixteen.clone() * v[4].clone())
                            + add * v[5].clone()
                            + rotate.clone() * v[1].clone(),
                        xor * (v[2].clone() - sixteen * v[5].clone()) + rotate * v[2].clone(),
                    ]
                };
                inputs.into_iter().zip(table).collect()
            });
        }
        meta.create_gate("exact radix256 addition and zero reserved cells", |meta| {
            let v: [_; 6] = std::array::from_fn(|i| meta.query_advice(advice[i], Rotation::cur()));
            let [load, _, add, rotate] = selectors.map(|q| meta.query_selector(q));
            let mut constraints = vec![
                add * (v[0].clone() + v[1].clone() + v[2].clone() + v[4].clone()
                    - v[3].clone()
                    - Expression::Constant(Scalar::from(256)) * v[5].clone()),
            ];
            constraints.extend(v[1..].iter().map(|value| load.clone() * value.clone()));
            constraints.push(rotate * v[5].clone());
            constraints
        });
        meta.set_minimum_degree(minimum_degree);
        Self {
            advice,
            table,
            operation,
            selectors,
            all_rotations,
        }
    }

    fn load_table(&self, layouter: &mut impl Layouter<Scalar>) -> Result<(), Error> {
        layouter.assign_table(
            || "finite byte table",
            |mut table| {
                let mut row = 0;
                let mut put = |values: [u64; 4]| -> Result<(), Error> {
                    for (column, value) in self.table.into_iter().zip(values) {
                        table.assign_cell(
                            || "tuple",
                            column,
                            row,
                            || Value::known(Scalar::from(value)),
                        )?;
                    }
                    row += 1;
                    Ok(())
                };
                put([0; 4])?;
                for byte in 0..256 {
                    put([LOAD, byte, 0, 0])?;
                }
                for a in 0..16 {
                    for b in 0..16 {
                        put([XOR, a, b, a ^ b])?;
                    }
                }
                for byte in 0..256 {
                    for carry in 0..3 {
                        put([ADD, byte, carry, 0])?;
                    }
                }
                for bits in 1..8 {
                    if !self.all_rotations && !matches!(bits, 1 | 4 | 7) {
                        continue;
                    }
                    for byte in 0..256 {
                        put([
                            SPLIT + bits - 1,
                            byte,
                            byte & ((1 << bits) - 1),
                            byte >> bits,
                        ])?;
                    }
                    for high in 0..(1 << (8 - bits)) {
                        for next_low in 0..(1 << bits) {
                            put([
                                JOIN + bits - 1,
                                high,
                                high + (next_low << (8 - bits)),
                                next_low,
                            ])?;
                        }
                    }
                }
                assert_eq!(
                    row,
                    if self.all_rotations {
                        TABLE_ROWS
                    } else {
                        HASH_TABLE_ROWS
                    }
                );
                Ok(())
            },
        )
    }
}

struct ByteWord<const N: usize> {
    cells: [Cell; N],
    value: Zeroizing<u64>,
}

impl<const N: usize> Drop for ByteWord<N> {
    fn drop(&mut self) {
        self.value.zeroize();
        CLEARED_WORDS.with(|count| count.set(count.get() + usize::from(*self.value == 0)));
    }
}
thread_local! {
    static CLEARED_WORDS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[derive(Clone, Copy, Debug)]
struct Fault {
    row: usize,
    column: usize,
    value: Scalar,
}

struct ByteRegion<'a, 'r> {
    config: &'a ByteConfig,
    region: &'a mut Region<'r, Scalar>,
    offset: usize,
    faults: &'a [Fault],
}

impl ByteRegion<'_, '_> {
    fn tuple(&mut self, row: usize, tag: u64, values: [u64; 6]) -> Result<[Cell; 6], Error> {
        self.region
            .assign_fixed(self.config.operation, row, Scalar::from(tag))?;
        let selector = match tag {
            LOAD => 0,
            XOR => 1,
            ADD => 2,
            _ => 3,
        };
        self.config.selectors[selector].enable(self.region, row)?;
        let cells: Vec<_> = values
            .into_iter()
            .enumerate()
            .map(|(column, value)| {
                let value = self
                    .faults
                    .iter()
                    .find(|fault| fault.row == row && fault.column == column)
                    .map_or(Scalar::from(value), |fault| fault.value);
                self.region
                    .assign_advice(self.config.advice[column], row, Value::known(value))
                    .map(|cell| cell.cell())
            })
            .collect::<Result<_, _>>()?;
        Ok(cells.try_into().expect("six byte cells"))
    }

    fn load<const N: usize>(&mut self, value: u64, constant: bool) -> Result<ByteWord<N>, Error> {
        if !matches!(N, 4 | 8) || (N == 4 && value > u64::from(u32::MAX)) {
            return Err(Error::Synthesis);
        }
        let mut cells = Vec::with_capacity(N);
        for i in 0..N {
            let byte = (value >> (8 * i)) & 255;
            let cell = self.tuple(self.offset + i, LOAD, [byte, 0, 0, 0, 0, 0])?[0];
            if constant {
                self.region.constrain_constant(cell, Scalar::from(byte))?;
            }
            cells.push(cell);
        }
        self.offset += N;
        Ok(ByteWord {
            cells: cells.try_into().expect("fixed byte width"),
            value: Zeroizing::new(value),
        })
    }

    fn add<const N: usize>(
        &mut self,
        a: &ByteWord<N>,
        b: &ByteWord<N>,
        c: &ByteWord<N>,
    ) -> Result<ByteWord<N>, Error> {
        let mut output = Zeroizing::new(0_u64);
        let mut carry = Zeroizing::new(0_u64);
        let mut previous = None;
        let mut cells = Vec::with_capacity(N);
        for i in 0..N {
            let terms = Zeroizing::new([
                (*a.value >> (8 * i)) & 255,
                (*b.value >> (8 * i)) & 255,
                (*c.value >> (8 * i)) & 255,
            ]);
            let sum = Zeroizing::new(terms.iter().sum::<u64>() + *carry);
            let assigned = self.tuple(
                self.offset + i,
                ADD,
                [terms[0], terms[1], terms[2], *sum & 255, *carry, *sum >> 8],
            )?;
            for (j, word) in [a, b, c].into_iter().enumerate() {
                self.region.constrain_equal(assigned[j], word.cells[i])?;
            }
            if let Some(previous) = previous {
                self.region.constrain_equal(assigned[4], previous)?;
            } else {
                self.region.constrain_constant(assigned[4], Scalar::ZERO)?;
            }
            previous = Some(assigned[5]);
            *carry = *sum >> 8;
            *output |= (*sum & 255) << (8 * i);
            cells.push(assigned[3]);
        }
        self.offset += N;
        Ok(ByteWord {
            cells: cells.try_into().expect("fixed byte width"),
            value: output,
        })
    }

    fn xor<const N: usize>(
        &mut self,
        a: &ByteWord<N>,
        b: &ByteWord<N>,
    ) -> Result<ByteWord<N>, Error> {
        let output = Zeroizing::new(*a.value ^ *b.value);
        let mut cells = Vec::with_capacity(N);
        for i in 0..N {
            let av = (*a.value >> (8 * i)) & 255;
            let bv = (*b.value >> (8 * i)) & 255;
            let out = av ^ bv;
            let assigned = self.tuple(
                self.offset + i,
                XOR,
                [av, bv, out, av >> 4, bv >> 4, out >> 4],
            )?;
            self.region.constrain_equal(assigned[0], a.cells[i])?;
            self.region.constrain_equal(assigned[1], b.cells[i])?;
            cells.push(assigned[2]);
        }
        self.offset += N;
        Ok(ByteWord {
            cells: cells.try_into().expect("fixed byte width"),
            value: output,
        })
    }

    fn rotate_right<const N: usize>(
        &mut self,
        word: &ByteWord<N>,
        bits: u32,
    ) -> Result<ByteWord<N>, Error> {
        let bits = bits % (8 * N) as u32;
        let whole = (bits / 8) as usize;
        let remainder = bits % 8;
        if !self.config.all_rotations && !matches!(remainder, 0 | 1 | 4 | 7) {
            return Err(Error::Synthesis);
        }
        let output = Zeroizing::new(if N == 4 {
            u64::from((*word.value as u32).rotate_right(bits))
        } else {
            word.value.rotate_right(bits)
        });
        if remainder == 0 {
            return Ok(ByteWord {
                cells: std::array::from_fn(|i| word.cells[(i + whole) % N]),
                value: output,
            });
        }
        let mut cells = Vec::with_capacity(N);
        let mut low_cells = Vec::with_capacity(N);
        let mut next_cells = Vec::with_capacity(N);
        for i in 0..N {
            let source = (i + whole) % N;
            let byte = (*word.value >> (8 * source)) & 255;
            let low = byte & ((1 << remainder) - 1);
            let next = (*word.value >> (8 * ((source + 1) % N))) & ((1 << remainder) - 1);
            let assigned = self.tuple(
                self.offset + i,
                SPLIT + u64::from(remainder) - 1,
                [
                    byte,
                    low,
                    byte >> remainder,
                    (*output >> (8 * i)) & 255,
                    next,
                    0,
                ],
            )?;
            self.region
                .constrain_equal(assigned[0], word.cells[source])?;
            low_cells.push(assigned[1]);
            next_cells.push(assigned[4]);
            cells.push(assigned[3]);
        }
        for i in 0..N {
            self.region
                .constrain_equal(next_cells[i], low_cells[(i + 1) % N])?;
        }
        self.offset += N;
        Ok(ByteWord {
            cells: cells.try_into().expect("fixed byte width"),
            value: output,
        })
    }
}

#[path = "ram_lfe_byte_tests.rs"]
mod tests;
